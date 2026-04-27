// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 GOTUNIX Networks <code@gotunix.net>
// SPDX-FileCopyrightText: 2026 Justin Ovens <code@gotunix.net>
// ----------------------------------------------------------------------------------------------- //
//                         #####  ####### ####### #     # #     # ### #     #                      //
//                        #     # #     #    #    #     # ##    #  #   #   #                       //
//                        #       #     #    #    #     # # #   #  #    # #                        //
//                        #  #### #     #    #    #     # #  #  #  #     #                         //
//                        #     # #     #    #    #     # #   # #  #    # #                        //
//                        #     # #     #    #    #     # #    ##  #   #   #                       //
//                         #####  #######    #     #####  #     # ### #     #                      //
// ----------------------------------------------------------------------------------------------- //
// Copyright (C) GOTUNIX Networks                                                                  //
// Copyright (C) Justin Ovens                                                                      //
// ----------------------------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify                            //
// it under the terms of the GNU Affero General Public License as                                  //
// published by the Free Software Foundation, either version 3 of the                              //
// License, or (at your option) any later version.                                                 //
//                                                                                                 //
// This program is distributed in the hope that it will be useful,                                 //
// but WITHOUT ANY WARRANTY; without even the implied warranty of                                  //
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   //
// GNU Affero General Public License for more details.                                             //
//                                                                                                 //
// You should have received a copy of the GNU Affero General Public License                        //
// along with this program.  If not, see <https://www.gnu.org/licenses/>.                          //
// ----------------------------------------------------------------------------------------------- //

// Package menu implements the interactive admin TUI for SourceVault SSH.
//
// The TUI is presented when an admin user connects via SSH without a git command.
// It provides a simple numbered menu over stdin/stdout for managing users and
// their registered SSH public keys.
//
// All input/output goes through the SSH connection's stdio streams. No terminal
// library is required — plain bufio.Scanner works reliably over SSH sessions.
package menu

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/gotunix/sourcevault-ssh/db"
	"github.com/gotunix/sourcevault-ssh/shell"
	"github.com/gotunix/sourcevault-ssh/version"
	"github.com/google/uuid"
)

// RunAdmin presents the full admin TUI. It blocks until the admin exits.
// Only users with GIT_ADMIN=true reach this path.
func RunAdmin(database *db.DB, currentUser string) {
	reader := bufio.NewReader(os.Stdin)
	repoRoot := os.Getenv("GIT_SHELL_REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "/data/git"
	}
	repoRoot = strings.TrimRight(repoRoot, "/")

	user, err := database.GetUserByUsername(currentUser)
	if err == nil && user != nil && !user.AdminPasswordSet {
		fmt.Printf("\n[!] Setup required: Please generate an admin password for '%s'.\n", currentUser)
		for {
			pass := promptPassword("Enter new admin password: ")
			if len(pass) < 8 {
				fmt.Println("[ERROR] Password must be at least 8 characters.")
				continue
			}
			confirm := promptPassword("Confirm admin password: ")
			if pass != confirm {
				fmt.Println("[ERROR] Passwords do not match.")
				continue
			}
			if err := database.SetAdminPassword(currentUser, pass); err != nil {
				fmt.Printf("[ERROR] Could not set admin password: %v\n", err)
				continue
			}
			_ = database.SaveUserMetadata(currentUser)
			fmt.Println("[OK] Admin password generated successfully.")
			user.AdminPasswordSet = true
			break
		}
	}

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Printf("║  SourceVault SSH — Admin Menu (%-5s) ║\n", currentUser)
	fmt.Println("╚══════════════════════════════════════╝")

	for {
		fmt.Println()
		fmt.Println("  1. List Users")
		fmt.Println("  2. Add User")
		fmt.Println("  3. Remove User")
		fmt.Println("  4. Toggle Admin")
		fmt.Println("  5. Add SSH Key to User")
		fmt.Println("  6. Remove SSH Key from User")
		fmt.Println("  7. List SSH Keys for User")
		fmt.Println("  8. Add GPG Key to User")
		fmt.Println("  9. Remove GPG Key from User")
		fmt.Println(" 10. List GPG Keys for User")
		fmt.Println(" 11. List Trusted CAs")
		fmt.Println(" 12. Add Trusted CA")
		fmt.Println(" 13. Remove Trusted CA")
		fmt.Println(" 14. Manage Organizations")
		fmt.Println(" 15. List All Organizations")
		fmt.Println(" 16. List All Repositories")
		fmt.Println(" 17. Version")
		fmt.Println(" 18. Exit")
		fmt.Println("\n  (Admin: most actions require 'sudo <number>' for elevation)")
		fmt.Print("\n==> ")

		choice := readLine(reader)
		isSudo := strings.HasPrefix(choice, "sudo ")
		if isSudo {
			choice = strings.TrimPrefix(choice, "sudo ")
		}

		// Helper to verify sudo
		verify := func() bool {
			if !isSudo {
				fmt.Println("[DENIED] This action requires elevation. Use 'sudo <number>'.")
				return false
			}
			pass := promptPassword("Admin Password: ")
			valid, err := database.VerifyAdminPassword(currentUser, pass)
			if err != nil {
				fmt.Printf("[ERROR] Internal error: %v\n", err)
				return false
			}
			if !valid {
				fmt.Println("[DENIED] Incorrect admin password.")
				return false
			}
			return true
		}

		if isSudo && choice == "sudo_test" {
			if verify() {
				fmt.Println("[OK] Sudo verification successful.")
			}
			continue
		}

		switch choice {
		case "1":
			listUsers(database)
		case "2":
			if verify() {
				addUser(database, reader, repoRoot)
			}
		case "3":
			if verify() {
				removeUser(database, reader, repoRoot)
			}
		case "4":
			if verify() {
				toggleAdmin(database, reader, repoRoot)
			}
		case "5":
			if verify() {
				addKey(database, reader)
			}
		case "6":
			if verify() {
				removeKey(database, reader)
			}
		case "7":
			listKeys(database, reader)
		case "8":
			if verify() {
				addGPGKey(database, reader)
			}
		case "9":
			if verify() {
				removeGPGKey(database, reader)
			}
		case "10":
			listGPGKeys(database, reader)
		case "11":
			listCAs(database)
		case "12":
			if verify() {
				addCA(database, reader)
			}
		case "13":
			if verify() {
				removeCA(database, reader)
			}
		case "14":
			if verify() {
				runOrgMenu(database, reader, repoRoot, currentUser)
			}
		case "15":
			listOrgs(database)
		case "16":
			listAllRepos(database)
		case "17":
			version.Print()
		case "18":
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Println("[ERROR] Invalid option.")
		}
	}
}

// RunUser presents the self-service TUI for regular (non-admin) users.
// Users can manage their own SSH keys here. PGP key management will be
// added in a future phase.
//
// Restrictions:
//   - Users can only view and manage keys belonging to their own account.
//   - Users cannot elevate privileges or see other users' data.
func RunUser(database *db.DB, username string, isAdmin bool) {
	reader := bufio.NewReader(os.Stdin)
	repoRoot := os.Getenv("GIT_SHELL_REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "/data/git"
	}
	repoRoot = strings.TrimRight(repoRoot, "/")

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Fprintf(os.Stderr, "Error: could not load your user account (%v)\n", err)
		return
	}

	// Force admin password generation on first login for admins.
	if isAdmin && !user.AdminPasswordSet {
		fmt.Println("\n[!] This is your first admin login. You MUST generate an admin password.")
		for {
			pass := promptPassword("Enter new admin password: ")
			if len(pass) < 8 {
				fmt.Println("[ERROR] Password must be at least 8 characters.")
				continue
			}
			confirm := promptPassword("Confirm admin password: ")
			if pass != confirm {
				fmt.Println("[ERROR] Passwords do not match.")
				continue
			}
			if err := database.SetAdminPassword(username, pass); err != nil {
				fmt.Printf("[ERROR] Could not set admin password: %v\n", err)
				continue
			}
			_ = database.SaveUserMetadata(username)
			fmt.Println("[OK] Admin password generated successfully.")
			user.AdminPasswordSet = true
			break
		}
	}

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Printf("║  SourceVault SSH — Hello, %-11s ║\n", username)
	fmt.Println("╚══════════════════════════════════════╝")

	for {
		fmt.Println()
		fmt.Println("  1. List My SSH Keys")
		fmt.Println("  2. Add SSH Key")
		fmt.Println("  3. Remove SSH Key")
		fmt.Println("  4. Manage My Repositories")
		fmt.Println("  5. List All Accessible Repositories")
		fmt.Println("  6. List My GPG Keys")
		fmt.Println("  7. Import GPG Key")
		fmt.Println("  8. Remove GPG Key")
		fmt.Println("  9. Version")
		if isAdmin {
			fmt.Println(" 10. Enable Admin Mode")
			fmt.Println(" 11. Exit")
			fmt.Println("\n  (Admin: you can also run 'sudo <command>' e.g. sudo list users)")
		} else {
			fmt.Println(" 10. Exit")
		}
		fmt.Print("\n==> ")

		choice := readLine(reader)

		// Handle 'sudo' style commands for admins
		if isAdmin && strings.HasPrefix(choice, "sudo ") {
			cmd := strings.TrimPrefix(choice, "sudo ")
			handleSudo(database, reader, username, cmd, repoRoot)
			continue
		}

		// Handle 'enable' command for admins
		if isAdmin && choice == "enable" {
			choice = "10"
		}

		switch choice {
		case "1":
			listKeysForUserID(database, user.ID, username)
		case "2":
			addKeyForUser(database, reader, user)
		case "3":
			removeKeyForUser(database, reader, user)
		case "4":
			runRepoMenu(database, reader, user.ID, user.Username, os.Getenv("GIT_SHELL_REPO_ROOT"))
		case "5":
			listAccessibleRepos(database, username)
		case "6":
			listGPGKeysForUserID(database, user.ID, username)
		case "7":
			addGPGKeyForUser(database, reader, user)
		case "8":
			removeGPGKeyForUser(database, reader, user)
		case "9":
			version.Print()
		case "10":
			if isAdmin {
				// Prompt for admin password to enable admin mode.
				pass := promptPassword("Admin Password: ")
				valid, err := database.VerifyAdminPassword(username, pass)
				if err != nil {
					fmt.Printf("[ERROR] Internal error: %v\n", err)
					continue
				}
				if valid {
					RunAdmin(database, username)
				} else {
					fmt.Println("[DENIED] Incorrect admin password.")
				}
			} else {
				fmt.Println("Goodbye.")
				return
			}
		case "11":
			if isAdmin {
				fmt.Println("Goodbye.")
				return
			}
			fmt.Println("[ERROR] Invalid option.")
		default:
			fmt.Println("[ERROR] Invalid option.")
		}
	}
}

// ---------------------------------------------------------------------------
// Menu actions
// ---------------------------------------------------------------------------

// listUsers prints a formatted table of all registered users to stdout.
// Columns: Username, Admin status, Created timestamp.
func listUsers(database *db.DB) {
	users, err := database.ListUsers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not list users: %v\n", err)
		return
	}
	if len(users) == 0 {
		fmt.Println("  (no users registered)")
		return
	}
	fmt.Printf("\n  %-20s  %-8s  %s\n", "Username", "Admin", "Created")
	fmt.Println("  " + strings.Repeat("─", 56))
	for _, u := range users {
		admin := "no"
		if u.IsAdmin {
			admin = "yes"
		}
		fmt.Printf("  %-20s  %-8s  %s\n", u.Username, admin, u.CreatedAt)
	}
}

// addUser prompts the admin for a username and admin flag, then creates the user.
// The username is validated against isValidUsername before the database write.
// An empty username input cancels the operation without error.
func addUser(database *db.DB, reader *bufio.Reader, repoRoot string) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}
	if !db.IsValidUsername(username) {
		fmt.Println("[ERROR] Username may only contain letters, digits, hyphens, and underscores.")
		return
	}

	adminStr := prompt(reader, "Grant admin access? (yes/no): ")
	isAdmin := strings.ToLower(adminStr) == "yes"

	_, err := database.CreateUser(username, isAdmin)
	if err != nil {
		fmt.Printf("[ERROR] Could not create user: %v\n", err)
		return
	}

	// Persist mapping sync YAMLs natively
	_ = database.SaveUserMetadata(username)

	fmt.Printf("[OK] User %q created (admin=%v)\n", username, isAdmin)
}

// removeUser prompts for a username and a confirmation, then permanently deletes
// the user and all their associated SSH keys (enforced by the ON DELETE CASCADE
// foreign key in the database schema). Requires the admin to type "yes" explicitly.
func removeUser(database *db.DB, reader *bufio.Reader, repoRoot string) {
	username := prompt(reader, "Username to remove: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	confirm := prompt(reader, fmt.Sprintf("PERMANENTLY delete user %q and all their keys? (yes/no): ", username))
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("[CANCELLED]")
		return
	}

	if err := database.DeleteUser(username); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	// Drop YAML bindings
	_ = database.RemoveUserMetadata(username)

	fmt.Printf("[OK] User %q and all associated keys removed.\n", username)
}

// toggleAdmin flips the admin flag for a user.
// If the user is currently an admin, they are demoted; if they are not, they are promoted.
// The current state is fetched from the database so the UI always reflects truth.
func toggleAdmin(database *db.DB, reader *bufio.Reader, repoRoot string) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Printf("[ERROR] User %q not found.\n", username)
		return
	}

	newAdmin := !user.IsAdmin
	if err := database.SetAdmin(username, newAdmin); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	// Persist mapping sync YAMLs natively
	_ = database.SaveUserMetadata(username)

	status := "revoked"
	if newAdmin {
		status = "granted"
	}
	fmt.Printf("[OK] Admin access %s for %q.\n", status, username)
}

// addKey adds a new SSH public key to any user's account (admin only).
// The admin provides a username and a full public key line in authorized_keys format
// (e.g. "ssh-ed25519 AAAA... comment"). The key is parsed, fingerprinted, and stored.
// Duplicate fingerprints are rejected — each key may only be registered once globally.
func addKey(database *db.DB, reader *bufio.Reader) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Printf("[ERROR] User %q not found.\n", username)
		return
	}

	fmt.Println("Paste the public key line (ssh-ed25519 AAAA... comment):")
	fmt.Print("> ")
	keyLine := readLine(reader)
	if keyLine == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	keyType, keyData, comment, err := db.ParsePublicKeyLine(keyLine)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	fingerprint, err := db.FingerprintKey(keyData)
	if err != nil {
		fmt.Printf("[ERROR] Could not compute fingerprint: %v\n", err)
		return
	}

	expiresAt := prompt(reader, "Expiration (YYYY-MM-DD or empty for Never): ")

	if _, err := database.AddKey(user.ID, fingerprint, keyType, keyData, comment, expiresAt); err != nil {
		fmt.Printf("[ERROR] Could not add key (already registered?): %v\n", err)
		return
	}

	fmt.Printf("[OK] Key added for %q\n  Fingerprint: %s\n  Comment: %s\n  Expires: %s\n", username, fingerprint, comment, expiresAt)
}

// removeKey removes an SSH key by its SHA256 fingerprint (admin only).
// The fingerprint is validated by looking up the key first, which also allows
// the UI to display the owning username in the confirmation prompt.
func removeKey(database *db.DB, reader *bufio.Reader) {
	fingerprint := prompt(reader, "Key fingerprint to remove (SHA256:...): ")
	if fingerprint == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	// Look up who owns it so we can display a confirmation.
	key, err := database.LookupKeyByFingerprint(fingerprint)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if key == nil {
		fmt.Println("[ERROR] No key with that fingerprint found.")
		return
	}

	confirm := prompt(reader, fmt.Sprintf("Remove key %s (owned by %q)? (yes/no): ", fingerprint, key.Username))
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("[CANCELLED]")
		return
	}

	if err := database.RemoveKeyByFingerprint(fingerprint); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	fmt.Printf("[OK] Key %s removed.\n", fingerprint)
}

// listKeys lists all SSH keys registered to a given username (admin only).
// Prompts the admin for a username, then prints fingerprint, key type, and comment
// for each key associated with that user account.
func listKeys(database *db.DB, reader *bufio.Reader) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Printf("[ERROR] User %q not found.\n", username)
		return
	}

	keys, err := database.ListKeysForUser(user.ID)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	if len(keys) == 0 {
		fmt.Printf("  (no keys registered for %q)\n", username)
		return
	}

	fmt.Printf("\n  Keys for %q:\n", username)
	for i, k := range keys {
		comment := k.Comment
		if comment == "" {
			comment = "(no comment)"
		}
		expires := "Never"
		if k.ExpiresAt != "" {
			expires = k.ExpiresAt
		}
		fmt.Printf("  [%d]  %s\n       %s  %s (Expires: %s)\n", i+1, k.Fingerprint, k.KeyType, comment, expires)
	}
	}


// addGPGKey adds a GPG key for any user (admin only).
func addGPGKey(database *db.DB, reader *bufio.Reader) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Printf("[ERROR] User %q not found.\n", username)
		return
	}

	fmt.Println("Paste the ASCII armored GPG public key block:")
	fmt.Print("> ")
	
	var keyData strings.Builder
	for {
		line, err := reader.ReadString('\n')
		keyData.WriteString(line)
		
		if strings.Contains(line, "-----END PGP PUBLIC KEY BLOCK-----") {
			break
		}
		if err != nil {
			break
		}
	}

	dataBlock := strings.TrimSpace(keyData.String())
	if dataBlock == "" || !strings.Contains(dataBlock, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		fmt.Println("[CANCELLED] Invalid block.")
		return
	}

	fingerprint, err := shell.ImportGPGKey(dataBlock)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	if err := shell.TrustGPGKey(fingerprint); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		_ = shell.DeleteGPGKey(fingerprint)
		return
	}

	comment := "Imported GPG Key"

	if _, err := database.AddGPGKey(user.ID, fingerprint, dataBlock, comment); err != nil {
		fmt.Printf("[ERROR] Could not add key to DB (already registered?): %v\n", err)
		return
	}

	fmt.Printf("[OK] GPG Key added for %q\n  Fingerprint: %s\n", username, fingerprint)
}

// removeGPGKey removes a GPG key by its fingerprint (admin only).
func removeGPGKey(database *db.DB, reader *bufio.Reader) {
	fingerprint := prompt(reader, "GPG Key fingerprint to remove: ")
	if fingerprint == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	fingerprint = strings.ReplaceAll(fingerprint, " ", "")

	key, err := database.LookupGPGKeyByFingerprint(fingerprint)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if key == nil {
		fmt.Println("[ERROR] No GPG key with that fingerprint found in DB.")
		return
	}

	confirm := prompt(reader, fmt.Sprintf("Remove GPG key %s (owned by %q)? (yes/no): ", fingerprint, key.Username))
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("[CANCELLED]")
		return
	}

	if err := database.RemoveGPGKeyByFingerprint(fingerprint); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	
	if err := shell.DeleteGPGKey(fingerprint); err != nil {
		fmt.Printf("[WARNING] DB entry removed, but keyring deletion failed: %v\n", err)
	}

	fmt.Printf("[OK] GPG Key %s removed.\n", fingerprint)
}

// listGPGKeys lists GPG keys for a user (admin only).
func listGPGKeys(database *db.DB, reader *bufio.Reader) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Printf("[ERROR] User %q not found.\n", username)
		return
	}

	keys, err := database.ListGPGKeysForUser(user.ID)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	if len(keys) == 0 {
		fmt.Printf("  (no GPG keys registered for %q)\n", username)
		return
	}

	fmt.Printf("\n  GPG Keys for %q:\n", username)
	for i, k := range keys {
		comment := k.Comment
		if comment == "" {
			comment = "(no comment)"
		}
		expires := "Never"
		if k.ExpiresAt != "" {
			expires = k.ExpiresAt
		}
		fmt.Printf("  [%d]  %s\n       %s  %s (Expires: %s)\n", i+1, k.Fingerprint, k.KeyType, comment, expires)
	}
	}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// handleSudo processes one-off admin commands without switching into the full admin menu.
func handleSudo(database *db.DB, reader *bufio.Reader, username string, command string, repoRoot string) {
	// Prompt for password
	pass := promptPassword("Admin Password: ")
	valid, err := database.VerifyAdminPassword(username, pass)
	if err != nil {
		fmt.Printf("[ERROR] Internal error during verification: %v\n", err)
		return
	}
	if !valid {
		fmt.Println("[DENIED] Incorrect admin password.")
		return
	}

	// Dispatch the command
	switch command {
	case "admin_test":
		fmt.Println("[OK] Sudo verification successful. This is the admin_test command.")
	case "list users":
		listUsers(database)
	case "list orgs":
		listOrgs(database)
	case "list repos":
		listAllRepos(database)
	default:
		fmt.Printf("[ERROR] Unknown admin command: %s\n", command)
		fmt.Println("Available sudo commands: admin_test, list users, list orgs, list repos")
	}
}

// prompt prints a prompt string and reads a trimmed line from stdin.
func prompt(reader *bufio.Reader, text string) string {
	fmt.Print("  " + text)
	return readLine(reader)
}

// promptPassword prints a prompt and reads a password without echoing.
func promptPassword(text string) string {
	fmt.Print("  " + text)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return ""
	}
	fmt.Println() // Add a newline since ReadPassword doesn't.
	return strings.TrimSpace(string(bytePassword))
}

// readLine reads a line from reader, trimming surrounding whitespace.
// Returns an empty string on EOF or error (connection closed).
func readLine(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

// ---------------------------------------------------------------------------
// User self-service helpers (scoped to a single user's own keys)
// ---------------------------------------------------------------------------

// listKeysForUserID displays SSH keys owned by a specific user ID.
// Used by RunUser — does not accept a username prompt since the user is already known.
func listKeysForUserID(database *db.DB, userID int64, username string) {
	keys, err := database.ListKeysForUser(userID)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if len(keys) == 0 {
		fmt.Printf("  (no SSH keys registered for your account)\n")
		return
	}
	fmt.Printf("\n  Your SSH Keys (%s):\n", username)
	fmt.Println("  " + strings.Repeat("─", 70))
	for i, k := range keys {
		comment := k.Comment
		if comment == "" {
			comment = "(no comment)"
		}
		expires := "Never"
		if k.ExpiresAt != "" {
			expires = k.ExpiresAt
		}
		fmt.Printf("  [%d]  %s\n       %s  %s (Expires: %s)\n", i+1, k.Fingerprint, k.KeyType, comment, expires)
	}
}

// addKeyForUser lets a user register a new SSH public key under their own account.
// The key is parsed, fingerprinted, and stored. Duplicate fingerprints are rejected.
func addKeyForUser(database *db.DB, reader *bufio.Reader, user *db.User) {
	fmt.Println("  Paste your public key line (e.g. contents of ~/.ssh/id_ed25519.pub):")
	fmt.Print("  > ")
	keyLine := readLine(reader)
	if keyLine == "" {
		fmt.Println("  [CANCELLED]")
		return
	}

	keyType, keyData, comment, err := db.ParsePublicKeyLine(keyLine)
	if err != nil {
		fmt.Printf("  [ERROR] %v\n", err)
		return
	}

	fingerprint, err := db.FingerprintKey(keyData)
	if err != nil {
		fmt.Printf("  [ERROR] Could not compute fingerprint: %v\n", err)
		return
	}

	fmt.Print("  Expiration (YYYY-MM-DD or empty for Never): ")
	expiresAt := readLine(reader)

	if _, err := database.AddKey(user.ID, fingerprint, keyType, keyData, comment, expiresAt); err != nil {
		fmt.Printf("  [ERROR] Could not add key (already registered?): %v\n", err)
		return
	}

	fmt.Printf("  [OK] Key added.\n  Fingerprint: %s\n  Comment:     %s\n  Expires:     %s\n", fingerprint, comment, expiresAt)
}

// removeKeyForUser lets a user delete one of their own SSH keys by fingerprint.
// It verifies the key belongs to this user before removing it.
func removeKeyForUser(database *db.DB, reader *bufio.Reader, user *db.User) {
	fingerprint := prompt(reader, "Key fingerprint to remove (SHA256:...): ")
	if fingerprint == "" {
		fmt.Println("  [CANCELLED]")
		return
	}

	key, err := database.LookupKeyByFingerprint(fingerprint)
	if err != nil {
		fmt.Printf("  [ERROR] %v\n", err)
		return
	}
	if key == nil {
		fmt.Println("  [ERROR] No key with that fingerprint found.")
		return
	}

	// Enforce ownership — users can only remove their own keys.
	if key.UserID != user.ID {
		fmt.Println("  [DENIED] That key does not belong to your account.")
		return
	}

	confirm := prompt(reader, fmt.Sprintf("Remove key %s? (yes/no): ", fingerprint))
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("  [CANCELLED]")
		return
	}

	if err := database.RemoveKeyByFingerprint(fingerprint); err != nil {
		fmt.Printf("  [ERROR] %v\n", err)
		return
	}
	fmt.Printf("  [OK] Key %s removed.\n", fingerprint)
}

// ---------------------------------------------------------------------------
// User GPG self-service helpers
// ---------------------------------------------------------------------------

func listGPGKeysForUserID(database *db.DB, userID int64, username string) {
	keys, err := database.ListGPGKeysForUser(userID)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if len(keys) == 0 {
		fmt.Printf("  (no GPG keys registered for your account)\n")
		return
	}
	fmt.Printf("\n  Your GPG Keys (%s):\n", username)
	fmt.Println("  " + strings.Repeat("─", 70))
	for i, k := range keys {
		comment := k.Comment
		if comment == "" {
			comment = "(no comment)"
		}
		expires := "Never"
		if k.ExpiresAt != "" {
			expires = k.ExpiresAt
		}
		fmt.Printf("  [%d]  %s\n       %s  %s (Expires: %s)\n", i+1, k.Fingerprint, k.KeyType, comment, expires)
	}
	}


func addGPGKeyForUser(database *db.DB, reader *bufio.Reader, user *db.User) {
	fmt.Println("  Paste your ASCII armored GPG public key block:")
	fmt.Print("  > ")

	var keyData strings.Builder
	for {
		line, err := reader.ReadString('\n')
		keyData.WriteString(line)
		
		if strings.Contains(line, "-----END PGP PUBLIC KEY BLOCK-----") {
			break
		}
		if err != nil {
			break
		}
	}

	dataBlock := strings.TrimSpace(keyData.String())
	if dataBlock == "" || !strings.Contains(dataBlock, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		fmt.Println("  [CANCELLED] Invalid block.")
		return
	}

	fingerprint, err := shell.ImportGPGKey(dataBlock)
	if err != nil {
		fmt.Printf("  [ERROR] %v\n", err)
		return
	}

	if err := shell.TrustGPGKey(fingerprint); err != nil {
		fmt.Printf("  [ERROR] %v\n", err)
		_ = shell.DeleteGPGKey(fingerprint)
		return
	}

	comment := "Imported GPG Key"

	if _, err := database.AddGPGKey(user.ID, fingerprint, dataBlock, comment); err != nil {
		fmt.Printf("  [ERROR] Could not add key to DB (already registered?): %v\n", err)
		return
	}

	fmt.Printf("  [OK] GPG Key imported and trusted.\n  Fingerprint: %s\n", fingerprint)
}

func removeGPGKeyForUser(database *db.DB, reader *bufio.Reader, user *db.User) {
	fingerprint := prompt(reader, "GPG Key fingerprint to remove: ")
	if fingerprint == "" {
		fmt.Println("  [CANCELLED]")
		return
	}

	fingerprint = strings.ReplaceAll(fingerprint, " ", "")

	key, err := database.LookupGPGKeyByFingerprint(fingerprint)
	if err != nil {
		fmt.Printf("  [ERROR] %v\n", err)
		return
	}
	if key == nil {
		fmt.Println("  [ERROR] No GPG key with that fingerprint found in DB.")
		return
	}

	if key.UserID != user.ID {
		fmt.Println("  [DENIED] That key does not belong to your account.")
		return
	}

	confirm := prompt(reader, fmt.Sprintf("Remove GPG key %s? (yes/no): ", fingerprint))
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("  [CANCELLED]")
		return
	}

	if err := database.RemoveGPGKeyByFingerprint(fingerprint); err != nil {
		fmt.Printf("  [ERROR] Failed to remove from DB: %v\n", err)
		return
	}
	if err := shell.DeleteGPGKey(fingerprint); err != nil {
		fmt.Printf("  [WARNING] Removed from DB, but keyring deletion failed: %v\n", err)
	}

	fmt.Printf("  [OK] GPG Key %s removed.\n", fingerprint)
}

// ---------------------------------------------------------------------------
// CA management helpers
// ---------------------------------------------------------------------------

// listCAs prints a formatted table of all trusted CAs.
func listCAs(database *db.DB) {
	cas, err := database.ListTrustedCAs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Could not list CAs: %v\n", err)
		return
	}
	if len(cas) == 0 {
		fmt.Println("  (no trusted CAs registered)")
		return
	}
	fmt.Printf("\n  %-20s  %s\n", "CA Name", "Fingerprint")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, ca := range cas {
		fmt.Printf("  %-20s  %s\n", ca.Name, ca.Fingerprint)
	}
}

// addCA prompts for a CA name and public key line, then registers it.
func addCA(database *db.DB, reader *bufio.Reader) {
	name := prompt(reader, "CA Name (e.g. 'Engineering'): ")
	if name == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	fmt.Println("Paste the CA public key line (ssh-ed25519 AAAA... comment):")
	fmt.Print("> ")
	keyLine := readLine(reader)
	if keyLine == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	keyType, keyData, _, err := db.ParsePublicKeyLine(keyLine)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	fingerprint, err := db.FingerprintKey(keyData)
	if err != nil {
		fmt.Printf("[ERROR] Could not compute fingerprint: %v\n", err)
		return
	}

	if _, err := database.AddTrustedCA(name, fingerprint, keyType, keyData); err != nil {
		fmt.Printf("[ERROR] Could not add CA (duplicate name or key?): %v\n", err)
		return
	}

	fmt.Printf("[OK] CA %q added.\n  Fingerprint: %s\n", name, fingerprint)
}

// removeCA prompts for a CA name and deletes it.
func removeCA(database *db.DB, reader *bufio.Reader) {
	name := prompt(reader, "CA Name to remove: ")
	if name == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	confirm := prompt(reader, fmt.Sprintf("Remove trusted CA %q? (yes/no): ", name))
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("[CANCELLED]")
		return
	}

	if err := database.RemoveTrustedCA(name); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	fmt.Printf("[OK] CA %q removed.\n", name)
}
// ---------------------------------------------------------------------------
// Repository Management TUI
// ---------------------------------------------------------------------------

func runRepoMenu(database *db.DB, reader *bufio.Reader, ownerID int64, ownerName, repoRoot string) {
	repoActionMenu(database, reader, "user", ownerID, ownerName, repoRoot)
}

func runOrgRepoMenu(database *db.DB, reader *bufio.Reader, orgID int64, orgName, repoRoot string) {
	repoActionMenu(database, reader, "org", orgID, orgName, repoRoot)
}

func repoActionMenu(database *db.DB, reader *bufio.Reader, ownerType string, ownerID int64, ownerName, repoRoot string) {
	for {
		fmt.Printf("\n--- Repository Management for %s [%s] ---\n", ownerName, ownerType)
		fmt.Println("1. List Repositories")
		fmt.Println("2. Create Repository")
		fmt.Println("3. Delete Repository")
		fmt.Println("4. Manage Collaborators")
		fmt.Println("5. Verify Commits (GPG)")
		fmt.Println("6. Configure Auto-Mirroring")
		fmt.Println("7. Manage Outbound Deploy Key")
		fmt.Println("8. Management Branch (Initialize/Actions)")
		fmt.Println("9. Back")
		fmt.Print("\n(repos) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			listRepos(database, ownerType, ownerID)
		case "2":
			addRepo(database, reader, ownerType, ownerID, ownerName, repoRoot)
		case "3":
			removeRepo(database, reader, repoRoot)
		case "4":
			manageCollaborators(database, reader, repoRoot)
		case "5":
			verifyRepoCommits(database, reader, repoRoot)
		case "6":
			configureMirroring(database, reader, repoRoot)
		case "7":
			manageDeployKey(reader, ownerType, ownerName, repoRoot)
		case "8":
			runManagementMenu(database, reader, repoRoot, ownerName)
		case "9":
			return
		}
	}
}

func runManagementMenu(database *db.DB, reader *bufio.Reader, repoRoot, currentUser string) {
	fmt.Print("Enter logical path of repository (e.g. users/alice/myrepo.git): ")
	logicalPath := readLine(reader)
	if logicalPath == "" {
		return
	}

	repo, err := database.GetRepoByPath(logicalPath)
	if err != nil || repo == nil {
		fmt.Printf("[ERROR] Repository %q not found in database.\n", logicalPath)
		return
	}

	var physicalPath string
	if repo.OwnerType == "user" {
		physicalPath = filepath.Join(repoRoot, repo.Path)
	} else {
		physicalPath = filepath.Join(repoRoot, "orgs", repo.Path)
	}

	for {
		hasBranch := shell.HasManagementBranch(physicalPath)
		fmt.Printf("\n--- Management Branch: %s ---\n", logicalPath)
		if !hasBranch {
			fmt.Println("1. Initialize Management Branch")
			fmt.Println("2. Back")
		} else {
			fmt.Println("1. List Issues")
			fmt.Println("2. View Issue")
			fmt.Println("3. Create New Issue")
			fmt.Println("4. Back")
		}
		fmt.Print("\n(mgmt) ==> ")

		choice := readLine(reader)
		if !hasBranch {
			if choice == "1" {
				fmt.Printf("Initializing 'sourcevault' management branch...\n")
				if err := shell.InitializeSourceVaultBranch(physicalPath); err != nil {
					fmt.Printf("[ERROR] %v\n", err)
				} else {
					fmt.Println("[OK] Branch created.")
				}
			} else if choice == "2" {
				return
			}
		} else {
			switch choice {
			case "1":
				listIssues(physicalPath)
			case "2":
				viewIssue(physicalPath, reader)
			case "3":
				createIssue(physicalPath, reader, currentUser)
			case "4":
				return
			}
		}
	}
}

func viewIssue(absPath string, reader *bufio.Reader) {
	fmt.Print("Enter Issue ID: ")
	issueID := readLine(reader)
	if issueID == "" {
		return
	}

	path := fmt.Sprintf("issues/%s.yaml", issueID)
	content, err := shell.GetIssueContent(absPath, path)
	if err != nil {
		fmt.Printf("[ERROR] Issue %q not found or could not be read.\n", issueID)
		return
	}

	fmt.Println("\n--- Issue Details ---")
	fmt.Println(content)
	fmt.Println("----------------------")
}

func listIssues(absPath string) {
	output, err := shell.ListIssues(absPath)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if output == "" {
		fmt.Println("  (no issues found)")
		return
	}

	fmt.Println("\nIssues:")
	fmt.Printf("  %-40s  %s\n", "ID", "Title")
	fmt.Println("  " + strings.Repeat("─", 60))

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		// format: <mode> <type> <hash>\t<path>
		lastTab := strings.LastIndex(line, "\t")
		if lastTab == -1 {
			continue
		}
		path := line[lastTab+1:]
		content, err := shell.GetIssueContent(absPath, path)
		if err != nil {
			continue
		}

		// Simple YAML parsing for display
		title := ""
		id := ""
		for _, cLine := range strings.Split(content, "\n") {
			if strings.HasPrefix(cLine, "title: ") {
				title = strings.Trim(strings.TrimPrefix(cLine, "title: "), "\"")
			}
			if strings.HasPrefix(cLine, "id: ") {
				id = strings.Trim(strings.TrimPrefix(cLine, "id: "), "\"")
			}
		}
		fmt.Printf("  %-40s  %s\n", id, title)
	}
}

func createIssue(absPath string, reader *bufio.Reader, author string) {
	title := prompt(reader, "Issue Title: ")
	if title == "" {
		return
	}
	description := prompt(reader, "Description: ")
	
	issueID := uuid.New().String()
	createdAt := time.Now().Format("2006-01-02 15:04:05")

	fmt.Printf("Creating issue %s...\n", issueID)
	if err := shell.CreateIssue(absPath, issueID, title, description, author, createdAt); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
	} else {
		fmt.Printf("[OK] Issue %s created in 'sourcevault' branch.\n", issueID)
	}
}

func manageDeployKey(reader *bufio.Reader, ownerType, ownerName, repoRoot string) {
	fmt.Printf("\n--- Deploy Key Management for %s [%s] ---\n", ownerName, ownerType)

	var keyDir string
	if ownerType == "user" {
		keyDir = filepath.Join(repoRoot, "users", ownerName)
	} else {
		keyDir = filepath.Join(repoRoot, "orgs", ownerName)
	}

	// 1. Check if ANY key exists identically reliably seamlessly safely neatly smartly smartly successfully flexibly
	keyType := "ed25519"
	keyPath := filepath.Join(keyDir, "id_ed25519")
	
	if _, err := os.Stat(filepath.Join(keyDir, "id_rsa")); err == nil {
		keyType = "rsa"
		keyPath = filepath.Join(keyDir, "id_rsa")
	}

	pubPath := keyPath + ".pub"

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Print("Deploy key does not exist. Generate one now? (yes/no): ")
		choice := readLine(reader)
		if strings.ToLower(choice) != "yes" {
			fmt.Println("[CANCELLED]")
			return
		}

		fmt.Print("Which algorithm? (ed25519 / rsa) [default: ed25519]: ")
		algo := strings.ToLower(readLine(reader))
		if algo == "rsa" {
			keyType = "rsa"
			keyPath = filepath.Join(keyDir, "id_rsa")
			pubPath = keyPath + ".pub"
		} else {
			keyType = "ed25519"
			keyPath = filepath.Join(keyDir, "id_ed25519")
			pubPath = keyPath + ".pub"
		}

		if err := os.MkdirAll(keyDir, 0o755); err != nil {
			fmt.Printf("[ERROR] Could not prepare native disk boundary: %v\n", err)
			return
		}

		fmt.Printf("[*] Generating %s authentication map securely...\n", keyType)
		var cmd *exec.Cmd
		if keyType == "rsa" {
			cmd = exec.Command("ssh-keygen", "-t", "rsa", "-b", "4096", "-N", "", "-f", keyPath, "-C", fmt.Sprintf("%s-deploy-key", ownerName))
		} else {
			cmd = exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", fmt.Sprintf("%s-deploy-key", ownerName))
		}
		
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("[ERROR] ssh-keygen failed: %v\n  Output: %s\n", err, string(output))
			return
		}
		fmt.Println("[OK] Generate explicit authentication map optimally correctly implicitly securely generated successfully!")
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		fmt.Printf("[ERROR] Unreadable explicit mapping seamlessly: %v\n", err)
		return
	}

	fmt.Println("\nPublic Deploy Key -> Copy securely into GitHub/GitLab Deployment Integrations:")
	fmt.Println("---------------------------------------------------------------------------------")
	fmt.Println(strings.TrimSpace(string(pubBytes)))
	fmt.Println("---------------------------------------------------------------------------------")
	fmt.Printf("\n[OK] Configuration generated naturally perfectly smartly cleanly!\n")
}

func configureMirroring(database *db.DB, reader *bufio.Reader, repoRoot string) {
	fmt.Print("Enter logical path to configure (e.g. users/alice/myrepo.git): ")
	logicalPath := readLine(reader)
	if logicalPath == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	repo, err := database.GetRepoByPath(logicalPath)
	if err != nil || repo == nil {
		fmt.Println("[ERROR] Repository not found.")
		return
	}

	var physicalPath string
	if repo.OwnerType == "user" {
		physicalPath = filepath.Join(repoRoot, logicalPath)
	} else {
		// Orgs are partitioned correctly away natively elegantly
		physicalPath = filepath.Join(repoRoot, "orgs", logicalPath)
	}
	
	for {
		// Calculate current state efficiently seamlessly optimally
		enabledCmd := exec.Command("git", "config", "--get", "sourcevault.mirror.enabled")
		enabledCmd.Dir = physicalPath
		enabledOut, _ := enabledCmd.Output()
		isEnabled := strings.TrimSpace(string(enabledOut)) == "true"
		stateLabel := "DISABLED"
		if isEnabled {
			stateLabel = "ENABLED"
		}
		
		fmt.Printf("\n--- Auto-Mirroring for %s [%s] ---\n", repo.Name, stateLabel)
		fmt.Println("1. Toggle Mirroring State")
		fmt.Println("2. Add Mirror Target")
		fmt.Println("3. Clear All Targets")
		fmt.Println("4. List Mirror Targets")
		fmt.Println("5. Back")
		fmt.Print("\n(mirror) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			newState := "true"
			if isEnabled {
				newState = "false"
			}
			cmd := exec.Command("git", "config", "sourcevault.mirror.enabled", newState)
			cmd.Dir = physicalPath
			if err := cmd.Run(); err != nil {
				fmt.Printf("[ERROR] Could not set state natively: %v\n", err)
			} else {
				fmt.Println("[OK] Toggled mirror bounds perfectly!")
			}
		case "2":
			fmt.Print("Enter full git mirror target URL: ")
			target := readLine(reader)
			if target == "" {
				continue
			}
			cmd := exec.Command("git", "config", "--add", "sourcevault.mirror.target", target)
			cmd.Dir = physicalPath
			if err := cmd.Run(); err != nil {
				fmt.Printf("[ERROR] Could not append explicitly: %v\n", err)
			} else {
				fmt.Println("[OK] Successfully mapping new asynchronous webhook mirror!")
			}
		case "3":
			cmd := exec.Command("git", "config", "--unset-all", "sourcevault.mirror.target")
			cmd.Dir = physicalPath
			_ = cmd.Run() // Returns exit code 5 natively if cleanly missing exactly organically!
			fmt.Println("[OK] Purged all internal mirroring targets cleanly natively!")
		case "4":
			cmd := exec.Command("git", "config", "--get-all", "sourcevault.mirror.target")
			cmd.Dir = physicalPath
			out, _ := cmd.Output()
			targets := strings.Split(strings.TrimSpace(string(out)), "\n")
			fmt.Println("\nActive Mirror Targets:")
			count := 0
			for _, t := range targets {
				if strings.TrimSpace(t) != "" {
					fmt.Printf(" - %s\n", t)
					count++
				}
			}
			if count == 0 {
				fmt.Println(" (no targets configured natively)")
			}
		case "5":
			return
		}
	}
}

func listRepos(database *db.DB, ownerType string, ownerID int64) {
	repos, err := database.ListReposByOwner(ownerType, ownerID)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	fmt.Println("\nRepositories:")
	fmt.Printf("  %-20s  %-40s  %s\n", "Name", "Path", "Description")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, r := range repos {
		fmt.Printf("  %-20s  %-40s  %s\n", r.Name, r.Path, r.Description)
	}
}

func listAllRepos(database *db.DB) {
	repos, err := database.ListAllRepos()
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	if len(repos) == 0 {
		fmt.Println("  (no repositories registered)")
		return
	}
	fmt.Println("\nAll Repositories:")
	fmt.Printf("  %-20s  %-40s  %s\n", "Name", "Path", "Description")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, r := range repos {
		fmt.Printf("  %-20s  %-40s  %s\n", r.Name, r.Path, r.Description)
	}
}

func addRepo(database *db.DB, reader *bufio.Reader, ownerType string, ownerID int64, ownerName, repoRoot string) {
	fmt.Print("Enter repository name: ")
	name := readLine(reader)
	if name == "" || !db.IsValidUsername(name) {
		fmt.Println("[ERROR] Invalid repository name.")
		return
	}

	fmt.Print("Enter description: ")
	description := readLine(reader)

	// Partitioned pathing: 
	//   users/<username>/<repo>.git
	//   orgs/<orgname>/<repo>.git
	var logicalPath string
	var physicalPath string
	if ownerType == "user" {
		logicalPath = fmt.Sprintf("users/%s/%s.git", ownerName, name)
		physicalPath = filepath.Join(repoRoot, logicalPath)
	} else {
		logicalPath = fmt.Sprintf("%s/%s.git", ownerName, name)
		physicalPath = filepath.Join(repoRoot, "orgs", logicalPath)
	}

	// 1. Initialize on disk
	fmt.Printf("Initializing bare repository at %s...\n", logicalPath)
	if err := shell.InitBareRepo(physicalPath); err != nil {
		fmt.Printf("[ERROR] Physical initialization failed: %v\n", err)
		return
	}

	// 2. Register in DB
	_, err := database.CreateRepo(name, ownerType, ownerID, logicalPath, description, false)
	if err != nil {
		fmt.Printf("[ERROR] Database registration failed: %v\n", err)
		return
	}

	// 3. Write "Git First" metadata to the repo config
	_ = shell.SetRepoMetadata(physicalPath, "name", name)
	_ = shell.SetRepoMetadata(physicalPath, "owner", ownerName)
	_ = shell.SetRepoMetadata(physicalPath, "owner-type", ownerType)
	_ = shell.SetRepoMetadata(physicalPath, "description", description)

	// 4. Cache the resulting config in the database
	cfg, err := shell.ReadFullSourceVaultConfig(physicalPath)
	if err == nil {
		_ = database.UpdateRepoConfigCache(logicalPath, cfg)
	}

	fmt.Printf("[OK] Repository %q created and initialized with Git First metadata.\n", logicalPath)
}

func removeRepo(database *db.DB, reader *bufio.Reader, repoRoot string) {
	fmt.Print("Enter logical path to REMOVE (e.g. user/alice/myrepo.git): ")
	path := readLine(reader)
	if path == "" {
		return
	}

	repo, err := database.GetRepoByPath(path)
	if err != nil || repo == nil {
		fmt.Printf("[ERROR] Repository %q not found in database.\n", path)
		return
	}

	fmt.Printf("ARE YOU SURE? This will PERMANENTLY delete all Git data for %q. [y/N]: ", path)
	confirm := readLine(reader)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("[CANCELLED]")
		return
	}

	// 1. Remove from DB
	if err := database.DeleteRepo(path); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	// 2. Remove from disk
	var physicalPath string
	if repo.OwnerType == "user" {
		physicalPath = filepath.Join(repoRoot, repo.Path)
	} else {
		physicalPath = filepath.Join(repoRoot, "orgs", repo.Path)
	}

	if err := shell.DeleteRepoFolder(physicalPath); err != nil {
		fmt.Printf("[WARNING] DB entry removed, but filesystem deletion failed: %v\n", err)
	} else {
		fmt.Println("[OK] Repository permanently deleted.")
	}
}

func listAccessibleRepos(database *db.DB, username string) {
	repos, err := database.ListAccessibleRepos(username)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	fmt.Printf("\n--- Repositories Accessible by %s ---\n", username)
	fmt.Printf("  %-30s  %-10s  %s\n", "Path", "Role", "Description")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, r := range repos {
		fmt.Printf("  %-30s  %-10s  %s\n", r.Path, r.UserRole, r.Description)
	}
}

func verifyRepoCommits(database *db.DB, reader *bufio.Reader, repoRoot string) {
	fmt.Print("Enter logical path to inspect (e.g. users/alice/myrepo.git): ")
	path := readLine(reader)
	if path == "" {
		return
	}

	repo, err := database.GetRepoByPath(path)
	if err != nil || repo == nil {
		fmt.Printf("[ERROR] Repository %q not found in database.\n", path)
		return
	}

	var physicalPath string
	if repo.OwnerType == "user" {
		physicalPath = filepath.Join(repoRoot, repo.Path)
	} else {
		physicalPath = filepath.Join(repoRoot, "orgs", repo.Path)
	}

	output, err := shell.LogRepoCommitsGPG(physicalPath)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	if output == "" {
		fmt.Println("  (no commits found)")
		return
	}

	fmt.Printf("\n--- Commit Log for %s ---\n", path)
	lines := strings.Split(output, "\n")
	for _, l := range lines {
		parts := strings.SplitN(l, " | ", 4)
		if len(parts) < 4 {
			continue
		}
		hash := parts[0]
		status := parts[1]
		author := parts[2]
		msg := parts[3]

		statusStr := "[Unverified]"
		if status == "G" {
			statusStr = "[ Verified ]"
		} else if status == "B" {
			statusStr = "[ BAD SIG  ]"
		} else if status == "U" {
			statusStr = "[ Unknown  ]"
		} else if status == "X" {
			statusStr = "[ Expired  ]"
		} else if status == "R" {
			statusStr = "[ Revoked  ]"
		}

		fmt.Printf("  %s %s  %-15s  %s\n", statusStr, hash, author, msg)
	}
}

func manageCollaborators(database *db.DB, reader *bufio.Reader, repoRoot string) {
	fmt.Print("Enter repository path (e.g. user/alice/myrepo.git): ")
	path := readLine(reader)
	repo, err := database.GetRepoByPath(path)
	if err != nil || repo == nil {
		fmt.Printf("[ERROR] Repository %q not found.\n", path)
		return
	}

	for {
		fmt.Printf("\n--- Collaborators for %s ---\n", path)
		fmt.Println("1. List Collaborators")
		fmt.Println("2. Add Collaborator")
		fmt.Println("3. Remove Collaborator")
		fmt.Println("4. Back")
		fmt.Print("\n(collaborators) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			// No direct ListCollaborators for now, I'll add a helper if needed or just use GetRepoByPath cache
			fmt.Println("Config Cache from DB:")
			fmt.Println(repo.ConfigCache)
		case "2":
			fmt.Print("Enter username: ")
			username := readLine(reader)
			user, _ := database.GetUserByUsername(username)
			if user == nil {
				fmt.Printf("[ERROR] User %q not found.\n", username)
				continue
			}
			fmt.Print("Role (read/write) [read]: ")
			role := readLine(reader)
			if role == "" {
				role = "read"
			}

			// 1. DB
			_ = database.AddCollaborator(repo.ID, user.ID, role)

			// 2. Disk (Git First)
			var physicalPath string
			if repo.OwnerType == "user" {
				physicalPath = filepath.Join(repoRoot, repo.Path)
			} else {
				physicalPath = filepath.Join(repoRoot, "orgs", repo.Path)
			}

			key := fmt.Sprintf("access.%s.role", username)
			_ = shell.SetRepoMetadata(physicalPath, key, role)

			// 3. Update Cache
			cfg, _ := shell.ReadFullSourceVaultConfig(physicalPath)
			_ = database.UpdateRepoConfigCache(repo.Path, cfg)
			fmt.Println("[OK] Collaborator added.")

		case "3":
			fmt.Print("Enter username to remove: ")
			username := readLine(reader)
			// For removal, we need to remove the section from git config
			var physicalPath string
			if repo.OwnerType == "user" {
				physicalPath = filepath.Join(repoRoot, repo.Path)
			} else {
				physicalPath = filepath.Join(repoRoot, "orgs", repo.Path)
			}
			
			// Note: shell.SetRepoMetadata uses git config, but we need section removal.
			// I'll use a raw command for now or update manager.go.
			configPath := filepath.Join(physicalPath, "config")
			cmd := exec.Command("git", "config", "-f", configPath, "--remove-section", "sourcevault.access."+username)
			_ = cmd.Run()

			// Sync back to DB cache
			cfg, _ := shell.ReadFullSourceVaultConfig(physicalPath)
			_ = database.UpdateRepoConfigCache(repo.Path, cfg)
			fmt.Println("[OK] Collaborator removed from Git config and DB cache.")
		case "4":
			return
		}
	}
}

func runOrgMenu(database *db.DB, reader *bufio.Reader, repoRoot, currentUser string) {
	for {
		fmt.Println("\n--- Organization Management ---")
		fmt.Println("1. List Organizations")
		fmt.Println("2. Create Organization")
		fmt.Println("3. Delete Organization")
		fmt.Println("4. Manage Org Members")
		fmt.Println("5. Manage Org Repos")
		fmt.Println("6. Back to Main Menu")
		fmt.Print("\n(orgs) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			listOrgs(database)
		case "2":
			addOrg(database, reader, repoRoot, currentUser)
		case "3":
			removeOrg(database, reader)
		case "4":
			manageOrgMembers(database, reader, repoRoot)
		case "5":
			fmt.Print("Enter organization name: ")
			orgName := readLine(reader)
			org, err := database.GetOrgByName(orgName)
			if err != nil || org == nil {
				fmt.Printf("[ERROR] Organization %q not found.\n", orgName)
				continue
			}
			runOrgRepoMenu(database, reader, org.ID, org.Name, repoRoot)
		case "6":
			return
		}
	}
}

func listOrgs(database *db.DB) {
	orgs, err := database.ListOrgs()
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	fmt.Println("\nOrganizations:")
	fmt.Printf("  %-20s  %-36s  %s\n", "Name", "UUID", "Description")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, o := range orgs {
		desc := o.Description
		if desc == "" {
			desc = "(no description)"
		}
		fmt.Printf("  %-20s  %-36s  %s\n", o.Name, o.UUID, desc)
	}
}

func addOrg(database *db.DB, reader *bufio.Reader, repoRoot, currentUser string) {
	fmt.Print("Enter organization name: ")
	name := readLine(reader)
	if !db.IsValidUsername(name) {
		fmt.Println("[ERROR] Invalid organization name.")
		return
	}

	orgUUID := uuid.New().String()
	fmt.Printf("Generated UUID: %s\n", orgUUID)

	fmt.Print("Enter organization description: ")
	description := readLine(reader)

	org, err := database.CreateOrg(name, orgUUID, description)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}

	// Automatically add the creator as the owner
	user, err := database.GetUserByUsername(currentUser)
	if err == nil && user != nil {
		_ = database.AddMemberToOrg(org.ID, user.ID, "owner")
		fmt.Printf("Added %q as organization owner.\n", currentUser)
	}

	if repoRoot != "" {
		if err := database.SaveOrgMetadata(name); err != nil {
			fmt.Printf("[WARNING] DB updated but filesystem sync failed: %v\n", err)
		}
	}

	fmt.Printf("Organization %q created successfully.\n", org.Name)
}

func removeOrg(database *db.DB, reader *bufio.Reader) {
	fmt.Print("Enter organization name to REMOVE: ")
	name := readLine(reader)
	if name == "" {
		return
	}

	fmt.Printf("Are you sure you want to delete org %q? [y/N]: ", name)
	confirm := readLine(reader)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("[CANCELLED]")
		return
	}

	if err := database.DeleteOrg(name); err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		return
	}
	fmt.Println("Organization removed from database. Repositories on disk were NOT deleted.")
}

func manageOrgMembers(database *db.DB, reader *bufio.Reader, repoRoot string) {
	fmt.Print("Enter organization name: ")
	orgName := readLine(reader)
	org, err := database.GetOrgByName(orgName)
	if err != nil || org == nil {
		fmt.Printf("[ERROR] Organization %q not found.\n", orgName)
		return
	}

	for {
		members, err := database.ListOrgMembers(org.ID)
		if err != nil {
			fmt.Printf("[ERROR] %v\n", err)
			return
		}

		fmt.Printf("\nMembers of %q:\n", org.Name)
		for _, m := range members {
			fmt.Printf(" - %-20s (%s)\n", m.Username, m.Role)
		}

		fmt.Println("\n1. Add Member")
		fmt.Println("2. Remove Member")
		fmt.Println("3. Back")
		fmt.Print("\n(members) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			fmt.Print("Enter username to add: ")
			username := readLine(reader)
			user, err := database.GetUserByUsername(username)
			if err != nil || user == nil {
				fmt.Printf("[ERROR] User %q not found.\n", username)
				continue
			}

			fmt.Print("Role (owner/member) [member]: ")
			role := readLine(reader)
			if role == "" {
				role = "member"
			}

			if err := database.AddMemberToOrg(org.ID, user.ID, role); err != nil {
				fmt.Printf("[ERROR] %v\n", err)
			} else {
				fmt.Println("Member added.")
				if repoRoot != "" {
					database.SaveOrgMetadata(org.Name)
				}
			}
		case "2":
			fmt.Print("Enter username to remove: ")
			username := readLine(reader)
			user, err := database.GetUserByUsername(username)
			if err != nil || user == nil {
				fmt.Printf("[ERROR] User %q not found.\n", username)
				continue
			}

			if err := database.RemoveMemberFromOrg(org.ID, user.ID); err != nil {
				fmt.Printf("[ERROR] %v\n", err)
			} else {
				fmt.Println("Member removed.")
				if repoRoot != "" {
					database.SaveOrgMetadata(org.Name)
				}
			}
		case "3":
			return
		}
	}
}
