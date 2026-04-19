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
	"strings"

	"github.com/gotunix/sourcevault-ssh/db"
	"github.com/gotunix/sourcevault-ssh/version"
)

// RunAdmin presents the full admin TUI. It blocks until the admin exits.
// Only users with GIT_ADMIN=true reach this path.
func RunAdmin(database *db.DB) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║     SourceVault SSH — Admin Menu     ║")
	fmt.Println("╚══════════════════════════════════════╝")

	for {
		fmt.Println()
		fmt.Println("  1. List Users")
		fmt.Println("  2. Add User")
		fmt.Println("  3. Remove User")
		fmt.Println("  4. Toggle Admin")
		fmt.Println("  5. Add SSH Key to User")
		fmt.Println("  6. Remove SSH Key from User")
		fmt.Println("  7. List Keys for User")
		fmt.Println("  8. List Trusted CAs")
		fmt.Println("  9. Add Trusted CA")
		fmt.Println(" 10. Remove Trusted CA")
		fmt.Println(" 11. Version")
		fmt.Println(" 12. Exit")
		fmt.Print("\n==> ")

		choice := readLine(reader)

		switch choice {
		case "1":
			listUsers(database)
		case "2":
			addUser(database, reader)
		case "3":
			removeUser(database, reader)
		case "4":
			toggleAdmin(database, reader)
		case "5":
			addKey(database, reader)
		case "6":
			removeKey(database, reader)
		case "7":
			listKeys(database, reader)
		case "8":
			listCAs(database)
		case "9":
			addCA(database, reader)
		case "10":
			removeCA(database, reader)
		case "11":
			version.Print()
		case "12":
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
func RunUser(database *db.DB, username string) {
	reader := bufio.NewReader(os.Stdin)

	user, err := database.GetUserByUsername(username)
	if err != nil || user == nil {
		fmt.Fprintf(os.Stderr, "Error: could not load your user account (%v)\n", err)
		return
	}

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Printf("║  SourceVault SSH — Hello, %-11s ║\n", username)
	fmt.Println("╚══════════════════════════════════════╝")

	for {
		fmt.Println()
		fmt.Println("  1. List My SSH Keys")
		fmt.Println("  2. Add SSH Key")
		fmt.Println("  3. Remove SSH Key")
		fmt.Println("  4. Version")
		fmt.Println("  5. Exit")
		fmt.Print("\n==> ")

		choice := readLine(reader)

		switch choice {
		case "1":
			listKeysForUserID(database, user.ID, username)
		case "2":
			addKeyForUser(database, reader, user)
		case "3":
			removeKeyForUser(database, reader, user)
		case "4":
			version.Print()
		case "5":
			fmt.Println("Goodbye.")
			return
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
func addUser(database *db.DB, reader *bufio.Reader) {
	username := prompt(reader, "Username: ")
	if username == "" {
		fmt.Println("[CANCELLED]")
		return
	}
	if !isValidUsername(username) {
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
	fmt.Printf("[OK] User %q created (admin=%v)\n", username, isAdmin)
}

// removeUser prompts for a username and a confirmation, then permanently deletes
// the user and all their associated SSH keys (enforced by the ON DELETE CASCADE
// foreign key in the database schema). Requires the admin to type "yes" explicitly.
func removeUser(database *db.DB, reader *bufio.Reader) {
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
	fmt.Printf("[OK] User %q and all associated keys removed.\n", username)
}

// toggleAdmin flips the admin flag for a user.
// If the user is currently an admin, they are demoted; if they are not, they are promoted.
// The current state is fetched from the database so the UI always reflects truth.
func toggleAdmin(database *db.DB, reader *bufio.Reader) {
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

	if _, err := database.AddKey(user.ID, fingerprint, keyType, keyData, comment); err != nil {
		fmt.Printf("[ERROR] Could not add key (already registered?): %v\n", err)
		return
	}

	fmt.Printf("[OK] Key added for %q\n  Fingerprint: %s\n  Comment: %s\n", username, fingerprint, comment)
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
	for _, k := range keys {
		comment := k.Comment
		if comment == "" {
			comment = "(no comment)"
		}
		fmt.Printf("  %-50s  %s  %s\n", k.Fingerprint, k.KeyType, comment)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// prompt prints a prompt string and reads a trimmed line from stdin.
func prompt(reader *bufio.Reader, text string) string {
	fmt.Print("  " + text)
	return readLine(reader)
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

// isValidUsername validates a username or email address.
// Allowed characters: letters, digits, @, ., -, _, +
// This covers standard email addresses (user@domain.com) as well as
// simple alphanumeric usernames.
func isValidUsername(s string) bool {
	if len(s) == 0 || len(s) > 254 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '@' || r == '+') {
			return false
		}
	}
	return true
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
		fmt.Printf("  [%d]  %s\n       %s  %s\n", i+1, k.Fingerprint, k.KeyType, comment)
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

	if _, err := database.AddKey(user.ID, fingerprint, keyType, keyData, comment); err != nil {
		fmt.Printf("  [ERROR] Could not add key (already registered?): %v\n", err)
		return
	}

	fmt.Printf("  [OK] Key added.\n  Fingerprint: %s\n  Comment:     %s\n", fingerprint, comment)
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
	fmt.Printf("\n  %-20s  %-8s  %s\n", "CA Name", "Admin", "Fingerprint")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, ca := range cas {
		admin := "no"
		if ca.IsAdmin {
			admin = "yes"
		}
		fmt.Printf("  %-20s  %-8s  %s\n", ca.Name, admin, ca.Fingerprint)
	}
}

// addCA prompts for a CA name and public key line, then registers it.
func addCA(database *db.DB, reader *bufio.Reader) {
	name := prompt(reader, "CA Name (e.g. 'Engineering'): ")
	if name == "" {
		fmt.Println("[CANCELLED]")
		return
	}

	adminStr := prompt(reader, "Treat all certs from this CA as admins? (yes/no): ")
	isAdmin := strings.ToLower(adminStr) == "yes"

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

	if _, err := database.AddTrustedCA(name, fingerprint, keyType, keyData, isAdmin); err != nil {
		fmt.Printf("[ERROR] Could not add CA (duplicate name or key?): %v\n", err)
		return
	}

	fmt.Printf("[OK] CA %q added (admin=%v)\n  Fingerprint: %s\n", name, isAdmin, fingerprint)
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
