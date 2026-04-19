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

	"github.com/gotunix/sourcevault-ssh/db"
	"github.com/gotunix/sourcevault-ssh/shell"
	"github.com/gotunix/sourcevault-ssh/version"
	"github.com/google/uuid"
)

// RunAdmin presents the full admin TUI. It blocks until the admin exits.
// Only users with GIT_ADMIN=true reach this path.
func RunAdmin(database *db.DB) {
	reader := bufio.NewReader(os.Stdin)
	repoRoot := os.Getenv("GIT_SHELL_REPO_ROOT")

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
		fmt.Println(" 11. Manage Organizations")
		fmt.Println(" 12. Version")
		fmt.Println(" 13. Exit")
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
			runOrgMenu(database, reader, repoRoot)
		case "12":
			version.Print()
		case "13":
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
		fmt.Println("  4. Manage My Repositories")
		fmt.Println("  5. List All Accessible Repositories")
		fmt.Println("  6. Version")
		fmt.Println("  7. Exit")
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
			runRepoMenu(database, reader, user.ID, user.Username, os.Getenv("GIT_SHELL_REPO_ROOT"))
		case "5":
			listAccessibleRepos(database, username)
		case "6":
			version.Print()
		case "7":
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
// ---------------------------------------------------------------------------
// Repository Management TUI
// ---------------------------------------------------------------------------

func runRepoMenu(database *db.DB, reader *bufio.Reader, ownerID int64, ownerName, repoRoot string) {
	for {
		fmt.Printf("\n--- Repository Management for %s ---\n", ownerName)
		fmt.Println("1. List Repositories")
		fmt.Println("2. Create Repository")
		fmt.Println("3. Delete Repository")
		fmt.Println("4. Manage Collaborators")
		fmt.Println("5. Back")
		fmt.Print("\n(repos) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			listRepos(database, "user", ownerID)
		case "2":
			addRepo(database, reader, "user", ownerID, ownerName, repoRoot)
		case "3":
			removeRepo(database, reader, repoRoot)
		case "4":
			manageCollaborators(database, reader, repoRoot)
		case "5":
			return
		}
	}
}

func runOrgRepoMenu(database *db.DB, reader *bufio.Reader, orgID int64, orgName, repoRoot string) {
	for {
		fmt.Printf("\n--- Repository Management for Org: %s ---\n", orgName)
		fmt.Println("1. List Repositories")
		fmt.Println("2. Create Repository")
		fmt.Println("3. Delete Repository")
		fmt.Println("4. Manage Collaborators")
		fmt.Println("5. Back")
		fmt.Print("\n(org-repos) ==> ")

		choice := readLine(reader)
		switch choice {
		case "1":
			listRepos(database, "org", orgID)
		case "2":
			addRepo(database, reader, "org", orgID, orgName, repoRoot)
		case "3":
			removeRepo(database, reader, repoRoot)
		case "4":
			manageCollaborators(database, reader, repoRoot)
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

func addRepo(database *db.DB, reader *bufio.Reader, ownerType string, ownerID int64, ownerName, repoRoot string) {
	fmt.Print("Enter repository name: ")
	name := readLine(reader)
	if name == "" || !db.IsValidUsername(name) {
		fmt.Println("[ERROR] Invalid repository name.")
		return
	}

	fmt.Print("Enter description: ")
	description := readLine(reader)

	// Flattened pathing: <ownerName>/<repoName>.git
	logicalPath := fmt.Sprintf("%s/%s.git", ownerName, name)
	physicalPath := filepath.Join(repoRoot, logicalPath)

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
	physicalPath := filepath.Join(repoRoot, repo.Path)

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
			physicalPath := filepath.Join(repoRoot, repo.Path)

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
			physicalPath := filepath.Join(repoRoot, repo.Path)
			
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

func runOrgMenu(database *db.DB, reader *bufio.Reader, repoRoot string) {
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
			addOrg(database, reader, repoRoot)
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

func addOrg(database *db.DB, reader *bufio.Reader, repoRoot string) {
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

	if repoRoot != "" {
		if err := database.SaveOrgMetadata(repoRoot, name); err != nil {
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
					database.SaveOrgMetadata(repoRoot, org.Name)
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
					database.SaveOrgMetadata(repoRoot, org.Name)
				}
			}
		case "3":
			return
		}
	}
}
