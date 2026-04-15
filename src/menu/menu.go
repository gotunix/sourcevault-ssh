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
		fmt.Println("  8. Exit")
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
		fmt.Println("  4. Exit")
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
