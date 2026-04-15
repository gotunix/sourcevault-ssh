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
// but WITHOUT ANY WARRANTY; without even the implied warranty of                                 //
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   //
// GNU Affero General Public License for more details.                                             //
//                                                                                                 //
// You should have received a copy of the GNU Affero General Public License                        //
// along with this program.  If not, see <https://www.gnu.org/licenses/>.                          //
// ----------------------------------------------------------------------------------------------- //

// Package db implements the SQLite data layer for SourceVault SSH.
//
// It manages two tables:
//   - users: internal app users with admin flag
//   - ssh_keys: public SSH keys linked to users, keyed by fingerprint
//
// The database lives at $GIT_SHELL_REPO_ROOT/sourcevault.db on the
// persistent volume so user data survives container rebuilds.
package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// Pure-Go SQLite driver — works with CGO_ENABLED=0.
	_ "modernc.org/sqlite"
)

// User represents an internal SourceVault application user.
type User struct {
	ID        int64
	Username  string
	IsAdmin   bool
	CreatedAt string
}

// SSHKey represents a public SSH key registered to a user.
type SSHKey struct {
	ID          int64
	UserID      int64
	Username    string // joined from users table
	Fingerprint string // SHA256:... format
	KeyType     string // e.g. ssh-ed25519
	KeyData     string // base64 key blob
	Comment     string // optional label
	CreatedAt   string
}

// DB wraps the SQLite connection and exposes domain-level operations.
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the SQLite database at dataDir/sourcevault.db
// and runs schema migrations. Safe to call multiple times.
func Open(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating data dir %q: %w", dataDir, err)
	}

	dbPath := filepath.Join(dataDir, "sourcevault.db")
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	// Enforce foreign key constraints — not enabled by default in SQLite.
	if _, err := conn.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return db, nil
}

// Close releases the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// migrate creates the schema if it does not already exist.
// New columns or tables should be added as separate ALTER TABLE statements
// below the initial CREATE to preserve idempotency.
func (d *DB) migrate() error {
	_, err := d.conn.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			username   TEXT    NOT NULL UNIQUE,
			is_admin   INTEGER NOT NULL DEFAULT 0,
			created_at TEXT    NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS ssh_keys (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			fingerprint TEXT    NOT NULL UNIQUE,
			key_type    TEXT    NOT NULL,
			key_data    TEXT    NOT NULL,
			comment     TEXT    NOT NULL DEFAULT '',
			created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
		);
	`)
	return err
}

// ---------------------------------------------------------------------------
// User operations
// ---------------------------------------------------------------------------

// IsEmpty returns true if no users have been registered yet.
// Used to detect first-boot bootstrap state.
func (d *DB) IsEmpty() (bool, error) {
	var count int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count == 0, err
}

// CreateUser inserts a new user. Returns an error if the username already exists.
func (d *DB) CreateUser(username string, isAdmin bool) (*User, error) {
	admin := 0
	if isAdmin {
		admin = 1
	}
	res, err := d.conn.Exec(
		`INSERT INTO users (username, is_admin) VALUES (?, ?)`,
		username, admin,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, IsAdmin: isAdmin}, nil
}

// GetUserByUsername fetches a user by their username. Returns nil if not found.
func (d *DB) GetUserByUsername(username string) (*User, error) {
	var u User
	var isAdmin int
	err := d.conn.QueryRow(
		`SELECT id, username, is_admin, created_at FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.Username, &isAdmin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	return &u, nil
}

// ListUsers returns all users ordered alphabetically.
func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.conn.Query(
		`SELECT id, username, is_admin, created_at FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var isAdmin int
		if err := rows.Scan(&u.ID, &u.Username, &isAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin == 1
		users = append(users, u)
	}
	return users, nil
}

// DeleteUser removes a user and all their associated SSH keys (CASCADE).
func (d *DB) DeleteUser(username string) error {
	_, err := d.conn.Exec(`DELETE FROM users WHERE username = ?`, username)
	return err
}

// SetAdmin promotes or demotes a user's admin status.
func (d *DB) SetAdmin(username string, isAdmin bool) error {
	admin := 0
	if isAdmin {
		admin = 1
	}
	_, err := d.conn.Exec(`UPDATE users SET is_admin = ? WHERE username = ?`, admin, username)
	return err
}

// ---------------------------------------------------------------------------
// SSH key operations
// ---------------------------------------------------------------------------

// FingerprintKey computes the SHA256 fingerprint of a raw base64 key blob.
// The output matches the format shown by `ssh-keygen -lf` (SHA256:...).
func FingerprintKey(keyData string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return "", fmt.Errorf("invalid key data (not valid base64): %w", err)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// ParsePublicKeyLine splits a standard authorized_keys-format line into its
// components (type, base64 data, comment). The comment field is optional.
func ParsePublicKeyLine(line string) (keyType, keyData, comment string, err error) {
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("expected at least 'key-type base64-data', got %d fields", len(parts))
	}

	validTypes := map[string]bool{
		"ssh-ed25519":             true,
		"ssh-rsa":                 true,
		"ecdsa-sha2-nistp256":     true,
		"ecdsa-sha2-nistp384":     true,
		"ecdsa-sha2-nistp521":     true,
		"sk-ssh-ed25519@openssh.com": true,
	}
	if !validTypes[parts[0]] {
		return "", "", "", fmt.Errorf("unsupported key type %q", parts[0])
	}

	if _, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return "", "", "", fmt.Errorf("key data is not valid base64")
	}

	comment = ""
	if len(parts) >= 3 {
		comment = strings.Join(parts[2:], " ")
	}

	return parts[0], parts[1], comment, nil
}

// AddKey registers a new public key for a user. Returns an error if the
// fingerprint is already registered (keys are globally unique).
func (d *DB) AddKey(userID int64, fingerprint, keyType, keyData, comment string) (*SSHKey, error) {
	res, err := d.conn.Exec(
		`INSERT INTO ssh_keys (user_id, fingerprint, key_type, key_data, comment) VALUES (?, ?, ?, ?, ?)`,
		userID, fingerprint, keyType, keyData, comment,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &SSHKey{
		ID: id, UserID: userID, Fingerprint: fingerprint,
		KeyType: keyType, KeyData: keyData, Comment: comment,
	}, nil
}

// LookupKeyByFingerprint finds a key and its owner by SHA256 fingerprint.
// Returns nil (not an error) if the fingerprint is not registered.
func (d *DB) LookupKeyByFingerprint(fingerprint string) (*SSHKey, error) {
	var k SSHKey
	err := d.conn.QueryRow(`
		SELECT k.id, k.user_id, u.username, k.fingerprint, k.key_type, k.key_data, k.comment, k.created_at
		FROM ssh_keys k JOIN users u ON k.user_id = u.id
		WHERE k.fingerprint = ?
	`, fingerprint).Scan(
		&k.ID, &k.UserID, &k.Username, &k.Fingerprint,
		&k.KeyType, &k.KeyData, &k.Comment, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListKeysForUser returns all SSH keys registered to a specific user.
func (d *DB) ListKeysForUser(userID int64) ([]SSHKey, error) {
	rows, err := d.conn.Query(`
		SELECT id, user_id, fingerprint, key_type, key_data, comment, created_at
		FROM ssh_keys WHERE user_id = ? ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SSHKey
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.KeyType, &k.KeyData, &k.Comment, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// RemoveKeyByFingerprint deletes a key by its fingerprint.
func (d *DB) RemoveKeyByFingerprint(fingerprint string) error {
	_, err := d.conn.Exec(`DELETE FROM ssh_keys WHERE fingerprint = ?`, fingerprint)
	return err
}
