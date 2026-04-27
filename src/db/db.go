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

	"golang.org/x/crypto/bcrypt"

	// Pure-Go SQLite driver — works with CGO_ENABLED=0.
	_ "modernc.org/sqlite"
)

// User represents an internal SourceVault application user.
type User struct {
	ID                int64
	UUID              string
	Username          string
	IsAdmin           bool
	AdminPasswordHash string
	AdminPasswordSet  bool
	CreatedAt         string
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

// GPGKey represents a trusted PGP/GPG key registered to a user for commit signing.
type GPGKey struct {
	ID          int64
	UserID      int64
	Username    string
	Fingerprint string
	KeyData     string // Armored block
	Comment     string
	CreatedAt   string
}

// TrustedCA represents a Certificate Authority public key trusted by the system.
type TrustedCA struct {
	ID          int64
	Name        string
	Fingerprint string
	KeyType     string
	KeyData     string
	CreatedAt   string
}

// Organization represents a group of users that own repositories.
type Organization struct {
	ID          int64
	Name        string
	UUID        string
	Description string
	YAMLCache   string
	CreatedAt   string
}

// OrgMember represents a user's membership in an organization.
type OrgMember struct {
	OrgID    int64
	UserID   int64
	Username string // Joined from users table
	OrgName  string // Joined from organizations table
	Role     string // owner, admin, member
}

// Repository represents a Git repository.
type Repository struct {
	ID          int64
	Name        string
	OwnerType   string // user or org
	OwnerID     int64
	Path        string // e.g. 'user/alice/project.git'
	Description string
	ConfigCache string
	IsPublic    bool
	CreatedAt   string
}

// AccessibleRepo includes the user's role for a specific repository.
type AccessibleRepo struct {
	Repository
	UserRole string // owner, read, write, member
}

// DB wraps the SQLite connection and exposes domain-level operations.
type DB struct {
	conn     *sql.DB
	DataDir  string
	RepoRoot string
}

// Open opens (or creates) the SQLite database at dataDir/sourcevault.db
// and runs schema migrations. Safe to call multiple times.
func Open(dataDir, repoRoot string) (*DB, error) {
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

	db := &DB{
		conn:     conn,
		DataDir:  dataDir,
		RepoRoot: repoRoot,
	}
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
			uuid       TEXT    NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16)))),
			username   TEXT    NOT NULL UNIQUE,
			is_admin   INTEGER NOT NULL DEFAULT 0,
			admin_password_hash TEXT NOT NULL DEFAULT '',
			admin_password_set  INTEGER NOT NULL DEFAULT 0,
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

		CREATE TABLE IF NOT EXISTS gpg_keys (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			fingerprint TEXT    NOT NULL UNIQUE,
			key_data    TEXT    NOT NULL,
			comment     TEXT    NOT NULL DEFAULT '',
			created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS trusted_cas (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT    NOT NULL UNIQUE,
			fingerprint TEXT    NOT NULL UNIQUE,
			key_type    TEXT    NOT NULL,
			key_data    TEXT    NOT NULL,
			is_admin    INTEGER NOT NULL DEFAULT 0,
			created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS organizations (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT    NOT NULL UNIQUE,
			uuid        TEXT    NOT NULL UNIQUE,
			description TEXT    NOT NULL DEFAULT '',
			yaml_cache  TEXT    NOT NULL DEFAULT '',
			created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS org_members (
			org_id      INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role        TEXT    NOT NULL DEFAULT 'member',
			PRIMARY KEY (org_id, user_id)
		);

		CREATE TABLE IF NOT EXISTS repositories (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT    NOT NULL,
			owner_type  TEXT    NOT NULL, -- 'user' or 'org'
			owner_id    INTEGER NOT NULL,
			path        TEXT    NOT NULL UNIQUE,
			description TEXT    NOT NULL DEFAULT '',
			config_cache TEXT   NOT NULL DEFAULT '',
			is_public   INTEGER NOT NULL DEFAULT 0,
			created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS repo_collaborators (
			repo_id     INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
			user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role        TEXT    NOT NULL DEFAULT 'read',
			PRIMARY KEY (repo_id, user_id)
		);
	`)

	// Inject UUID dynamically into legacy SQLite stores safely
	d.conn.Exec(`ALTER TABLE users ADD COLUMN uuid TEXT NOT NULL DEFAULT (lower(hex(randomblob(16))))`)
	d.conn.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)`)

	// Inject admin password columns dynamically into legacy SQLite stores
	d.conn.Exec(`ALTER TABLE users ADD COLUMN admin_password_hash TEXT NOT NULL DEFAULT ''`)
	d.conn.Exec(`ALTER TABLE users ADD COLUMN admin_password_set INTEGER NOT NULL DEFAULT 0`)

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
	_, err := d.conn.Exec(
		`INSERT INTO users (username, is_admin) VALUES (?, ?)`,
		username, admin,
	)
	if err != nil {
		return nil, err
	}
	return d.GetUserByUsername(username) // Re-fetch to retrieve the randomly generated UUID mapping
}

// RestoreUser forces an exact metadata insert mapping to reconstruct a user structurally
func (d *DB) RestoreUser(id int64, uuid string, username string, isAdmin bool, passwordHash string, passwordSet bool, createdAt string) (*User, error) {
	admin := 0
	if isAdmin {
		admin = 1
	}
	passSet := 0
	if passwordSet {
		passSet = 1
	}
	_, err := d.conn.Exec(
		`INSERT INTO users (id, uuid, username, is_admin, admin_password_hash, admin_password_set, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, uuid, username, admin, passwordHash, passSet, createdAt,
	)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:                id,
		UUID:              uuid,
		Username:          username,
		IsAdmin:           isAdmin,
		AdminPasswordHash: passwordHash,
		AdminPasswordSet:  passwordSet,
		CreatedAt:         createdAt,
	}, nil
}

// GetUserByUsername fetches a user by their username. Returns nil if not found.
func (d *DB) GetUserByUsername(username string) (*User, error) {
	var u User
	var isAdmin int
	var adminPasswordSet int
	err := d.conn.QueryRow(
		`SELECT id, uuid, username, is_admin, admin_password_hash, admin_password_set, created_at FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.UUID, &u.Username, &isAdmin, &u.AdminPasswordHash, &adminPasswordSet, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	u.AdminPasswordSet = adminPasswordSet == 1
	return &u, nil
}

// ListUsers returns all users ordered alphabetically.
func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.conn.Query(
		`SELECT id, uuid, username, is_admin, admin_password_hash, admin_password_set, created_at FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var isAdmin int
		var adminPasswordSet int
		if err := rows.Scan(&u.ID, &u.UUID, &u.Username, &isAdmin, &u.AdminPasswordHash, &adminPasswordSet, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin == 1
		u.AdminPasswordSet = adminPasswordSet == 1
		users = append(users, u)
	}
	return users, nil
}

// DeleteUser removes a user and all their associated SSH keys (CASCADE).
func (d *DB) DeleteUser(username string) error {
	_, err := d.conn.Exec(`DELETE FROM users WHERE username = ?`, username)
	return err
}

// SetAdmin promoted or demoted a user's admin status.
func (d *DB) SetAdmin(username string, isAdmin bool) error {
	admin := 0
	if isAdmin {
		admin = 1
	}
	_, err := d.conn.Exec(`UPDATE users SET is_admin = ? WHERE username = ?`, admin, username)
	return err
}

// SetAdminPassword updates the admin password for a user.
func (d *DB) SetAdminPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	_, err = d.conn.Exec(
		`UPDATE users SET admin_password_hash = ?, admin_password_set = 1 WHERE username = ?`,
		string(hash), username,
	)
	return err
}

// VerifyAdminPassword verifies the admin password for a user.
func (d *DB) VerifyAdminPassword(username, password string) (bool, error) {
	var hash string
	err := d.conn.QueryRow(`SELECT admin_password_hash FROM users WHERE username = ?`, username).Scan(&hash)
	if err != nil {
		return false, err
	}

	if hash == "" {
		return false, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
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

// IsValidUsername validates a username or email address.
// Allowed characters: letters, digits, @, ., -, _, +
// This covers standard email addresses (user@domain.com) as well as
// simple alphanumeric usernames.
func IsValidUsername(s string) bool {
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

// ---------------------------------------------------------------------------
// Trusted CA operations
// ---------------------------------------------------------------------------

// AddTrustedCA registers a new trusted CA public key.
func (d *DB) AddTrustedCA(name, fingerprint, keyType, keyData string) (*TrustedCA, error) {
	res, err := d.conn.Exec(
		`INSERT INTO trusted_cas (name, fingerprint, key_type, key_data) VALUES (?, ?, ?, ?)`,
		name, fingerprint, keyType, keyData,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &TrustedCA{
		ID: id, Name: name, Fingerprint: fingerprint,
		KeyType: keyType, KeyData: keyData,
	}, nil
}

// ListTrustedCAs returns all trusted CAs ordered by name.
func (d *DB) ListTrustedCAs() ([]TrustedCA, error) {
	rows, err := d.conn.Query(
		`SELECT id, name, fingerprint, key_type, key_data, created_at FROM trusted_cas ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []TrustedCA
	for rows.Next() {
		var ca TrustedCA
		if err := rows.Scan(&ca.ID, &ca.Name, &ca.Fingerprint, &ca.KeyType, &ca.KeyData, &ca.CreatedAt); err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}
	return cas, nil
}

// LookupCAByFingerprint finds a trusted CA by its SHA256 fingerprint.
func (d *DB) LookupCAByFingerprint(fingerprint string) (*TrustedCA, error) {
	var ca TrustedCA
	err := d.conn.QueryRow(`
		SELECT id, name, fingerprint, key_type, key_data, created_at
		FROM trusted_cas WHERE fingerprint = ?
	`, fingerprint).Scan(
		&ca.ID, &ca.Name, &ca.Fingerprint, &ca.KeyType, &ca.KeyData, &ca.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ca, nil
}

// RemoveTrustedCA deletes a trusted CA by its name.
func (d *DB) RemoveTrustedCA(name string) error {
	_, err := d.conn.Exec(`DELETE FROM trusted_cas WHERE name = ?`, name)
	return err
}

// ---------------------------------------------------------------------------
// Organization operations
// ---------------------------------------------------------------------------

// CreateOrg creates a new organization.
func (d *DB) CreateOrg(name, uuid, description string) (*Organization, error) {
	res, err := d.conn.Exec(
		`INSERT INTO organizations (name, uuid, description) VALUES (?, ?, ?)`,
		name, uuid, description,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Organization{ID: id, Name: name, UUID: uuid, Description: description}, nil
}

// UpdateOrgCache stores the raw YAML metadata in the database.
func (d *DB) UpdateOrgCache(name, yaml string) error {
	_, err := d.conn.Exec(`UPDATE organizations SET yaml_cache = ? WHERE name = ?`, yaml, name)
	return err
}

// GetOrgByName fetches an organization by its name.
func (d *DB) GetOrgByName(name string) (*Organization, error) {
	var o Organization
	err := d.conn.QueryRow(
		`SELECT id, name, uuid, description, yaml_cache, created_at FROM organizations WHERE name = ?`, name,
	).Scan(&o.ID, &o.Name, &o.UUID, &o.Description, &o.YAMLCache, &o.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// ListOrgs returns all organizations ordered alphabetically.
func (d *DB) ListOrgs() ([]Organization, error) {
	rows, err := d.conn.Query(`SELECT id, name, uuid, description, yaml_cache, created_at FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.UUID, &o.Description, &o.YAMLCache, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, nil
}

// DeleteOrg removes an organization.
func (d *DB) DeleteOrg(name string) error {
	_, err := d.conn.Exec(`DELETE FROM organizations WHERE name = ?`, name)
	return err
}

// AddMemberToOrg registers a user as a member of an organization.
func (d *DB) AddMemberToOrg(orgID, userID int64, role string) error {
	_, err := d.conn.Exec(
		`INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, ?)`,
		orgID, userID, role,
	)
	return err
}

// RemoveMemberFromOrg removes a user from an organization.
func (d *DB) RemoveMemberFromOrg(orgID, userID int64) error {
	_, err := d.conn.Exec(`DELETE FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID)
	return err
}

// ListOrgMembers returns all members of an organization.
func (d *DB) ListOrgMembers(orgID int64) ([]OrgMember, error) {
	rows, err := d.conn.Query(`
		SELECT m.org_id, m.user_id, u.username, o.name, m.role
		FROM org_members m
		JOIN users u ON m.user_id = u.id
		JOIN organizations o ON m.org_id = o.id
		WHERE m.org_id = ?
		ORDER BY m.role DESC, u.username ASC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []OrgMember
	for rows.Next() {
		var m OrgMember
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Username, &m.OrgName, &m.Role); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, nil
}

// IsMemberOfOrg checks if a user is a member of an organization.
func (d *DB) IsMemberOfOrg(username, orgName string) (bool, error) {
	var count int
	err := d.conn.QueryRow(`
		SELECT COUNT(*)
		FROM org_members m
		JOIN users u ON m.user_id = u.id
		JOIN organizations o ON m.org_id = o.id
		WHERE u.username = ? AND o.name = ?
	`, username, orgName).Scan(&count)
	return count > 0, err
}

// ---------------------------------------------------------------------------
// Repository operations
// ---------------------------------------------------------------------------

// CreateRepo registers a new repository in the database.
func (d *DB) CreateRepo(name, ownerType string, ownerID int64, path, description string, isPublic bool) (*Repository, error) {
	public := 0
	if isPublic {
		public = 1
	}
	res, err := d.conn.Exec(
		`INSERT INTO repositories (name, owner_type, owner_id, path, description, is_public) VALUES (?, ?, ?, ?, ?, ?)`,
		name, ownerType, ownerID, path, description, public,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Repository{ID: id, Name: name, OwnerType: ownerType, OwnerID: ownerID, Path: path, Description: description, IsPublic: isPublic}, nil
}

// GetRepoByPath fetches a repository by its logical path.
func (d *DB) GetRepoByPath(path string) (*Repository, error) {
	var r Repository
	var public int
	err := d.conn.QueryRow(
		`SELECT id, name, owner_type, owner_id, path, description, config_cache, is_public, created_at FROM repositories WHERE path = ?`, path,
	).Scan(&r.ID, &r.Name, &r.OwnerType, &r.OwnerID, &r.Path, &r.Description, &r.ConfigCache, &public, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.IsPublic = public == 1
	return &r, nil
}

// UpdateRepoConfigCache stores the raw Git config metadata in the database.
func (d *DB) UpdateRepoConfigCache(path, config string) error {
	_, err := d.conn.Exec(`UPDATE repositories SET config_cache = ? WHERE path = ?`, config, path)
	return err
}

// ListReposByOwner returns all repositories for a given owner.
func (d *DB) ListReposByOwner(ownerType string, ownerID int64) ([]Repository, error) {
	rows, err := d.conn.Query(
		`SELECT id, name, owner_type, owner_id, path, description, config_cache, is_public, created_at FROM repositories WHERE owner_type = ? AND owner_id = ? ORDER BY name`,
		ownerType, ownerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []Repository
	for rows.Next() {
		var r Repository
		var public int
		if err := rows.Scan(&r.ID, &r.Name, &r.OwnerType, &r.OwnerID, &r.Path, &r.Description, &r.ConfigCache, &public, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.IsPublic = public == 1
		repos = append(repos, r)
	}
	return repos, nil
}

// ListAllRepos returns all repositories registered in the database.
func (d *DB) ListAllRepos() ([]Repository, error) {
	rows, err := d.conn.Query(
		`SELECT id, name, owner_type, owner_id, path, description, config_cache, is_public, created_at FROM repositories ORDER BY path`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []Repository
	for rows.Next() {
		var r Repository
		var public int
		if err := rows.Scan(&r.ID, &r.Name, &r.OwnerType, &r.OwnerID, &r.Path, &r.Description, &r.ConfigCache, &public, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.IsPublic = public == 1
		repos = append(repos, r)
	}
	return repos, nil
}

// DeleteRepo removes a repository from the database.
func (d *DB) DeleteRepo(path string) error {
	_, err := d.conn.Exec(`DELETE FROM repositories WHERE path = ?`, path)
	return err
}

// AddCollaborator adds a user to a repository with a specific role.
func (d *DB) AddCollaborator(repoID, userID int64, role string) error {
	_, err := d.conn.Exec(`INSERT OR REPLACE INTO repo_collaborators (repo_id, user_id, role) VALUES (?, ?, ?)`, repoID, userID, role)
	return err
}

// IsCollaborator checks if a user has access to a repository.
func (d *DB) IsCollaborator(userID, repoID int64) (bool, error) {
	var count int
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM repo_collaborators WHERE repo_id = ? AND user_id = ?`, repoID, userID).Scan(&count)
	return count > 0, err
}

// ListAccessibleRepos returns all repositories a user has at least read access to.
func (d *DB) ListAccessibleRepos(username string) ([]AccessibleRepo, error) {
	query := `
		-- 1. Repositories owned by the user
		SELECT r.id, r.name, r.owner_type, r.owner_id, r.path, r.description, r.config_cache, r.is_public, r.created_at, 'owner' as user_role
		FROM repositories r
		JOIN users u ON r.owner_id = u.id AND r.owner_type = 'user'
		WHERE u.username = ?

		UNION

		-- 2. Repositories where the user is an explicit collaborator
		SELECT r.id, r.name, r.owner_type, r.owner_id, r.path, r.description, r.config_cache, r.is_public, r.created_at, c.role as user_role
		FROM repositories r
		JOIN repo_collaborators c ON r.id = c.repo_id
		JOIN users u ON c.user_id = u.id
		WHERE u.username = ?

		UNION

		-- 3. Repositories belonging to organizations the user is a member of
		SELECT r.id, r.name, r.owner_type, r.owner_id, r.path, r.description, r.config_cache, r.is_public, r.created_at, 'member' as user_role
		FROM repositories r
		JOIN organizations o ON r.owner_id = o.id AND r.owner_type = 'org'
		JOIN org_members m ON o.id = m.org_id
		JOIN users u ON m.user_id = u.id
		WHERE u.username = ?
		
		ORDER BY path ASC
	`

	rows, err := d.conn.Query(query, username, username, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []AccessibleRepo
	for rows.Next() {
		var r AccessibleRepo
		var public int
		err := rows.Scan(
			&r.ID, &r.Name, &r.OwnerType, &r.OwnerID, &r.Path, &r.Description, &r.ConfigCache, &public, &r.CreatedAt, &r.UserRole,
		)
		if err != nil {
			return nil, err
		}
		r.IsPublic = public == 1
		repos = append(repos, r)
	}
	return repos, nil
}

// ---------------------------------------------------------------------------
// GPG key operations
// ---------------------------------------------------------------------------

// AddGPGKey registers a new GPG public key for a user.
func (d *DB) AddGPGKey(userID int64, fingerprint, keyData, comment string) (*GPGKey, error) {
	res, err := d.conn.Exec(
		`INSERT INTO gpg_keys (user_id, fingerprint, key_data, comment) VALUES (?, ?, ?, ?)`,
		userID, fingerprint, keyData, comment,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &GPGKey{
		ID: id, UserID: userID, Fingerprint: fingerprint,
		KeyData: keyData, Comment: comment,
	}, nil
}

// LookupGPGKeyByFingerprint finds a GPG key and its owner by varying formats of fingerprint.
func (d *DB) LookupGPGKeyByFingerprint(fingerprint string) (*GPGKey, error) {
	var k GPGKey
	err := d.conn.QueryRow(`
		SELECT k.id, k.user_id, u.username, k.fingerprint, k.key_data, k.comment, k.created_at
		FROM gpg_keys k JOIN users u ON k.user_id = u.id
		WHERE k.fingerprint = ?
	`, fingerprint).Scan(
		&k.ID, &k.UserID, &k.Username, &k.Fingerprint,
		&k.KeyData, &k.Comment, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListGPGKeysForUser returns all GPG keys registered to a specific user.
func (d *DB) ListGPGKeysForUser(userID int64) ([]GPGKey, error) {
	rows, err := d.conn.Query(`
		SELECT id, user_id, fingerprint, key_data, comment, created_at
		FROM gpg_keys WHERE user_id = ? ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []GPGKey
	for rows.Next() {
		var k GPGKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.KeyData, &k.Comment, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// RemoveGPGKeyByFingerprint deletes a GPG key by its fingerprint.
func (d *DB) RemoveGPGKeyByFingerprint(fingerprint string) error {
	_, err := d.conn.Exec(`DELETE FROM gpg_keys WHERE fingerprint = ?`, fingerprint)
	return err
}
