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

package db

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserMetadata represents the "Git First" source of truth mapped sequentially onto the system
type UserMetadata struct {
	ID                int64    `yaml:"id"`
	UUID              string   `yaml:"uuid"`
	Username          string   `yaml:"username"`
	IsAdmin           bool     `yaml:"is_admin"`
	AdminPasswordHash string   `yaml:"admin_password_hash"`
	AdminPasswordSet  bool     `yaml:"admin_password_set"`
	KeyHistory        []string `yaml:"key_history"` // list of fingerprints
	CreatedAt         string   `yaml:"created_at"`
}

// OrgMetadata represents the "Git First" source of truth stored in the registry.
type OrgMetadata struct {
	Name        string   `yaml:"name"`
	UUID        string   `yaml:"uuid"`
	Description string   `yaml:"description"`
	CreatedAt   string   `yaml:"created_at"`
	Owners      []string `yaml:"owners"`
	Users       map[string]string `yaml:"users"` // username: role
}

// SaveUserMetadata writes the user's account state to a metadata file in the registry.
func (d *DB) SaveUserMetadata(username string) error {
	localPath, err := d.EnsureRegistry()
	if err != nil {
		return err
	}
	_ = d.pullRegistry(localPath)

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("user %q not found", username)
	}

	history, err := d.ListKeyHistoryForUser(user.ID)
	if err != nil {
		history = []string{}
	}

	metadata := UserMetadata{
		ID:                user.ID,
		UUID:              user.UUID,
		Username:          user.Username,
		IsAdmin:           user.IsAdmin,
		AdminPasswordHash: user.AdminPasswordHash,
		AdminPasswordSet:  user.AdminPasswordSet,
		KeyHistory:        history,
		CreatedAt:         user.CreatedAt,
	}

	userDir := filepath.Join(localPath, "users")
	if err := os.MkdirAll(userDir, 0o750); err != nil {
		return fmt.Errorf("creating users directory: %w", err)
	}

	metaPath := filepath.Join(userDir, user.UUID+".yaml")
	data, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, data, 0o640); err != nil {
		return err
	}

	return d.commitAndPushRegistry(localPath, "Update user: "+username)
}

// RemoveUserMetadata deletes the metadata file from the registry.
func (d *DB) RemoveUserMetadata(username string) error {
	localPath, err := d.EnsureRegistry()
	if err != nil {
		return err
	}
	_ = d.pullRegistry(localPath)

	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		return nil
	}

	metaPath := filepath.Join(localPath, "users", user.UUID+".yaml")
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return d.commitAndPushRegistry(localPath, "Remove user: "+username)
}

// SaveOrgMetadata writes the organization's membership list to a metadata file in the registry.
func (d *DB) SaveOrgMetadata(orgName string) error {
	localPath, err := d.EnsureRegistry()
	if err != nil {
		return err
	}
	_ = d.pullRegistry(localPath)

	org, err := d.GetOrgByName(orgName)
	if err != nil {
		return err
	}
	if org == nil {
		return fmt.Errorf("organization %q not found", orgName)
	}

	members, err := d.ListOrgMembers(org.ID)
	if err != nil {
		return err
	}

	metadata := OrgMetadata{
		Name:        orgName,
		UUID:        org.UUID,
		Description: org.Description,
		CreatedAt:   org.CreatedAt,
		Users:       make(map[string]string),
	}

	for _, m := range members {
		if m.Role == "owner" {
			metadata.Owners = append(metadata.Owners, m.Username)
		} else {
			metadata.Users[m.Username] = m.Role
		}
	}

	orgDir := filepath.Join(localPath, "orgs")
	if err := os.MkdirAll(orgDir, 0o750); err != nil {
		return fmt.Errorf("creating orgs directory: %w", err)
	}

	metaPath := filepath.Join(orgDir, org.UUID+".yaml")
	data, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	// Cache the raw YAML in the database
	if err := d.UpdateOrgCache(orgName, string(data)); err != nil {
		return fmt.Errorf("caching metadata in db: %w", err)
	}

	if err := os.WriteFile(metaPath, data, 0o640); err != nil {
		return err
	}

	return d.commitAndPushRegistry(localPath, "Update organization: "+orgName)
}

// SyncFromRegistry scans the registry for user and organization metadata files
// and reconstructs the database state. This is the "Recovery" path.
func (d *DB) SyncFromRegistry() error {
	localPath, err := d.EnsureRegistry()
	if err != nil {
		return err
	}
	_ = d.pullRegistry(localPath)

	// 1. Sync Users
	if err := d.syncUsers(filepath.Join(localPath, "users")); err != nil {
		return err
	}

	// 2. Sync Organizations
	if err := d.syncOrganizations(filepath.Join(localPath, "orgs")); err != nil {
		return err
	}

	// 3. Sync Personal Repositories (walking repoRoot/users/<username>/<repo>.git)
	if err := d.syncRepositories(filepath.Join(d.RepoRoot, "users"), "user"); err != nil {
		return err
	}

	// 4. Sync Organization Repositories (walking repoRoot/orgs/<org>/<repo>.git)
	if err := d.syncRepositories(filepath.Join(d.RepoRoot, "orgs"), "org"); err != nil {
		return err
	}

	return nil
}

func (d *DB) syncUsers(usersDir string) error {
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		metaPath := filepath.Join(usersDir, entry.Name())
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var metadata UserMetadata
		if err := yaml.Unmarshal(data, &metadata); err != nil {
			continue
		}

		user, err := d.GetUserByUsername(metadata.Username)
		if err != nil {
			return err
		}
		if user == nil {
			log.Printf("[sync] Re-creating user: %s", metadata.Username)
			user, err = d.RestoreUser(metadata.ID, metadata.UUID, metadata.Username, metadata.IsAdmin, metadata.AdminPasswordHash, metadata.AdminPasswordSet, metadata.CreatedAt)
			if err != nil {
				return err
			}
		} else if user.IsAdmin != metadata.IsAdmin {
			adminVal := 0
			if metadata.IsAdmin {
				adminVal = 1
			}
			d.conn.Exec(`UPDATE users SET is_admin = ? WHERE id = ?`, adminVal, metadata.ID)
		}

		// Restore key history
		for _, fp := range metadata.KeyHistory {
			_ = d.RestoreKeyHistory(fp, user.ID)
		}
	}
	return nil
}

func (d *DB) syncOrganizations(orgsDir string) error {
	entries, err := os.ReadDir(orgsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		metaPath := filepath.Join(orgsDir, entry.Name())
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var metadata OrgMetadata
		if err := yaml.Unmarshal(data, &metadata); err != nil {
			continue
		}

		org, err := d.GetOrgByName(metadata.Name)
		if err != nil {
			return err
		}
		if org == nil {
			log.Printf("[sync] Re-creating organization: %s", metadata.Name)
			org, err = d.CreateOrg(metadata.Name, metadata.UUID, metadata.Description)
			if err != nil {
				return err
			}
		}

		for _, username := range metadata.Owners {
			_ = d.syncMember(org, username, "owner")
		}
		for username, role := range metadata.Users {
			_ = d.syncMember(org, username, role)
		}
	}
	return nil
}

func (d *DB) syncRepositories(baseDir, ownerType string) error {
	return filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || filepath.Ext(path) != ".git" {
			return nil
		}

		// Found a repo!
		configPath := filepath.Join(path, "config")
		cmd := exec.Command("git", "config", "-f", configPath, "--get-regexp", "^sourcevault\\.")
		out, err := cmd.Output()
		if err != nil {
			return nil // No sourcevault config
		}

		meta := make(map[string]string)
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "sourcevault.")
				meta[key] = strings.TrimSpace(parts[1])
			}
		}

		name := meta["name"]
		ownerName := meta["owner"]
		description := meta["description"]
		if name == "" || ownerName == "" {
			return nil
		}

		// Construct logical path
		var logicalPath string
		var ownerID int64
		if ownerType == "user" {
			logicalPath = fmt.Sprintf("users/%s/%s.git", ownerName, name)
			user, _ := d.GetUserByUsername(ownerName)
			if user != nil {
				ownerID = user.ID
			}
		} else {
			logicalPath = fmt.Sprintf("%s/%s.git", ownerName, name)
			org, _ := d.GetOrgByName(ownerName)
			if org != nil {
				ownerID = org.ID
			}
		}

		if ownerID == 0 {
			log.Printf("[sync] Skipping repo %q: owner %q not found in DB", logicalPath, ownerName)
			return nil
		}

		repo, _ := d.GetRepoByPath(logicalPath)
		if repo == nil {
			log.Printf("[sync] Re-registering repository: %s", logicalPath)
			_, err = d.CreateRepo(name, ownerType, ownerID, logicalPath, description, false)
			if err != nil {
				return err
			}
			_ = d.UpdateRepoConfigCache(logicalPath, string(out))
		}

		// Retroactively explicitly orchestrate execution hooks smoothly locally
		// Ensures existing repos that predated the Go port obtain standard native bindings properly symmetrically
		_ = d.deployHooksToPath(path)

		return filepath.SkipDir // Don't look inside .git
	})
}

func (d *DB) syncMember(org *Organization, username, role string) error {
	user, err := d.GetUserByUsername(username)
	if err != nil {
		return err
	}
	if user == nil {
		return nil
	}

	isMember, err := d.IsMemberOfOrg(username, org.Name)
	if err != nil {
		return err
	}
	if !isMember {
		log.Printf("[sync] Re-adding member %q to org %q", username, org.Name)
		return d.AddMemberToOrg(org.ID, user.ID, role)
	}
	return nil
}

// deployHooksToPath scaffolds standard orchestration shell proxies explicitly natively purely securely intelligently
func (d *DB) deployHooksToPath(repoPath string) error {
	postReceivePath := filepath.Join(repoPath, "hooks", "post-receive")
	if err := os.MkdirAll(filepath.Dir(postReceivePath), 0o755); err != nil {
		return err
	}

	scriptContent := `#!/usr/bin/env bash
# SourceVault Standard Lifecycle Invocation Bridge dynamically managed elegantly
exec /usr/local/bin/git-shell --hook post-receive
`
	return os.WriteFile(postReceivePath, []byte(scriptContent), 0o755)
}
