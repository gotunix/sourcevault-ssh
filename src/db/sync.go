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

// OrgMetadata represents the "Git First" source of truth stored on the filesystem.
// It allows recovering organization memberships if the SQLite database is lost.
type OrgMetadata struct {
	Name        string   `yaml:"name"`
	UUID        string   `yaml:"uuid"`
	Description string   `yaml:"description"`
	CreatedAt   string   `yaml:"created_at"`
	Owners      []string `yaml:"owners"`
	Users       map[string]string `yaml:"users"` // username: role
}

// SaveOrgMetadata writes the organization's membership list to a metadata file
// on the filesystem (org.yaml) inside the organization's root folder.
func (d *DB) SaveOrgMetadata(repoRoot, orgName string) error {
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

	orgDir := filepath.Join(repoRoot, "organizations", orgName)
	if err := os.MkdirAll(orgDir, 0o750); err != nil {
		return fmt.Errorf("creating org directory: %w", err)
	}

	metaPath := filepath.Join(orgDir, "org.yaml")
	data, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	// Cache the raw YAML in the database
	if err := d.UpdateOrgCache(orgName, string(data)); err != nil {
		return fmt.Errorf("caching metadata in db: %w", err)
	}

	return os.WriteFile(metaPath, data, 0o640)
}

// SyncFromFilesystem scans the repository root for organization metadata files
// and reconstructs the database state. This is the "Recovery" path.
func (d *DB) SyncFromFilesystem(repoRoot string) error {
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip known system or hidden directories
		if strings.HasPrefix(name, ".") || name == "lost+found" {
			continue
		}

		dirPath := filepath.Join(repoRoot, name)

		// Check if it's an organization
		orgYamlPath := filepath.Join(dirPath, "org.yaml")
		if _, err := os.Stat(orgYamlPath); err == nil {
			// Found an organization!
			if err := d.syncSingleOrganization(name, orgYamlPath); err != nil {
				log.Printf("[sync] Error syncing organization %q: %v", name, err)
				continue
			}
			// Now sync its repositories
			if err := d.syncRepositories(dirPath, "org", name); err != nil {
				log.Printf("[sync] Error syncing repositories for org %q: %v", name, err)
			}
		} else {
			// Treat as a user namespace
			// We only sync user repos if the user actually exists in the DB
			user, _ := d.GetUserByUsername(name)
			if user != nil {
				if err := d.syncRepositories(dirPath, "user", name); err != nil {
					log.Printf("[sync] Error syncing repositories for user %q: %v", name, err)
				}
			}
		}
	}

	return nil
}

func (d *DB) syncSingleOrganization(name, yamlPath string) error {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return err
	}

	var metadata OrgMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return err
	}

	org, err := d.GetOrgByName(name)
	if err != nil {
		return err
	}
	if org == nil {
		log.Printf("[sync] Re-creating organization: %s", name)
		org, err = d.CreateOrg(name, metadata.UUID, metadata.Description)
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
	return nil
}

func (d *DB) syncRepositories(baseDir, ownerType, ownerName string) error {
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

		repoName := meta["name"]
		if repoName == "" {
			return nil
		}

		// Logical path is now just namespace/repo.git
		logicalPath := fmt.Sprintf("%s/%s", ownerName, filepath.Base(path))

		var ownerID int64
		if ownerType == "user" {
			user, _ := d.GetUserByUsername(ownerName)
			if user != nil {
				ownerID = user.ID
			}
		} else {
			org, _ := d.GetOrgByName(ownerName)
			if org != nil {
				ownerID = org.ID
			}
		}

		if ownerID == 0 {
			return nil
		}

		repo, _ := d.GetRepoByPath(logicalPath)
		if repo == nil {
			log.Printf("[sync] Re-registering repository: %s", logicalPath)
			_, err = d.CreateRepo(repoName, ownerType, ownerID, logicalPath, meta["description"], false)
			if err != nil {
				return err
			}
			_ = d.UpdateRepoConfigCache(logicalPath, string(out))
		}

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
