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
	"os"
	"os/exec"
	"path/filepath"
)

// EnsureRegistry bare repo exists in repoRoot and is cloned to dataDir/registry.
func (d *DB) EnsureRegistry() (string, error) {
	registryBarePath := filepath.Join(d.RepoRoot, "_registry.git")
	registryLocalPath := filepath.Join(d.DataDir, "registry")

	// 1. Ensure bare repo exists
	if _, err := os.Stat(registryBarePath); os.IsNotExist(err) {
		cmd := exec.Command("git", "init", "--bare", registryBarePath)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("initializing bare registry: %w", err)
		}
	}

	// 2. Ensure local clone exists
	if _, err := os.Stat(registryLocalPath); os.IsNotExist(err) {
		cmd := exec.Command("git", "clone", registryBarePath, registryLocalPath)
		if err := cmd.Run(); err != nil {
			// If it's a new repo, clone will fail if there are no commits.
			if err := os.MkdirAll(registryLocalPath, 0o750); err != nil {
				return "", err
			}
			initCmd := exec.Command("git", "-C", registryLocalPath, "init")
			if err := initCmd.Run(); err != nil {
				return "", err
			}
			remoteCmd := exec.Command("git", "-C", registryLocalPath, "remote", "add", "origin", registryBarePath)
			if err := remoteCmd.Run(); err != nil {
				return "", err
			}
		}
	}

	return registryLocalPath, nil
}

func (d *DB) pullRegistry(localPath string) error {
	cmd := exec.Command("git", "-C", localPath, "pull", "origin", "HEAD")
	// ignore error if it's a new repo with no commits or if branch doesn't exist yet
	_ = cmd.Run()
	return nil
}

func (d *DB) commitAndPushRegistry(localPath, message string) error {
	// Set user.email and user.name locally if not set
	_ = exec.Command("git", "-C", localPath, "config", "user.email", "sv-shell@sourcevault").Run()
	_ = exec.Command("git", "-C", localPath, "config", "user.name", "SourceVault Registry").Run()

	// git add .
	addCmd := exec.Command("git", "-C", localPath, "add", ".")
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("git add: %w", err)
	}

	// git commit -m ...
	// check if there are changes first
	statusCmd := exec.Command("git", "-C", localPath, "status", "--porcelain")
	statusOut, _ := statusCmd.Output()
	if len(statusOut) == 0 {
		return nil // No changes
	}

	commitCmd := exec.Command("git", "-C", localPath, "commit", "-m", message)
	if err := commitCmd.Run(); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}

	// git push origin HEAD
	pushCmd := exec.Command("git", "-C", localPath, "push", "origin", "HEAD")
	if err := pushCmd.Run(); err != nil {
		return fmt.Errorf("git push: %w", err)
	}

	return nil
}
