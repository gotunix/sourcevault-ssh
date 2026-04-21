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

package shell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InitBareRepo initializes a new bare Git repository at the specified absolute path.
func InitBareRepo(absPath string) error {
	// 1. Create parent directories
	parentDir := filepath.Dir(absPath)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("creating parent directory %q: %w", parentDir, err)
	}

	// 2. Run git init --bare
	cmd := exec.Command("git", "init", "--bare", absPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git init failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// DeleteRepoFolder permanently removes the repository directory from the filesystem.
func DeleteRepoFolder(absPath string) error {
	// Safety check: ensure it looks like a git repo directory (ends in .git)
	if filepath.Ext(absPath) != ".git" {
		return fmt.Errorf("safety check failed: directory %q does not end in .git", absPath)
	}

	return os.RemoveAll(absPath)
}

// SetRepoMetadata writes a metadata key to the repository's Git config file.
func SetRepoMetadata(absPath, key, value string) error {
	configPath := filepath.Join(absPath, "config")
	cmd := exec.Command("git", "config", "-f", configPath, "sourcevault."+key, value)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set %s in %s: %w (output: %s)", key, configPath, err, string(output))
	}
	return nil
}

// GetRepoMetadata reads a metadata key from the repository's Git config file.
func GetRepoMetadata(absPath, key string) (string, error) {
	configPath := filepath.Join(absPath, "config")
	cmd := exec.Command("git", "config", "-f", configPath, "--get", "sourcevault."+key)
	output, err := cmd.Output()
	if err != nil {
		// git config returns exit code 1 if the key is not found
		return "", nil
	}
	return string(output), nil
}

// ReadFullSourceVaultConfig returns all sourcevault.* keys from the repo config.
func ReadFullSourceVaultConfig(absPath string) (string, error) {
	configPath := filepath.Join(absPath, "config")
	cmd := exec.Command("git", "config", "-f", configPath, "--get-regexp", "^sourcevault\\.")
	output, err := cmd.Output()
	if err != nil {
		return "", nil
	}
	return string(output), nil
}

// LogRepoCommitsGPG returns the last 15 commits formatted with GPG verification status.
func LogRepoCommitsGPG(absPath string) (string, error) {
	cmd := exec.Command("git", "log", "-n", "15", "--pretty=format:%h | %G? | %an | %s")
	cmd.Dir = absPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to read commits (is the repository empty?): %v", strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
