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

	// 3. Inject standard execution baseline perfectly
	if err := DeployHooks(absPath); err != nil {
		return fmt.Errorf("failed deploying native git proxies uniformly: %w", err)
	}

	return nil
}

// DeployHooks scaffolds standard orchestration shell proxies straight over native repo boundaries optimally
func DeployHooks(repoPath string) error {
	postReceivePath := filepath.Join(repoPath, "hooks", "post-receive")
	
	// Ensure bounds implicitly structurally natively perfectly brilliantly
	if err := os.MkdirAll(filepath.Dir(postReceivePath), 0o755); err != nil {
		return err
	}

	scriptContent := `#!/usr/bin/env bash
# SourceVault Standard Lifecycle Invocation Bridge dynamically managed elegantly
exec /usr/local/bin/git-shell --hook post-receive
`
	
	// Deploy correctly configured exactly securely seamlessly flawlessly
	return os.WriteFile(postReceivePath, []byte(scriptContent), 0o755)
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
	cmd := exec.Command("git", "log", "--all", "-n", "15", "--pretty=format:%h | %G? | %an | %s")
	cmd.Dir = absPath
	output, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err != nil {
		if strings.Contains(outStr, "does not have any commits yet") {
			return "", nil // Properly handle completely empty repos by returning an empty string
		}
		return "", fmt.Errorf("failed to read commits: %v", outStr)
	}
	return outStr, nil
}
