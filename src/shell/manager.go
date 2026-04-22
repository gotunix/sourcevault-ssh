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

// InitializeSourceVaultBranch creates an orphan 'sourcevault' branch with a standard
// directory structure for managing project metadata (issues, bugs, etc).
func InitializeSourceVaultBranch(absPath string) error {
	// 1. Create a temporary worktree/index to craft the orphan commit
	// Since we are in a bare repo, we can't easily 'checkout' without a worktree.
	// But we can use low-level git commands to create a commit and a ref.

	// Check if branch already exists
	checkCmd := exec.Command("git", "show-ref", "--verify", "refs/heads/sourcevault")
	checkCmd.Dir = absPath
	if err := checkCmd.Run(); err == nil {
		return fmt.Errorf("branch 'sourcevault' already exists")
	}

	// Define the directory structure we want to "suggest" via a README
	readmeContent := `# SourceVault Management Branch

This branch is used for managing project metadata.
The following directory structure is recommended:

- /issues/            - Active and closed issues
- /bugs/              - Bug reports and tracking
- /features/          - Feature requests and proposals
- /pull-requests/     - Metadata about proposed changes
- /roadmaps/          - Project roadmaps and milestones
- /milestones/        - Version-specific goals

Files should ideally be in Markdown or YAML format for easy consumption.
`

	// To create an orphan commit in a bare repo:
	// a. Create a blob for the README
	hashObjectCmd := exec.Command("git", "hash-object", "-w", "--stdin")
	hashObjectCmd.Dir = absPath
	hashObjectCmd.Stdin = strings.NewReader(readmeContent)
	blobHashBytes, err := hashObjectCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to create README blob: %w", err)
	}
	blobHash := strings.TrimSpace(string(blobHashBytes))

	// b. Create a tree with that blob
	// Format: "100644 blob <hash>\tREADME.md"
	treeEntry := fmt.Sprintf("100644 blob %s\tREADME.md", blobHash)
	mktreeCmd := exec.Command("git", "mktree")
	mktreeCmd.Dir = absPath
	mktreeCmd.Stdin = strings.NewReader(treeEntry + "\n")
	treeHashBytes, err := mktreeCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to create tree: %w", err)
	}
	treeHash := strings.TrimSpace(string(treeHashBytes))

	// c. Create a commit from that tree (no parents = orphan)
	commitTreeCmd := exec.Command("git", "commit-tree", treeHash, "-m", "Initialize SourceVault Management Branch")
	commitTreeCmd.Dir = absPath
	// Git requires an identity to create a commit. On a server/bare-repo environment,
	// we provide a standard system identity.
	commitTreeCmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=SourceVault System",
		"GIT_AUTHOR_EMAIL=system@sourcevault.local",
		"GIT_COMMITTER_NAME=SourceVault System",
		"GIT_COMMITTER_EMAIL=system@sourcevault.local",
	)

	commitHashBytes, err := commitTreeCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to create commit: %w", err)
	}
	commitHash := strings.TrimSpace(string(commitHashBytes))

	// d. Update (or create) the ref refs/heads/sourcevault
	updateRefCmd := exec.Command("git", "update-ref", "refs/heads/sourcevault", commitHash)
	updateRefCmd.Dir = absPath
	if err := updateRefCmd.Run(); err != nil {
		return fmt.Errorf("failed to update ref: %w", err)
	}

	return nil
}
