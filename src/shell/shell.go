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

// Package shell implements the git command proxy for SourceVault SSH.
//
// When a user runs a git operation (push, clone, fetch) over SSH, the SSH daemon
// sets SSH_ORIGINAL_COMMAND to the raw command string (e.g. "git-receive-pack 'users/alice/repo.git'").
// This package validates and sanitizes that string, enforces per-user access
// control, maps the logical repository path to its absolute location on disk,
// and hands off to the system git-shell via syscall.Exec (process replacement).
//
// FUTURE API INTEGRATION: The access control check and path resolution steps
// are the natural integration points for the SourceVault web API when running
// in platform mode.
package shell

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"github.com/gotunix/sourcevault-ssh/db"
	"golang.org/x/crypto/ssh"
)

// allowedBinaries is the strict whitelist of git wire-protocol executables.
// Anything not in this map is rejected before any path inspection occurs.
var allowedBinaries = map[string]bool{
	"git-upload-pack":    true, // git fetch / git clone (read)
	"git-receive-pack":   true, // git push (write)
	"git-upload-archive": true, // git archive (read)
}

// repoPathRegex enforces a safe character set for repository paths.
// Only alphanumerics, dots, dashes, underscores, and forward slashes are allowed.
var repoPathRegex = regexp.MustCompile(`^[a-zA-Z0-9\._\-/]+$`)

// shellSplit tokenises a shell-style command string, respecting single-quoted
// segments. This handles the exact format OpenSSH uses when passing git commands
// (e.g. "git-receive-pack 'users/alice/repo.git'").
//
// Intentionally minimal: no double-quote or backslash support — git never
// produces commands that require them.
func shellSplit(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inSingleQuote := false

	for _, r := range s {
		switch {
		case r == '\'' && !inSingleQuote:
			inSingleQuote = true
		case r == '\'' && inSingleQuote:
			inSingleQuote = false
		case unicode.IsSpace(r) && !inSingleQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if inSingleQuote {
		return nil, fmt.Errorf("unterminated single quote in command")
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}

// sanitizeCommand parses the raw SSH_ORIGINAL_COMMAND string and validates all
// components. Returns the executable and repository path, or an error if any
// constraint is violated.
func sanitizeCommand(cmdStr string) (executable, repoPath string, err error) {
	args, err := shellSplit(cmdStr)
	if err != nil {
		return "", "", fmt.Errorf("malformed command: %v", err)
	}
	if len(args) < 2 {
		return "", "", fmt.Errorf("command must specify both an executable and a repository path")
	}

	executable = args[0]
	repoPath = args[1]

	if !allowedBinaries[executable] {
		return "", "", fmt.Errorf("'%s' is not an allowed git service binary", executable)
	}

	// Block directory traversal and absolute paths.
	if strings.HasPrefix(repoPath, "/") || strings.Contains(repoPath, "..") {
		return "", "", fmt.Errorf("illegal path traversal in repository path")
	}

	if !repoPathRegex.MatchString(repoPath) {
		return "", "", fmt.Errorf("repository path contains invalid characters")
	}

	return executable, repoPath, nil
}

// Proxy is the main entry point for git command proxying.
//
// It validates the SSH_ORIGINAL_COMMAND, enforces that the authenticated user
// (gitUser, injected via GIT_USER env var by the key resolver) can access the
// requested repository, maps the logical path to an absolute path on disk,
// and replaces the current process with git-shell via syscall.Exec.
//
// Parameters:
//   - repoRoot: base directory where all repositories are stored (e.g. /data/git)
//   - gitUser:  the internal username authenticated via SSH key lookup
//   - isAdmin:  whether the user has admin privileges (bypasses namespace check)
//   - origCmd:  the raw SSH_ORIGINAL_COMMAND string
func Proxy(database *db.DB, repoRoot, gitUser string, isAdmin bool, origCmd string) {
	// Handle proxy identity injection: PROXY_REMOTE_USER="user" git-command...
	if strings.HasPrefix(origCmd, "PROXY_REMOTE_USER=") {
		parts := strings.SplitN(origCmd, " ", 2)
		if len(parts) == 2 {
			envPart := parts[0]
			remainingCmd := parts[1]

			// Extract the value: PROXY_REMOTE_USER="value" -> value
			kv := strings.SplitN(envPart, "=", 2)
			if len(kv) == 2 {
				remoteUser := strings.Trim(kv[1], "\"")
				if remoteUser != "" {
					log.Printf("Proxy identity detected: %s (replacing %s)", remoteUser, gitUser)
					gitUser = remoteUser
					// We might want to re-evaluate isAdmin here based on the new gitUser,
					// but for now we'll stick to the user's base identity or trust the proxy.
					user, err := database.GetUserByUsername(gitUser)
					if err == nil && user != nil {
						isAdmin = user.IsAdmin
					}
				}
			}
			origCmd = remainingCmd
		}
	}

	executable, repoPath, err := sanitizeCommand(origCmd)
	if err != nil {
		log.Printf("Command rejected for user %q: %v", gitUser, err)
		fmt.Fprintf(os.Stderr, "Forbidden: %v\n", err)
		os.Exit(1)
	}

	// Access control for repositories.
	//
	// Convention:
	//   users/<username>/... — personal repos
	//   <org>/...            — organisation repos
	//
	var absoluteRepoPath string
	if strings.HasPrefix(repoPath, "users/") {
		parts := strings.SplitN(repoPath, "/", 3)
		if len(parts) >= 2 && parts[1] != gitUser && !isAdmin {
			log.Printf("Access denied: user %q attempted to access %q", gitUser, repoPath)
			fmt.Fprintf(os.Stderr, "Access denied: you do not have permission to access %s\n", repoPath)
			os.Exit(1)
		}
		absoluteRepoPath = filepath.Join(repoRoot, repoPath)
	} else {
		// Organization path
		parts := strings.SplitN(repoPath, "/", 2)
		orgName := parts[0]
		if !isAdmin {
			member, err := database.IsMemberOfOrg(gitUser, orgName)
			if err != nil {
				log.Printf("Internal error checking membership for user %q in org %q: %v", gitUser, orgName, err)
				fmt.Fprintf(os.Stderr, "Internal error: could not verify permissions.\n")
				os.Exit(1)
			}
			if !member {
				log.Printf("Access denied: user %q is not a member of organization %q", gitUser, orgName)
				fmt.Fprintf(os.Stderr, "Access denied: you are not a member of organization %q\n", orgName)
				os.Exit(1)
			}
		}
		absoluteRepoPath = filepath.Join(repoRoot, "orgs", repoPath)
	}

	// Verify the repository is registered in the database.
	// This prevents access to directories on disk that aren't officially "SourceVault Repositories".
	repo, err := database.GetRepoByPath(repoPath)
	if err != nil {
		log.Printf("Error looking up repo %q: %v", repoPath, err)
		fmt.Fprintf(os.Stderr, "Internal error.\n")
		os.Exit(1)
	}
	if repo == nil && !isAdmin {
		log.Printf("Access denied: repo %q is not registered in the database", repoPath)
		fmt.Fprintf(os.Stderr, "Access denied: repository %q does not exist or is not registered.\n", repoPath)
		os.Exit(1)
	}

	finalCmd := fmt.Sprintf("%s '%s'", executable, absoluteRepoPath)
	log.Printf("Access granted for user %q — dispatching: %s", gitUser, finalCmd)

	// Check if we should proxy to an upstream SSH server
	upstreamAddr := os.Getenv("UPSTREAM_SSH_ADDR")
	if upstreamAddr != "" {
		UpstreamProxy(gitUser, upstreamAddr, finalCmd)
		return
	}

	// Replace this process with git-shell (syscall.Exec, not exec.Command).
	// Using process replacement means git-shell inherits our PID, file descriptors,
	// and signal handlers cleanly — essential for correct git wire protocol operation.
	if err := syscall.Exec(
		"/usr/bin/git-shell",
		[]string{"git-shell", "-c", finalCmd},
		os.Environ(),
	); err != nil {
		log.Printf("syscall.Exec failed: %v", err)
		fmt.Fprintf(os.Stderr, "Internal error: could not exec git-shell\n")
		os.Exit(1)
	}
}

// UpstreamProxy dials an upstream SSH server and forwards the git command.
func UpstreamProxy(gitUser, upstreamAddr, cmd string) {
	upstreamUser := os.Getenv("UPSTREAM_SSH_USER")
	if upstreamUser == "" {
		upstreamUser = "git"
	}

	keyPath := os.Getenv("UPSTREAM_SSH_KEY_PATH")
	certPath := os.Getenv("UPSTREAM_SSH_CERT_PATH")

	var signer ssh.Signer
	if keyPath != "" {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			log.Printf("Failed to read upstream key %q: %v", keyPath, err)
			fmt.Fprintf(os.Stderr, "Internal error: could not read upstream key\n")
			os.Exit(1)
		}
		signer, err = ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Printf("Failed to parse upstream key %q: %v", keyPath, err)
			fmt.Fprintf(os.Stderr, "Internal error: could not parse upstream key\n")
			os.Exit(1)
		}
	} else {
		log.Printf("UPSTREAM_SSH_ADDR is set but UPSTREAM_SSH_KEY_PATH is not")
		fmt.Fprintf(os.Stderr, "Internal error: upstream key not configured\n")
		os.Exit(1)
	}

	if certPath != "" {
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			log.Printf("Failed to read upstream cert %q: %v", certPath, err)
			fmt.Fprintf(os.Stderr, "Internal error: could not read upstream cert\n")
			os.Exit(1)
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		if err != nil {
			log.Printf("Failed to parse upstream cert %q: %v", certPath, err)
			fmt.Fprintf(os.Stderr, "Internal error: could not parse upstream cert\n")
			os.Exit(1)
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			log.Printf("Upstream cert %q does not contain a certificate", certPath)
			fmt.Fprintf(os.Stderr, "Internal error: invalid upstream cert\n")
			os.Exit(1)
		}
		signer, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			log.Printf("Failed to create cert signer: %v", err)
			fmt.Fprintf(os.Stderr, "Internal error: could not create cert signer\n")
			os.Exit(1)
		}
	}

	config := &ssh.ClientConfig{
		User: upstreamUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", upstreamAddr, config)
	if err != nil {
		log.Printf("Failed to dial upstream %s: %v", upstreamAddr, err)
		fmt.Fprintf(os.Stderr, "Internal error: could not connect to upstream\n")
		os.Exit(1)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Printf("Failed to create upstream session: %v", err)
		fmt.Fprintf(os.Stderr, "Internal error: could not create upstream session\n")
		os.Exit(1)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Printf("Failed to get upstream stdin: %v", err)
		os.Exit(1)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Printf("Failed to get upstream stdout: %v", err)
		os.Exit(1)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		log.Printf("Failed to get upstream stderr: %v", err)
		os.Exit(1)
	}

	// Inject PROXY_REMOTE_USER
	injectedCmd := fmt.Sprintf("PROXY_REMOTE_USER=%q %s", gitUser, cmd)
	log.Printf("Proxying command upstream for user %s: %s", gitUser, injectedCmd)

	if err := session.Start(injectedCmd); err != nil {
		log.Printf("Failed to start upstream command: %v", err)
		fmt.Fprintf(os.Stderr, "Internal error: could not start upstream command\n")
		os.Exit(1)
	}

	// Pump data
	go func() {
		_, _ = io.Copy(stdin, os.Stdin)
		stdin.Close()
	}()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(os.Stdout, stdout)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stderr, stderr)
		done <- struct{}{}
	}()

	log.Printf("Waiting for upstream command to finish...")
	err = session.Wait()
	log.Printf("Upstream command finished with err: %v", err)

	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			os.Exit(exitErr.ExitStatus())
		}
		os.Exit(1)
	}
	os.Exit(0)
}
