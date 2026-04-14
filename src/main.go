// Package main implements SourceVault SSH — a secure Git shell orchestrator.
//
// This binary is intended to be used as an SSH ForceCommand, replacing the default
// git-shell. It intercepts SSH_ORIGINAL_COMMAND, validates and sanitizes the
// requested git operation, maps the logical repository path to an absolute
// filesystem path, then hands off execution to the native /usr/bin/git-shell
// via syscall.Exec (process replacement, not a subprocess).
//
// FUTURE API INTEGRATION: Hooks are documented throughout for eventual
// integration with the SourceVault web application API.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"
)

// allowedBinaries is the strict whitelist of git service executables.
// Any SSH command whose first token is not in this map is rejected immediately.
// FUTURE API INTEGRATION: This list can be extended or queried from an API
// endpoint to support custom git hooks or pluggable remote helpers.
var allowedBinaries = map[string]bool{
	"git-upload-pack":    true,
	"git-receive-pack":   true,
	"git-upload-archive": true,
}

// repoPathRegex enforces that repository paths contain only safe characters.
// This prevents shell injection, unicode tricks, and other path-based attacks.
var repoPathRegex = regexp.MustCompile(`^[a-zA-Z0-9\._\-/]+$`)

// shellSplit splits a shell-style command string into tokens, respecting
// single-quoted strings. It is intentionally minimal — it handles the exact
// format produced by OpenSSH when passing a git command
// (e.g. "git-receive-pack 'users/me/repo.git'").
//
// It does NOT support: double quotes, backslash escapes, or nested quoting.
// That is sufficient for the sanitized git command format we accept.
func shellSplit(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inSingleQuote := false

	for i, r := range s {
		switch {
		case r == '\'' && !inSingleQuote:
			// Opening single quote — begin accumulating quoted content.
			inSingleQuote = true
		case r == '\'' && inSingleQuote:
			// Closing single quote — end of quoted segment.
			inSingleQuote = false
		case unicode.IsSpace(r) && !inSingleQuote:
			// Unquoted whitespace — flush current token if non-empty.
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			_ = i
			current.WriteRune(r)
		}
	}

	if inSingleQuote {
		return nil, fmt.Errorf("unterminated single quote in command string")
	}

	// Flush the final token.
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

// sanitizeCommand parses the raw SSH_ORIGINAL_COMMAND string and enforces
// all safety constraints before any execution is attempted.
//
// Returns the validated executable name and repository path, or an error
// if any constraint is violated.
//
// FUTURE API INTEGRATION: Validation rules here (binary whitelist, path regex)
// can be synchronised with the web application's REST API to ensure parity
// between SSH and HTTP access controls.
func sanitizeCommand(cmdStr string) (string, string, error) {
	if cmdStr == "" {
		return "", "", fmt.Errorf("empty command")
	}

	args, err := shellSplit(cmdStr)
	if err != nil {
		return "", "", fmt.Errorf("invalid shell formatting: %v", err)
	}

	if len(args) < 2 {
		return "", "", fmt.Errorf("command must have both an executable and a repository path")
	}

	executable := args[0]
	repoPath := args[1]

	// Enforce binary whitelist.
	if !allowedBinaries[executable] {
		return "", "", fmt.Errorf("binary '%s' is not an allowed git service", executable)
	}

	// Block absolute paths and directory traversal attempts.
	if strings.HasPrefix(repoPath, "/") || strings.Contains(repoPath, "..") {
		return "", "", fmt.Errorf("illegal path traversal in repository path")
	}

	// Enforce safe character set.
	if !repoPathRegex.MatchString(repoPath) {
		return "", "", fmt.Errorf("malicious characters detected in repository path")
	}

	return executable, repoPath, nil
}

func main() {
	// Direct all log output to stderr. This is critical: git wire protocols
	// (upload-pack, receive-pack) communicate over stdout, so any stray
	// output to stdout will corrupt the git data stream.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stderr)

	// GIT_SHELL_REPO_ROOT defines where all physical git repositories live.
	// Defaults to /data/git to match the expected Docker volume mount.
	repoRoot := os.Getenv("GIT_SHELL_REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "/data/git"
	}
	repoRoot = strings.TrimRight(repoRoot, "/")

	// SSH_ORIGINAL_COMMAND is set by the SSH daemon when a client runs a
	// remote command (e.g. git push / git clone). If it is absent the user
	// connected interactively without a command.
	origCmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	if origCmd == "" {
		// FUTURE API INTEGRATION: When interactive mode is implemented,
		// this block will invoke the TUI or pipe requests to the web API
		// for repository management (create, delete, list, etc.).
		log.Println("No SSH_ORIGINAL_COMMAND; interactive access is not yet enabled.")
		fmt.Fprintf(os.Stderr, "Restricted: Interactive access is not enabled.\n")
		os.Exit(1)
	}

	// Parse and validate the inbound command.
	executable, repoPath, err := sanitizeCommand(origCmd)
	if err != nil {
		log.Printf("Command rejected: %v", err)
		fmt.Fprintf(os.Stderr, "Forbidden: %v\n", err)
		os.Exit(1)
	}

	// Map the logical repository path to an absolute filesystem path.
	//
	// Routing convention (mirrors the Python orchestrator):
	//   users/<username>/<repo>.git  →  $REPO_ROOT/users/<username>/<repo>.git
	//   <anything else>              →  $REPO_ROOT/orginizations/<path>
	//
	// FUTURE API INTEGRATION: This translation can be replaced with an API
	// call to resolve logical paths to UUIDs or arbitrary storage backends.
	var absoluteRepoPath string
	if strings.HasPrefix(repoPath, "users/") {
		absoluteRepoPath = filepath.Join(repoRoot, repoPath)
	} else {
		absoluteRepoPath = filepath.Join(repoRoot, "orginizations", repoPath)
	}

	// Reconstruct the command in the format expected by git-shell's -c flag.
	finalCmd := fmt.Sprintf("%s '%s'", executable, absoluteRepoPath)
	log.Printf("Access granted — dispatching: %s", finalCmd)

	// Hand off to the native git-shell via syscall.Exec (process replacement).
	// This is preferable to exec.Command because it replaces the current
	// process image rather than spawning a child, keeping the process tree
	// clean and ensuring signal handling is transparent.
	gitShellPath := "/usr/bin/git-shell"
	if err := syscall.Exec(gitShellPath, []string{"git-shell", "-c", finalCmd}, os.Environ()); err != nil {
		log.Printf("syscall.Exec failed: %v", err)
		fmt.Fprintf(os.Stderr, "Internal error: could not execute git-shell.\n")
		os.Exit(1)
	}
}
