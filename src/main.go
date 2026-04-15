// SourceVault SSH — Secure Git Shell Orchestrator
//
// This is the entry point for the sv-shell binary. It operates in one of three
// modes depending on how it was invoked:
//
//  1. Key Resolver (AuthorizedKeysCommand):
//     Invoked by sshd as: sv-shell --keys <SHA256:fingerprint>
//     Looks up the key in the SQLite database and writes the authorized_keys
//     line to stdout. sshd uses this to authenticate and inject the user identity.
//
//  2. Git Proxy (ForceCommand / command= in authorized_keys):
//     Invoked when SSH_ORIGINAL_COMMAND is set (user ran git push/clone/fetch).
//     Reads GIT_USER from the environment (injected by the key resolver),
//     validates the command, enforces access control, and execs git-shell.
//
//  3. Admin TUI:
//     Invoked when SSH_ORIGINAL_COMMAND is absent and GIT_ADMIN=true.
//     Presents an interactive menu for managing users and SSH keys.
//
// Bootstrap:
//     On first run the database is empty. Set BOOTSTRAP_ADMIN_KEY in .env
//     to a public key (e.g. "ssh-ed25519 AAAA... admin@host"). This key is
//     automatically registered as the first admin user ("admin") on first boot,
//     then the env var has no further effect once the user exists.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gotunix/sourcevault-ssh/auth"
	"github.com/gotunix/sourcevault-ssh/db"
	"github.com/gotunix/sourcevault-ssh/menu"
	"github.com/gotunix/sourcevault-ssh/shell"
)

func main() {
	// All log output goes to stderr to avoid corrupting git wire protocol or
	// AuthorizedKeysCommand output on stdout.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stderr)

	// Resolve the repo root — where bare git repositories are stored (NFS volume).
	repoRoot := os.Getenv("GIT_SHELL_REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "/data/git"
	}
	repoRoot = strings.TrimRight(repoRoot, "/")

	// SOURCEVAULT_DB_DIR is the directory where sourcevault.db lives.
	// This MUST be a local (non-NFS) volume — SQLite does not support NFS file locking.
	// Default: /data/sourcevault — mount a named Docker volume here (see docker-compose.yaml).
	// Override with any local path for non-Docker deployments.
	dbDir := os.Getenv("SOURCEVAULT_DB_DIR")
	if dbDir == "" {
		dbDir = "/data/sourcevault"
	}

	// ------------------------------------------------------------------
	// Mode 1: AuthorizedKeysCommand — sv-shell --keys <fingerprint>
	// ------------------------------------------------------------------
	// sshd calls this before authenticating. We must respond quickly with
	// the authorized_keys line or nothing (deny). No database writes here.
	if len(os.Args) == 3 && os.Args[1] == "--keys" {
		fingerprint := os.Args[2]
		database, err := openDB(dbDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sourcevault-ssh] db error: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		// Bootstrap: if the database is empty and BOOTSTRAP_ADMIN_KEY is set,
		// register it as the first admin before doing the lookup. This ensures
		// the very first admin key gets resolved on its first connection.
		if err := maybeBootstrap(database); err != nil {
			fmt.Fprintf(os.Stderr, "[sourcevault-ssh] bootstrap error: %v\n", err)
			// Non-fatal — continue with the lookup anyway.
		}

		auth.Resolve(database, fingerprint)
		return
	}

	// ------------------------------------------------------------------
	// Mode 2: Git Proxy — SSH_ORIGINAL_COMMAND is set
	// ------------------------------------------------------------------
	origCmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	if origCmd != "" {
		gitUser := os.Getenv("GIT_USER")
		if gitUser == "" {
			// This should never happen if sshd_config is correct (key resolver
			// always injects GIT_USER). Guard against misconfiguration.
			log.Println("GIT_USER is not set — check AuthorizedKeysCommand and PermitUserEnvironment config")
			fmt.Fprintf(os.Stderr, "Forbidden: user identity could not be determined.\n")
			os.Exit(1)
		}
		isAdmin := os.Getenv("GIT_ADMIN") == "true"
		shell.Proxy(repoRoot, gitUser, isAdmin, origCmd)
		return
	}

	// ------------------------------------------------------------------
	// Mode 3: Interactive SSH session — no git command was sent
	// ------------------------------------------------------------------
	database, err := openDB(dbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Internal error: could not open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	isAdmin := os.Getenv("GIT_ADMIN") == "true"
	gitUser := os.Getenv("GIT_USER")

	if isAdmin {
		// Admin TUI — full user and key management.
		menu.RunAdmin(database)
	} else if gitUser != "" {
		// User self-service TUI — manage own keys and (future) PGP keys.
		menu.RunUser(database, gitUser)
	} else {
		fmt.Fprintf(os.Stderr, "Restricted: Interactive access is not enabled for this user.\n")
		os.Exit(1)
	}
}

// openDB opens the SQLite database at the given directory path.
// The directory must be on a local volume — SQLite does not work correctly over NFS.
func openDB(dbDir string) (*db.DB, error) {
	return db.Open(dbDir)
}

// maybeBootstrap checks if the database is empty and, if so, registers the
// key specified in BOOTSTRAP_ADMIN_KEY as the first admin user.
//
// BOOTSTRAP_ADMIN_KEY should be a full public key line:
//
//	ssh-ed25519 AAAA... admin@myhost
//
// Once at least one user exists, this function is a no-op. It is safe to
// leave BOOTSTRAP_ADMIN_KEY set after bootstrapping.
func maybeBootstrap(database *db.DB) error {
	bootstrapKey := os.Getenv("BOOTSTRAP_ADMIN_KEY")
	if bootstrapKey == "" {
		return nil // Not configured — skip.
	}

	empty, err := database.IsEmpty()
	if err != nil {
		return fmt.Errorf("checking db state: %w", err)
	}
	if !empty {
		return nil // Already bootstrapped.
	}

	keyType, keyData, comment, err := db.ParsePublicKeyLine(bootstrapKey)
	if err != nil {
		return fmt.Errorf("BOOTSTRAP_ADMIN_KEY is invalid: %w", err)
	}

	fingerprint, err := db.FingerprintKey(keyData)
	if err != nil {
		return fmt.Errorf("computing bootstrap key fingerprint: %w", err)
	}

	user, err := database.CreateUser("admin", true)
	if err != nil {
		return fmt.Errorf("creating bootstrap admin user: %w", err)
	}

	if _, err := database.AddKey(user.ID, fingerprint, keyType, keyData, comment); err != nil {
		return fmt.Errorf("registering bootstrap admin key: %w", err)
	}

	log.Printf("Bootstrap complete — first admin user 'admin' created with key %s", fingerprint)
	return nil
}
