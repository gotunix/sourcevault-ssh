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
	"github.com/gotunix/sourcevault-ssh/version"
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
		dbDir = "/data"
	}

	// ------------------------------------------------------------------
	// Mode 0: Bootstrap — sv-shell --bootstrap
	// ------------------------------------------------------------------
	// Called from entrypoint.sh at container startup where the full container
	// environment is available. Seeds the first admin user from
	// BOOTSTRAP_ADMIN_KEY. Exits immediately — never reached via sshd.
	if len(os.Args) == 2 && os.Args[1] == "--bootstrap" {
		log.Printf("[bootstrap] startup mode — dbDir=%s", dbDir)
		database, err := openDB(dbDir)
		if err != nil {
			log.Printf("[bootstrap] FATAL: could not open db: %v", err)
			os.Exit(1)
		}
		defer database.Close()

		// BOOTSTRAP_ADMIN_USER sets the username for the first admin.
		// Defaults to "admin" if not specified.
		adminUser := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
		if adminUser == "" {
			adminUser = "admin"
		}
		log.Printf("[bootstrap] admin username: %s", adminUser)

		if err := maybeBootstrap(database, adminUser); err != nil {
			log.Printf("[bootstrap] ERROR (user): %v", err)
			os.Exit(1)
		}

		if err := maybeBootstrapCA(database); err != nil {
			log.Printf("[bootstrap] ERROR (ca): %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// ------------------------------------------------------------------
	// Mode 0b: Sync — sv-shell --sync
	// ------------------------------------------------------------------
	// Synchronizes organization metadata from the filesystem into the database.
	// This is the "Recovery" path if the database is lost.
	if len(os.Args) == 2 && os.Args[1] == "--sync" {
		database, err := openDB(dbDir)
		if err != nil {
			log.Printf("[sync] FATAL: could not open db: %v", err)
			os.Exit(1)
		}
		defer database.Close()

		log.Printf("[sync] starting filesystem sync from %s...", repoRoot)
		if err := database.SyncFromFilesystem(repoRoot); err != nil {
			log.Printf("[sync] ERROR: %v", err)
			os.Exit(1)
		}
		log.Printf("[sync] sync complete")
		os.Exit(0)
	}

	// ------------------------------------------------------------------
	// Mode 1: AuthorizedKeysCommand — sv-shell --keys <fingerprint>
	// ------------------------------------------------------------------
	// sshd calls this before authenticating. We must respond quickly with
	// the authorized_keys line or nothing (deny). No database writes here.
	if len(os.Args) == 3 && os.Args[1] == "--keys" {
		fingerprint := os.Args[2]
		log.Printf("[key-resolver] invoked — fingerprint=%s dbDir=%s", fingerprint, dbDir)

		database, err := openDB(dbDir)
		if err != nil {
			log.Printf("[key-resolver] FATAL: could not open db at %s: %v", dbDir, err)
			fmt.Fprintf(os.Stderr, "[sourcevault-ssh] db error: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()
		log.Printf("[key-resolver] db opened at %s", dbDir)

		auth.Resolve(database, fingerprint)
		return
	}

	// ------------------------------------------------------------------
	// Mode 2: Git Proxy — SSH_ORIGINAL_COMMAND is set or invoked via -c
	// ------------------------------------------------------------------
	origCmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	// If invoked as a shell (e.g. sv-shell -c "git-upload-pack ..."), 
	// the command is in the arguments.
	if origCmd == "" && len(os.Args) >= 3 && os.Args[1] == "-c" {
		origCmd = os.Args[2]
	}

	if origCmd != "" {
		fmt.Fprintf(os.Stderr, "SourceVault SSH v%s\n", version.Version)

		database, err := openDB(dbDir)
		if err != nil {
			log.Printf("Internal error: could not open database: %v", err)
			fmt.Fprintf(os.Stderr, "Forbidden: internal error.\n")
			os.Exit(1)
		}
		defer database.Close()

		gitUser := os.Getenv("GIT_USER")
		isAdmin := os.Getenv("GIT_ADMIN") == "true"

		// If GIT_USER is not set, we might be authenticating via an SSH certificate
		// that bypassed the resolver but is exposed via SSH_USER_AUTH.
		authFile := os.Getenv("SSH_USER_AUTH")
		if gitUser == "" && authFile != "" {
			var resolveErr error
			gitUser, isAdmin, resolveErr = auth.ResolveFromAuthInfo(authFile, database)
			if resolveErr != nil {
				log.Printf("Certificate resolution failed: %v", resolveErr)
				fmt.Fprintf(os.Stderr, "Forbidden: certificate could not be resolved or is untrusted.\n")
				os.Exit(1)
			}
			log.Printf("Identity resolved via certificate: user=%s isAdmin=%v", gitUser, isAdmin)
		}

		if gitUser == "" {
			// This should never happen if sshd_config is correct.
			log.Println("GIT_USER is not set and no valid certificate found — check AuthorizedKeysCommand and ExposeAuthInfo config")
			fmt.Fprintf(os.Stderr, "Forbidden: user identity could not be determined.\n")
			os.Exit(1)
		}

		shell.Proxy(database, repoRoot, gitUser, isAdmin, origCmd)
		return
	}

	// ------------------------------------------------------------------
	// Mode 3: Interactive SSH session — no git command was sent
	// ------------------------------------------------------------------
	fmt.Fprintf(os.Stderr, "%s v%s\n", version.AppName, version.Version)
	database, err := openDB(dbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Internal error: could not open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	isAdmin := os.Getenv("GIT_ADMIN") == "true"
	gitUser := os.Getenv("GIT_USER")

	// Fallback to certificate resolution for interactive sessions too.
	authFile := os.Getenv("SSH_USER_AUTH")
	if gitUser == "" && authFile != "" {
		var resolveErr error
		gitUser, isAdmin, resolveErr = auth.ResolveFromAuthInfo(authFile, database)
		if resolveErr != nil {
			log.Printf("Certificate resolution failed for interactive session: %v", resolveErr)
			fmt.Fprintf(os.Stderr, "Restricted: identity could not be resolved from certificate.\n")
			os.Exit(1)
		}
		log.Printf("Identity resolved via certificate for interactive session: user=%s isAdmin=%v", gitUser, isAdmin)
	}

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

// maybeBootstrap seeds the first admin user if the database is empty.
// adminUser is the username to register (typically from BOOTSTRAP_ADMIN_USER).
// BOOTSTRAP_ADMIN_KEY must contain the full public key line.
func maybeBootstrap(database *db.DB, adminUser string) error {
	bootstrapKey := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_KEY"))
	if bootstrapKey == "" {
		log.Printf("[bootstrap] BOOTSTRAP_ADMIN_KEY is not set — skipping")
		return nil
	}

	empty, err := database.IsEmpty()
	if err != nil {
		return fmt.Errorf("checking db state: %w", err)
	}
	if !empty {
		log.Printf("[bootstrap] database already has users — skipping")
		return nil
	}

	log.Printf("[bootstrap] database is empty — seeding first admin: %s", adminUser)
	log.Printf("[bootstrap] parsing key (first 40 chars): %.40s...", bootstrapKey)

	keyType, keyData, comment, err := db.ParsePublicKeyLine(bootstrapKey)
	if err != nil {
		return fmt.Errorf("BOOTSTRAP_ADMIN_KEY is invalid: %w", err)
	}
	log.Printf("[bootstrap] parsed key: type=%s comment=%q", keyType, comment)

	fingerprint, err := db.FingerprintKey(keyData)
	if err != nil {
		return fmt.Errorf("computing bootstrap key fingerprint: %w", err)
	}
	log.Printf("[bootstrap] computed fingerprint: %s", fingerprint)

	user, err := database.CreateUser(adminUser, true)
	if err != nil {
		return fmt.Errorf("creating bootstrap admin user %q: %w", adminUser, err)
	}
	log.Printf("[bootstrap] created user %q with id=%d", adminUser, user.ID)

	if _, err := database.AddKey(user.ID, fingerprint, keyType, keyData, comment); err != nil {
		return fmt.Errorf("registering bootstrap admin key: %w", err)
	}

	log.Printf("[bootstrap] SUCCESS — admin user %q created, key registered: %s", adminUser, fingerprint)
	return nil
}

// maybeBootstrapCA seeds a trusted CA from BOOTSTRAP_CA_KEY if provided.
func maybeBootstrapCA(database *db.DB) error {
	caKey := strings.TrimSpace(os.Getenv("BOOTSTRAP_CA_KEY"))
	if caKey == "" {
		log.Printf("[bootstrap] BOOTSTRAP_CA_KEY is not set — skipping CA bootstrap")
		return nil
	}

	isAdmin := os.Getenv("BOOTSTRAP_CA_IS_ADMIN") == "true"
	caName := os.Getenv("BOOTSTRAP_CA_NAME")
	if caName == "" {
		caName = "InitialCA"
	}

	log.Printf("[bootstrap] Attempting to trust CA: name=%q isAdmin=%v key_len=%d", caName, isAdmin, len(caKey))

	keyType, keyData, _, err := db.ParsePublicKeyLine(caKey)
	if err != nil {
		return fmt.Errorf("BOOTSTRAP_CA_KEY is invalid (could not parse): %w", err)
	}

	fingerprint, err := db.FingerprintKey(keyData)
	if err != nil {
		return fmt.Errorf("computing CA fingerprint failed: %w", err)
	}

	log.Printf("[bootstrap] CA fingerprint calculated: %s", fingerprint)

	// Check if already exists
	existing, err := database.LookupCAByFingerprint(fingerprint)
	if err != nil {
		return fmt.Errorf("db error checking for existing CA: %w", err)
	}
	if existing != nil {
		log.Printf("[bootstrap] CA already trusted in database: %s — skip registration", fingerprint)
		return nil
	}

	log.Printf("[bootstrap] CA not found in DB, registering now...")
	if _, err := database.AddTrustedCA(caName, fingerprint, keyType, keyData, isAdmin); err != nil {
		return fmt.Errorf("registering bootstrap CA into DB failed: %w", err)
	}

	log.Printf("[bootstrap] SUCCESS — CA %q is now trusted: %s", caName, fingerprint)
	return nil
}
