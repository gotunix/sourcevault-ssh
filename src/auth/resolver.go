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

// Package auth implements the AuthorizedKeysCommand resolver for SourceVault SSH.
//
// When sshd receives a connection, it calls this binary as:
//
//	sv-shell --keys <fingerprint>
//
// This package looks up the fingerprint in the SQLite database and writes
// the correct authorized_keys line to stdout. sshd reads it and either
// allows or denies the connection. If the fingerprint is unknown, nothing
// is written and sshd denies access silently.
//
// The generated authorized_keys line injects two environment variables into
// the session that the git proxy mode reads:
//
//	GIT_USER  — the internal username the connecting key belongs to
//	GIT_ADMIN — "true" if the user has admin privileges
//
// FUTURE API INTEGRATION: Replace db.LookupKeyByFingerprint with an HTTP call
// to the SourceVault web API when running in platform mode.
package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/gotunix/sourcevault-ssh/db"
)

// Resolve looks up the given SSH key fingerprint in the database and writes
// the authorized_keys output line to stdout for sshd to consume.
//
// If the fingerprint is not registered, nothing is printed and the process
// exits cleanly — sshd interprets the empty output as "key not found" and
// denies the connection without exposing any information to the client.
func Resolve(database *db.DB, fingerprint string) {
	key, err := database.LookupKeyByFingerprint(fingerprint)
	if err != nil {
		// Log to stderr only — we must not corrupt ssh key-lookup stdout output.
		fmt.Fprintf(os.Stderr, "[sourcevault-ssh] key lookup error: %v\n", err)
		os.Exit(1)
	}

	if key == nil {
		// Unknown fingerprint — print nothing, sshd will deny the connection.
		fmt.Fprintf(os.Stderr, "[key-resolver] fingerprint not found in db: %s\n", fingerprint)
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "[key-resolver] key found: fingerprint=%s user=%s\n", fingerprint, key.Username)

	// Check if the key has an artificial expiration date set.
	if key.ExpiresAt != "" {
		expires, err := time.Parse("2006-01-02 15:04:05", key.ExpiresAt)
		if err != nil {
			// Fallback to date-only if needed, but we should aim for standard SQLite format.
			expires, err = time.Parse("2006-01-02", key.ExpiresAt)
		}

		if err == nil {
			if time.Now().After(expires) {
				fmt.Fprintf(os.Stderr, "[key-resolver] DENIED: key expired on %s\n", key.ExpiresAt)
				os.Exit(0)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[key-resolver] WARNING: could not parse expiration date %q: %v\n", key.ExpiresAt, err)
		}
	}

	// Fetch the user record to determine admin status.
	user, err := database.GetUserByUsername(key.Username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[key-resolver] user lookup error for %s: %v\n", key.Username, err)
		os.Exit(0)
	}
	if user == nil {
		fmt.Fprintf(os.Stderr, "[key-resolver] user record missing for %s — key exists but user does not\n", key.Username)
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "[key-resolver] user resolved: username=%s isAdmin=%v\n", user.Username, user.IsAdmin)

	isAdmin := "false"
	if user.IsAdmin {
		isAdmin = "true"
	}

	// Build the options string based on the user's role.
	//
	// Regular users: no-pty is enforced since they only ever run git wire-protocol commands.
	//   Allowing a PTY for a git session is unnecessary and slightly reduces attack surface.
	//
	// Admin users: no-pty is omitted so the interactive TUI can render correctly
	//   over an SSH session. All other restrictions remain in place.
	//
	// FUTURE: When the user self-service menu is added, regular users will also
	//   need no-pty removed to access their own management TUI.
	var restrictions string
	if user.IsAdmin {
		// Admins get an interactive session — PTY allowed, everything else locked down.
		restrictions = "no-port-forwarding,no-X11-forwarding,no-agent-forwarding"
	} else {
		// Regular users: git only — no PTY, no forwarding.
		restrictions = "no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty"
	}

	line := fmt.Sprintf(
		`command="/usr/local/bin/git-shell",%s,environment="GIT_USER=%s",environment="GIT_ADMIN=%s" %s %s %s`,
		restrictions,
		key.Username,
		isAdmin,
		key.KeyType,
		key.KeyData,
		key.Comment,
	)
	fmt.Fprintf(os.Stderr, "[key-resolver] emitting authorized_keys line for user=%s admin=%s\n", key.Username, isAdmin)
	fmt.Println(line)
}
