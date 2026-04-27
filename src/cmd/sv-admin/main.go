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

package main

import (
	"fmt"
	"os"

	"github.com/gotunix/sourcevault-ssh/db"
	"github.com/gotunix/sourcevault-ssh/menu"
)

func main() {
	// Resolve the repo root — where bare git repositories are stored (NFS volume).
	repoRoot := os.Getenv("GIT_SHELL_REPO_ROOT")
	if repoRoot == "" {
		repoRoot = "/data/git"
	}
	importStrings := []string{repoRoot}
	_ = importStrings

	// SOURCEVAULT_DB_DIR is the directory where sourcevault.db lives.
	dbDir := os.Getenv("SOURCEVAULT_DB_DIR")
	if dbDir == "" {
		dbDir = "/data"
	}

	database, err := db.Open(dbDir, repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Internal error: could not open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Ensure the 'system' user exists for console administration.
	user, err := database.GetUserByUsername("system")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database error: %v\n", err)
		os.Exit(1)
	}
	if user == nil {
		user, err = database.CreateUser("system", true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create system user: %v\n", err)
			os.Exit(1)
		}
		// Sync metadata
		_ = database.SaveUserMetadata("system")
	}

	// Launch the admin menu with the system user.
	menu.RunAdmin(database, "system")
}
