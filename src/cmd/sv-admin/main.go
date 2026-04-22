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
	// SOURCEVAULT_DB_DIR is the directory where sourcevault.db lives.
	dbDir := os.Getenv("SOURCEVAULT_DB_DIR")
	if dbDir == "" {
		dbDir = "/data"
	}

	database, err := db.Open(dbDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Internal error: could not open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Launch the admin menu with a system-console identifier.
	// This identifier is used for internal logging/metadata when no user is present.
	menu.RunAdmin(database, "system-console")
}
