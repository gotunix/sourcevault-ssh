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
// but WITHOUT ANY WARRANTY; without even the implied warranty of                                 //
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   //
// GNU Affero General Public License for more details.                                             //
//                                                                                                 //
// You should have received a copy of the GNU Affero General Public License                        //
// along with this program.  If not, see <https://www.gnu.org/licenses/>.                          //
// ----------------------------------------------------------------------------------------------- //

// Package version provides build and runtime version information for SourceVault SSH.
//
// The internal Version constant follows semantic versioning (MAJOR.MINOR.PATCH).
// Bump this manually when releasing. Module dependency versions are read
// at runtime from the Go build info embedded in the binary by the linker.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the internal SourceVault SSH release version.
// Bump this when cutting a release.
const Version = "0.1.0"

// AppName is the human-readable application name.
const AppName = "SourceVault SSH"

// inner is the number of printable characters between the box borders.
// 80 fits any standard terminal and leaves room for long module paths.
const inner = 80

// nameWidth and verWidth are fixed column widths for dependency rows.
// nameWidth + verWidth + 4 (indent) + 2 (gap) == inner  →  48 + 26 + 4 + 2 = 80
const (
	nameWidth = 48
	verWidth  = 26
)

// trunc hard-caps s to max visible characters, appending "…" if cut.
// Module paths and semver strings are ASCII so byte length == display width.
func trunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// bar returns a horizontal divider line.
func bar(left, mid, right string) string {
	return "  " + left + strings.Repeat(mid, inner) + right
}

// row formats a single content line padded to exactly inner width.
// If content is somehow longer than inner it is hard-capped so the right
// border always aligns.
func row(content string) string {
	if len(content) > inner {
		content = content[:inner-1] + "…"
	}
	return fmt.Sprintf("  ║%-*s║", inner, content)
}

// kv formats a labelled value row; label occupies a fixed 22-char left column.
func kv(label, value string) string {
	const labelWidth = 22
	return row(fmt.Sprintf("  %-*s%s", labelWidth, label, value))
}

// Print writes the full version block to stdout.
func Print() {
	sep := bar("╠", "═", "╣")

	fmt.Println()
	fmt.Println(bar("╔", "═", "╗"))

	// Title — app name left-aligned, version right-aligned.
	left := fmt.Sprintf("  %-*s", inner/2, AppName)
	right := fmt.Sprintf("%*s", inner/2-2, "v"+Version)
	fmt.Println("  ║" + left + right + "║")
	fmt.Println(sep)

	fmt.Println(kv("Go Runtime:", runtime.Version()))
	fmt.Println(kv("OS / Arch:", runtime.GOOS+"/"+runtime.GOARCH))

	// Module dependency info embedded by the linker at build time.
	info, ok := debug.ReadBuildInfo()
	if ok && len(info.Deps) > 0 {
		fmt.Println(sep)
		fmt.Println(row("  Dependencies:"))
		for _, dep := range info.Deps {
			// Truncate both columns to their guaranteed max widths so
			// pseudo-versions like v0.0.0-20230129092748-24d4a6f8daec never overflow.
			name := trunc(dep.Path, nameWidth)
			ver := dep.Version
			if dep.Replace != nil {
				ver = dep.Replace.Version
			}
			ver = trunc(ver, verWidth)
			fmt.Println(row(fmt.Sprintf("    %-*s  %-*s", nameWidth, name, verWidth, ver)))
		}
	}

	// VCS metadata — short git commit hash and dirty flag.
	if ok {
		var commit, dirty string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) > 8 {
					commit = s.Value[:8]
				} else {
					commit = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = " (modified)"
				}
			}
		}
		if commit != "" {
			fmt.Println(sep)
			fmt.Println(kv("Git Commit:", commit+dirty))
		}
	}

	fmt.Println(bar("╚", "═", "╝"))
	fmt.Println()
}
