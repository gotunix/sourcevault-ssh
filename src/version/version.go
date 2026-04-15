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
const inner = 70

// bar returns a horizontal divider line.
func bar(left, mid, right string) string {
	return "  " + left + strings.Repeat(mid, inner) + right
}

// row formats a single content line padded to fill the box exactly.
func row(content string) string {
	// Pad content to fill the inner width exactly, then wrap in borders.
	padded := fmt.Sprintf("%-*s", inner, content)
	return "  ║" + padded + "║"
}

// kv formats a key-value row with the key left-aligned in a fixed column.
func kv(label, value string) string {
	// Label column: 22 chars. Value column: inner - 22 chars.
	const labelWidth = 22
	content := fmt.Sprintf("  %-*s%s", labelWidth, label, value)
	return row(content)
}

// Print writes a full version block to stdout.
func Print() {
	sep := bar("╠", "═", "╣")

	fmt.Println()
	fmt.Println(bar("╔", "═", "╗"))

	// Title — app name left, version right.
	title := fmt.Sprintf("  %-*s%*s", inner/2, AppName, inner/2-2, "v"+Version)
	fmt.Println("  ║" + title + "║")
	fmt.Println(sep)

	fmt.Println(kv("Go Runtime:", runtime.Version()))
	fmt.Println(kv("OS / Arch:", runtime.GOOS+"/"+runtime.GOARCH))

	// Module dependency info embedded by the linker at build time.
	info, ok := debug.ReadBuildInfo()
	if ok && len(info.Deps) > 0 {
		fmt.Println(sep)
		fmt.Println(row("  Dependencies:"))
		for _, dep := range info.Deps {
			name := dep.Path
			ver := dep.Version
			if dep.Replace != nil {
				ver = dep.Replace.Version + " (replaced)"
			}
			// Truncate long module paths to keep columns tidy.
			const nameWidth = 45
			if len(name) > nameWidth {
				parts := strings.Split(name, "/")
				name = "…/" + strings.Join(parts[len(parts)-2:], "/")
			}
			fmt.Println(row(fmt.Sprintf("    %-*s%s", nameWidth, name, ver)))
		}
	}

	// VCS metadata (git commit hash + dirty flag).
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

