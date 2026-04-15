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

// Print writes a full version block to stdout, including:
//   - Internal application version
//   - Go runtime version
//   - All module dependencies and their versions
//
// Output goes to stdout so it renders correctly over an SSH TUI session.
func Print() {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════╗")
	fmt.Printf("  ║  %-44s║\n", fmt.Sprintf("%s  v%s", AppName, Version))
	fmt.Println("  ╠══════════════════════════════════════════════╣")

	// Go runtime version (e.g. "go1.22.0").
	fmt.Printf("  ║  %-18s %-25s║\n", "Go Runtime:", runtime.Version())
	fmt.Printf("  ║  %-18s %-25s║\n", "OS/Arch:", runtime.GOOS+"/"+runtime.GOARCH)

	// Read module dependency info embedded by the linker at build time.
	info, ok := debug.ReadBuildInfo()
	if ok {
		fmt.Println("  ╠══════════════════════════════════════════════╣")
		fmt.Printf("  ║  %-44s║\n", "Dependencies:")
		for _, dep := range info.Deps {
			// Trim long module paths to fit the column width.
			name := dep.Path
			if len(name) > 30 {
				parts := strings.Split(name, "/")
				name = "…/" + parts[len(parts)-1]
			}
			ver := dep.Version
			if dep.Replace != nil {
				ver = dep.Replace.Version + " (replaced)"
			}
			fmt.Printf("  ║    %-26s %-17s║\n", name, ver)
		}

		// VCS build metadata (commit hash, dirty flag) if available.
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
			fmt.Println("  ╠══════════════════════════════════════════════╣")
			fmt.Printf("  ║  %-18s %-25s║\n", "Git Commit:", commit+dirty)
		}
	}

	fmt.Println("  ╚══════════════════════════════════════════════╝")
	fmt.Println()
}
