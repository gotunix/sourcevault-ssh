package hooks

import (
	"log"
	"os"
)

// Run acts as the primary router for intercepting git hook invocations properly
func Run(hookName string) int {
	repoDir, err := os.Getwd()
	if err != nil {
		log.Printf("Failed to get working directory natively: %v", err)
		return 1
	}

	if hookName == "post-receive" {
		PostReceive(repoDir)
	}

	// Always emit zero so git doesn't crash on standard hook resolutions
	return 0
}
