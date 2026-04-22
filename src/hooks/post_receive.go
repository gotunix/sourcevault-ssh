package hooks

import (
	"log"
	"os/exec"
	"strings"
)

// PostReceive logic sequence loop executed during git commits effortlessly
func PostReceive(repoDir string) {
	// Execute Mirror Plugin mapping cleanly natively
	runMirrorPlugin(repoDir)
}

func runMirrorPlugin(repoDir string) {
	// 1. Enforce explicit enable flag optimally solidly smoothly
	enabledCmd := exec.Command("git", "config", "--get", "sourcevault.mirror.enabled")
	enabledCmd.Dir = repoDir
	enabledOut, err := enabledCmd.Output()
	if err != nil || strings.TrimSpace(string(enabledOut)) != "true" {
		return
	}

	// 2. Map multiple target URLs transparently structurally completely natively
	cmd := exec.Command("git", "config", "--get-all", "sourcevault.mirror.target")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return // Silently pass if there's no target elements
	}

	rawTargets := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, target := range rawTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		log.Printf("[*] SourceVault Auto-Mirror Hook Triggered! Synchronizing to: %s", target)

		// Detach asynchronous execution sequence organically for EVERY endpoint universally optimally natively
		pushCmd := exec.Command("git", "push", "--mirror", target, "--quiet")
		pushCmd.Dir = repoDir
		
		if err := pushCmd.Start(); err != nil {
			log.Printf("[!] Fatal mirror start error natively: %v", err)
		}
	}
}
