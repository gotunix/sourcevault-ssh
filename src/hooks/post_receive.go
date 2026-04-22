package hooks

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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

	// Determine logical key path explicitly natively accurately
	var keyPath string
	parts := strings.Split(strings.Trim(repoDir, "/"), "/")
	if len(parts) >= 3 {
		// handle .../users/username/repo.git or .../orgs/orgname/repo.git
		ownerType := parts[len(parts)-3]
		ownerName := parts[len(parts)-2]
		
		if ownerType == "users" || ownerType == "orgs" {
			repoRootParts := parts[:len(parts)-3]
			repoRoot := "/" + strings.Join(repoRootParts, "/")
			
			edPath := filepath.Join(repoRoot, ownerType, ownerName, "id_ed25519")
			rsaPath := filepath.Join(repoRoot, ownerType, ownerName, "id_rsa")
			
			if _, err := os.Stat(edPath); err == nil {
				keyPath = edPath
			} else if _, err := os.Stat(rsaPath); err == nil {
				keyPath = rsaPath
			}
		}
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
		
		// If custom identity securely strictly cleanly maps implicitly effectively elegantly intuitively
		if keyPath != "" {
			if _, err := os.Stat(keyPath); err == nil {
				pushCmd.Env = append(os.Environ(), fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", keyPath))
				log.Printf("[*] Overriding SSH Context natively structurally efficiently using Deploy Key cleanly seamlessly: %s", keyPath)
			}
		}

		if err := pushCmd.Start(); err != nil {
			log.Printf("[!] Fatal mirror start error natively: %v", err)
		}
	}
}
