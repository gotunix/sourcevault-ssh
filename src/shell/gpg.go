package shell

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ImportGPGKey imports an ASCII armored GPG public key into the local GPG keyring,
// returning its fingerprint.
func ImportGPGKey(keyData string) (string, error) {
	// Create temp file for the key
	tmpFile, err := os.CreateTemp("", "gpg-key-*.asc")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(keyData); err != nil {
		return "", fmt.Errorf("writing key to temp file: %w", err)
	}
	tmpFile.Close()

	// Run gpg --with-colons --import-options show-only --import <tmpFile>
	showCmd := exec.Command("gpg", "--with-colons", "--import-options", "show-only", "--import", tmpFile.Name())
	showOut, err := showCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to parse GPG key (make sure it is a valid ASCII armored public key): %w", err)
	}

	var fingerprint string
	lines := strings.Split(string(showOut), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) >= 10 && parts[0] == "fpr" {
			fingerprint = parts[9]
			break
		}
	}

	if fingerprint == "" {
		return "", fmt.Errorf("could not extract fingerprint from keyring output")
	}

	// Now actually import it
	importCmd := exec.Command("gpg", "--import", tmpFile.Name())
	if err := importCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to import GPG key: %w", err)
	}

	return fingerprint, nil
}

// TrustGPGKey marks a GPG key as ultimately trusted by its fingerprint.
func TrustGPGKey(fingerprint string) error {
	cmd := exec.Command("gpg", "--import-ownertrust")
	trustString := fmt.Sprintf("%s:6:\n", fingerprint)
	cmd.Stdin = strings.NewReader(trustString)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set ownertrust for GPG key: %w", err)
	}
	return nil
}

// DeleteGPGKey removes a GPG key from the keyring by fingerprint.
func DeleteGPGKey(fingerprint string) error {
	cmd := exec.Command("gpg", "--batch", "--yes", "--delete-key", fingerprint)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete GPG key: %w", err)
	}
	return nil
}
