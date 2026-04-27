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

package auth

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/gotunix/sourcevault-ssh/db"
	"golang.org/x/crypto/ssh"
)

// ResolveFromAuthInfo parses the OpenSSH authentication info file (ExposeAuthInfo)
// and returns the identity found in a valid, trusted SSH certificate.
func ResolveFromAuthInfo(authInfoPath string, database *db.DB, repoRoot string) (string, bool, error) {
	file, err := os.Open(authInfoPath)
	if err != nil {
		return "", false, fmt.Errorf("could not open auth info file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 || parts[0] != "publickey" {
			continue
		}

		// parts[1] is the key type (e.g. ssh-ed25519-cert-v01@openssh.com)
		// parts[2] is the base64 blob
		blob := parts[2]
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return "", false, fmt.Errorf("invalid base64 in auth info: %w", err)
		}

		pub, err := ssh.ParsePublicKey(raw)
		if err != nil {
			return "", false, fmt.Errorf("could not parse public key from auth info: %w", err)
		}

		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			// It's a regular public key, not a certificate.
			// We already handle these via Mode 1 (Resolver).
			continue
		}

		// 1. Identify the signer (CA).
		caFingerprint, err := db.FingerprintKey(base64.StdEncoding.EncodeToString(cert.SignatureKey.Marshal()))
		if err != nil {
			return "", false, fmt.Errorf("could not fingerprint CA key: %w", err)
		}

		// 2. Check if the CA is trusted in our DB.
		ca, err := database.LookupCAByFingerprint(caFingerprint)
		if err != nil {
			return "", false, fmt.Errorf("db error looking up CA: %w", err)
		}

		if ca == nil {
			return "", false, fmt.Errorf("certificate signed by untrusted CA: %s", caFingerprint)
		}

		// 3. Extract identity.
		// By default we use KeyId. If the user wants to use principals, we'd need more logic.
		username := cert.KeyId
		if username == "" {
			return "", false, fmt.Errorf("certificate has empty KeyId")
		}

		// 4. Determine admin status.
		// A certificate makes a user an admin if it contains the 'admin' principal.
		isAdmin := false
		for _, p := range cert.ValidPrincipals {
			if p == "admin" {
				isAdmin = true
				break
			}
		}

		// 5. JIT Provisioning.
		// Check if the user exists in the database. If not, create them.
		user, err := database.GetUserByUsername(username)
		if err != nil {
			return "", false, fmt.Errorf("db error checking for user %q: %w", username, err)
		}

		if user == nil {
			// User doesn't exist, create them now.
			if !db.IsValidUsername(username) {
				return "", false, fmt.Errorf("certificate identity %q is not a valid SourceVault username", username)
			}

			_, err = database.CreateUser(username, isAdmin)
			if err != nil {
				return "", false, fmt.Errorf("failed to auto-provision user %q: %w", username, err)
			}
			
			// Persist JIT-created user out to GitOps YAML mapping
			_ = database.SaveUserMetadata(username)

			fmt.Fprintf(os.Stderr, "[auth] Auto-provisioned new user: %s (isAdmin=%v)\n", username, isAdmin)
		} else {
			// If the user already exists, we might want to update their admin status
			// if the CA is an admin CA but they weren't marked as admin before.
			if isAdmin && !user.IsAdmin {
				if err := database.SetAdmin(username, true); err != nil {
					return "", false, fmt.Errorf("failed to promote user %q to admin via CA: %w", username, err)
				}
				
				// Persist promotion mapping
				_ = database.SaveUserMetadata(username)

				fmt.Fprintf(os.Stderr, "[auth] Promoted user %s to admin via CA trust\n", username)
			}
		}

		return username, isAdmin, nil
	}

	if err := scanner.Err(); err != nil {
		return "", false, fmt.Errorf("error reading auth info file: %w", err)
	}

	return "", false, fmt.Errorf("no valid SSH certificate found in auth info")
}
