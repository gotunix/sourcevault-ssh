#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 GOTUNIX Networks <code@gotunix.net>
# SPDX-FileCopyrightText: 2026 Justin Ovens <code@gotunix.net>
# ----------------------------------------------------------------------------------------------- #
#                          #####  ####### ####### #     # #     # ### #     #                     #
#                         #     # #     #    #    #     # ##    #  #   #   #                      #
#                         #       #     #    #    #     # # #   #  #    # #                       #
#                         #  #### #     #    #    #     # #  #  #  #     #                        #
#                         #     # #     #    #    #     # #   # #  #    # #                       #
#                         #     # #     #    #    #     # #    ##  #   #   #                      #
#                          #####  #######    #     #####  #     # ### #     #                     #
# ----------------------------------------------------------------------------------------------- #
# Copyright (C) GOTUNIX Networks                                                                  #
# Copyright (C) Justin Ovens                                                                      #
# ----------------------------------------------------------------------------------------------- #
# This program is free software: you can redistribute it and/or modify                            #
# it under the terms of the GNU Affero General Public License as                                  #
# published by the Free Software Foundation, either version 3 of the                              #
# License, or (at your option) any later version.                                                 #
#                                                                                                 #
# This program is distributed in the hope that it will be useful,                                 #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                 #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   #
# GNU Affero General Public License for more details.                                             #
#                                                                                                 #
# You should have received a copy of the GNU Affero General Public License                        #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                          #
# ----------------------------------------------------------------------------------------------- #

import os
import re
import sys
import shlex
import logging
import subprocess
import tempfile
import textwrap
import shutil
from typing import Dict, List, Optional, Tuple, Any

# Configure logging to stderr by default or a specific file if needed.
# These can be overridden by environment variables.
REPO_ROOT = os.environ.get("GIT_SHELL_REPO_ROOT", "/data/git").rstrip("/")
# Default to /var/log/git/ssh.log because SSHD often strips env vars
LOG_PATH = os.environ.get("GIT_SHELL_LOG_PATH", "/var/log/git/ssh.log")

def setup_logging() -> None:
    """Sets up logging configuration."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers = [] # Clear existing handlers

    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

    # Note: We do NOT add a StreamHandler here to avoid polluting the SSH session.
    # We rely on 'entrypoint.sh' tailing the log file to stderr for Docker logs.
    
    # 1. Log to file if configured
    if LOG_PATH and LOG_PATH.lower() != "stderr":
        log_dir = os.path.dirname(LOG_PATH)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception as e:
                 logging.error(f"Could not create log directory {log_dir}: {e}")
                 return

        try:
            file_handler = logging.FileHandler(LOG_PATH)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
             logging.error(f"Could not open log file {LOG_PATH}: {e}")

def ensure_server_key():
    """Generates a local server key if one does not exist and ensures it has Ultimate trust."""
    gnupg_home = os.environ.get("GNUPGHOME", "/data/git/home/.gnupg")
    
    server_email = "server@gitshell.local"
    key_exists = False

    # Check for secret keys
    try:
        res = subprocess.run(["gpg", "--list-secret-keys", "--with-colons", server_email], capture_output=True, text=True)
        if "sec:" in res.stdout:
            key_exists = True
    except Exception:
        pass

    if not key_exists:
        print("Initializing server GPG key (Trust Anchor)...")
        batch_config = f"""
        Key-Type: 1
        Key-Length: 2048
        Name-Real: Git Shell Server
        Name-Email: {server_email}
        Expire-Date: 0
        %no-protection
        %commit
        """
        try:
            subprocess.run(["gpg", "--batch", "--generate-key"], input=textwrap.dedent(batch_config), text=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to generate server key: {e.stderr}")
            return

    # Ensure Ultimate Trust
    try:
             # Get Fingerprint (Robust)
             res = subprocess.run(
                 ["gpg", "--list-keys", "--with-colons", "Git Shell Server"], 
                 capture_output=True, text=True, check=True
             )
             fingerprint = None
             for line in res.stdout.splitlines():
                 if line.startswith("fpr:"):
                     parts = line.split(":")
                     if len(parts) >= 10:
                         fingerprint = parts[9]
                         break
             
             if not fingerprint:
                 logging.error("Could not determine server key fingerprint despite existence.")
                 return

             # Set Ownertrust (Ultimate)
             # Format for --import-ownertrust is "FINGERPRINT:6:"
             trust_data = f"{fingerprint}:6:\n"
             subprocess.run(["gpg", "--import-ownertrust"], input=trust_data, text=True, check=True, capture_output=True)
             
             # Force update of trustdb
             subprocess.run(["gpg", "--check-trustdb"], check=True, capture_output=True)
             
    except Exception as e:
        logging.error(f"Failed to set server key trust: {e}")

def get_cert_info() -> Dict[str, Any]:
    """
    Retrieves and parses SSH certificate information from the SSH_USER_AUTH environment variable.
    Returns a dictionary with 'key_id', 'serial', and 'principals'.
    """
    auth_info_path = os.environ.get("SSH_USER_AUTH")
    if not auth_info_path:
        logging.error("SSH_USER_AUTH environment variable is not set")
        sys.exit(1)

    if not os.path.exists(auth_info_path):
        logging.error(f"Auth info file {auth_info_path} does not exist")
        sys.exit(1)

    try:
        with open(auth_info_path, 'r') as f:
            content = f.read().strip()
    except IOError as e:
        logging.error(f"Failed to read auth info: {e}")
        sys.exit(1)

    if content.startswith("publickey "):
        content = content.replace("publickey ", "", 1)

    # Use a secure temporary file
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=True) as tf:
            tf.write(content)
            tf.flush()

            logging.info("Checking certificate information")
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-L", "-f", tf.name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            except subprocess.CalledProcessError as e:
                logging.error(f"ssh-keygen failed: {e}")
                sys.exit(1)

    except IOError as e:
        logging.error(f"Temp file operation failed: {e}")
        sys.exit(1)

    lines = result.stdout.splitlines()
    data: Dict[str, Any] = {"key_id": None, "serial": None, "principals": []}

    collecting_principals = False
    stop_headers = ["Critical Options:", "Extensions:", "Valid:"]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("Key ID:"):
            # Format: "        Key ID: "user_id""
            # After strip: "Key ID: "user_id""
            parts = line.split(":", 1)
            if len(parts) > 1:
                data["key_id"] = parts[1].strip().replace('"', '')
            continue

        if line.startswith("Serial:"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                data["serial"] = parts[1].strip()
            continue

        if line.startswith("Principals:"):
            collecting_principals = True
            continue

        if any(line.startswith(header) for header in stop_headers):
            collecting_principals = False
            continue

        if collecting_principals:
            if line and line != "(none)":
                data["principals"].append(line)

    return data

def sanitize_git_command(command_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parses and sanitizes the git command.
    Returns a tuple (executable, repo_path).
    """
    if not command_str:
        return None, None

    try:
        args = shlex.split(command_str)
    except ValueError:
        logging.error("Invalid shell formatting in command")
        sys.exit(1)

    if len(args) < 2:
        return args[0], None

    executable = args[0]
    repo_path = args[1]

    # 1. Whitelist the binary
    allowed_binaries = ["git-upload-pack", "git-receive-pack", "git-upload-archive"]
    if executable not in allowed_binaries:
        logging.error(f"Forbidden binary attempted: {executable}")
        sys.stderr.write(f"Forbidden: {executable} is not an allowed git service.\n")
        sys.exit(1)

    # 2. Sanitize the Repo Path
    # Disallow absolute paths and directory traversal
    if repo_path.startswith("/") or ".." in repo_path:
        logging.error(f"Path traversal attempt: {repo_path}")
        sys.stderr.write("Forbidden: Illegal path traversal.\n")
        sys.exit(1)

    # Only allow safe characters
    if not re.match(r"^[a-zA-Z0-9\._\-/]+$", repo_path):
        logging.error(f"Malicious characters in repo path: {repo_path}")
        sys.stderr.write("Forbidden: Malicious characters in repository name.\n")
        sys.exit(1)

    return executable, repo_path

def check_authorization(principals: List[str], repo_path: str, mode: str = "read") -> bool:
    """
    Checks if the user is authorized to access the repository.
    Mode should be 'read' or 'write'.
    """
    if not repo_path:
        return True

    # 0. Admin always has access
    if "admin" in principals:
        return True

    # Normalize path: remove .git suffix if present
    clean_path = repo_path
    if clean_path.endswith('.git'):
        clean_path = clean_path[:-4]

    parts = clean_path.split('/')

    # Helper to check a specific scope
    def check_scope(scope_prefix: str) -> bool:
        # Check explicit Write scope
        if f"write-{scope_prefix}" in principals:
            return True
        # If we only need Read access, check standard scope
        if mode == "read" and scope_prefix in principals:
            return True
        return False

    # 1. Personal Repo Scope: users/<username>/repo.git matches principal user-<username>
    # Personal users have Read/Write access to their own repos (Owner Override)
    if len(parts) >= 2 and parts[0] == "users":
        username = parts[1]
        owner_principal = f"user-{username}"
        if owner_principal in principals:
            return True
        # If not owner, fall through to standard 'check_scope' logic below
        # which will check for 'repo-users/username/repo' (Read) or 'write-repo-...' (Write)

    # 2. Repo Scope
    if check_scope(f"repo-{clean_path}"):
        return True

    # 3. Project Scope
    if len(parts) >= 2:
        if check_scope(f"project-{parts[0]}/{parts[1]}"):
            return True

    # 4. Org Scope
    if len(parts) >= 1:
        if check_scope(f"org-{parts[0]}"):
            return True

    return False

def create_bare_repo(absolute_path: str) -> None:
    """Creates a bare git repository at the specified path."""
    try:
        os.makedirs(absolute_path, exist_ok=True)
        # Using git init --bare
        subprocess.run(["git", "init", "--bare", absolute_path], check=True, capture_output=True)
        print(f"\n[SUCCESS] Created repository at {absolute_path}")
        logging.info(f"Created repository: {absolute_path}")
    except Exception as e:
        print(f"\n[ERROR] Failed to create repository: {e}")
        logging.error(f"Failed to create repository at {absolute_path}: {e}")

def list_repos(principals: List[str]) -> None:
    """Lists repositories accessible to the user."""
    print("\n--- Accessible Repositories ---")
    
    if not os.path.exists(REPO_ROOT):
        print(f"No repositories found (Root {REPO_ROOT} does not exist).")
        return

    found_any = False
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        # We are looking for directories that end in .git
        # If we find one, we generally don't recurse into it
        
        # Modify dirnames in-place to prune recursion into .git directories
        # But wait, os.walk(topdown=True) allows modifying dirnames
        
        git_dirs = [d for d in dirnames if d.endswith(".git")]
        
        for git_dir in git_dirs:
            full_path = os.path.join(dirpath, git_dir)
            
            # Convert full_path to relative 'repo_path' for authorization check
            # Logic: 
            # /git/users/... -> users/...
            # /git/orginizations/... -> ... (remove /git/orginizations/)
            
            # Handle variable REPO_ROOT safely
            if full_path.startswith(REPO_ROOT):
                 # Strip REPO_ROOT and leading slashes
                 relative_internal = full_path[len(REPO_ROOT):].lstrip("/")
            else:
                 continue

            rel_path = None
            # logic: Users or Orginizations
            if relative_internal.startswith("users/"):
                rel_path = relative_internal # Already matches 'users/...'
            elif relative_internal.startswith("orginizations/"):
                # Strip 'orginizations/' for auth check
                rel_path = relative_internal.replace("orginizations/", "", 1)
            
            if rel_path:
                if check_authorization(principals, rel_path, mode="read"):
                    print(f"- {rel_path}")
                    found_any = True
        
        # Don't recurse into .git directories
        dirnames[:] = [d for d in dirnames if not d.endswith(".git")]

    if not found_any:
        print("(No accessible repositories found)")

def delete_repo(principals: List[str]) -> None:
    """Deletes a repository if authorized."""
    repo_name = get_input("Enter Repository Path to delete (e.g. users/me/repo.git): ")
    if not repo_name:
        return

    # 1. Determine Absolute Path
    # Reuse logical mapping from main/create logic
    if repo_name.startswith("users/"):
        abs_path = os.path.join(REPO_ROOT, repo_name)
    else:
        abs_path = os.path.join(REPO_ROOT, "orginizations", repo_name)
    
    # 2. Check Existence
    if not os.path.exists(abs_path):
        print(f"\n[ERROR] Repository does not exist: {abs_path}")
        return
    
    # 3. Authorization (WRITE required)
    if check_authorization(principals, repo_name, mode="write"):
        confirm = get_input(f"Are you sure you want to PERMANENTLY DELETE {repo_name}? (yes/no): ")
        if confirm.lower() == "yes":
            try:
                shutil.rmtree(abs_path)
                print(f"\n[SUCCESS] Deleted {repo_name}")
                logging.info(f"Deleted repository: {abs_path}")
            except Exception as e:
                print(f"\n[ERROR] Failed to delete: {e}")
                logging.error(f"Failed to delete {abs_path}: {e}")
        else:
            print("Deletion cancelled.")
    else:
        print(f"\n[DENIED] You do not have permission to delete {repo_name}.")

def view_readme(principals: List[str]) -> None:
    """Displays the README.md from a specified repository and branch."""
    repo_name = get_input("Enter Repository Path (e.g. users/me/repo.git): ")
    if not repo_name:
        return

    # 1. Determine Absolute Path
    if repo_name.startswith("users/"):
        abs_path = os.path.join(REPO_ROOT, repo_name)
    else:
        abs_path = os.path.join(REPO_ROOT, "orginizations", repo_name)
    
    # 2. Check Existence
    if not os.path.exists(abs_path):
        print(f"\n[ERROR] Repository does not exist: {abs_path}")
        return

    # 3. Authorization (READ required)
    if check_authorization(principals, repo_name, mode="read"):
        branch = get_input("Enter Branch Name (default 'main'): ")
        if not branch:
            branch = "main"
        
        # Sanitize Branch
        if not re.match(r"^[a-zA-Z0-9\._\-\/]+$", branch):
            print("\n[ERROR] Invalid branch name.")
            return

        try:
            # git --git-dir=... show branch:README.md
            cmd = ["git", "--git-dir", abs_path, "show", f"{branch}:README.md"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"\n--- README.md ({repo_name} @ {branch}) ---")
            print(result.stdout)
            print("---------------------------------------------")
        except subprocess.CalledProcessError:
             print(f"\n[ERROR] Could not find README.md on branch '{branch}' (or branch does not exist).")
    else:
        print(f"\n[DENIED] You do not have permission to read {repo_name}.")

def view_history(principals: List[str]) -> None:
    """Displays the commit history from a specified repository and branch."""
    repo_name = get_input("Enter Repository Path (e.g. users/me/repo.git): ")
    if not repo_name:
        return

    # 1. Determine Absolute Path
    if repo_name.startswith("users/"):
        abs_path = os.path.join(REPO_ROOT, repo_name)
    else:
        abs_path = os.path.join(REPO_ROOT, "orginizations", repo_name)
    
    # 2. Check Existence
    if not os.path.exists(abs_path):
        print(f"\n[ERROR] Repository does not exist: {abs_path}")
        return

    # 3. Authorization (READ required)
    if check_authorization(principals, repo_name, mode="read"):
        branch = get_input("Enter Branch Name (default 'main'): ")
        if not branch:
            branch = "main"
        
        # Sanitize Branch
        if not re.match(r"^[a-zA-Z0-9\._\-\/]+$", branch):
            print("\n[ERROR] Invalid branch name.")
            return

        limit_str = get_input("Enter Number of Commits (default 10): ")
        if not limit_str:
            limit_str = "10"
        
        if not limit_str.isdigit():
             print("\n[ERROR] Invalid limit. Must be a number.")
             return
        
        try:
            # Custom format to allow parsing:
            # COMMIT_START
            # %h %s (%an)  <- Header
            # %GG          <- Raw GPG output (Empty if no signature)
            separator = "COMMIT_START"
            fmt = f"{separator}%n%h %s (%an)%n%GG"
            
            # Using --show-signature ensures GPG logic is fully engaged
            # UPDATE: Removing --show-signature to avoid duplicate display, relying on %GG
            cmd = ["git", "--git-dir", abs_path, "log", "-n", limit_str, f"--pretty=format:{fmt}", branch]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            print(f"\n--- Commit History ({repo_name} @ {branch}) ---")
            
            # Parse output
            # Split by separator, ignore empty first element if any
            commits = result.stdout.split(separator)
            for commit_block in commits:
                if not commit_block.strip():
                    continue
                
                lines = commit_block.strip().split('\n')
                if len(lines) >= 1:
                    header = lines[0]
                    gpg_lines = lines[1:]
                    
                    print(f"\n{header}")
                    
                    # Check if we have any non-empty GPG lines
                    has_signature = any(line.strip() for line in gpg_lines)
                    
                    if has_signature:
                         for gline in gpg_lines:
                             if gline.strip():
                                 print(f"  {gline}")
                    else:
                         print("  No signature")
                
            print("\n---------------------------------------------")
        except subprocess.CalledProcessError:
             print(f"\n[ERROR] Could not retrieve history for branch '{branch}'.")
    else:
        print(f"\n[DENIED] You do not have permission to read {repo_name}.")

def manage_keys(principals: List[str], current_key_id: str) -> None:
    """
    Interactive menu for GPG key management.
    Restricted: Users can only delete keys they own (imported), unless admin.
    """
    while True:
        print("\n--- Manage GPG Keys ---")
        print("1. List Imported Keys")
        print("2. Import Public Key")
        print("3. Remove Public Key")
        print("4. Back to Main Menu")
        
        choice = get_input("\nSelect an option: ")
        
        if choice == "1":
            print("\n--- GPG Keys ---")
            try:
                # Update trustdb before listing
                subprocess.run(["gpg", "--check-trustdb"], capture_output=True)
                # Run gpg --list-keys
                subprocess.run(["gpg", "--list-keys"], check=True)
            except subprocess.CalledProcessError:
                print("Error listing keys.")
            except FileNotFoundError:
                print("Error: gpg not found.")
                
        elif choice == "2":
            print("\n--- Import Public Key ---")
            print("Paste your ASCII armored public key block below.")
            print("Type 'END' on a new line when finished, or 'CANCEL' to abort.")
            
            key_lines = []
            while True:
                 line = get_input("> ")
                 if line.strip() == "END":
                     break
                 if line.strip() == "CANCEL":
                     key_lines = []
                     break
                 key_lines.append(line)
            
            if key_lines:
                key_data = "\n".join(key_lines)
                
                # 1. Detect Fingerprint
                print("\nAnalyzing key data...")
                detected_fingerprint = get_fingerprint_from_block(key_data)
                
                if not detected_fingerprint:
                     print("[ERROR] Could not detect a valid public key fingerprint in the provided block.")
                     continue
                
                print(f"Detected Fingerprint: {detected_fingerprint}")

                try:
                    # 2. Import Key
                    proc = subprocess.run(["gpg", "--import"], input=key_data, text=True, capture_output=True)
                    if proc.returncode == 0:
                        print("\n[SUCCESS] Key imported/updated.")
                        print(proc.stderr) # Show details

                        # 3. Auto-sign with server key
                        print(f"Auto-signing key {detected_fingerprint} with server trust anchor...")
                        try:
                            # Use quick-sign-key (exportable) instead of lsign for broader compatibility
                            sign_cmd = ["gpg", "--batch", "--yes", "--quick-sign-key", detected_fingerprint]
                            sign_proc = subprocess.run(sign_cmd, capture_output=True, text=True)
                            
                            if sign_proc.returncode == 0:
                                print(f"[SUCCESS] Key {detected_fingerprint} is now trusted by the server.")
                                # 4. Update TrustDB immediately
                                subprocess.run(["gpg", "--check-trustdb"], capture_output=True)
                                
                                # 5. Record Ownership
                                owners = load_gpg_owners()
                                owners[detected_fingerprint] = current_key_id
                                save_gpg_owners(owners)
                                logging.info(f"Recorded ownership of GPG key {detected_fingerprint} for SSH key {current_key_id}")
                            else:
                                 print(f"[WARNING] Failed to auto-sign key: {sign_proc.stderr}")
                        except Exception as e:
                             print(f"[WARNING] Auto-signing error: {e}")

                    else:
                        print("\n[ERROR] Failed to import key.")
                        print(proc.stderr)
                except FileNotFoundError:
                     print("Error: gpg not found.")
            else:
                print("Import cancelled.")

        elif choice == "3":
            print("\n--- Remove Public Key ---")
            key_input = get_input("Enter Key ID or Email to remove: ")
            if not key_input:
                print("Operation cancelled.")
                continue
            
            try:
                # Resolve input to fingerprint first to check ownership
                # gpg --list-keys --with-colons <key_input>
                res = subprocess.run(["gpg", "--list-keys", "--with-colons", key_input], capture_output=True, text=True)
                if res.returncode != 0:
                    print(f"[ERROR] Key '{key_input}' not found.")
                    continue
                
                fingerprint = None
                for line in res.stdout.splitlines():
                     if line.startswith("fpr:"):
                         parts = line.split(":")
                         if len(parts) >= 10:
                             fingerprint = parts[9]
                             break
                
                if not fingerprint:
                    print(f"[ERROR] Could not resolve fingerprint for '{key_input}'.")
                    continue
                
                # Check Ownership
                owners = load_gpg_owners()
                owner_ssh_id = owners.get(fingerprint)
                
                is_admin = "admin" in principals
                is_owner = (owner_ssh_id == current_key_id)
                
                if not is_admin and not is_owner:
                    if owner_ssh_id:
                         print(f"[DENIED] You do not own this GPG key. It belongs to SSH key '{owner_ssh_id}'.")
                    else:
                         print(f"[DENIED] This key has no recorded owner. Only admins can remove it.")
                    logging.warning(f"Unauthorized deletion attempt of GPG key {fingerprint} by {current_key_id}")
                    continue

                # Proceed with deletion
                cmd = ["gpg", "--batch", "--yes", "--delete-keys", fingerprint]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode == 0:
                     print(f"\n[SUCCESS] Key '{key_input}' (Fingerprint: {fingerprint}) removed.")
                     # Remove from mapping
                     if fingerprint in owners:
                         del owners[fingerprint]
                         save_gpg_owners(owners)
                else:
                     print(f"\n[ERROR] Failed to remove key '{key_input}'.")
                     print(proc.stderr)
            except FileNotFoundError:
                 print("Error: gpg not found.")
            except Exception as e:
                 print(f"Error: {e}")

        elif choice == "4":
            break
        else:
            print("Invalid option.")

def get_input(prompt: str) -> str:
    """Safe input helper."""
    try:
        return input(prompt).strip()
    except EOFError:
        return ""

def interactive_menu(principals: List[str], key_id: str) -> None:
    """
    Provides an interactive menu for users.
    """
    print(f"Welcome to Git Shell, {key_id}!")
    
    # Ensure server key exists (Trust Anchor)
    ensure_server_key()

    while True:
        print("\n--- Menu ---")
        print("1. Create Personal Repository")
        print("2. Create Organization/Project Repository")
        print("3. List Accessible Repositories")
        print("4. Delete Repository")
        print("5. View Repository README")
        print("6. View Commit History")
        print("7. Manage GPG Keys")
        print("8. Exit")
        choice = get_input("Select an option: ")

        if choice == "1":
            # Personal: users/<username>/<repo>.git
            # 1. Determine Identity (Username)
            allowed_users = [p.replace("user-", "") for p in principals if p.startswith("user-")]
            
            if not allowed_users:
                 print("\n[DENIED] You do not have a 'user-*' principal.")
                 continue
            
            target_user = allowed_users[0]
            if len(allowed_users) > 1:
                print(f"Available users: {', '.join(allowed_users)}")
                inp = get_input(f"Enter username (default {target_user}): ")
                if inp:
                    if inp in allowed_users:
                        target_user = inp
                    else:
                        print("\n[ERROR] Invalid user selection.")
                        continue

            repo_name = get_input("Enter Repository Name: ")
            if not re.match(r"^[a-zA-Z0-9\._\-]+$", repo_name):
                print("\n[ERROR] Invalid repository name (alphanumeric, dot, underscore, dash only).")
                continue

            rel_path = f"users/{target_user}/{repo_name}.git"
            
            # Authorization Check
            if check_authorization(principals, rel_path, mode="write"):
                abs_path = os.path.join(REPO_ROOT, rel_path)
                create_bare_repo(abs_path)
            else:
                 print(f"\n[DENIED] You are not authorized to create {rel_path}.")

        elif choice == "2":
            # Org/Project
            org_name = get_input("Enter Organization Name: ")
            if not re.match(r"^[a-zA-Z0-9\._\-]+$", org_name):
                 print("\n[ERROR] Invalid organization name.")
                 continue

            proj_name = get_input("Enter Project Name (optional, press Enter to skip): ")
            if proj_name and not re.match(r"^[a-zA-Z0-9\._\-]+$", proj_name):
                 print("\n[ERROR] Invalid project name.")
                 continue
            
            repo_name = get_input("Enter Repository Name: ")
            if not re.match(r"^[a-zA-Z0-9\._\-]+$", repo_name):
                 print("\n[ERROR] Invalid repository name.")
                 continue
            
            if proj_name:
                rel_path = f"{org_name}/{proj_name}/{repo_name}.git"
                abs_path = os.path.join(REPO_ROOT, "orginizations", org_name, proj_name, f"{repo_name}.git")
            else:
                rel_path = f"{org_name}/{repo_name}.git"
                abs_path = os.path.join(REPO_ROOT, "orginizations", org_name, f"{repo_name}.git")

            # Authorization Check
            if check_authorization(principals, rel_path, mode="write"):
                create_bare_repo(abs_path)
            else:
                print(f"\n[DENIED] You are not authorized to create {rel_path} (Requires write permissions).")

        elif choice == "3":
            list_repos(principals)
        elif choice == "4":
            delete_repo(principals)
        elif choice == "5":
            view_readme(principals)
        elif choice == "6":
            view_history(principals)
        elif choice == "7":
            manage_keys(principals, key_id)
        elif choice == "8":
            print("Goodbye.")
            break
        else:
             print("\n[ERROR] Invalid option.")
    
    # Exit cleanly after loop
    sys.exit(0)

def get_fingerprint_from_block(key_data: str) -> Optional[str]:
    """Extracts the full fingerprint from an ASCII armored block."""
    try:
        res = subprocess.run(["gpg", "--show-keys", "--with-colons"], input=key_data, text=True, capture_output=True, check=True)
        # Look for fpr line. Format: fpr:::::::::FINGERPRINT:
        # We want index 9 (FINGERPRINT).
        for line in res.stdout.splitlines():
            if line.startswith("fpr:"):
                parts = line.split(":")
                if len(parts) >= 10:
                     return parts[9]
            # Fallback: some versions might output pub line with fingerprint in index 4 if it's full length?
            # No, 'fpr' is standard for fingerprint.
    except Exception as e:
        logging.error(f"Failed to get fingerprint from block: {e}")
    return None

import json

OWNERS_FILE = os.path.join(REPO_ROOT, "gpg_owners.json")

def load_gpg_owners() -> Dict[str, str]:
    """Loads GPG key ownership mapping (fingerprint -> ssh_key_id)."""
    if not os.path.exists(OWNERS_FILE):
        return {}
    try:
        with open(OWNERS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load GPG owners: {e}")
        return {}

def save_gpg_owners(owners: Dict[str, str]) -> None:
    """Saves GPG key ownership mapping."""
    try:
        with open(OWNERS_FILE, 'w') as f:
            json.dump(owners, f, indent=4)
    except Exception as e:
        logging.error(f"Failed to save GPG owners: {e}")

def main() -> None:
    setup_logging()
    
    # Ensure GNUPGHOME is set globally for all operations (including git subcommands)
    # We use /data/git/home/.gnupg (standard location, persistent volume)
    gnupg_home = os.environ.get("GNUPGHOME", "/data/git/home/.gnupg")
    os.environ["GNUPGHOME"] = gnupg_home
    if not os.path.exists(gnupg_home):
        try:
             os.makedirs(gnupg_home, mode=0o700, exist_ok=True)
        except OSError as e:
             logging.error(f"Could not create GNUPGHOME {gnupg_home}: {e}")

    info = get_cert_info()
    logging.info(f"Authenticated: Key_ID [{info['key_id']}] Serial [{info['serial']}] Principals [{info['principals']}]")

    original_cmd = os.environ.get("SSH_ORIGINAL_COMMAND")

    if not original_cmd:
        # Require 'interactive' or 'admin' principal for menu access
        principals = info['principals']
        if "interactive" in principals or "admin" in principals:
            logging.info("No SSH_ORIGINAL_COMMAND, entering interactive menu.")
            interactive_menu(info['principals'], info['key_id'])
            # interactive_menu calls sys.exit(0) on exit, so we stop here.
            sys.exit(0)
        else:
            logging.warning(f"Interactive access denied for {info['key_id']}.")
            sys.stderr.write("Restricted: Interactive access is not enabled for this user.\n")
            sys.exit(1)
    
    executable, repo_path = sanitize_git_command(original_cmd)

    # Determine Access Mode
    access_mode = "read"
    if executable == "git-receive-pack":
        access_mode = "write"

    # Principal-based Security Gate
    if repo_path:
        if not check_authorization(info['principals'], repo_path, mode=access_mode):
            logging.warning(f"Access Denied ({access_mode}) for {info['key_id']} to {repo_path}")
            sys.stderr.write(f"Access Denied: Principal matching '{repo_path}' not found for {access_mode} operation.\n")
            sys.exit(1)

    # Final Execution
    git_shell = "/usr/bin/git-shell"

    # Double check executable is safe (redundant but good)
    if executable:
         # Construct the absolute path
         # Custom Logic:
         # 1. Personal repos: users/username/repo -> /git/users/username/repo
         # 2. Org repos: orgname/repo -> /git/orginizations/orgname/repo

         if repo_path.startswith("users/"):
             absolute_repo_path = os.path.join(REPO_ROOT, repo_path)
         else:
             absolute_repo_path = os.path.join(REPO_ROOT, "orginizations", repo_path)

         # Reconstruct the command safely
         # We use simple quoting since we know repo_path is strictly sanitized
         final_cmd = f"{executable} '{absolute_repo_path}'"

         logging.info(f"Executing: {final_cmd}")
         os.execv(git_shell, ["git-shell", "-c", final_cmd])
    else:
         # Should not happen if original_cmd is present and sanitized, but as a fallback
         os.execv(git_shell, ["git-shell"])

if __name__ == "__main__":
    main()
