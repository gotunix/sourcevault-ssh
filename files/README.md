# Git Shell (git-shell.py)

`git-shell.py` is a custom Python script designed to provide a secure and restricted shell environment for Git operations performed over SSH. It acts as a robust gatekeeper, preventing users from gaining full shell access while enabling them to interact with Git repositories and manage them through a controlled interface.

## Purpose

The primary goal of `git-shell.py` is to offer a managed and secure way to expose Git services via SSH. It supports standard Git commands (like push and pull) and provides an interactive menu for repository administration and GPG key management, all underpinned by a granular authorization system.

## Key Features

### 1. Secure Git Command Execution

-   **Command Sanitization:** The script meticulously sanitizes incoming Git commands (`git-upload-pack`, `git-receive-pack`, `git-upload-archive`) received via the `SSH_ORIGINAL_COMMAND` environment variable. This prevents path traversal vulnerabilities (`..`, absolute paths) and ensures that only whitelisted Git binaries are executed.
-   **Restricted Environment:** By acting as a restricted shell, it effectively limits what users can do on the server, enhancing overall system security.

### 2. Fine-Grained Authentication and Authorization

-   **SSH Certificate Principals:** It leverages information from the user's SSH certificate, specifically "principals" (roles or groups), to determine access rights.
-   **Flexible Access Control:** Authorization rules can be defined for:
    -   **`admin`**: Grants full administrative access.
    -   **`interactive`**: Allows access to the interactive management menu.
    -   **`user-<username>`**: Provides ownership and write access to personal repositories under `users/<username>/`.
    -   **`repo-<path>`**: Specifies read/write access to a particular repository.
    -   **`project-<org>/<project>`**: Grants access to all repositories within a specific project.
    -   **`org-<org>`**: Provides access to all repositories belonging to an organization.

### 3. Repository Management

-   **Logical to Physical Mapping:** The script translates logical repository paths (e.g., `users/myuser/myrepo.git` or `myorg/myproject/myrepo.git`) into their physical locations on the server's filesystem, typically within a configurable `REPO_ROOT`.
-   **Interactive Menu:** For authorized users, an interactive menu offers direct repository administration capabilities:
    -   **Create Repositories:** Allows users to create new personal, organizational, or project-specific Git repositories.
    -   **List Accessible Repositories:** Displays a list of repositories the user is authorized to read.
    -   **Delete Repositories:** Enables authorized users to delete existing repositories (requires `write` permissions).
    -   **View README:** Fetches and displays the `README.md` file from a specified branch of a repository.
    -   **View Commit History:** Shows the commit log for a given repository and branch, including checks for GPG signatures.

### 4. GPG Key Management

-   **Server Trust Anchor:** The script manages a self-signed GPG key that acts as a trust anchor. This key is used to sign user-imported GPG public keys.
-   **User GPG Key Import:** Users can import their GPG public keys, which are then automatically signed by the server's trust anchor, establishing a chain of trust.
-   **Key Ownership Tracking:** To enhance security, the script records the ownership of imported GPG keys (mapping the GPG key's fingerprint to the SSH Key ID of the importer). This ensures that only the original importer or an administrator can remove a specific GPG key.

### 5. Logging

-   **Auditing and Debugging:** Configures detailed logging to a designated file (default: `/var/log/git/ssh.log`) or stderr, providing an audit trail of operations and aiding in troubleshooting.

## How it Works (High-Level)

1.  **SSH Connection:** A user connects via SSH, and `sshd` invokes `git-shell.py`.
2.  **Auth Info Retrieval:** The script retrieves SSH certificate information (principals) from the `SSH_USER_AUTH` environment variable.
3.  **Command Handling:**
    *   If `SSH_ORIGINAL_COMMAND` is present, it's parsed, sanitized, and authorized. If successful, the corresponding Git command is executed using `os.execv` to securely replace the current process.
    *   If `SSH_ORIGINAL_COMMAND` is absent and the user has the "interactive" or "admin" principal, the interactive management menu is presented.
4.  **Authorization Decisions:** All sensitive actions (creating, deleting, accessing repositories) are gated by `check_authorization` based on the user's principals.

`git-shell.py` provides a robust, secure, and flexible solution for managing Git access and repositories in a controlled SSH environment.
