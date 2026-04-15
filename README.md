# SourceVault SSH

**SourceVault SSH** is a secure, high-performance Git SSH orchestrator and proxy written in Go. It provides a managed layer over OpenSSH and the system `git-shell` to enforce granular access control, logical repository namespacing, and an interactive administrative interface for user and key management.

## 🚀 Key Features

*   **Dynamic Key Resolution**: Integrated with OpenSSH's `AuthorizedKeysCommand` to look up public keys in a local SQLite database, eliminating the need for a massive flat `authorized_keys` file.
*   **Secure Git Proxying**: Sanitizes and validates all incoming Git commands (`push`, `pull`, `clone`, `archive`) before execution.
*   **Logical Namespacing**: Enforces repository path conventions:
    *   `users/<username>/<repo>.git` — Private user repositories.
    *   `<org>/<repo>.git` — Organization repositories.
*   **Interactive TUI**: Provides a simple terminal-based menu for administrators and users to manage their own SSH keys and accounts.
*   **Bootstrap Mode**: Easily seed the first administrator account via environment variables on first boot.
*   **Container-Native**: Designed to run as a Docker service with persistent volume support for Git data and user metadata.

---

## 🏗️ Architecture

SourceVault SSH operates as a multi-mode orchestrator. In the container environment, the Go binary is installed at `/usr/local/bin/git-shell`, where it intercepts all SSH interactions before optionally delegating to the system's standard `/usr/bin/git-shell`.

It operates in three distinct modes:

1.  **Key Resolver (`--keys`)**: Invoked by `sshd`'s `AuthorizedKeysCommand`. It performs a fingerprint lookup in the SQLite database and returns an `authorized_keys` formatted line with restricted environment variables (`GIT_USER`, `GIT_ADMIN`) and a `command="..."` prefix that points back to itself.
2.  **Git Proxy (`SSH_ORIGINAL_COMMAND`)**: Triggered when a user runs a Git command. It validates the command, checks the user's permissions, translates logical paths to physical paths on disk, and then `execs` (process replacement) into the system `/usr/bin/git-shell`.
3.  **Interactive Menu**: Triggered when a user connects via SSH without a command. Admins see a full management TUI; regular users see a self-service key management menu.

---

## 🛠️ Getting Started

### Prerequisites

*   **Docker** and **Docker Compose**
*   **NFS Volume** (optional) for Git repository storage (the SQLite database must reside on a **local** volume).

### Deployment

1.  **Configuration**: Define your environment in `.env` (refer to `.env.sample`):
    ```bash
    # Path to where bare git repos are stored
    GIT_SHELL_REPO_ROOT=/data/git
    # Path to where the SQLite database is stored (must be local volume)
    SOURCEVAULT_DB_DIR=/data
    # The public key of the first admin user
    BOOTSTRAP_ADMIN_KEY="ssh-ed25519 AAAA..."
    ```

2.  **Run with Docker Compose**:
    ```bash
    docker-compose up -d
    ```

3.  **Bootstrap**: On the first start, the container will detect an empty database and automatically register the user defined in `BOOTSTRAP_ADMIN_KEY` as the first administrator.

---

## 📂 Project Structure

*   `src/main.go`: Application entry point and mode dispatcher.
*   `src/auth/`: Implementation of the `AuthorizedKeysCommand` resolver.
*   `src/db/`: SQLite data layer for user and key management.
*   `src/menu/`: Interactive TUI logic (Admin and User menus).
*   `src/shell/`: Git command sanitization, path mapping, and proxying.
*   `src/version/`: Build and runtime version information.
*   `files/`: Legacy Python scripts and base SSH configurations used by the Docker build.

---

## 🔧 Development

### Building the Binary
To build the orchestrator locally:
```bash
cd src
go build -o sv-shell .
```

### Docker Build
The project uses a multi-stage Dockerfile that builds a custom OpenSSH (v9.8p1) and the Go orchestrator:
```bash
docker build -t sourcevault-ssh .
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
