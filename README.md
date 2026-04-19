# SourceVault SSH

> **Secure Git SSH Orchestrator** — a self-contained Docker service that provides managed SSH access to Git repositories with per-user key management, access control, and an interactive admin TUI.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## Overview

SourceVault SSH replaces a static `authorized_keys` file with a SQLite-backed user registry. It sits between OpenSSH and `git-shell`, dynamically resolving connecting SSH keys to internal user accounts and enforcing repository-level access control — all without modifying the underlying NFS-mounted Git data.

The entire stack is shipped as a single Docker image containing a custom-built OpenSSH (9.8p1) and a Go binary (`sv-shell`) that orchestrates every SSH interaction.

---

## How It Works

Every connection goes through three layers:

```
Client SSH Key
      │
      ▼
OpenSSH (sshd)
      │  AuthorizedKeysCommand
      ▼
sv-shell --keys <fingerprint>        ← looks up key in SQLite
      │  emits ForceCommand + env vars back to sshd
      ▼
sv-shell (ForceCommand)
      │
      ├─── SSH_ORIGINAL_COMMAND set? ──► Git Proxy mode
      │                                  validates + exec git-shell
      │
      └─── No command (interactive)? ──► Admin TUI  (if GIT_ADMIN=true)
                                         User TUI   (if GIT_ADMIN=false)
```

### Operating Modes

| Mode | Trigger | Description |
|------|---------|-------------|
| **Key Resolver** | `sv-shell --keys <fingerprint>` | Called by sshd's `AuthorizedKeysCommand`. Looks up the SHA256 key fingerprint in SQLite and emits the `authorized_keys` line (or nothing, to deny). |
| **Bootstrap** | `sv-shell --bootstrap` | Called once at container startup from `entrypoint.sh`. Seeds the first admin user from env vars while the full container environment is available. |
| **Git Proxy** | `SSH_ORIGINAL_COMMAND` set | Sanitizes and validates the incoming git command, maps logical repo paths to disk paths, and `exec`s into the system `/usr/bin/git-shell`. |
| **Admin TUI** | Interactive SSH, `GIT_ADMIN=true` | Full management menu: add/remove users, manage SSH keys, toggle admin status. |
| **User TUI** | Interactive SSH, `GIT_ADMIN=false` | Self-service menu: view and manage own SSH keys. |

---

## Repository Paths

Repositories are accessed using logical paths that are mapped to physical paths under `GIT_SHELL_REPO_ROOT`:

| SSH path | Disk path | Purpose |
|----------|-----------|---------|
| `users/<username>/<repo>.git` | `$REPO_ROOT/users/<username>/<repo>.git` | Private user repository |
| `<org>/<repo>.git` | `$REPO_ROOT/<org>/<repo>.git` | Organization / shared repository |

**Example:**
```bash
git clone git@yourserver:users/alice@example.com/myproject.git
git clone git@yourserver:acme/infrastructure.git
```

---

## Getting Started

### Prerequisites

- Docker and Docker Compose
- (Optional) An NFS volume for Git repository storage — the **SQLite database must be on a local volume**, not NFS

### 1. Configure

```bash
cp .env.sample .env
$EDITOR .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BOOTSTRAP_ADMIN_KEY` | **Yes** (first boot) | — | Full SSH public key line for the first admin user |
| `BOOTSTRAP_ADMIN_USER` | No | `admin` | Username (email recommended) for the first admin |
| `PUID` | No | `401` | UID for the `git` user inside the container |
| `PGID` | No | `401` | GID for the `git` user inside the container |
| `SOURCEVAULT_DB_DIR` | No | `/data` | Path for `sourcevault.db` — **must be a local volume, not NFS** |
| `GIT_SHELL_REPO_ROOT` | No | `/data/git` | Root path for bare Git repositories |
| `GIT_SHELL_LOG_PATH` | No | `/var/log/git/ssh.log` | SSH access log path inside container |
| `TS_AUTHKEY` | No | — | Tailscale auth key for the sidecar container |

### 2. Deploy

```bash
docker-compose up -d
```

On first start, the container will:
1. Generate SSH host keys (if missing)
2. Write `/data/.sv-env` for the key resolver subprocess
3. Run `sv-shell --bootstrap` to seed the first admin user
4. Start `sshd` in foreground

### 3. First Login

```bash
ssh git@<your-server>
```

If your key matches `BOOTSTRAP_ADMIN_KEY` you will see the admin TUI. From there you can add additional users and their keys.

---

## Admin TUI

Accessible by SSH-ing in as any user with admin privileges:

```
╔══════════════════════════════╗
║  SourceVault SSH — Admin     ║
╠══════════════════════════════╣
  1. List Users
  2. Add User
  3. Remove User
  4. Toggle Admin
  5. Add SSH Key to User
  6. Remove SSH Key from User
  7. List Keys for User
  8. Version
  9. Exit
```

---

## Project Structure

```
sourcevault-ssh/
├── Dockerfile              # Multi-stage build: OpenSSH 9.8p1 + Go binary
├── docker-compose.yaml     # Service definition (sshd + Tailscale sidecar)
├── entrypoint.sh           # Container startup: host keys, bootstrap, sshd
├── .env.sample             # Configuration template
├── files/
│   ├── sshd_config         # OpenSSH configuration (AuthorizedKeysCommand etc.)
│   └── ssh_config          # SSH client config for git operations
└── src/
    ├── main.go             # Entry point — mode dispatcher
    ├── auth/               # AuthorizedKeysCommand resolver
    ├── db/                 # SQLite data layer (users + SSH keys)
    ├── menu/               # Interactive TUI (admin + user menus)
    ├── shell/              # Git command sanitization and proxy
    └── version/            # Build and runtime version info
```

---

## Volumes

| Volume | Type | Purpose |
|--------|------|---------|
| `git-data` | NFS | Bare Git repositories (`/data/git`) |
| `sourcevault-data` | Local named volume | SQLite database (`/data`) |
| `ssh-config` | Local named volume | Persistent SSH host keys (`/etc/ssh`) |
| `./logs` | Bind mount | SSH access logs |

> ⚠️ **Do not put `sourcevault.db` on an NFS volume.** SQLite requires POSIX advisory file locking which NFS does not support reliably.

---

## License

Copyright (C) GOTUNIX Networks  
Copyright (C) Justin Ovens

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for the full text.
