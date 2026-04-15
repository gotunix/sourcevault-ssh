#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# SSH host key generation
# ---------------------------------------------------------------------------
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "[entrypoint] Generating SSH host keys..."
    /usr/bin/ssh-keygen -A
fi

# ---------------------------------------------------------------------------
# Install runtime SSH configs from /tmp staging area
# ---------------------------------------------------------------------------
rm -f /etc/ssh/ssh_config /etc/ssh/sshd_config /etc/ssh/ca.pub
mv /tmp/sshd_config /etc/ssh/sshd_config
mv /tmp/ssh_config  /etc/ssh/ssh_config
mv /tmp/ca.pub      /etc/ssh/ca.pub

# ---------------------------------------------------------------------------
# Data directory setup (NFS volume — repos only)
# ---------------------------------------------------------------------------
mkdir -p /data/git/home
mkdir -p /data/git/home/.gnupg
chmod 700 /data/git/home/.gnupg
chown -R git:git /data/git/home

# ---------------------------------------------------------------------------
# Local DB directory setup (named Docker volume — NOT NFS)
# ---------------------------------------------------------------------------
DB_DIR="${SOURCEVAULT_DB_DIR:-/data}"
mkdir -p "$DB_DIR"
chown git:git "$DB_DIR"

# Write an env file to DB_DIR so that sv-shell can read it when spawned
# by sshd's AuthorizedKeysCommand. sshd strips most env vars from the
# subprocess environment, so we persist the values we need here.
ENV_FILE="$DB_DIR/.sv-env"
{
    echo "SOURCEVAULT_DB_DIR=${DB_DIR}"
    echo "GIT_SHELL_REPO_ROOT=${GIT_SHELL_REPO_ROOT:-/data/git}"
    echo "GIT_SHELL_LOG_PATH=${GIT_SHELL_LOG_PATH:-/var/log/git/ssh.log}"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"
chown git:git "$ENV_FILE"
echo "[entrypoint] Environment file written to $ENV_FILE"

# ---------------------------------------------------------------------------
# Bootstrap: seed the first admin user if the database is empty.
# This runs here (at startup) rather than inside AuthorizedKeysCommand
# because sshd strips most env vars from the AuthorizedKeysCommand subprocess.
# ---------------------------------------------------------------------------
if [ -n "$BOOTSTRAP_ADMIN_KEY" ]; then
    echo "[entrypoint] BOOTSTRAP_ADMIN_KEY is set — running bootstrap as git user"
    su-exec git /usr/local/bin/git-shell --bootstrap
else
    echo "[entrypoint] BOOTSTRAP_ADMIN_KEY not set — skipping bootstrap"
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
mkdir -p /var/log/git
touch /var/log/git/ssh.log
chown git:git /var/log/git/ssh.log
# Tail the log file to stderr so it appears in docker logs
tail -F /var/log/git/ssh.log 1>&2 &

# ---------------------------------------------------------------------------
# Launch sshd in foreground
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting sshd..."
exec /usr/sbin/sshd -D -u sshd -e
