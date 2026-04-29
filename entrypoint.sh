#!/bin/bash
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
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                  #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   #
# GNU Affero General Public License for more details.                                             #
#                                                                                                 #
# You should have received a copy of the GNU Affero General Public License                        #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                          #
# ----------------------------------------------------------------------------------------------- #

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
#rm -f /etc/ssh/ssh_config /etc/ssh/sshd_config /etc/ssh/ca.pub
#mv /tmp/sshd_config /etc/ssh/sshd_config
#mv /tmp/ssh_config  /etc/ssh/ssh_config
#mv /tmp/ca.pub      /etc/ssh/ca.pub

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

# Write an env file so sv-shell can read key config values when spawned
# by sshd's AuthorizedKeysCommand (which runs with a stripped environment).
ENV_FILE="$DB_DIR/.sv-env"
{
    echo "SOURCEVAULT_DB_DIR=${DB_DIR}"
    echo "GIT_SHELL_REPO_ROOT=${GIT_SHELL_REPO_ROOT:-/data/git}"
    echo "GIT_SHELL_LOG_PATH=${GIT_SHELL_LOG_PATH:-/var/log/git/ssh.log}"
    echo "UPSTREAM_SSH_ADDR=${UPSTREAM_SSH_ADDR}"
    echo "UPSTREAM_SSH_USER=${UPSTREAM_SSH_USER}"
    echo "UPSTREAM_SSH_KEY_PATH=${UPSTREAM_SSH_KEY_PATH}"
    echo "UPSTREAM_SSH_CERT_PATH=${UPSTREAM_SSH_CERT_PATH}"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"
chown git:git "$ENV_FILE"
echo "[entrypoint] Environment file written to $ENV_FILE"

# ---------------------------------------------------------------------------
# Bootstrap: seed the first admin user at startup while env vars are available.
# gosu drops from root to the git user before running the binary.
# ---------------------------------------------------------------------------
if [ -n "$BOOTSTRAP_ADMIN_KEY" ] || [ -n "$BOOTSTRAP_CA_KEY" ]; then
    echo "[entrypoint] Bootstrap required — running bootstrap as git user"
    gosu git /usr/local/bin/git-shell --bootstrap
    echo "[entrypoint] Bootstrap complete (exit code: $?)"
else
    echo "[entrypoint] No bootstrap keys provided — skipping bootstrap"
fi

# ---------------------------------------------------------------------------
# Sync GitOps Configs out of local volume storage back into SQLite seamlessly
# ---------------------------------------------------------------------------
echo "[entrypoint] Synchronizing GitOps state mappings from persistent storage..."
gosu git /usr/local/bin/git-shell --sync
echo "[entrypoint] Sync complete (exit code: $?)"

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
