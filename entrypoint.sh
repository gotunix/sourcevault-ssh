#!/bin/bash

# Check for existing host keys and generate if missing
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    /usr/bin/ssh-keygen -A
fi

rm -f /etc/ssh/ssh_config
rm -f /etc/ssh/sshd_config
rm -f /etc/ssh/ca.pub
mv /tmp/sshd_config /etc/ssh
mv /tmp/ssh_config /etc/ssh
mv /tmp/ca.pub /etc/ssh

# Setup home directory
# Setup home directory
mkdir -p /data/git/home
mkdir -p /data/git/home/.gnupg
chmod 700 /data/git/home/.gnupg
chown -R git:git /data/git/home

# Setup logging
mkdir -p /var/log/git
touch /var/log/git/ssh.log
chown git:git /var/log/git/ssh.log
# Tail the log file to stderr (so it shows in docker logs) in the background
tail -F /var/log/git/ssh.log 1>&2 &

# Prevent SSHD from daemonizing (run in foreground)
exec /usr/sbin/sshd -D -u sshd -e

