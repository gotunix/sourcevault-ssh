#!/bin/bash

# Fetch the latest stable OpenSSH portable version
echo "Checking for latest OpenSSH version..."
OPENSSH_VERSION=$(curl -s https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/ | \
    grep -oE 'openssh-[0-9]+\.[0-9]+p[0-9]+' | \
    sed 's/openssh-//' | \
    sort -V | \
    tail -n 1)

if [ -z "$OPENSSH_VERSION" ]; then
    echo "Error: Could not determine latest OpenSSH version."
    exit 1
fi

echo "Latest OpenSSH version found: $OPENSSH_VERSION"
echo "Building Docker image 'sourcevault-ssh'..."

docker build \
    --build-arg OPENSSH_VERSION="$OPENSSH_VERSION" \
    -t sourcevault-ssh \
    "$@" \
    .
