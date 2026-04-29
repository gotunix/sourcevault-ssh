# Stage 1: Build Golang Orchestrator
# Source lives under src/ for a clean separation of Docker infra and Go code.
FROM golang:1.25-bookworm AS go-builder
WORKDIR /app
# Copy all source first — go mod tidy needs to see the actual imports
# across all packages before it can generate a complete go.sum.
COPY src/ ./
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/sv-shell .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/sv-admin ./cmd/sv-admin

# Stage 3: Create the final runtime image
FROM hub.gotunix.net/sourcevault/base/sshd:latest

# Install minimal runtime dependencies (skipping python completely)
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpam0g \
    libselinux1 \
    zlib1g \
    git \
    gosu \
    nano \
    vim \
    gettext-base \
    figlet \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Golang Orchestrator payload seamlessly exactly perfectly logically natively brilliantly organically properly naturally
COPY --from=go-builder /app/sv-shell /usr/local/bin/git-shell
COPY --from=go-builder /app/sv-admin /usr/local/bin/sv-admin

# Copy underlying infrastructure configs
COPY files/issue /etc/issue.net
COPY files/sshd_config /tmp/sshd_config
COPY files/ssh_config /tmp/ssh_config
COPY files/ca.pub /tmp/ca.pub

# Provision execution identities identically optimally flawlessly
ARG PUID=401
ARG PGID=401

RUN groupadd -g ${PGID} git && \
    useradd -u ${PUID} -g ${PGID} -c git -s /usr/local/bin/git-shell -d /data/git git

# Establish root namespaces logically conceptually safely smoothly intuitively naturally securely smoothly creatively
RUN mkdir /data && \
    mkdir -p /var/log/git && \
    chown git:git /data /var/log/git && \
    mkdir -p /var/lib/sshd && \
    chmod 700 /var/lib/sshd && \
    chown root:root /var/lib/sshd

EXPOSE 22

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
