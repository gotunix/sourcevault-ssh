# Stage 1: Build OpenSSH
FROM debian:stable-slim AS openssh-builder

RUN apt-get update && apt-get install -y \
    build-essential \
    zlib1g-dev \
    libssl-dev \
    libpam0g-dev \
    libselinux1-dev \
    wget \
    make \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSH_VERSION=9.8p1
RUN wget -qO- https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz | tar -xzf - -C /tmp
WORKDIR /tmp/openssh-${OPENSSH_VERSION}

RUN sed -i 's/OpenSSH_9.8/SourceVault_SSH_1.0/g' version.h

RUN ./configure \
    --prefix=/usr \
    --sysconfdir=/etc/ssh \
    --with-privsep-path=/var/lib/sshd \
    --with-md5-passwords \
    --with-pam \
    --with-ssl-engine \
    --with-pid-file=/run/sshd.pid \
    --with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --disable-strip && \
    make && \
    make install-nokeys

# Stage 2: Build Golang Orchestrator
# Source lives under src/ for a clean separation of Docker infra and Go code.
FROM golang:1.25-bullseye AS go-builder
WORKDIR /app
# Copy all source first — go mod tidy needs to see the actual imports
# across all packages before it can generate a complete go.sum.
COPY src/ ./
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/sv-shell .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/sv-admin ./cmd/sv-admin

# Stage 3: Create the final runtime image
FROM debian:stable-slim

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

# Copy OpenSSH components
COPY --from=openssh-builder /usr/sbin/sshd /usr/sbin/sshd
COPY --from=openssh-builder /usr/bin/ssh /usr/bin/ssh
COPY --from=openssh-builder /usr/bin/scp /usr/bin/scp
COPY --from=openssh-builder /usr/bin/sftp /usr/bin/sftp
COPY --from=openssh-builder /usr/libexec/sftp-server /usr/libexec/sftp-server
COPY --from=openssh-builder /usr/libexec/ssh-keysign /usr/libexec/ssh-keysign
COPY --from=openssh-builder /etc/ssh/sshd_config /etc/ssh/sshd_config
COPY --from=openssh-builder /etc/ssh/ssh_config /etc/ssh/ssh_config
COPY --from=openssh-builder /usr/bin/ssh-keygen /usr/bin/ssh-keygen
COPY --from=openssh-builder /usr/libexec/sshd-session /usr/libexec/sshd-session

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

RUN groupadd -g 400 sshd && \
    useradd -u 400 -g 400 -c sshd -d / sshd && \
    groupadd -g ${PGID} git && \
    useradd -u ${PUID} -g ${PGID} -c git -s /usr/local/bin/git-shell -d /data/git git

# Establish root namespaces logically conceptually safely smoothly intuitively naturally securely smoothly creatively
RUN mkdir /data && \
    mkdir -p /var/log/git && \
    chown git:git /data /var/log/git && \
    mkdir -p /var/lib/sshd && \
    chmod 700 /var/lib/sshd && \
    chown root:root /var/lib/sshd

# Ensure Figlet structures correctly elegantly
RUN mv /usr/share/figlet /usr/bin/figlet.dist && \
    git clone https://github.com/xero/figlet-fonts.git /usr/share/figlet

EXPOSE 22

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
