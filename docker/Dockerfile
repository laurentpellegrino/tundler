# Build stage for the tundler API binary
FROM golang:1.24 AS builder
WORKDIR /build

# Dependencies first for better layer-cache
COPY go.mod ./
RUN go mod download

# Project sources
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" \
    -o tundler-api ./cmd/tundler-api

# Runtime stage building the tundler
FROM ubuntu:24.10

ARG INSTALL_EXPRESSVPN=true
ARG INSTALL_MULLVAD=true
ARG INSTALL_NORDVPN=true
ARG INSTALL_TUNDLER_PROXY=true

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root

# Install packages needed
RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get install -y curl dbus sudo systemd unzip wget zip gpg \
                       iproute2 iptables && \
    apt-get install -y --no-install-recommends apt-transport-https ca-certificates

# Create non-root user `tundler` with sudo privileges
RUN useradd -m -s /bin/bash tundler \
    && echo "tundler ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && chown tundler:tundler /root

# Install tinyproxy
COPY docker/config/tinyproxy.conf /tmp/tinyproxy.conf
RUN if [ "$INSTALL_TUNDLER_PROXY" = "true" ]; then \
      apt-get update && \
      apt-get install -y tinyproxy && \
      mv /tmp/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf; \
    else \
      rm -f /tmp/tinyproxy.conf; \
    fi


RUN rm /usr/sbin/policy-rc.d

COPY docker/providers /opt/providers
RUN chmod +x /opt/providers/*/install.sh

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install all VPN provider clients
RUN set -euo pipefail && \
    for dir in /opt/providers/*; do \
        provider="$(basename "$dir")"; \
        flag="INSTALL_${provider^^}"; \
        if [[ "${!flag:-true}" == "true" ]]; then \
            bash "$dir/install.sh"; \
        else \
            rm -rf "$dir"; \
        fi; \
    done

# Copy static Tundler API binary from build stage
COPY --from=builder /build/tundler-api /usr/local/bin/tundler-api

# Copy custom scripts and services
COPY docker/services/tundler-configure.sh /usr/local/bin/tundler-configure.sh
COPY docker/services/setup-netns.sh /usr/local/bin/setup-netns.sh
COPY docker/services/tundler-api.service /etc/systemd/system/

# Make script executable
RUN chmod +x /usr/local/bin/tundler-configure.sh /usr/local/bin/setup-netns.sh && \
    systemctl enable tundler-api.service && \
    systemctl set-default multi-user.target && \
    systemctl mask getty@tty1.service console-getty.service

# Clean up
RUN apt-get autoremove -y
RUN apt-get autoclean -y
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 4242/tcp
EXPOSE 8484/tcp

VOLUME ["/sys/fs/cgroup"]
STOPSIGNAL SIGRTMIN+3

ENTRYPOINT ["/lib/systemd/systemd"]
