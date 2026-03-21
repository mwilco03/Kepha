# Multi-stage build for Gatekeeper.
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

# Runtime image.
FROM alpine:3.20

RUN apk add --no-cache nftables dnsmasq wireguard-tools sqlite

COPY --from=builder /src/bin/gatekeeperd /usr/local/bin/gatekeeperd
COPY --from=builder /src/bin/gk /usr/local/bin/gk

# Run as non-root user with only the capabilities we need (CAP_NET_ADMIN
# is granted at container runtime via --cap-add, not baked in).
RUN addgroup -S gatekeeper && adduser -S -G gatekeeper gatekeeper \
    && mkdir -p /var/lib/gatekeeper /etc/gatekeeper /var/log/gatekeeper /run/gatekeeper \
    && chown -R gatekeeper:gatekeeper /var/lib/gatekeeper /etc/gatekeeper /var/log/gatekeeper /run/gatekeeper

USER gatekeeper

LABEL org.opencontainers.image.title="Gatekeeper" \
      org.opencontainers.image.description="Network firewall appliance for Alpine Linux LXC" \
      org.opencontainers.image.source="https://github.com/mwilco03/Kepha" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8080
VOLUME ["/var/lib/gatekeeper"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/healthz || exit 1

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/gatekeeperd"]
CMD ["--listen=:8080", "--db=/var/lib/gatekeeper/gatekeeper.db"]
