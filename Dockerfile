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

RUN mkdir -p /var/lib/gatekeeper /etc/gatekeeper

EXPOSE 8080
VOLUME ["/var/lib/gatekeeper"]

ENTRYPOINT ["/usr/local/bin/gatekeeperd"]
CMD ["--listen=:8080", "--db=/var/lib/gatekeeper/gatekeeper.db"]
