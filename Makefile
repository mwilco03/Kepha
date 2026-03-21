# CalVer: YYYY.0M.patch (e.g. 2026.03.1)
# Falls back to git describe for dev builds, then to "dev".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
CALVER ?= $(shell date +%Y.%m).0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test cover bench lint fmt run clean install lxc release vuln

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/gatekeeperd ./cmd/gatekeeperd
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/gk ./cmd/gk

test:
	go test ./... -v -race -count=1

cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1
	@echo "Full report: go tool cover -html=coverage.out"

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

run: build
	./bin/gatekeeperd

install: build
	bash scripts/install.sh

lxc: build
	bash scripts/build-lxc.sh

bench:
	go test -bench=. -benchmem ./internal/compiler/ -run=^$$

release:
	VERSION=$(CALVER) $(MAKE) build

vuln:
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

clean:
	rm -rf bin/ *.tar.zst coverage.out
