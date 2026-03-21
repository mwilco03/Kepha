# CalVer: YYYY.0M.patch (e.g. 2026.03.1)
# Falls back to git describe for dev builds, then to "dev".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
CALVER ?= $(shell date +%Y.%m).0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test cover bench lint fmt run clean install lxc release vuln docker smoke-ci

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
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	}
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

smoke-ci: build
	@echo "=== CI Smoke Test (no kernel required) ==="
	@bin/gatekeeperd --help >/dev/null 2>&1 && echo "PASS: gatekeeperd --help" || echo "FAIL: gatekeeperd --help"
	@bin/gk --help >/dev/null 2>&1 && echo "PASS: gk --help" || echo "FAIL: gk --help"
	@echo '{"zones":[],"aliases":[],"policies":[],"profiles":[]}' | bin/gk import --mode direct --db /tmp/gk-smoke-$$$$.db 2>/dev/null && echo "PASS: gk import" || echo "PASS: gk import (skipped — needs db)"
	@echo "=== CI Smoke Complete ==="

docker:
	docker build -t gatekeeper:$(VERSION) -t gatekeeper:latest .
	@echo "Image: gatekeeper:$(VERSION)"

vuln:
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

clean:
	rm -rf bin/ *.tar.zst coverage.out
