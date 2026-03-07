# CalVer: YYYY.0M.patch (e.g. 2026.03.1)
# Falls back to git describe for dev builds, then to "dev".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
CALVER ?= $(shell date +%Y.%m).0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test bench lint fmt run clean install lxc release

build:
	go build $(LDFLAGS) -o bin/gatekeeperd ./cmd/gatekeeperd
	go build $(LDFLAGS) -o bin/gk ./cmd/gk

test:
	go test ./... -v -race -count=1

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

clean:
	rm -rf bin/ *.tar.zst
