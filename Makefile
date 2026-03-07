VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint fmt run clean install lxc

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

clean:
	rm -rf bin/ *.tar.zst
