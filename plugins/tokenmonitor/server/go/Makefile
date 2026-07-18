BIN    := tokenmonitor-mcp-go
PKG    := github.com/fractal-manifold/tokenmonitor-mcp/cmd/tokenmonitor-mcp
PREFIX ?= $(HOME)/.local

# Version comes from the repository-root VERSION file (single source of
# truth shared by the Go, Python and JS impls); the git describe is kept
# as a fallback so dev builds still get something meaningful.
VERSION_FILE := $(realpath $(CURDIR)/../VERSION)
VERSION := $(shell cat $(VERSION_FILE) 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

# Prebuilt-binary release matrix (shipped in ../bin/, exec'd by the launcher
# with no Go toolchain). Windows binaries get a .exe suffix in the script.
BINDIR    := $(realpath $(CURDIR)/..)/bin
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build release-bins test vet fmt install clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/tokenmonitor-mcp

# Cross-compile the whole matrix into ../bin/ + regenerate SHA256SUMS. Atomic:
# a failed target leaves the existing ../bin/ untouched. Run on every broker
# VERSION bump (see docs/releasing.md Procedure C).
release-bins:
	sh ./build-prebuilt.sh "$(VERSION)" "$(BINDIR)" $(PLATFORMS)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install: build
	install -Dm755 $(BIN) $(PREFIX)/bin/$(BIN)
	@echo "Installed to $(PREFIX)/bin/$(BIN)"
	@echo "Now install the launcher so Claude Code can find it:"
	@echo "    sh ../tokenmonitor-mcp-launcher/install.sh"
	@echo "(The launcher exposes 'tokenmonitor-mcp' on PATH and picks Go/Python/JS"
	@echo " in priority order.)"

clean:
	rm -f $(BIN)
