# Obscura Scan — build automation
BINARY      := obscura
PKG         := ./cmd/obscura
VERSION     ?= 9.0.0
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

export CGO_ENABLED := 0

.PHONY: build build-all test lint vet fmt docker run clean

build: ## Build the obscura binary for the host platform
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

build-all: ## Cross-compile for linux/amd64, linux/arm64, windows/amd64, darwin/arm64
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64     $(PKG)
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64     $(PKG)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-amd64.exe $(PKG)
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64    $(PKG)

test: ## Run tests with the race detector
	go test -race ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go source
	gofmt -w .

lint: vet ## Run gofmt check + vet
	@test -z "$$(gofmt -l .)" || (echo "unformatted files:"; gofmt -l .; exit 1)

run: build ## Build and run
	./bin/$(BINARY)

docker: ## Build the distroless container image
	docker build -t obscurascan:$(VERSION) .

clean: ## Remove build artifacts
	rm -rf bin
