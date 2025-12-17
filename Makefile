# TelemetryFlow Agent - Makefile
#
# TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
# Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
#
# Build and development commands for TelemetryFlow Agent

# Build configuration
PRODUCT_NAME := TelemetryFlow Agent
BINARY_NAME := tfo-agent
VERSION ?= 1.0.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GO_VERSION := $(shell go version | cut -d ' ' -f 3)

# Directories
BUILD_DIR := ./build
CONFIG_DIR := ./configs
DIST_DIR := ./dist

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags (uses internal/version package)
LDFLAGS := -s -w \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.Version=$(VERSION)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitCommit=$(GIT_COMMIT)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitBranch=$(GIT_BRANCH)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.BuildTime=$(BUILD_TIME)'

# Platforms for cross-compilation
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

.PHONY: all build build-all clean test deps lint run install help tidy version

# Default target
all: build

# Help target
help:
	@echo "$(GREEN)$(PRODUCT_NAME) - Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Build Commands:$(NC)"
	@echo "  make                  - Build agent (default)"
	@echo "  make build            - Build agent for current platform"
	@echo "  make build-all        - Build agent for all platforms"
	@echo "  make build-linux      - Build for Linux (amd64 and arm64)"
	@echo "  make build-darwin     - Build for macOS (amd64 and arm64)"
	@echo ""
	@echo "$(YELLOW)Development Commands:$(NC)"
	@echo "  make run              - Build and run: $(BUILD_DIR)/$(BINARY_NAME) start"
	@echo "  make dev              - Run with go run (faster for development)"
	@echo "  make test             - Run tests"
	@echo "  make test-coverage    - Run tests with coverage report"
	@echo "  make lint             - Run linter"
	@echo "  make fmt              - Format code"
	@echo "  make vet              - Run go vet"
	@echo ""
	@echo "$(YELLOW)Dependencies:$(NC)"
	@echo "  make deps             - Download dependencies"
	@echo "  make deps-update      - Update dependencies"
	@echo "  make tidy             - Tidy go modules"
	@echo ""
	@echo "$(YELLOW)Other Commands:$(NC)"
	@echo "  make clean            - Clean build artifacts"
	@echo "  make install          - Install binary to /usr/local/bin"
	@echo "  make uninstall        - Uninstall binary"
	@echo "  make docker-build     - Build Docker image"
	@echo "  make docker-push      - Push Docker image"
	@echo "  make version          - Show version information"
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  VERSION=$(VERSION)"
	@echo "  GIT_COMMIT=$(GIT_COMMIT)"
	@echo "  GIT_BRANCH=$(GIT_BRANCH)"
	@echo "  BUILD_TIME=$(BUILD_TIME)"
	@echo "  GO_VERSION=$(GO_VERSION)"

## Build commands
build:
	@echo "$(GREEN)Building $(BINARY_NAME) v$(VERSION)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tfo-agent
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

build-all:
	@echo "$(GREEN)Building $(BINARY_NAME) for all platforms...$(NC)"
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} ; \
		output="$(DIST_DIR)/$(BINARY_NAME)-$${GOOS}-$${GOARCH}" ; \
		if [ "$${GOOS}" = "windows" ]; then output="$${output}.exe"; fi ; \
		echo "$(YELLOW)Building for $${GOOS}/$${GOARCH}...$(NC)" ; \
		GOOS=$${GOOS} GOARCH=$${GOARCH} $(GOBUILD) -ldflags "$(LDFLAGS)" -o $${output} ./cmd/tfo-agent ; \
	done
	@echo "$(GREEN)All builds complete in $(DIST_DIR)$(NC)"

build-linux:
	@echo "$(GREEN)Building $(BINARY_NAME) for Linux...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tfo-agent
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/tfo-agent
	@echo "$(GREEN)Linux builds complete$(NC)"

build-darwin:
	@echo "$(GREEN)Building $(BINARY_NAME) for macOS...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/tfo-agent
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tfo-agent
	@echo "$(GREEN)macOS builds complete$(NC)"

## Development commands
run: build
	@echo "$(GREEN)Starting $(BINARY_NAME)...$(NC)"
	@$(BUILD_DIR)/$(BINARY_NAME) start --config $(CONFIG_DIR)/tfo-agent.yaml

dev:
	@echo "$(GREEN)Starting $(BINARY_NAME) in dev mode...$(NC)"
	@$(GOCMD) run ./cmd/tfo-agent start --config $(CONFIG_DIR)/tfo-agent.yaml

## Test commands
test:
	@echo "$(GREEN)Running tests...$(NC)"
	@$(GOTEST) -v -race -cover ./...

test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	@$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report: coverage.html$(NC)"

## Dependencies
deps:
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	@$(GOMOD) download
	@$(GOMOD) tidy
	@echo "$(GREEN)Dependencies downloaded$(NC)"

deps-update:
	@echo "$(GREEN)Updating dependencies...$(NC)"
	@$(GOGET) -u ./...
	@$(GOMOD) tidy
	@echo "$(GREEN)Dependencies updated$(NC)"

tidy:
	@echo "$(GREEN)Tidying go modules...$(NC)"
	@$(GOMOD) tidy
	@echo "$(GREEN)Go modules tidied$(NC)"

## Code quality
lint:
	@echo "$(GREEN)Running linter...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping...$(NC)"; \
	fi

fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@$(GOCMD) fmt ./...

vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	@$(GOCMD) vet ./...

## Cleanup
clean:
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(DIST_DIR)
	@rm -f coverage.out coverage.html
	@echo "$(GREEN)Clean complete$(NC)"

## Installation
install: build
	@echo "$(GREEN)Installing $(BINARY_NAME) to /usr/local/bin...$(NC)"
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(GREEN)Installed successfully$(NC)"

uninstall:
	@echo "$(GREEN)Removing $(BINARY_NAME) from /usr/local/bin...$(NC)"
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)Uninstalled successfully$(NC)"

## Docker
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	@docker build -t telemetryflow/tfo-agent:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		.
	@docker tag telemetryflow/tfo-agent:$(VERSION) telemetryflow/tfo-agent:latest
	@echo "$(GREEN)Docker image built: telemetryflow/tfo-agent:$(VERSION)$(NC)"

docker-push: docker-build
	@echo "$(GREEN)Pushing Docker image...$(NC)"
	@docker push telemetryflow/tfo-agent:$(VERSION)
	@docker push telemetryflow/tfo-agent:latest

## Version info
version:
	@echo "$(GREEN)$(PRODUCT_NAME)$(NC)"
	@echo "  Version:      $(VERSION)"
	@echo "  Git Commit:   $(GIT_COMMIT)"
	@echo "  Git Branch:   $(GIT_BRANCH)"
	@echo "  Build Time:   $(BUILD_TIME)"
	@echo "  Go Version:   $(GO_VERSION)"
