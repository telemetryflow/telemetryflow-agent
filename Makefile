# TelemetryFlow Agent - Makefile
#
# TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
# Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
#
# Build and development commands for TelemetryFlow Agent

# Build configuration
PRODUCT_NAME := TelemetryFlow Agent
BINARY_NAME := tfo-agent
VERSION ?= 1.1.1
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

.PHONY: all build build-all build-linux build-darwin clean test test-unit test-integration test-e2e test-all test-coverage test-script test-short bench \
	run dev deps deps-update tidy lint lint-fix fmt vet check validate-config install uninstall ci release-check docs godoc \
	docker-build docker-push version help fmt-check staticcheck verify deps-verify test-unit-ci test-integration-ci test-e2e-ci \
	security govulncheck coverage-merge coverage-report ci-lint ci-test ci-build

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
	@echo "  make validate-config  - Validate configuration file"
	@echo ""
	@echo "$(YELLOW)Testing Commands:$(NC)"
	@echo "  make test             - Run unit and integration tests"
	@echo "  make test-e2e         - Run E2E tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-all         - Run all tests"
	@echo "  make test-coverage    - Run tests with coverage report"
	@echo "  make test-script      - Run test script"
	@echo "  make test-short       - Run short tests (skip E2E)"
	@echo "  make bench            - Run benchmarks"
	@echo ""
	@echo "$(YELLOW)Code Quality:$(NC)"
	@echo "  make lint             - Run linter"
	@echo "  make lint-fix         - Run linter with auto-fix"
	@echo "  make fmt              - Format code"
	@echo "  make vet              - Run go vet"
	@echo "  make check            - Run all checks (fmt, vet, lint, test)"
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
test: test-unit test-integration
	@echo "$(GREEN)All tests completed$(NC)"

test-unit:
	@echo "$(GREEN)Running unit tests...$(NC)"
	@$(GOTEST) -v -timeout 5m -coverprofile=coverage-unit.out ./tests/unit/...

test-integration:
	@echo "$(GREEN)Running integration tests...$(NC)"
	@$(GOTEST) -v -timeout 5m -coverprofile=coverage-integration.out ./tests/integration/...

test-e2e:
	@echo "$(GREEN)Running E2E tests...$(NC)"
	@$(GOTEST) -v -timeout 10m ./tests/e2e/...

test-all: test-unit test-integration test-e2e
	@echo "$(GREEN)All tests completed$(NC)"

test-coverage:
	@echo "$(GREEN)Generating coverage reports...$(NC)"
	@$(GOCMD) tool cover -html=coverage-unit.out -o coverage-unit.html 2>/dev/null || true
	@$(GOCMD) tool cover -html=coverage-integration.out -o coverage-integration.html 2>/dev/null || true
	@echo "$(GREEN)Coverage reports generated$(NC)"

test-script:
	@echo "$(GREEN)Running test script...$(NC)"
	@./scripts/test.sh

test-short:
	@echo "$(GREEN)Running short tests (skip E2E)...$(NC)"
	@./scripts/test.sh short

bench:
	@echo "$(GREEN)Running benchmarks...$(NC)"
	@$(GOTEST) -bench=. -benchmem ./...

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

lint-fix:
	@echo "$(GREEN)Running linter with auto-fix...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --fix ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping...$(NC)"; \
	fi

fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@$(GOCMD) fmt ./...
	@echo "$(GREEN)Code formatted$(NC)"

vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	@$(GOCMD) vet ./...
	@echo "$(GREEN)Vet complete$(NC)"

check: fmt vet lint test
	@echo "$(GREEN)All checks passed$(NC)"

## Configuration
validate-config:
	@echo "$(GREEN)Validating configuration...$(NC)"
	@$(BUILD_DIR)/$(BINARY_NAME) config validate --config $(CONFIG_DIR)/tfo-agent.yaml || \
		(echo "$(RED)Build agent first with 'make build'$(NC)" && exit 1)

## Cleanup
clean:
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(DIST_DIR)
	@rm -f coverage*.out coverage*.html
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

## CI pipeline
ci: deps check
	@echo "$(GREEN)CI pipeline completed$(NC)"

release-check:
	@echo "$(GREEN)Checking release readiness...$(NC)"
	@echo "$(BLUE)1. Running tests...$(NC)"
	@$(MAKE) test
	@echo "$(BLUE)2. Running linter...$(NC)"
	@$(MAKE) lint
	@echo "$(BLUE)3. Building...$(NC)"
	@$(MAKE) build
	@echo "$(GREEN)Release checks passed$(NC)"

## Documentation
docs:
	@echo "$(GREEN)Documentation locations:$(NC)"
	@echo "  - Command: docs/COMMANDS.md"
	@echo "  - Configuration: docs/CONFIGURATION.md"
	@echo "  - GitHub Workflow: docs/GITHUB-WORKFLOWS.md"
	@echo "  - Installation: docs/INSTALLATION.md"
	@echo "  - Security: SECURTY.md"
	@echo "  - Contributing: CONTRIBUTING.md"

godoc:
	@echo "$(GREEN)Starting godoc server...$(NC)"
	@if command -v godoc > /dev/null; then \
		echo "$(GREEN)Open http://localhost:6060$(NC)"; \
		godoc -http=:6060; \
	else \
		echo "$(YELLOW)godoc not installed. Install with: go install golang.org/x/tools/cmd/godoc@latest$(NC)"; \
	fi

## Docker
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	@docker build -t telemetryflow/telemetryflow-agent:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		.
	@docker tag telemetryflow/telemetryflow-agent:$(VERSION) telemetryflow/telemetryflow-agent:latest
	@echo "$(GREEN)Docker image built: telemetryflow/telemetryflow-agent:$(VERSION)$(NC)"

docker-push: docker-build
	@echo "$(GREEN)Pushing Docker image...$(NC)"
	@docker push telemetryflow/telemetryflow-agent:$(VERSION)
	@docker push telemetryflow/telemetryflow-agent:latest

## Version info
version:
	@echo "$(GREEN)$(PRODUCT_NAME)$(NC)"
	@echo "  Version:      $(VERSION)"
	@echo "  Git Commit:   $(GIT_COMMIT)"
	@echo "  Git Branch:   $(GIT_BRANCH)"
	@echo "  Build Time:   $(BUILD_TIME)"
	@echo "  Go Version:   $(GO_VERSION)"

# =============================================================================
# CI-Specific Targets
# =============================================================================
# These targets are optimized for CI/CD pipelines with proper exit codes,
# coverage output, and race detection.

## CI: Check formatting (fails if code needs formatting)
fmt-check:
	@echo "$(GREEN)Checking code formatting...$(NC)"
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "$(RED)The following files need formatting:$(NC)"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "$(GREEN)Code formatting OK$(NC)"

## CI: Run staticcheck
staticcheck:
	@echo "$(GREEN)Running staticcheck...$(NC)"
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "$(YELLOW)Installing staticcheck...$(NC)"; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
		staticcheck ./...; \
	fi

## CI: Verify dependencies
verify:
	@echo "$(GREEN)Verifying dependencies...$(NC)"
	@$(GOMOD) verify
	@echo "$(GREEN)Dependencies verified$(NC)"

## CI: Download and verify dependencies
deps-verify: deps verify
	@echo "$(GREEN)Dependencies downloaded and verified$(NC)"

## CI: Run unit tests with race detection and coverage
test-unit-ci:
	@echo "$(GREEN)Running unit tests (CI mode)...$(NC)"
	@$(GOTEST) -v -race -timeout 10m -coverprofile=coverage-unit.out -covermode=atomic ./tests/unit/...

## CI: Run integration tests with race detection and coverage
test-integration-ci:
	@echo "$(GREEN)Running integration tests (CI mode)...$(NC)"
	@$(GOTEST) -v -race -timeout 10m -coverprofile=coverage-integration.out -covermode=atomic ./tests/integration/...

## CI: Run E2E tests
test-e2e-ci:
	@echo "$(GREEN)Running E2E tests (CI mode)...$(NC)"
	@$(GOTEST) -v -timeout 15m ./tests/e2e/...

## CI: Run security scan with gosec
security:
	@echo "$(GREEN)Running security scan...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -no-fail -fmt sarif -out gosec-results.sarif ./...; \
	else \
		echo "$(YELLOW)gosec not installed, skipping...$(NC)"; \
	fi

## CI: Run govulncheck
govulncheck:
	@echo "$(GREEN)Running govulncheck...$(NC)"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./... || true; \
	else \
		echo "$(YELLOW)Installing govulncheck...$(NC)"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./... || true; \
	fi

## CI: Merge coverage files
coverage-merge:
	@echo "$(GREEN)Merging coverage files...$(NC)"
	@if command -v gocovmerge >/dev/null 2>&1; then \
		if [ -f coverage-integration.out ]; then \
			gocovmerge coverage-unit.out coverage-integration.out > coverage-merged.out; \
		else \
			cp coverage-unit.out coverage-merged.out; \
		fi; \
	else \
		echo "$(YELLOW)Installing gocovmerge...$(NC)"; \
		go install github.com/wadey/gocovmerge@latest; \
		if [ -f coverage-integration.out ]; then \
			gocovmerge coverage-unit.out coverage-integration.out > coverage-merged.out; \
		else \
			cp coverage-unit.out coverage-merged.out; \
		fi; \
	fi
	@echo "$(GREEN)Coverage merged to coverage-merged.out$(NC)"

## CI: Generate coverage report
coverage-report: coverage-merge
	@echo "$(GREEN)Generating coverage report...$(NC)"
	@$(GOCMD) tool cover -func=coverage-merged.out | tee coverage-summary.txt
	@$(GOCMD) tool cover -html=coverage-merged.out -o coverage.html
	@echo "$(GREEN)Coverage report generated$(NC)"

## CI: Complete lint pipeline
ci-lint: deps-verify fmt-check vet staticcheck security
	@echo "$(GREEN)CI lint pipeline completed$(NC)"

## CI: Complete test pipeline
ci-test: test-unit-ci test-integration-ci
	@echo "$(GREEN)CI test pipeline completed$(NC)"

## CI: Complete build verification for a specific platform
ci-build:
	@echo "$(GREEN)Building for CI ($(GOOS)/$(GOARCH))...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@OUTPUT="$(BUILD_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)"; \
	if [ "$(GOOS)" = "windows" ]; then OUTPUT="$${OUTPUT}.exe"; fi; \
	CGO_ENABLED=0 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $${OUTPUT} ./cmd/tfo-agent; \
	echo "$(GREEN)Built: $${OUTPUT}$(NC)"
