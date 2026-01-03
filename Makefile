# TelemetryFlow Agent - Makefile
#
# TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
# Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
#
# Build and development commands for TelemetryFlow Agent

# =============================================================================
# Build Configuration
# =============================================================================
PRODUCT_NAME := TelemetryFlow Agent
BINARY_NAME := tfo-agent
VERSION ?= 1.1.2
OTEL_SDK_VERSION := 1.39.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GO_VERSION := $(shell go version | cut -d ' ' -f 3)

# =============================================================================
# Directories
# =============================================================================
BUILD_DIR := ./build
CONFIG_DIR := ./configs
DIST_DIR := ./dist
SCRIPTS_DIR := ./scripts
TESTS_DIR := ./tests

# =============================================================================
# Go Parameters
# =============================================================================
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GORUN := $(GOCMD) run
GOINSTALL := $(GOCMD) install

# =============================================================================
# Build Flags (uses internal/version package)
# =============================================================================
LDFLAGS := -s -w \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.Version=$(VERSION)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.OTELSDKVersion=$(OTEL_SDK_VERSION)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitCommit=$(GIT_COMMIT)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitBranch=$(GIT_BRANCH)' \
	-X 'github.com/telemetryflow/telemetryflow-agent/internal/version.BuildTime=$(BUILD_TIME)'

# =============================================================================
# Platforms for Cross-Compilation
# =============================================================================
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# =============================================================================
# Colors for Output
# =============================================================================
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
BLUE := \033[0;34m
CYAN := \033[0;36m
NC := \033[0m

# =============================================================================
# Phony Targets
# =============================================================================
.PHONY: all build build-all build-linux build-darwin build-windows clean \
	test test-unit test-integration test-e2e test-all test-coverage test-script test-short bench \
	test-run test-list test-verbose test-race \
	run run-debug dev dev-watch \
	deps deps-update deps-verify tidy verify \
	lint lint-fix fmt fmt-check vet staticcheck check \
	validate-config \
	install uninstall \
	ci ci-lint ci-test ci-build ci-release \
	security govulncheck coverage-merge coverage-report \
	test-unit-ci test-integration-ci test-e2e-ci \
	docker docker-build docker-push docker-run \
	release-check docs godoc \
	version help info integrations

# =============================================================================
# Default Target
# =============================================================================
all: build

# =============================================================================
# Help Target
# =============================================================================
help:
	@echo "$(GREEN)$(PRODUCT_NAME) - Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Primary Build ($(BUILD_DIR)/$(BINARY_NAME)):$(NC)"
	@echo "  make                  - Build agent (default)"
	@echo "  make build            - Build agent for current platform"
	@echo "  make run              - Build and run: $(BUILD_DIR)/$(BINARY_NAME) start"
	@echo "  make tidy             - Tidy go modules"
	@echo ""
	@echo "$(YELLOW)Platform Builds:$(NC)"
	@echo "  make build-linux      - Build for Linux (amd64 and arm64)"
	@echo "  make build-darwin     - Build for macOS (amd64 and arm64)"
	@echo "  make build-windows    - Build for Windows (amd64)"
	@echo "  make build-all        - Build for all platforms"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  make dev              - Run with go run (faster for development)"
	@echo "  make dev-watch        - Run with file watching (requires watchexec)"
	@echo "  make run-debug        - Run in debug mode"
	@echo "  make validate-config  - Validate configuration file"
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@echo "  make test             - Run unit and integration tests"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make test-e2e         - Run E2E tests only"
	@echo "  make test-all         - Run all tests"
	@echo "  make test-coverage    - Generate coverage reports"
	@echo "  make test-run         - Run specific test (PKG=<pkg> TEST=<name>)"
	@echo "  make test-list        - List available test packages"
	@echo "  make test-verbose     - Run tests with verbose output"
	@echo "  make test-race        - Run tests with race detection"
	@echo "  make bench            - Run benchmarks"
	@echo ""
	@echo "$(YELLOW)Code Quality:$(NC)"
	@echo "  make lint             - Run linters"
	@echo "  make lint-fix         - Run linters with auto-fix"
	@echo "  make fmt              - Format code"
	@echo "  make fmt-check        - Check code formatting (CI)"
	@echo "  make vet              - Run go vet"
	@echo "  make staticcheck      - Run staticcheck"
	@echo "  make check            - Run all checks (fmt, vet, lint, test)"
	@echo ""
	@echo "$(YELLOW)Security:$(NC)"
	@echo "  make security         - Run security scan (gosec)"
	@echo "  make govulncheck      - Run vulnerability check"
	@echo ""
	@echo "$(YELLOW)Dependencies:$(NC)"
	@echo "  make deps             - Download dependencies"
	@echo "  make deps-update      - Update dependencies"
	@echo "  make deps-verify      - Download and verify dependencies"
	@echo "  make tidy             - Tidy go modules"
	@echo "  make verify           - Verify dependencies"
	@echo ""
	@echo "$(YELLOW)CI/CD Pipeline:$(NC)"
	@echo "  make ci               - Run full CI pipeline"
	@echo "  make ci-lint          - Run CI lint pipeline"
	@echo "  make ci-test          - Run CI test pipeline"
	@echo "  make ci-build         - Run CI build (GOOS/GOARCH)"
	@echo "  make ci-release       - Run release checks"
	@echo "  make coverage-merge   - Merge coverage files"
	@echo "  make coverage-report  - Generate coverage report"
	@echo ""
	@echo "$(YELLOW)Docker:$(NC)"
	@echo "  make docker           - Build Docker image"
	@echo "  make docker-build     - Build Docker image (alias)"
	@echo "  make docker-push      - Push Docker image"
	@echo "  make docker-run       - Run Docker container"
	@echo ""
	@echo "$(YELLOW)Other:$(NC)"
	@echo "  make clean            - Clean build artifacts"
	@echo "  make install          - Install binary to /usr/local/bin"
	@echo "  make uninstall        - Uninstall binary"
	@echo "  make version          - Show version information"
	@echo "  make info             - Show build configuration"
	@echo "  make integrations     - List supported integrations"
	@echo "  make docs             - Show documentation locations"
	@echo "  make godoc            - Start godoc server"
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  VERSION=$(VERSION)"
	@echo "  OTEL_SDK_VERSION=$(OTEL_SDK_VERSION)"
	@echo "  GIT_COMMIT=$(GIT_COMMIT)"
	@echo "  GIT_BRANCH=$(GIT_BRANCH)"

# =============================================================================
# Build Targets
# =============================================================================

## Build for current platform
build:
	@echo "$(GREEN)Building $(BINARY_NAME) v$(VERSION)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tfo-agent
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

## Build for all platforms
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

## Build for Linux
build-linux:
	@echo "$(GREEN)Building $(BINARY_NAME) for Linux...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tfo-agent
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/tfo-agent
	@echo "$(GREEN)Linux builds complete$(NC)"

## Build for macOS
build-darwin:
	@echo "$(GREEN)Building $(BINARY_NAME) for macOS...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/tfo-agent
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tfo-agent
	@echo "$(GREEN)macOS builds complete$(NC)"

## Build for Windows
build-windows:
	@echo "$(GREEN)Building $(BINARY_NAME) for Windows...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/tfo-agent
	@echo "$(GREEN)Windows build complete$(NC)"

# =============================================================================
# Run & Development Targets
# =============================================================================

## Run the agent
run: build
	@echo "$(GREEN)Starting $(BINARY_NAME)...$(NC)"
	@$(BUILD_DIR)/$(BINARY_NAME) start --config $(CONFIG_DIR)/tfo-agent.yaml

## Run with debug output
run-debug: build
	@echo "$(GREEN)Starting $(BINARY_NAME) in debug mode...$(NC)"
	@$(BUILD_DIR)/$(BINARY_NAME) start --config $(CONFIG_DIR)/tfo-agent.yaml --log-level debug

## Run with go run (faster for development)
dev:
	@echo "$(GREEN)Starting $(BINARY_NAME) in dev mode...$(NC)"
	@$(GORUN) ./cmd/tfo-agent start --config $(CONFIG_DIR)/tfo-agent.yaml

## Run with file watching (requires watchexec)
dev-watch:
	@echo "$(GREEN)Starting development mode with file watching...$(NC)"
	@which watchexec > /dev/null || (echo "$(RED)watchexec not found. Install with: brew install watchexec$(NC)" && exit 1)
	@watchexec -r -e go,yaml -- make run

## Validate configuration
validate-config: build
	@echo "$(GREEN)Validating configuration...$(NC)"
	@$(BUILD_DIR)/$(BINARY_NAME) config validate --config $(CONFIG_DIR)/tfo-agent.yaml || \
		(echo "$(RED)Configuration validation failed$(NC)" && exit 1)

# =============================================================================
# Testing Targets
# =============================================================================

## Run unit and integration tests
test: test-unit test-integration
	@echo "$(GREEN)All tests completed$(NC)"

## Run unit tests only
test-unit:
	@echo "$(GREEN)Running unit tests...$(NC)"
	@$(GOTEST) -v -timeout 5m -coverprofile=coverage-unit.out ./tests/unit/...

## Run integration tests only
test-integration:
	@echo "$(GREEN)Running integration tests...$(NC)"
	@$(GOTEST) -v -timeout 5m -coverprofile=coverage-integration.out ./tests/integration/...

## Run E2E tests only
test-e2e:
	@echo "$(GREEN)Running E2E tests...$(NC)"
	@$(GOTEST) -v -timeout 10m ./tests/e2e/...

## Run all tests
test-all: test-unit test-integration test-e2e
	@echo "$(GREEN)All tests completed$(NC)"

## Generate coverage reports
test-coverage:
	@echo "$(GREEN)Generating coverage reports...$(NC)"
	@$(GOCMD) tool cover -html=coverage-unit.out -o coverage-unit.html 2>/dev/null || true
	@$(GOCMD) tool cover -html=coverage-integration.out -o coverage-integration.html 2>/dev/null || true
	@echo "$(GREEN)Coverage reports generated$(NC)"

## Run test script
test-script:
	@echo "$(GREEN)Running test script...$(NC)"
	@./scripts/test.sh

## Run short tests (skip E2E)
test-short:
	@echo "$(GREEN)Running short tests (skip E2E)...$(NC)"
	@./scripts/test.sh short

## Run benchmarks
bench:
	@echo "$(GREEN)Running benchmarks...$(NC)"
	@$(GOTEST) -bench=. -benchmem ./...

## Run specific test (usage: make test-run PKG=integrations or TEST=TestPerconaCollector)
test-run:
	@if [ -n "$(PKG)" ] && [ -n "$(TEST)" ]; then \
		./scripts/test-specific.sh $(PKG):$(TEST); \
	elif [ -n "$(PKG)" ]; then \
		./scripts/test-specific.sh $(PKG); \
	elif [ -n "$(TEST)" ]; then \
		./scripts/test-specific.sh $(TEST); \
	else \
		echo "$(YELLOW)Usage: make test-run PKG=<package> TEST=<test-name>$(NC)"; \
		echo "  Examples:"; \
		echo "    make test-run PKG=integrations"; \
		echo "    make test-run TEST=TestPerconaCollector"; \
		echo "    make test-run PKG=domain/agent TEST=TestAgentStart"; \
		./scripts/test-specific.sh -l; \
	fi

## List available test packages
test-list:
	@./scripts/test-specific.sh -l

## Run tests with verbose output
test-verbose:
	@echo "$(GREEN)Running tests with verbose output...$(NC)"
	@$(GOTEST) -v ./tests/unit/... ./tests/integration/...

## Run tests with race detection
test-race:
	@echo "$(GREEN)Running tests with race detection...$(NC)"
	@$(GOTEST) -race -v ./tests/unit/... ./tests/integration/...

# =============================================================================
# Dependencies Targets
# =============================================================================

## Download dependencies
deps:
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	@$(GOMOD) download
	@$(GOMOD) tidy
	@echo "$(GREEN)Dependencies downloaded$(NC)"

## Update dependencies
deps-update:
	@echo "$(GREEN)Updating dependencies...$(NC)"
	@$(GOGET) -u ./...
	@$(GOMOD) tidy
	@echo "$(GREEN)Dependencies updated$(NC)"

## Download and verify dependencies
deps-verify: deps verify
	@echo "$(GREEN)Dependencies downloaded and verified$(NC)"

## Tidy go modules
tidy:
	@echo "$(GREEN)Tidying go modules...$(NC)"
	@$(GOMOD) tidy
	@echo "$(GREEN)Go modules tidied$(NC)"

## Verify dependencies
verify:
	@echo "$(GREEN)Verifying dependencies...$(NC)"
	@$(GOMOD) verify
	@echo "$(GREEN)Dependencies verified$(NC)"

# =============================================================================
# Code Quality Targets
# =============================================================================

## Run linter
lint:
	@echo "$(GREEN)Running linter...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping...$(NC)"; \
	fi

## Run linter with auto-fix
lint-fix:
	@echo "$(GREEN)Running linter with auto-fix...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --fix ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping...$(NC)"; \
	fi

## Format code
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@$(GOCMD) fmt ./...
	@echo "$(GREEN)Code formatted$(NC)"

## Check code formatting (fails if code needs formatting)
fmt-check:
	@echo "$(GREEN)Checking code formatting...$(NC)"
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "$(RED)The following files need formatting:$(NC)"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "$(GREEN)Code formatting OK$(NC)"

## Run go vet
vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	@$(GOCMD) vet ./...
	@echo "$(GREEN)Vet complete$(NC)"

## Run staticcheck
staticcheck:
	@echo "$(GREEN)Running staticcheck...$(NC)"
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "$(YELLOW)Installing staticcheck...$(NC)"; \
		$(GOINSTALL) honnef.co/go/tools/cmd/staticcheck@latest; \
		staticcheck ./...; \
	fi

## Run all checks (fmt, vet, lint, test)
check: fmt vet lint test
	@echo "$(GREEN)All checks passed$(NC)"

# =============================================================================
# Security Targets
# =============================================================================

## Run security scan with gosec
security:
	@echo "$(GREEN)Running security scan...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -no-fail -fmt sarif -out gosec-results.sarif ./...; \
	else \
		echo "$(YELLOW)gosec not installed, skipping...$(NC)"; \
		echo "$(YELLOW)Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest$(NC)"; \
	fi

## Run govulncheck
govulncheck:
	@echo "$(GREEN)Running govulncheck...$(NC)"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./... || true; \
	else \
		echo "$(YELLOW)Installing govulncheck...$(NC)"; \
		$(GOINSTALL) golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./... || true; \
	fi

# =============================================================================
# CI-Specific Targets
# =============================================================================
# These targets are optimized for CI/CD pipelines with proper exit codes,
# coverage output, and race detection.

## CI: Run full CI pipeline
ci: deps-verify ci-lint ci-test ci-build
	@echo "$(GREEN)CI pipeline completed$(NC)"

## CI: Complete lint pipeline
ci-lint: deps-verify fmt-check vet staticcheck security
	@echo "$(GREEN)CI lint pipeline completed$(NC)"

## CI: Complete test pipeline
ci-test: test-unit-ci test-integration-ci
	@echo "$(GREEN)CI test pipeline completed$(NC)"

## CI: Run unit tests with race detection and coverage
test-unit-ci:
	@echo "$(GREEN)Running unit tests (CI mode with race detection)...$(NC)"
	@$(GOTEST) -v -race -timeout 10m -coverprofile=coverage-unit.out -covermode=atomic ./tests/unit/...

## CI: Run integration tests with race detection and coverage
test-integration-ci:
	@echo "$(GREEN)Running integration tests (CI mode)...$(NC)"
	@$(GOTEST) -v -race -timeout 10m -coverprofile=coverage-integration.out -covermode=atomic ./tests/integration/...

## CI: Run E2E tests
test-e2e-ci:
	@echo "$(GREEN)Running E2E tests (CI mode)...$(NC)"
	@$(GOTEST) -v -timeout 15m ./tests/e2e/...

## CI: Build for a specific platform (used by GitHub Actions)
ci-build:
	@echo "$(GREEN)Building $(BINARY_NAME) for CI ($(GOOS)/$(GOARCH))...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@OUTPUT="$(BUILD_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)"; \
	if [ "$(GOOS)" = "windows" ]; then OUTPUT="$${OUTPUT}.exe"; fi; \
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -ldflags "$(LDFLAGS)" -o $${OUTPUT} ./cmd/tfo-agent; \
	echo "$(GREEN)Built: $${OUTPUT}$(NC)"; \
	ls -la "$${OUTPUT}"

## CI: Run release checks
ci-release: release-check
	@echo "$(GREEN)CI release checks completed$(NC)"

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
		$(GOINSTALL) github.com/wadey/gocovmerge@latest; \
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

# =============================================================================
# Docker Targets
# =============================================================================

## Build Docker image
docker: docker-build

## Build Docker image
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	@docker build -t telemetryflow/telemetryflow-agent:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		.
	@docker tag telemetryflow/telemetryflow-agent:$(VERSION) telemetryflow/telemetryflow-agent:latest
	@echo "$(GREEN)Docker image built: telemetryflow/telemetryflow-agent:$(VERSION)$(NC)"

## Push Docker image
docker-push: docker-build
	@echo "$(GREEN)Pushing Docker image...$(NC)"
	@docker push telemetryflow/telemetryflow-agent:$(VERSION)
	@docker push telemetryflow/telemetryflow-agent:latest

## Run Docker container
docker-run:
	@echo "$(GREEN)Running Docker container...$(NC)"
	@docker run -it --rm \
		-v $(PWD)/configs:/etc/tfo-agent \
		telemetryflow/telemetryflow-agent:$(VERSION)

# =============================================================================
# Clean & Install Targets
# =============================================================================

## Clean build artifacts
clean:
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(DIST_DIR)
	@rm -f coverage*.out coverage*.html coverage-summary.txt
	@rm -f gosec-results.sarif
	@echo "$(GREEN)Clean complete$(NC)"

## Install binary to /usr/local/bin
install: build
	@echo "$(GREEN)Installing $(BINARY_NAME) to /usr/local/bin...$(NC)"
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(GREEN)Installed successfully$(NC)"

## Uninstall binary from /usr/local/bin
uninstall:
	@echo "$(GREEN)Removing $(BINARY_NAME) from /usr/local/bin...$(NC)"
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)Uninstalled successfully$(NC)"

# =============================================================================
# Release Targets
# =============================================================================

## Check release readiness
release-check:
	@echo "$(GREEN)Checking release readiness...$(NC)"
	@echo "$(BLUE)1. Running tests...$(NC)"
	@$(MAKE) test
	@echo "$(BLUE)2. Running linter...$(NC)"
	@$(MAKE) lint
	@echo "$(BLUE)3. Building...$(NC)"
	@$(MAKE) build
	@echo "$(GREEN)Release checks passed$(NC)"

# =============================================================================
# Documentation Targets
# =============================================================================

## Show documentation locations
docs:
	@echo "$(GREEN)Documentation locations:$(NC)"
	@echo "  - README:        README.md"
	@echo "  - Architecture:  docs/ARCHITECTURE.md"
	@echo "  - Commands:      docs/COMMANDS.md"
	@echo "  - Configuration: docs/CONFIGURATION.md"
	@echo "  - Development:   docs/DEVELOPMENT.md"
	@echo "  - Installation:  docs/INSTALLATION.md"
	@echo "  - System Info:   docs/SYSTEM-INFO.md"
	@echo "  - Integrations:  docs/integrations/"
	@echo "  - Security:      SECURITY.md"
	@echo "  - Contributing:  CONTRIBUTING.md"
	@echo "  - Changelog:     CHANGELOG.md"

## Start godoc server
godoc:
	@echo "$(GREEN)Starting godoc server...$(NC)"
	@if command -v godoc > /dev/null; then \
		echo "$(GREEN)Open http://localhost:6060$(NC)"; \
		godoc -http=:6060; \
	else \
		echo "$(YELLOW)godoc not installed. Install with: go install golang.org/x/tools/cmd/godoc@latest$(NC)"; \
	fi

# =============================================================================
# Info Targets
# =============================================================================

## Show version information
version:
	@echo "$(GREEN)$(PRODUCT_NAME)$(NC)"
	@echo "  Version:          $(VERSION)"
	@echo "  OTEL SDK Version: $(OTEL_SDK_VERSION)"
	@echo "  Git Commit:       $(GIT_COMMIT)"
	@echo "  Git Branch:       $(GIT_BRANCH)"
	@echo "  Build Time:       $(BUILD_TIME)"
	@echo "  Go Version:       $(GO_VERSION)"

## Show build configuration
info:
	@echo "$(GREEN)Build Configuration$(NC)"
	@echo ""
	@echo "$(YELLOW)Product:$(NC)"
	@echo "  Name:             $(PRODUCT_NAME)"
	@echo "  Binary:           $(BINARY_NAME)"
	@echo "  Version:          $(VERSION)"
	@echo ""
	@echo "$(YELLOW)Versions:$(NC)"
	@echo "  Go:               $(GO_VERSION)"
	@echo "  OTEL SDK:         $(OTEL_SDK_VERSION)"
	@echo ""
	@echo "$(YELLOW)Git:$(NC)"
	@echo "  Commit:           $(GIT_COMMIT)"
	@echo "  Branch:           $(GIT_BRANCH)"
	@echo ""
	@echo "$(YELLOW)Directories:$(NC)"
	@echo "  Build:            $(BUILD_DIR)"
	@echo "  Config:           $(CONFIG_DIR)"
	@echo "  Dist:             $(DIST_DIR)"
	@echo ""
	@echo "$(YELLOW)Platforms:$(NC)"
	@echo "  $(PLATFORMS)"

## List supported integrations
integrations:
	@echo "$(GREEN)Supported Integrations (35+)$(NC)"
	@echo ""
	@echo "$(YELLOW)Cloud Providers:$(NC)"
	@echo "  - Alibaba Cloud (CMS, SLS, ARMS)"
	@echo "  - AWS CloudWatch"
	@echo "  - Azure Monitor / Application Insights"
	@echo "  - Azure Arc"
	@echo "  - Google Cloud (Monitoring, Logging, Trace)"
	@echo ""
	@echo "$(YELLOW)APM Platforms:$(NC)"
	@echo "  - Datadog"
	@echo "  - Dynatrace"
	@echo "  - IBM Instana"
	@echo "  - ManageEngine (OpManager, AppManager)"
	@echo "  - New Relic"
	@echo ""
	@echo "$(YELLOW)Open Source Observability:$(NC)"
	@echo "  - Coroot (eBPF-based)"
	@echo "  - HyperDX (ClickStack)"
	@echo "  - Netdata Cloud"
	@echo "  - OpenObserve"
	@echo "  - SigNoz"
	@echo ""
	@echo "$(YELLOW)Time Series & Logging:$(NC)"
	@echo "  - Elasticsearch"
	@echo "  - Grafana Loki"
	@echo "  - InfluxDB (v1/v2)"
	@echo "  - Prometheus (Remote Write)"
	@echo "  - Splunk HEC"
	@echo ""
	@echo "$(YELLOW)Distributed Tracing:$(NC)"
	@echo "  - Jaeger"
	@echo "  - Zipkin"
	@echo ""
	@echo "$(YELLOW)Infrastructure:$(NC)"
	@echo "  - Nutanix (Prism Central)"
	@echo "  - Proxmox VE"
	@echo "  - VMware vSphere"
	@echo ""
	@echo "$(YELLOW)Network:$(NC)"
	@echo "  - Cisco (DNA Center, Meraki)"
	@echo "  - SNMP (v1/v2c/v3)"
	@echo ""
	@echo "$(YELLOW)Messaging:$(NC)"
	@echo "  - Apache Kafka"
	@echo "  - MQTT"
	@echo ""
	@echo "$(YELLOW)Other:$(NC)"
	@echo "  - Blackbox (Synthetic Monitoring)"
	@echo "  - eBPF (Linux only)"
	@echo "  - Grafana Alloy"
	@echo "  - Percona PMM"
	@echo "  - Telegraf"
	@echo "  - Webhooks"
