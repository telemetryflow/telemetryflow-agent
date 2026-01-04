<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg">
    <img src="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg" alt="TelemetryFlow Logo" width="80%">
  </picture>

  <h3>TelemetryFlow Agent (OTEL Agent)</h3>

[![Version](https://img.shields.io/badge/Version-1.1.2-orange.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org/)
[![OTEL SDK](https://img.shields.io/badge/OpenTelemetry_SDK-1.39.0-blueviolet)](https://opentelemetry.io/)
[![OpenTelemetry](https://img.shields.io/badge/OTLP-100%25%20Compliant-success?logo=opentelemetry)](https://opentelemetry.io/)

</div>

---

# Contributing to TelemetryFlow Agent

Thank you for your interest in contributing to TelemetryFlow Agent! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior to [support@devopscorner.id](mailto:support@devopscorner.id).

## Getting Started

### Prerequisites

- **Go 1.24** or later
- **Git**
- **Make**
- **Docker** (optional, for container builds)
- **golangci-lint** (for linting)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/telemetryflow-agent.git
cd telemetryflow-agent
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/telemetryflow/telemetryflow-agent.git
```

## Development Setup

### Install Dependencies

```bash
# Download Go dependencies
make deps

# Or manually
go mod download
go mod tidy
```

### Build the Agent

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Build for specific platforms
make build-linux
make build-darwin
```

### Install Development Tools

```bash
# Install golangci-lint (macOS)
brew install golangci-lint

# Install golangci-lint (Linux)
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
```

## Project Structure

```
telemetryflow-agent/
├── cmd/tfo-agent/           # CLI entry point
├── internal/
│   ├── agent/               # Core agent lifecycle
│   ├── buffer/              # Disk-backed retry buffer
│   ├── collector/           # Metric collectors
│   │   └── system/          # System metrics collector
│   ├── config/              # Configuration management
│   ├── exporter/            # OTLP data exporters
│   └── version/             # Version and banner info
├── pkg/                     # LEGO Building Blocks (reusable)
│   ├── api/                 # HTTP API client
│   ├── banner/              # Startup banner
│   ├── config/              # Config loader utilities
│   └── plugin/              # Plugin registry system
├── configs/                 # Configuration templates
├── tests/
│   ├── unit/                # Unit tests
│   ├── integration/         # Integration tests
│   └── e2e/                 # End-to-end tests
├── scripts/                 # Build/install scripts
├── build/                   # Build output
├── docs/                    # Documentation
├── Makefile
├── Dockerfile
└── docker-compose.yml
```

### Key Packages

| Package              | Description                          |
| -------------------- | ------------------------------------ |
| `cmd/tfo-agent`      | Main entry point with Cobra CLI      |
| `internal/agent`     | Core agent lifecycle management      |
| `internal/collector` | Telemetry collectors                 |
| `internal/config`    | Configuration parsing and validation |
| `internal/exporter`  | OTLP exporters                       |
| `pkg/plugin`         | Plugin registry for extensibility    |

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-kubernetes-collector`
- `fix/memory-leak-in-buffer`
- `docs/update-configuration-guide`
- `refactor/simplify-exporter-logic`

### Create a Feature Branch

```bash
# Sync with upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create your branch
git checkout -b feature/your-feature-name
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:

```
feat(collector): add network metrics collector

fix(buffer): resolve memory leak in retry logic

docs(readme): update installation instructions
```

## Testing

### Run All Tests

```bash
# Run unit and integration tests
make test

# Run all tests including E2E
make test-all
```

### Run Specific Tests

```bash
# Unit tests only
make test-unit

# Integration tests only
make test-integration

# E2E tests only
make test-e2e

# Run short tests (skip E2E)
make test-short
```

### Test Coverage

```bash
# Generate coverage report
make test-coverage

# View coverage in browser
go tool cover -html=coverage-unit.out
```

### Writing Tests

- Place unit tests in `tests/unit/` mirroring the package structure
- Place integration tests in `tests/integration/`
- Place E2E tests in `tests/e2e/`
- Use table-driven tests where appropriate
- Mock external dependencies

Example test:

```go
func TestCollector_CollectMetrics(t *testing.T) {
    tests := []struct {
        name    string
        config  Config
        want    []Metric
        wantErr bool
    }{
        {
            name:   "collect CPU metrics",
            config: Config{EnableCPU: true},
            want:   []Metric{{Name: "system.cpu.usage"}},
        },
        // Add more test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            c := NewCollector(tt.config)
            got, err := c.CollectMetrics()
            if (err != nil) != tt.wantErr {
                t.Errorf("CollectMetrics() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            // Assert results...
        })
    }
}
```

## Submitting Changes

### Code Quality Checks

Before submitting, ensure your code passes all checks:

```bash
# Format code
make fmt

# Run linter
make lint

# Run go vet
make vet

# Run all tests
make test-all
```

### Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md if applicable
5. Submit a pull request to `main` branch

### Pull Request Template

```markdown
## Description

Brief description of changes

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] E2E tests added/updated

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
```

## Coding Standards

### Go Style

- Follow [Effective Go](https://golang.org/doc/effective_go)
- Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting
- Keep functions focused and small
- Use meaningful variable names

### Error Handling

```go
// Good: Handle errors explicitly
result, err := doSomething()
if err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// Good: Use error wrapping for context
if err := validateConfig(cfg); err != nil {
    return fmt.Errorf("config validation: %w", err)
}
```

### Logging

Use structured logging with `zap`:

```go
logger.Info("starting collector",
    zap.String("collector", "system"),
    zap.Duration("interval", interval),
)

logger.Error("failed to export metrics",
    zap.Error(err),
    zap.Int("count", len(metrics)),
)
```

### Configuration

- Use YAML for configuration files
- Provide sensible defaults
- Document all configuration options
- Validate configuration on load

## Documentation

### Code Documentation

- Add package-level documentation
- Document exported functions, types, and constants
- Use examples where helpful

```go
// Package collector provides telemetry collection functionality.
//
// It supports collecting system metrics including CPU, memory,
// disk, and network statistics.
package collector

// Collector collects system telemetry data.
// It implements the plugin.Plugin interface for extensibility.
type Collector struct {
    // ...
}

// NewCollector creates a new Collector with the given configuration.
// If config is nil, default values are used.
func NewCollector(config *Config) *Collector {
    // ...
}
```

### User Documentation

- Update README.md for user-facing changes
- Add/update docs in the `docs/` directory
- Include examples for new features

## Community

### Getting Help

- **GitHub Issues**: Report bugs or request features
- **Discussions**: Ask questions and share ideas
- **Email**: [support@devopscorner.id](mailto:support@devopscorner.id)

### Recognition

Contributors are recognized in:

- Release notes
- CONTRIBUTORS.md file
- GitHub contributors page

## License

By contributing to TelemetryFlow Agent, you agree that your contributions will be licensed under the Apache License 2.0.

---

**Thank you for contributing to TelemetryFlow Agent!**

Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
