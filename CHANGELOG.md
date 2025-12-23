<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg">
    <img src="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg" alt="TelemetryFlow Logo" width="80%">
  </picture>

  <h3>TelemetryFlow Agent (OTEL Agent)</h3>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org/)
[![OTEL](https://img.shields.io/badge/OpenTelemetry-Agent-blueviolet)](https://opentelemetry.io/)

</div>

---

# Changelog

All notable changes to TelemetryFlow Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2024-12-17

### Added

- GitHub Actions workflow for Docker image building with semantic versioning
- Multi-platform Docker support (linux/amd64, linux/arm64)
- SBOM generation for Docker images
- Trivy security scanning in CI/CD pipeline
- GitHub Container Registry publishing
- Docker Hub publishing support
- GitHub Workflows documentation

### Changed

- Updated documentation structure with new GITHUB-WORKFLOWS.md

## [1.0.0] - 2024-12-17

### Added

- Initial release of TelemetryFlow Agent
- OpenTelemetry native telemetry collection
- OTLP export for metrics, logs, and traces
- Agent registration with TelemetryFlow backend
- Heartbeat monitoring and health status sync
- System metrics collection (CPU, memory, disk, network)
- Disk-backed buffer for resilient retry
- Auto-reconnection with exponential backoff
- Graceful shutdown signal handling
- Cross-platform support (Linux, macOS, Windows)
- Docker and Docker Compose support
- Systemd service configuration
- RPM and DEB package builds
- macOS DMG installer
- Windows ZIP with PowerShell installer
- CLI commands: `start`, `version`, `config validate`
- LEGO building blocks architecture
- Plugin registry system

### Documentation

- README with quick start guide
- Installation guide for all platforms
- Configuration reference
- CLI commands reference

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2024-12-17 | Initial release |

## Upgrade Guide

### From Pre-release to 1.0.0

This is the initial stable release. No upgrade steps required.

### Future Upgrades

For future upgrades, check the changelog for breaking changes and follow the upgrade instructions provided.

## Support

- **Issues**: [GitHub Issues](https://github.com/telemetryflow/telemetryflow-platform/issues)
- **Documentation**: [https://docs.telemetryflow.id](https://docs.telemetryflow.id)
- **Email**: support@telemetryflow.id
