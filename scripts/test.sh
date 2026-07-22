#!/bin/bash
# Test runner script for TelemetryFlow Agent
#
# TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
# Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# Test configuration
COVERAGE_THRESHOLD=95
TIMEOUT=5m
# Source packages to measure coverage for. The unit tests live in external
# packages (tests/unit/...), so without -coverpkg the profile only covers those
# test packages ("[no statements]"). Instrument the real source packages so the
# threshold reflects actual source coverage.
COVERPKG="./internal/...,./pkg/..."

echo -e "${GREEN}Running TelemetryFlow Agent Tests${NC}"

# Unit tests
echo -e "${YELLOW}Running unit tests...${NC}"
go test -v -timeout ${TIMEOUT} -coverpkg="${COVERPKG}" -coverprofile=coverage-unit.out ./tests/unit/...

# Integration tests
echo -e "${YELLOW}Running integration tests...${NC}"
go test -v -timeout ${TIMEOUT} -coverpkg="${COVERPKG}" -coverprofile=coverage-integration.out ./tests/integration/...

# E2E tests (skip in short mode)
if [ "$1" != "short" ]; then
    echo -e "${YELLOW}Running E2E tests...${NC}"
    go test -v -timeout ${TIMEOUT} ./tests/e2e/...
fi

# Generate coverage report
echo -e "${YELLOW}Generating coverage report...${NC}"
go tool cover -html=coverage-unit.out -o coverage-unit.html
go tool cover -html=coverage-integration.out -o coverage-integration.html

# Check coverage threshold
COVERAGE=$(go tool cover -func=coverage-unit.out | grep total | awk '{print $3}' | sed 's/%//')
if (( $(echo "$COVERAGE < $COVERAGE_THRESHOLD" | bc -l) )); then
    echo -e "${RED}Coverage $COVERAGE% is below threshold $COVERAGE_THRESHOLD%${NC}"
    exit 1
fi

echo -e "${GREEN}All tests passed! Coverage: $COVERAGE%${NC}"
