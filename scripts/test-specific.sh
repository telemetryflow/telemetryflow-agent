#!/bin/bash
# Specific Test Runner Script for TelemetryFlow Agent
#
# TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
# Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
#
# This script allows running specific unit tests separately for faster development
# and debugging workflows.

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default configuration
TIMEOUT="5m"
VERBOSE="-v"
COVERAGE=""
RACE=""
COUNT="1"
SHORT=""

# Script name for usage
SCRIPT_NAME=$(basename "$0")

# Usage function
usage() {
    echo -e "${GREEN}TelemetryFlow Agent - Specific Test Runner${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $SCRIPT_NAME [options] <test-target>"
    echo ""
    echo -e "${YELLOW}Test Targets:${NC}"
    echo "  <package>         Run all tests in a package (e.g., integrations, domain/agent)"
    echo "  <test-name>       Run specific test by name pattern (e.g., TestPerconaCollector)"
    echo "  <package>:<test>  Run specific test in a package (e.g., integrations:TestKafka)"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -h, --help        Show this help message"
    echo "  -l, --list        List all available test packages"
    echo "  -q, --quiet       Quiet mode (no verbose output)"
    echo "  -c, --coverage    Generate coverage report"
    echo "  -r, --race        Enable race detector"
    echo "  -s, --short       Run in short mode (skip long-running tests)"
    echo "  -t, --timeout     Set test timeout (default: 5m)"
    echo "  -n, --count       Run tests N times (default: 1)"
    echo "  --ci              Run with CI settings (race + coverage)"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $SCRIPT_NAME integrations                    # Run all integration tests"
    echo "  $SCRIPT_NAME domain/agent                    # Run agent domain tests"
    echo "  $SCRIPT_NAME TestPerconaCollector            # Run test by name pattern"
    echo "  $SCRIPT_NAME integrations:TestKafka          # Run Kafka tests in integrations"
    echo "  $SCRIPT_NAME -c infrastructure/buffer        # Run with coverage"
    echo "  $SCRIPT_NAME -r -n 3 TestExporter            # Run with race detector 3 times"
    echo "  $SCRIPT_NAME --ci domain                     # Run domain tests with CI settings"
    echo ""
    echo -e "${YELLOW}Available Test Packages:${NC}"
    list_packages
}

# List available test packages
list_packages() {
    echo -e "${CYAN}Unit Tests (./tests/unit/):${NC}"
    for dir in ./tests/unit/*/; do
        if [ -d "$dir" ]; then
            pkg=$(basename "$dir")
            count=$(find "$dir" -name "*_test.go" 2>/dev/null | wc -l | tr -d ' ')
            if [ "$count" -gt 0 ]; then
                echo "  - $pkg ($count test files)"
                # Show subdirectories if they exist
                for subdir in "$dir"*/; do
                    if [ -d "$subdir" ]; then
                        subpkg=$(basename "$subdir")
                        subcount=$(find "$subdir" -name "*_test.go" 2>/dev/null | wc -l | tr -d ' ')
                        if [ "$subcount" -gt 0 ]; then
                            echo "    └── $pkg/$subpkg ($subcount test files)"
                        fi
                    fi
                done
            fi
        fi
    done
    echo ""
    echo -e "${CYAN}Integration Tests (./tests/integration/):${NC}"
    for dir in ./tests/integration/*/; do
        if [ -d "$dir" ]; then
            pkg=$(basename "$dir")
            count=$(find "$dir" -name "*_test.go" 2>/dev/null | wc -l | tr -d ' ')
            if [ "$count" -gt 0 ]; then
                echo "  - $pkg ($count test files)"
            fi
        fi
    done
    echo ""
    echo -e "${CYAN}E2E Tests (./tests/e2e/):${NC}"
    count=$(find ./tests/e2e -name "*_test.go" 2>/dev/null | wc -l | tr -d ' ')
    echo "  - e2e ($count test files)"
}

# Find test functions matching a pattern
find_tests() {
    local pattern="$1"
    echo -e "${CYAN}Finding tests matching '${pattern}'...${NC}"
    grep -rh "func Test" ./tests/unit --include="*_test.go" 2>/dev/null | \
        grep -i "$pattern" | \
        sed 's/func \(Test[^(]*\).*/\1/' | \
        sort | uniq || true
}

# Run tests for a specific package
run_package_tests() {
    local package="$1"
    local test_pattern="$2"
    local test_path=""

    # Determine the full test path
    if [ -d "./tests/unit/$package" ]; then
        test_path="./tests/unit/$package/..."
    elif [ -d "./tests/integration/$package" ]; then
        test_path="./tests/integration/$package/..."
    elif [ -d "./tests/e2e" ] && [ "$package" = "e2e" ]; then
        test_path="./tests/e2e/..."
    else
        echo -e "${RED}Error: Package '$package' not found${NC}"
        echo "Use '$SCRIPT_NAME -l' to list available packages"
        exit 1
    fi

    # Build the test command
    local cmd="go test $VERBOSE $RACE $SHORT -timeout $TIMEOUT -count=$COUNT"

    if [ -n "$COVERAGE" ]; then
        local coverage_file="coverage-${package//\//-}.out"
        cmd="$cmd -coverprofile=$coverage_file"
    fi

    if [ -n "$test_pattern" ]; then
        cmd="$cmd -run '$test_pattern'"
    fi

    cmd="$cmd $test_path"

    echo -e "${GREEN}Running: $cmd${NC}"
    echo ""
    eval "$cmd"

    # Generate HTML coverage if coverage was enabled
    if [ -n "$COVERAGE" ]; then
        local coverage_file="coverage-${package//\//-}.out"
        if [ -f "$coverage_file" ]; then
            local html_file="coverage-${package//\//-}.html"
            go tool cover -html="$coverage_file" -o "$html_file" 2>/dev/null || true
            echo ""
            echo -e "${GREEN}Coverage report: $html_file${NC}"
            go tool cover -func="$coverage_file" | tail -1
        fi
    fi
}

# Run tests matching a name pattern across all packages
run_pattern_tests() {
    local pattern="$1"

    echo -e "${GREEN}Running tests matching pattern: $pattern${NC}"
    echo ""

    # Build the test command
    local cmd="go test $VERBOSE $RACE $SHORT -timeout $TIMEOUT -count=$COUNT"

    if [ -n "$COVERAGE" ]; then
        cmd="$cmd -coverprofile=coverage-pattern.out"
    fi

    cmd="$cmd -run '$pattern' ./tests/unit/..."

    echo -e "${CYAN}Command: $cmd${NC}"
    echo ""
    eval "$cmd"

    # Generate HTML coverage if coverage was enabled
    if [ -n "$COVERAGE" ] && [ -f "coverage-pattern.out" ]; then
        go tool cover -html="coverage-pattern.out" -o "coverage-pattern.html" 2>/dev/null || true
        echo ""
        echo -e "${GREEN}Coverage report: coverage-pattern.html${NC}"
        go tool cover -func="coverage-pattern.out" | tail -1
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -l|--list)
                echo -e "${GREEN}TelemetryFlow Agent - Available Test Packages${NC}"
                echo ""
                list_packages
                exit 0
                ;;
            -q|--quiet)
                VERBOSE=""
                shift
                ;;
            -c|--coverage)
                COVERAGE="true"
                shift
                ;;
            -r|--race)
                RACE="-race"
                shift
                ;;
            -s|--short)
                SHORT="-short"
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -n|--count)
                COUNT="$2"
                shift 2
                ;;
            --ci)
                RACE="-race"
                COVERAGE="true"
                TIMEOUT="10m"
                shift
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use '$SCRIPT_NAME -h' for help"
                exit 1
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
}

# Main function
main() {
    parse_args "$@"

    if [ -z "$TARGET" ]; then
        usage
        exit 1
    fi

    echo -e "${GREEN}TelemetryFlow Agent - Specific Test Runner${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Check if target contains a colon (package:test format)
    if [[ "$TARGET" == *":"* ]]; then
        package="${TARGET%%:*}"
        test_pattern="${TARGET#*:}"
        run_package_tests "$package" "$test_pattern"
    # Check if target looks like a test function name (starts with Test)
    elif [[ "$TARGET" == Test* ]]; then
        run_pattern_tests "$TARGET"
    # Check if target is a path-like package
    elif [[ "$TARGET" == *"/"* ]] || [ -d "./tests/unit/$TARGET" ] || [ -d "./tests/integration/$TARGET" ] || [ "$TARGET" = "e2e" ]; then
        run_package_tests "$TARGET" ""
    # Otherwise, treat as a test pattern
    else
        # First check if it's a valid package
        if [ -d "./tests/unit/$TARGET" ]; then
            run_package_tests "$TARGET" ""
        else
            # Treat as a test name pattern
            run_pattern_tests "$TARGET"
        fi
    fi

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Tests completed successfully!${NC}"
}

# Run main function
main "$@"
