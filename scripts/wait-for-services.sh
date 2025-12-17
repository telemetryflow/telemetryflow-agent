#!/bin/bash
# Wait for services to be ready for E2E tests
#
# TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
# Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
#
# Usage:
#   ./scripts/wait-for-services.sh          # Wait for all services
#   ./scripts/wait-for-services.sh collector # Wait for collector only
#   ./scripts/wait-for-services.sh backend   # Wait for mock backend only

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

TIMEOUT=60
INTERVAL=2

wait_for_service() {
    local service=$1
    local port=$2
    local timeout=$3

    echo -e "${YELLOW}Waiting for $service on port $port...${NC}"

    for ((i=0; i<timeout; i+=INTERVAL)); do
        if nc -z localhost $port 2>/dev/null; then
            echo -e "${GREEN}$service is ready!${NC}"
            return 0
        fi
        sleep $INTERVAL
    done

    echo -e "${RED}Timeout waiting for $service${NC}"
    return 1
}

wait_for_http() {
    local service=$1
    local url=$2
    local timeout=$3

    echo -e "${YELLOW}Waiting for $service at $url...${NC}"

    for ((i=0; i<timeout; i+=INTERVAL)); do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo -e "${GREEN}$service is ready!${NC}"
            return 0
        fi
        sleep $INTERVAL
    done

    echo -e "${RED}Timeout waiting for $service${NC}"
    return 1
}

case "${1:-all}" in
    collector)
        wait_for_service "OTLP Collector gRPC" 4317 $TIMEOUT
        wait_for_service "OTLP Collector HTTP" 4318 $TIMEOUT
        wait_for_http "OTLP Collector Health" "http://localhost:13133/" $TIMEOUT
        ;;
    backend)
        wait_for_service "Mock Backend" 8080 $TIMEOUT
        ;;
    jaeger)
        wait_for_service "Jaeger UI" 16686 $TIMEOUT
        ;;
    all|*)
        echo -e "${GREEN}Waiting for all E2E services...${NC}"
        wait_for_service "OTLP Collector gRPC" 4317 $TIMEOUT
        wait_for_service "OTLP Collector HTTP" 4318 $TIMEOUT
        wait_for_http "OTLP Collector Health" "http://localhost:13133/" $TIMEOUT
        wait_for_service "Mock Backend" 8080 $TIMEOUT
        wait_for_service "Jaeger UI" 16686 $TIMEOUT || true  # Optional
        ;;
esac

echo -e "${GREEN}All services are ready!${NC}"
