#!/usr/bin/env bash
set -euo pipefail

IMAGE="telemetryflow/telemetryflow-agent"
VERSION="1.1.9"
COMMIT=$(git rev-parse --short HEAD)
YYYYMMDD=$(date +"%Y%m%d")

echo "Building container..."
echo "----------------------------------------------------------"
docker build --no-cache -t $IMAGE:latest -f Dockerfile .
echo ""

echo "Tagging images Agent..."
echo "----------------------------------------------------------"
echo docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}"
echo docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}-${COMMIT}"
echo docker tag "${IMAGE}:latest" "${IMAGE}:demo-${YYYYMMDD}"
docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}"
docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}-${COMMIT}"
docker tag "${IMAGE}:latest" "${IMAGE}:demo-${YYYYMMDD}"
echo ""

echo "Pushing images Agent..."
echo "----------------------------------------------------------"
docker push "${IMAGE}:latest"
docker push "${IMAGE}:${VERSION}"
docker push "${IMAGE}:${VERSION}-${COMMIT}"
docker push "${IMAGE}:demo-${YYYYMMDD}"
echo ""

echo "Done. Pushed:"
echo "----------------------------------------------------------"
echo "  ${IMAGE}:latest"
echo "  ${IMAGE}:${VERSION}"
echo "  ${IMAGE}:${VERSION}-${COMMIT}"
echo "  ${IMAGE}:demo-${YYYYMMDD}"
