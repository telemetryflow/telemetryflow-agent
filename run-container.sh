#!/usr/bin/env bash
# ===========================================================================
# run-container.sh
# Build, tag, and/or push TelemetryFlow Agent Docker image.
#
# Usage:
#   ./run-container.sh [options]
#
# Options:
#   -b, --build            Build the Docker image
#   -t, --tag <version>    Override version tag (default: 1.2.0)
#   -p, --push             Push image to registry (skip build)
#   -c, --complete         Complete: build, tag, and push
#   -m, --multiarch        Build multi-arch (linux/amd64,linux/arm64)
#   -h, --help             Show help
#
# Examples:
#   ./run-container.sh                  # Build + tag (default)
#   ./run-container.sh -t 2.0.0         # Build with custom tag
#   ./run-container.sh -p               # Push only (no build)
#   ./run-container.sh -c               # Build, tag, push
#   ./run-container.sh -c -t 2.0.0      # Complete with custom tag
#   ./run-container.sh -m               # Multi-arch build + tag
#   ./run-container.sh -m -c            # Multi-arch build + push
#
# Image: telemetryflow/telemetryflow-agent
#
# Tags generated:
#   :latest, :<version>, :<version>-<commit>, :demo-<YYYYMMDD>
# ===========================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IMAGE="telemetryflow/telemetryflow-agent"
VERSION="1.2.2"
COMMIT=$(git rev-parse --short HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
YYYYMMDD=$(date +"%Y%m%d")

# All tags for the image
tags() {
  echo "${IMAGE}:latest"
  echo "${IMAGE}:${VERSION}"
  echo "${IMAGE}:${VERSION}-${COMMIT}"
  echo "${IMAGE}:demo-${YYYYMMDD}"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
header() { echo -e "\n$1\n----------------------------------------------------------"; }

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -b, --build            Build the Docker image
  -t, --tag <version>    Override version tag (default: ${VERSION})
  -p, --push             Push image to registry (skip build)
  -c, --complete         Complete: build, tag, and push
  -m, --multiarch        Build multi-arch (linux/amd64,linux/arm64)
  -h, --help             Show this help

Examples:
  $0                  # Build + tag (default)
  $0 -t 2.0.0         # Build with custom tag
  $0 -p               # Push only (no build)
  $0 -c               # Build, tag, push
  $0 -c -t 2.0.0      # Complete with custom tag
  $0 -m               # Multi-arch build + tag
  $0 -m -c            # Multi-arch build + push
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build_image() {
  header "Building ${IMAGE}:${VERSION}..."
  docker build \
    --build-arg VERSION="${VERSION}" \
    --build-arg GIT_COMMIT="${COMMIT}" \
    --build-arg GIT_BRANCH="${BRANCH}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    -t "${IMAGE}:latest" \
    .
}

build_multiarch() {
  header "Building ${IMAGE}:${VERSION} (multi-arch: linux/amd64,linux/arm64)..."

  local push_flags=""
  if $DO_PUSH; then
    push_flags="--push"
  else
    push_flags="--load"
    echo "  Note: --load only supports single platform; building for current arch."
    echo "  Use -c/--complete with -m to push multi-arch images to registry."
  fi

  local tag_flags=""
  for t in $(tags); do
    tag_flags="${tag_flags} -t ${t}"
  done

  # shellcheck disable=SC2086
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --build-arg VERSION="${VERSION}" \
    --build-arg GIT_COMMIT="${COMMIT}" \
    --build-arg GIT_BRANCH="${BRANCH}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    ${tag_flags} \
    ${push_flags} \
    .
}

# ---------------------------------------------------------------------------
# Tag
# ---------------------------------------------------------------------------
tag_image() {
  header "Tagging ${IMAGE}..."
  docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}"
  docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}-${COMMIT}"
  docker tag "${IMAGE}:latest" "${IMAGE}:demo-${YYYYMMDD}"
}

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------
push_image() {
  header "Pushing ${IMAGE}..."
  for t in $(tags); do
    docker push "${t}"
  done
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
  local action=$1
  echo "  [TFO-Agent] ${action}"
  for t in $(tags); do
    echo "    ${t}"
  done
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
DO_BUILD=false
DO_PUSH=false
DO_COMPLETE=false
DO_MULTIARCH=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--build)     DO_BUILD=true;     shift   ;;
    -t|--tag)       VERSION="$2";      shift 2 ;;
    -p|--push)      DO_PUSH=true;      shift   ;;
    -c|--complete)  DO_COMPLETE=true;   shift   ;;
    -m|--multiarch) DO_MULTIARCH=true;  shift   ;;
    -h|--help)      usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# --complete overrides: build + push
if $DO_COMPLETE; then
  DO_BUILD=true
  DO_PUSH=true
fi

# Default: build if no flags given
if ! $DO_BUILD && ! $DO_PUSH; then
  DO_BUILD=true
fi

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------
if $DO_MULTIARCH; then
  # Multi-arch: buildx handles build + tag (+ push if -c)
  build_multiarch
else
  # Standard single-arch flow
  if $DO_BUILD; then
    build_image
    tag_image
  fi

  if $DO_PUSH; then
    push_image
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Done."
if $DO_MULTIARCH; then
  if $DO_PUSH; then
    print_summary "multi-arch built+tagged+pushed"
  else
    print_summary "multi-arch built+tagged (local)"
  fi
else
  if $DO_BUILD && $DO_PUSH; then
    print_summary "built+tagged+pushed"
  elif $DO_BUILD; then
    print_summary "built+tagged"
  elif $DO_PUSH; then
    print_summary "pushed"
  fi
fi
