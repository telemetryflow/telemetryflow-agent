#!/usr/bin/env bash
# ===========================================================================
# run-container.sh
# Build, tag, and/or push the TelemetryFlow Agent Docker image (local/registry
# by image name — see run-ecr.sh for AWS ECR). Mirrors the TFO-Platform
# run-container.sh conventions (git provenance, -sha worktree builds, immutable
# per-commit tag) adapted to the agent's single Go image.
#
# Usage:
#   ./run-container.sh [options]
#
# Options:
#   -b, --build            Build the Docker image
#   -t, --tag <version>    Override version tag (default: 1.3.7)
#   -sha, --sha <hash>     Build from a specific git commit (short/full hash,
#                          tag, or anything rev-parse accepts) using a temporary
#                          detached worktree — the current working tree and the
#                          ongoing development on this branch are NEVER touched.
#                          Only :<version>-<commit> and :<commit> tags are
#                          produced; :latest / :<version> / :demo-* stay on the
#                          current build.
#   -p, --push             Push image to registry (skip build)
#   -c, --complete         Complete: build, tag, and push
#   -m, --multiarch        Build multi-arch (linux/amd64,linux/arm64)
#   -n, --no-cache         Build without Docker cache
#   -h, --help             Show help
#
# Examples:
#   ./run-container.sh                    # Build + tag (default)
#   ./run-container.sh -t 1.3.7           # Build with custom tag
#   ./run-container.sh -p                 # Push only (no build)
#   ./run-container.sh -c                 # Build, tag, push
#   ./run-container.sh -c -t 1.3.7        # Complete with custom tag
#   ./run-container.sh -m                 # Multi-arch build + tag
#   ./run-container.sh -m -c              # Multi-arch build + push
#   ./run-container.sh -n                 # Build without Docker cache
#   ./run-container.sh -sha abc1234       # Rebuild a specific commit (worktree)
#
# Image: telemetryflow/telemetryflow-agent
#
# Tags generated:
#   :latest, :<version>, :<version>-<commit>, :<commit>[-dirty], :demo-<YYYYMMDD>
# The bare :<commit> tag is the immutable per-build identity — it survives
# version bumps and never moves (dirty builds get :<commit>-dirty so the clean
# alias is never overwritten). The :<version> tag stays the release identity.
#
# With -sha <hash>, the image is built from that commit inside a temporary
# detached git worktree: only :<version>-<commit> and :<commit> are tagged/
# pushed, so a historical rebuild can never clobber the current :latest /
# :<version> / :demo-* and never disturbs uncommitted work on the branch.
# ===========================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IMAGE="telemetryflow/telemetryflow-agent"
VERSION="1.3.7"
COMMIT=$(git rev-parse --short HEAD)
COMMIT_FULL=$(git rev-parse HEAD)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached")
GIT_DIRTY=$(test -n "$(git status --porcelain 2>/dev/null)" && echo "-dirty" || echo "")
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
YYYYMMDD=$(date +"%Y%m%d")

# Immutable per-build identity: the bare short commit hash. A dirty working tree
# appends -dirty so the clean per-commit alias is never overwritten by a local
# dev build on the same branch.
HASH_TAG="${COMMIT}${GIT_DIRTY}"

# OCI provenance labels baked into every image so the running container reports
# exactly which git commit it was built from (docker inspect / kubectl).
GIT_LABELS=(
  --label "org.opencontainers.image.revision=${COMMIT_FULL}"
  --label "com.telemetryflow.git.commit=${COMMIT}${GIT_DIRTY}"
  --label "com.telemetryflow.git.branch=${GIT_BRANCH}"
)

# -sha specific-commit build state
ARG_SHA=""
IS_COMMIT_BUILD=false
BUILD_CTX="."
WORKTREE_DIR=""

# All tags for the image (in -sha mode only the immutable identity tags).
tags() {
  if $IS_COMMIT_BUILD; then
    echo "${IMAGE}:${VERSION}-${COMMIT}"
    echo "${IMAGE}:${HASH_TAG}"
    return 0
  fi
  echo "${IMAGE}:latest"
  echo "${IMAGE}:${VERSION}"
  echo "${IMAGE}:${VERSION}-${COMMIT}"
  echo "${IMAGE}:${HASH_TAG}"
  echo "${IMAGE}:demo-${YYYYMMDD}"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
header() { echo -e "\n$1\n----------------------------------------------------------"; }

show_build_commit() {
  echo ""
  echo "  ── Git provenance ─────────────────────────────────────"
  echo "     commit : ${COMMIT}${GIT_DIRTY}  (${COMMIT_FULL})"
  echo "     branch : ${GIT_BRANCH}"
  echo "     tag    : ${VERSION}-${COMMIT}"
  echo "     hash   : ${HASH_TAG}  (immutable per-build)"
  $IS_COMMIT_BUILD && echo "     mode   : specific-commit build (temporary worktree)"
  [ -n "${GIT_DIRTY}" ] && echo "     WARNING: working tree has uncommitted changes (-dirty)"
  echo "  ───────────────────────────────────────────────────────"
  echo ""
}

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -b, --build            Build the Docker image
  -t, --tag <version>    Override version tag (default: ${VERSION})
  -sha, --sha <hash>     Build from a specific git commit via a temporary
                         worktree (current working tree untouched; only
                         :<version>-<commit> and :<commit> tags are produced)
  -p, --push             Push image to registry (skip build)
  -c, --complete         Complete: build, tag, and push
  -m, --multiarch        Build multi-arch (linux/amd64,linux/arm64)
  -n, --no-cache         Build without Docker cache
  -h, --help             Show this help

Examples:
  $0                  # Build + tag (default)
  $0 -t 1.3.7         # Build with custom tag
  $0 -p               # Push only (no build)
  $0 -c               # Build, tag, push
  $0 -c -t 1.3.7      # Complete with custom tag
  $0 -m               # Multi-arch build + tag
  $0 -m -c            # Multi-arch build + push
  $0 -n               # Build without Docker cache
  $0 -sha abc1234     # Rebuild a specific commit (worktree)

Image: ${IMAGE}
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Specific-commit build (-sha) — temporary detached worktree
# ---------------------------------------------------------------------------
# Building an arbitrary historical commit must never disturb the current
# development flow: the main working tree (including uncommitted changes and
# build artifacts) stays exactly as it is. We materialize the target commit in
# a throw-away `git worktree add --detach`, build there, and remove it after.
# The Go build happens inside the Dockerfile (COPY . . + go build), so no
# host-side dependency install is needed in the worktree.
setup_commit_vars() {
  local resolved
  resolved=$(git rev-parse --verify --quiet "${ARG_SHA}^{commit}") || {
    echo "Error: commit '${ARG_SHA}' not found in this repository."
    exit 1
  }
  IS_COMMIT_BUILD=true
  COMMIT_FULL="$resolved"
  COMMIT=$(git rev-parse --short "$COMMIT_FULL")
  GIT_BRANCH="detached@${COMMIT}"
  GIT_DIRTY=""        # a worktree checkout is always clean
  HASH_TAG="$COMMIT"  # immutable alias for the target commit
  # Re-bake provenance labels for the TARGET commit (not HEAD).
  GIT_LABELS=(
    --label "org.opencontainers.image.revision=${COMMIT_FULL}"
    --label "com.telemetryflow.git.commit=${COMMIT}"
    --label "com.telemetryflow.git.branch=${GIT_BRANCH}"
  )
}

enter_worktree() {
  WORKTREE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/tfo-agent-build-${COMMIT}-XXXXXX")
  git worktree add --detach "$WORKTREE_DIR" "$COMMIT_FULL"
  BUILD_CTX="$WORKTREE_DIR"
  echo "  worktree: ${WORKTREE_DIR}  (@${COMMIT})"
}

cleanup_commit_build() {
  if [[ -n "$WORKTREE_DIR" && -d "$WORKTREE_DIR" ]]; then
    git worktree remove --force "$WORKTREE_DIR" || true
    git worktree prune || true
    echo "  worktree removed: ${WORKTREE_DIR}"
  fi
}
trap cleanup_commit_build EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
docker_build_flags() {
  if $NO_CACHE; then echo "--no-cache"; else echo ""; fi
}

build_image() {
  header "Building ${IMAGE}:${VERSION}..."
  show_build_commit
  # shellcheck disable=SC2046
  docker build \
    --build-arg VERSION="${VERSION}" \
    --build-arg GIT_COMMIT="${COMMIT}" \
    --build-arg GIT_BRANCH="${GIT_BRANCH}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    $(docker_build_flags) \
    "${GIT_LABELS[@]}" \
    -t "${IMAGE}:latest" \
    "${BUILD_CTX}"
}

build_multiarch() {
  header "Building ${IMAGE}:${VERSION} (multi-arch: linux/amd64,linux/arm64)..."
  show_build_commit

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

  # shellcheck disable=SC2046,SC2086
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --build-arg VERSION="${VERSION}" \
    --build-arg GIT_COMMIT="${COMMIT}" \
    --build-arg GIT_BRANCH="${GIT_BRANCH}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    $(docker_build_flags) \
    "${GIT_LABELS[@]}" \
    ${tag_flags} \
    ${push_flags} \
    "${BUILD_CTX}"
}

# ---------------------------------------------------------------------------
# Tag — in specific-commit mode only the immutable identity tags are created,
# so :latest / :<version> / :demo-* keep pointing at the current build.
# ---------------------------------------------------------------------------
tag_image() {
  header "Tagging ${IMAGE}..."
  if $IS_COMMIT_BUILD; then
    docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}-${COMMIT}"
    docker tag "${IMAGE}:latest" "${IMAGE}:${HASH_TAG}"
    return 0
  fi
  docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}"
  docker tag "${IMAGE}:latest" "${IMAGE}:${VERSION}-${COMMIT}"
  docker tag "${IMAGE}:latest" "${IMAGE}:${HASH_TAG}"
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
NO_CACHE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--build)     DO_BUILD=true;     shift   ;;
    -t|--tag)       VERSION="$2";      shift 2 ;;
    -sha|--sha)
      if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
        echo "Error: -sha/--sha requires a commit hash argument."
        exit 1
      fi
      ARG_SHA="$2"; shift 2 ;;
    -p|--push)      DO_PUSH=true;      shift   ;;
    -c|--complete)  DO_COMPLETE=true;   shift   ;;
    -m|--multiarch) DO_MULTIARCH=true;  shift   ;;
    -n|--no-cache)  NO_CACHE=true;      shift   ;;
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
# Execute — Specific-commit mode setup (before any build)
# ---------------------------------------------------------------------------
if [[ -n "$ARG_SHA" ]]; then
  setup_commit_vars
fi

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------
if $DO_MULTIARCH; then
  # Multi-arch: buildx handles build + tag (+ push if -c)
  [[ -n "$ARG_SHA" ]] && enter_worktree
  build_multiarch
else
  # Standard single-arch flow
  if $DO_BUILD; then
    [[ -n "$ARG_SHA" ]] && enter_worktree
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
