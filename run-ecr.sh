#!/usr/bin/env bash
# ===========================================================================
# run-ecr.sh
# Build, tag, and/or push the TelemetryFlow Agent image to AWS ECR.
#
# SECURITY: this script contains NO account-specific data. The AWS account ID
# and region are resolved at RUNTIME from the caller's own AWS credentials /
# environment, never hardcoded here — so the committed file leaks nothing:
#   - AWS_ACCOUNT_ID : $AWS_ACCOUNT_ID if set, else `aws sts get-caller-identity`
#   - AWS_REGION     : $AWS_REGION / $AWS_DEFAULT_REGION, else `aws configure get region`
# The ECR login uses `aws ecr get-login-password | docker login --password-stdin`
# so the token is streamed to docker and never printed or stored in a variable.
#
# Usage:
#   AWS_REGION=ap-southeast-1 ./run-ecr.sh [options]
#   (or rely on your configured default region / AWS_DEFAULT_REGION)
#
# Options:
#   -b, --build            Build the image (and tag onto the ECR path)
#   -t, --tag <version>    Override version tag (default: 1.3.7)
#   -sha, --sha <hash>     Build from a specific git commit using a temporary
#                          detached worktree (working tree untouched; only
#                          :<version>-<commit> and :<commit> tags are produced)
#   -p, --push             Push to ECR (skip build)
#   -c, --complete         Complete: build, tag, and push
#   -m, --multiarch        Build + push multi-arch (linux/amd64,linux/arm64)
#   -n, --no-cache         Build without Docker cache
#   -h, --help             Show help
#
# Examples:
#   ./run-ecr.sh                     # Build + tag onto ECR path
#   ./run-ecr.sh -c                  # Build, tag, push to ECR
#   ./run-ecr.sh -p                  # Push only (no build)
#   ./run-ecr.sh -m -c               # Multi-arch build + push to ECR
#   ./run-ecr.sh -sha abc1234 -c     # Rebuild + push a specific commit
#   AWS_ACCOUNT_ID=... AWS_REGION=... ./run-ecr.sh -c   # explicit target
#
# Image (ECR):  <account>.dkr.ecr.<region>.amazonaws.com/telemetryflow/telemetryflow-agent
#
# Tags generated:
#   :latest, :<version>, :<version>-<commit>, :<commit>[-dirty], :demo-<YYYYMMDD>
# The bare :<commit> tag is the immutable per-build identity. With -sha only
# :<version>-<commit> and :<commit> are tagged/pushed.
# ===========================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# AWS target — resolved at runtime, NEVER hardcoded (no secret/ID in this file)
# ---------------------------------------------------------------------------
resolve_aws() {
  AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}"
  if [[ -z "${AWS_REGION}" ]]; then
    echo "Error: AWS region not set. Export AWS_REGION (or AWS_DEFAULT_REGION), or run 'aws configure'." >&2
    exit 1
  fi
  if [[ -z "${AWS_ACCOUNT_ID:-}" ]]; then
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)
  fi
  if [[ -z "${AWS_ACCOUNT_ID}" || "${AWS_ACCOUNT_ID}" == "None" ]]; then
    echo "Error: could not resolve AWS account ID. Export AWS_ACCOUNT_ID or configure AWS credentials." >&2
    exit 1
  fi
  ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
  ECR_IMAGE="${ECR_REGISTRY}/${IMAGE}"
}

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
HASH_TAG="${COMMIT}${GIT_DIRTY}"

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

# Populated by resolve_aws()
AWS_REGION="${AWS_REGION:-}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
ECR_REGISTRY=""
ECR_IMAGE=""

# ECR tags for the image (in -sha mode only the immutable identity tags).
tags() {
  if $IS_COMMIT_BUILD; then
    echo "${ECR_IMAGE}:${VERSION}-${COMMIT}"
    echo "${ECR_IMAGE}:${HASH_TAG}"
    return 0
  fi
  echo "${ECR_IMAGE}:latest"
  echo "${ECR_IMAGE}:${VERSION}"
  echo "${ECR_IMAGE}:${VERSION}-${COMMIT}"
  echo "${ECR_IMAGE}:${HASH_TAG}"
  echo "${ECR_IMAGE}:demo-${YYYYMMDD}"
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
Usage: AWS_REGION=<region> $0 [options]

Options:
  -b, --build            Build the image (and tag onto the ECR path)
  -t, --tag <version>    Override version tag (default: ${VERSION})
  -sha, --sha <hash>     Build from a specific git commit via a temporary
                         worktree (working tree untouched; only
                         :<version>-<commit> and :<commit> tags are produced)
  -p, --push             Push to ECR (skip build)
  -c, --complete         Complete: build, tag, and push
  -m, --multiarch        Build + push multi-arch (linux/amd64,linux/arm64)
  -n, --no-cache         Build without Docker cache
  -h, --help             Show this help

AWS target is resolved at runtime (never hardcoded):
  AWS_ACCOUNT_ID  env, else 'aws sts get-caller-identity'
  AWS_REGION      env / AWS_DEFAULT_REGION, else 'aws configure get region'

Image (ECR): <account>.dkr.ecr.<region>.amazonaws.com/${IMAGE}
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Login ECR (token streamed to docker; never printed or stored)
# ---------------------------------------------------------------------------
ECR_LOGGED_IN=false
login_ecr() {
  $ECR_LOGGED_IN && return 0
  header "Login ECR — ${ECR_REGISTRY}"
  aws ecr get-login-password --region "$AWS_REGION" \
    | docker login --username AWS --password-stdin "$ECR_REGISTRY"
  ECR_LOGGED_IN=true
}

# ---------------------------------------------------------------------------
# Specific-commit build (-sha) — temporary detached worktree
# ---------------------------------------------------------------------------
setup_commit_vars() {
  local resolved
  resolved=$(git rev-parse --verify --quiet "${ARG_SHA}^{commit}") || {
    echo "Error: commit '${ARG_SHA}' not found in this repository." >&2
    exit 1
  }
  IS_COMMIT_BUILD=true
  COMMIT_FULL="$resolved"
  COMMIT=$(git rev-parse --short "$COMMIT_FULL")
  GIT_BRANCH="detached@${COMMIT}"
  GIT_DIRTY=""
  HASH_TAG="$COMMIT"
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
  # A specific-commit rebuild must not move the ECR :latest pointer.
  $IS_COMMIT_BUILD || docker tag "${IMAGE}:latest" "${ECR_IMAGE}:latest"
}

build_multiarch() {
  header "Building ${IMAGE}:${VERSION} (multi-arch → ECR, pushed by buildx)..."
  show_build_commit
  local tag_flags=""
  for t in $(tags); do
    tag_flags="${tag_flags} -t ${t}"
  done
  # Multi-arch manifests cannot be --load'd locally; buildx pushes straight to ECR.
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
    --push \
    "${BUILD_CTX}"
}

# ---------------------------------------------------------------------------
# Tag (local :latest → ECR tags)
# ---------------------------------------------------------------------------
tag_image() {
  header "Tagging ${ECR_IMAGE}..."
  if $IS_COMMIT_BUILD; then
    docker tag "${IMAGE}:latest" "${ECR_IMAGE}:${VERSION}-${COMMIT}"
    docker tag "${IMAGE}:latest" "${ECR_IMAGE}:${HASH_TAG}"
    return 0
  fi
  docker tag "${IMAGE}:latest" "${ECR_IMAGE}:${VERSION}"
  docker tag "${IMAGE}:latest" "${ECR_IMAGE}:${VERSION}-${COMMIT}"
  docker tag "${IMAGE}:latest" "${ECR_IMAGE}:${HASH_TAG}"
  docker tag "${IMAGE}:latest" "${ECR_IMAGE}:demo-${YYYYMMDD}"
}

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------
push_image() {
  header "Pushing ${ECR_IMAGE}..."
  for t in $(tags); do
    docker push "${t}"
  done
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
  local action=$1
  echo "  [TFO-Agent → ECR] ${action}"
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
        echo "Error: -sha/--sha requires a commit hash argument." >&2
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

if $DO_COMPLETE; then
  DO_BUILD=true
  DO_PUSH=true
fi

if ! $DO_BUILD && ! $DO_PUSH && ! $DO_MULTIARCH; then
  DO_BUILD=true
fi

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------
[[ -n "$ARG_SHA" ]] && setup_commit_vars
resolve_aws

if $DO_MULTIARCH; then
  # buildx builds + pushes the multi-arch manifest to ECR in one step.
  login_ecr
  [[ -n "$ARG_SHA" ]] && enter_worktree
  build_multiarch
else
  if $DO_BUILD; then
    login_ecr
    [[ -n "$ARG_SHA" ]] && enter_worktree
    build_image
    tag_image
  fi
  if $DO_PUSH; then
    login_ecr
    push_image
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Done."
if $DO_MULTIARCH; then
  print_summary "multi-arch built+pushed"
elif $DO_BUILD && $DO_PUSH; then
  print_summary "built+tagged+pushed"
elif $DO_BUILD; then
  print_summary "built+tagged"
elif $DO_PUSH; then
  print_summary "pushed"
fi
