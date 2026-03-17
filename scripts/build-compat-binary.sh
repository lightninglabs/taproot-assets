#!/usr/bin/env bash

# build-compat-binary.sh builds the tapd-integrated binary from a specific
# git tag for backward compatibility testing. Built binaries are cached in
# a local directory so subsequent invocations are instant.
#
# Usage:
#   ./scripts/build-compat-binary.sh <version-tag> [cache-dir]
#
# Examples:
#   ./scripts/build-compat-binary.sh v0.8.0
#   ./scripts/build-compat-binary.sh v0.8.0 /tmp/compat-bins
#
# The script prints the absolute path to the built binary on success.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <version-tag> [cache-dir]" >&2
    exit 1
fi

VERSION_TAG="$1"
CACHE_DIR="${2:-${HOME}/.tapd-compat-bins}"
BINARY_NAME="tapd-integrated-${VERSION_TAG}"
BINARY_PATH="${CACHE_DIR}/${BINARY_NAME}"

# If the binary already exists in the cache, skip the build.
if [ -x "${BINARY_PATH}" ]; then
    echo "${BINARY_PATH}"
    exit 0
fi

mkdir -p "${CACHE_DIR}"

# We need the repo root to create a temporary worktree.
REPO_ROOT="$(git rev-parse --show-toplevel)"
WORK_DIR="$(mktemp -d)"

cleanup() {
    # Remove the worktree and temp directory.
    git -C "${REPO_ROOT}" worktree remove --force "${WORK_DIR}" \
        2>/dev/null || true
    rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Building tapd-integrated at ${VERSION_TAG}..." >&2

# Create a detached worktree at the requested tag. This avoids touching
# the developer's working copy.
git -C "${REPO_ROOT}" worktree add --detach "${WORK_DIR}" "${VERSION_TAG}"

# Build the integrated binary inside the worktree. CGO is disabled for
# portability, matching the itest build.
(
    cd "${WORK_DIR}"
    CGO_ENABLED=0 go build -tags="dev monitoring" \
        -o "${BINARY_PATH}" \
        ./cmd/tapd-integrated
)

chmod +x "${BINARY_PATH}"

echo "Cached ${BINARY_NAME} at ${BINARY_PATH}" >&2
echo "${BINARY_PATH}"
