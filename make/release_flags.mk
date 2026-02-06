# One can either specify a git tag as the version suffix or one that is
# generated from the current date.
VERSION_TAG = $(shell date +%Y%m%d)-01
VERSION_CHECK = @$(call print, "Building master with date version tag")

ifneq ($(tag),)
VERSION_TAG = $(tag)
VERSION_CHECK = ./scripts/release.sh check-tag "$(VERSION_TAG)" "$(VERSION_GO_FILE)"
endif

# Use DOCKER/IS_PODMAN from Makefile.

# For Podman rootless, use --user=0:0 to avoid permission issues.
# For Docker, use current user to ensure generated files are user-owned.
ifeq ($(IS_PODMAN),1)
USER_ARGS = --user=0:0
else
USER_ARGS = --user $(shell id -u):$(shell id -g)
endif

# Cache volume mounts for reproducible builds.
GOCACHE_VOLUME = -v $(shell bash -c "go env GOCACHE || \
  (mkdir -p /tmp/go-cache; echo /tmp/go-cache)"):/tmp/build/.cache
GOMODCACHE_VOLUME = -v $(shell bash -c "go env GOMODCACHE || \
  (mkdir -p /tmp/go-modcache; echo /tmp/go-modcache)"):/tmp/build/.modcache

# Canonical GitHub repository URL.
REPO_URL = https://github.com/lightninglabs/taproot-assets.git

# Common docker run arguments for release builds.
DOCKER_RELEASE_ARGS = --rm $(USER_ARGS) \
  $(GOCACHE_VOLUME) $(GOMODCACHE_VOLUME) \
  -e SKIP_VERSION_CHECK

BUILD_SYSTEM = darwin-amd64 \
darwin-arm64 \
linux-386 \
linux-amd64 \
linux-armv6 \
linux-armv7 \
linux-arm64 \
windows-amd64

RELEASE_TAGS = monitoring

# By default we will build all systems. But with the 'sys' tag, a specific
# system can be specified. This is useful to release for a subset of
# systems/architectures.
ifneq ($(sys),)
BUILD_SYSTEM = $(sys)
endif

# Use all build tags by default but allow them to be overwritten.
ifneq ($(tags),)
RELEASE_TAGS = $(tags)
endif
