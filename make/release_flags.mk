# One can either specify a git tag as the version suffix or one that is
# generated from the current date.
VERSION_TAG = $(shell date +%Y%m%d)-01
VERSION_CHECK = @$(call print, "Building master with date version tag")

ifneq ($(tag),)
VERSION_TAG = $(tag)
VERSION_CHECK = ./scripts/release.sh check-tag "$(VERSION_TAG)" "$(VERSION_GO_FILE)"
endif

DOCKER_RELEASE_HELPER = docker run \
  -it \
  --rm \
  --user $(shell id -u):$(shell id -g) \
  -v $(shell pwd):/tmp/build/taproot-assets \
  -v $(shell bash -c "go env GOCACHE || (mkdir -p /tmp/go-cache; echo /tmp/go-cache)"):/tmp/build/.cache \
  -v $(shell bash -c "go env GOMODCACHE || (mkdir -p /tmp/go-modcache; echo /tmp/go-modcache)"):/tmp/build/.modcache \
  -e SKIP_VERSION_CHECK \
  taproot-assets-release-helper

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
