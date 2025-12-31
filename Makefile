PKG := github.com/lightninglabs/taproot-assets

BTCD_PKG := github.com/btcsuite/btcd
LND_PKG := github.com/lightningnetwork/lnd
GOIMPORTS_PKG := github.com/rinchsan/gosimports/cmd/gosimports
TOOLS_DIR := tools

GO_BIN := ${GOPATH}/bin
GOIMPORTS_BIN := $(GO_BIN)/gosimports
MIGRATE_BIN := $(GO_BIN)/migrate

# VERSION_GO_FILE is the golang file which defines the current project version.
VERSION_GO_FILE := "version.go"

COMMIT := $(shell git describe --tags --dirty --always)

GOBUILD := go build -v
GOINSTALL := go install -v
GOTEST := go test
GOMOD := go mod

GOLIST := go list -deps $(PKG)/... | grep '$(PKG)'
GOLIST_COVER := $$(go list -deps $(PKG)/... | grep '$(PKG)')
GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*" -not -name "*pb.go" -not -name "*pb.gw.go" -not -name "*.pb.json.go")

RM := rm -f
CP := cp
MAKE := make
XARGS := xargs -L 1
UNAME_S := $(shell uname -s)

include make/testing_flags.mk
include make/release_flags.mk
include make/fuzz_flags.mk

# We only return the part inside the double quote here to avoid escape issues
# when calling the external release script. The second parameter can be used to
# add additional ldflags if needed (currently only used for the release).
make_ldflags = $(1) -X $(PKG).Commit=$(COMMIT)

DEV_GCFLAGS := -gcflags "all=-N -l"
DEV_LDFLAGS := -ldflags "$(call make_ldflags)"

# For the release, we want to remove the symbol table and debug information (-s)
# and omit the DWARF symbol table (-w). Also we clear the build ID.
RELEASE_LDFLAGS := $(call make_ldflags, -s -w -buildid=)

# Linting uses a lot of memory, so keep it under control by limiting the number
# of workers if requested.
ifneq ($(workers),)
LINT_WORKERS = --concurrency=$(workers)
endif

# Worktree support: golangci-lint's issues.new-from-rev compares against git
# history, but worktrees keep .git metadata outside the worktree root. When
# lint runs in Docker without those dirs mounted, new-from-rev cannot resolve,
# so we bind-mount the git dir/common dir into the container.
GIT_DIR := $(shell git rev-parse --git-dir 2>/dev/null)
GIT_COMMON_DIR := $(shell git rev-parse --git-common-dir 2>/dev/null)
DOCKER_GIT_MOUNTS :=
ifneq ($(filter /%,$(GIT_DIR)),)
DOCKER_GIT_MOUNTS += -v $(GIT_DIR):$(GIT_DIR)
endif
ifneq ($(filter /%,$(GIT_COMMON_DIR)),)
ifneq ($(GIT_COMMON_DIR),$(GIT_DIR))
DOCKER_GIT_MOUNTS += -v $(GIT_COMMON_DIR):$(GIT_COMMON_DIR)
endif
endif

# Docker cache mounting strategy:
# - CI (GitHub Actions): Use bind mounts to host paths that GA caches persist.
# - Local: Use Docker named volumes (much faster on macOS/Windows due to
#   avoiding slow host-syncing overhead).
# Paths inside container must match GOCACHE/GOMODCACHE in tools/Dockerfile.
ifdef CI
# CI mode: bind mount to host paths that GitHub Actions caches.
DOCKER_TOOLS = docker run \
  --rm \
  -v $${HOME}/.cache/go-build:/tmp/build/.cache \
  -v $${HOME}/go/pkg/mod:/tmp/build/.modcache \
  -v $${HOME}/.cache/golangci-lint:/root/.cache/golangci-lint \
  $(DOCKER_GIT_MOUNTS) \
  -v $$(pwd):/build taproot-assets-tools
else
# Local mode: Docker named volumes for fast macOS/Windows performance.
DOCKER_TOOLS = docker run \
  --rm \
  -v tapd-go-build-cache:/tmp/build/.cache \
  -v tapd-go-mod-cache:/tmp/build/.modcache \
  -v tapd-go-lint-cache:/root/.cache/golangci-lint \
  $(DOCKER_GIT_MOUNTS) \
  -v $$(pwd):/build taproot-assets-tools
endif

GO_VERSION = 1.24.9

GREEN := "\\033[0;32m"
NC := "\\033[0m"
define print
	echo $(GREEN)$1$(NC)
endef

default: scratch

all: scratch check install

# ============
# DEPENDENCIES
# ============

$(GOIMPORTS_BIN):
	@$(call print, "Installing goimports.")
	cd $(TOOLS_DIR); go install -trimpath $(GOIMPORTS_PKG)

# ============
# INSTALLATION
# ============

build:
	@$(call print, "Building debug tapd and tapcli.")
	$(GOBUILD) -tags="$(DEV_TAGS)" -o tapd-debug $(DEV_GCFLAGS) $(DEV_LDFLAGS) $(PKG)/cmd/tapd
	$(GOBUILD) -tags="$(DEV_TAGS)" -o tapcli-debug $(DEV_GCFLAGS) $(DEV_LDFLAGS) $(PKG)/cmd/tapcli

build-itest:
	@if [ ! -f itest/chantools/chantools ]; then \
		$(call print, "Building itest chantools."); \
		rm -rf itest/chantools; \
		git clone --depth 1 --branch v0.14.0 https://github.com/lightninglabs/chantools.git itest/chantools; \
		cd itest/chantools && go build ./cmd/chantools; \
	else \
		$(call print, "Chantools is already installed and available in itest/chantools."); \
	fi

	@$(call print, "Building itest btcd.")
	CGO_ENABLED=0 $(GOBUILD) -tags="integration" -o itest/btcd-itest $(BTCD_PKG)

	@$(call print, "Building itest lnd.")
	CGO_ENABLED=0 $(GOBUILD) -mod=mod -tags="$(ITEST_TAGS)" -o itest/lnd-itest $(DEV_LDFLAGS) $(LND_PKG)/cmd/lnd

build-itest-binary:
	@$(call print, "Building itest binary for ${backend} backend.")
	CGO_ENABLED=0 $(GOTEST) -v $(ITEST_COVERAGE) ./itest -tags="$(ITEST_TAGS)" -c -o itest/itest.test

build-loadtest:
	CGO_ENABLED=0 $(GOTEST) -c -tags="$(LOADTEST_TAGS)" -o loadtest $(PKG)/itest/loadtest

build-docs-examples:
	@$(call print, "Building docs examples.")
	$(MAKE) -C ./docs/examples build

install:
	@$(call print, "Installing tapd and tapcli.")
	$(GOINSTALL) -tags="${tags}" -ldflags="$(RELEASE_LDFLAGS)" $(PKG)/cmd/tapd
	$(GOINSTALL) -tags="${tags}" -ldflags="$(RELEASE_LDFLAGS)" $(PKG)/cmd/tapcli

release-install:
	@$(call print, "Installing release tapd and tapcli.")
	env CGO_ENABLED=0 $(GOINSTALL) -v -trimpath -ldflags="$(RELEASE_LDFLAGS)" -tags="$(RELEASE_TAGS)" $(PKG)/cmd/tapd
	env CGO_ENABLED=0 $(GOINSTALL) -v -trimpath -ldflags="$(RELEASE_LDFLAGS)" -tags="$(RELEASE_TAGS)" $(PKG)/cmd/tapcli

release:
	@$(call print, "Releasing tapd and tapcli binaries.")
	$(VERSION_CHECK)
	./scripts/release.sh build-release "$(VERSION_TAG)" "$(BUILD_SYSTEM)" "$(RELEASE_TAGS)" "$(RELEASE_LDFLAGS)" "$(GO_VERSION)"

release-tag:
	@$(call print, "Adding release tag.")

	tag=$$(./scripts/get-git-tag-name.sh ${VERSION_GO_FILE}); \
	exit_status=$$?; \
	if [ $$exit_status -ne 0 ]; then \
		echo "Script encountered an error with exit status $$exit_status."; \
	fi; \
	echo "Adding git tag: $$tag"; \
	git tag -as -m "Tag generated using command \`make release-tag\`." "$$tag";

docker-release:
	@$(call print, "Building release helper docker image.")
	if [ "$(tag)" = "" ]; then echo "Must specify tag=<commit_or_tag>!"; exit 1; fi

	docker build -t taproot-assets-release-helper -f make/builder.Dockerfile make/

	# Run the actual compilation inside the docker image. We pass in all flags
	# that we might want to overwrite in manual tests.
	$(DOCKER_RELEASE_HELPER) make release tag="$(tag)" sys="$(sys)" COMMIT="$(COMMIT)" 

docker-tools:
	@$(call print, "Building tools docker image.")
	docker build -q -t taproot-assets-tools $(TOOLS_DIR)

scratch: build

# ===================
# DATABASE MIGRATIONS
# ===================

migrate-up: $(MIGRATE_BIN)
	migrate -path tapdb/sqlc/migrations -database $(TAP_DB_CONNECTIONSTRING) -verbose up

migrate-down: $(MIGRATE_BIN)
	migrate -path tapdb/sqlc/migrations -database $(TAP_DB_CONNECTIONSTRING) -verbose down 1

migrate-create: $(MIGRATE_BIN)
	migrate create -dir tapdb/sqlc/migrations -seq -ext sql $(patchname)

# =======
# TESTING
# =======

check: unit

unit:
	@$(call print, "Running unit tests.")
	$(UNIT)

unit-debug:
	@$(call print, "Running unit tests in debug mode (showing test output).")
	$(UNIT_DEBUG)

unit-trace:
	@$(call print, "Running unit tests in trace mode (enabling package loggers on level trace).")
	$(UNIT_TRACE)

unit-cover:
	@$(call print, "Running unit coverage tests.")
	$(UNIT_COVER)

unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(UNIT_RACE)

itest: build-itest itest-only

itest-trace: build-itest itest-only-trace

itest-only: aperture-dir clean-itest-logs
	@$(call print, "Running integration tests with ${backend} backend.")
	date
	$(GOTEST) ./itest -v $(ITEST_COVERAGE) -tags="$(ITEST_TAGS)" $(TEST_FLAGS) $(ITEST_FLAGS) -btcdexec=./btcd-itest -logdir=regtest

itest-only-trace: aperture-dir clean-itest-logs
	@$(call print, "Running integration tests with ${backend} backend.")
	rm -rf itest/regtest; date
	$(GOTEST) ./itest -v -tags="$(ITEST_TAGS)" $(TEST_FLAGS) $(ITEST_FLAGS) -loglevel=trace -btcdexec=./btcd-itest -logdir=regtest

itest-parallel: aperture-dir clean-itest-logs build-itest build-itest-binary
	@$(call print, "Running integration tests in parallel with ${backend} backend.")
	date
	scripts/itest_parallel.sh $(ITEST_PARALLELISM) $(NUM_ITEST_TRANCHES) $(SHUFFLE_SEED) $(TEST_FLAGS) $(ITEST_FLAGS)
	$(COLLECT_ITEST_COVERAGE)

clean-itest-logs:
	rm -rf itest/regtest

aperture-dir:
ifeq ($(UNAME_S),Linux)
	mkdir -p $$HOME/.aperture
endif
ifeq ($(UNAME_S),Darwin)
	mkdir -p "$$HOME/Library/Application Support/Aperture"
endif

# =============
# FLAKE HUNTING
# =============

flakehunter: build-itest
	@$(call print, "Flake hunting ${backend} integration tests.")
	while [ $$? -eq 0 ]; do make itest-only-trace; done

flake-unit:
	@$(call print, "Flake hunting unit tests.")
	while [ $$? -eq 0 ]; do make unit nocache=1; done

flake-unit-trace:
	@$(call print, "Flake hunting unit tests in debug mode.")
	while [ $$? -eq 0 ]; do make unit-trace nocache=1; done

flake-unit-race:
	@$(call print, "Flake hunting races in unit tests.")
	while [ $$? -eq 0 ]; do make unit-race nocache=1; done

flake-unit-race-trace:
	@$(call print, "Flake hunting races in unit tests.")
	while [ $$? -eq 0 ]; do make unit-race log='stdout trace' nocache=1; done

# =============
# FUZZING
# =============

fuzz:
	@$(call print, "Fuzzing packages '$(FUZZPKG)'.")
	scripts/fuzz.sh run "$(FUZZPKG)" "$(FUZZ_TEST_RUN_TIME)" "$(FUZZ_NUM_PROCESSES)" "$(FUZZ_TEST_TIMEOUT)"

# =========
# UTILITIES
# =========

gen: rpc sqlc

sqlc:
	@$(call print, "Generating sql models and queries in Go")
	./scripts/gen_sqlc_docker.sh
	@$(call print, "Merging SQL migrations into consolidated schemas")
	go run ./cmd/merge-sql-schemas/main.go

sqlc-check: sqlc
	@$(call print, "Verifying sql code generation.")
	@if [ ! -f tapdb/sqlc/schemas/generated_schema.sql ]; then \
		echo "Missing file: tapdb/sqlc/schemas/generated_schema.sql"; \
		exit 1; \
	fi
	@if test -n "$$(git status --porcelain '*.go')"; then \
		echo "SQL models not properly generated!"; \
		git status --porcelain '*.go'; \
		exit 1; \
	fi

rpc:
	@$(call print, "Compiling protos.")
	cd ./taprpc; ./gen_protos_docker.sh

rpc-format:
	@$(call print, "Formatting protos.")
	cd ./taprpc; find . -name "*.proto" | xargs clang-format --style=file -i

rpc-check: rpc
	@$(call print, "Verifying protos.")
	cd ./taprpc; ../scripts/check-rest-annotations.sh
	if test -n "$$(git status --porcelain)"; then echo "Protos not properly formatted or not compiled with correct version"; git status; git diff; exit 1; fi

vendor:
	@$(call print, "Re-creating vendor directory.")
	rm -r vendor/; go mod vendor

fmt: $(GOIMPORTS_BIN)
	@$(call print, "Fixing imports.")
	gosimports -w $(GOFILES_NOVENDOR)
	@$(call print, "Formatting source.")
	gofmt -l -w -s $(GOFILES_NOVENDOR)

check-go-version-yaml:
	@$(call print, "Checking for target Go version (v$(GO_VERSION)) in  YAML files (*.yaml, *.yml)")
	./scripts/check-go-version-yaml.sh $(GO_VERSION)

check-go-version-dockerfile:
	@$(call print, "Checking for target Go version (v$(GO_VERSION)) in Dockerfile files (*Dockerfile)")
	./scripts/check-go-version-dockerfile.sh $(GO_VERSION)

lint-source: docker-tools
	@$(call print, "Linting source.")
	$(DOCKER_TOOLS) golangci-lint run -v $(LINT_WORKERS)

lint: lint-source check-go-version-dockerfile check-go-version-yaml

list:
	@$(call print, "Listing commands.")
	@$(MAKE) -qp | \
		awk -F':' '/^[a-zA-Z0-9][^$$#\/\t=]*:([^=]|$$)/ {split($$1,A,/ /);for(i in A)print A[i]}' | \
		grep -v Makefile | \
		sort

mod-tidy:
	@$(call print, "Tidying modules.")
	$(GOMOD) tidy

mod-check: mod-tidy
	@$(call print, "Checking modules.")
	if test -n "$$(git status | grep -e "go.mod\|go.sum")"; then echo "Running go mod tidy changes go.mod/go.sum"; git status; git diff; exit 1; fi

sample-conf-check:
	@$(call print, "Checking that default values in the sample-tapd.conf file are set correctly")
	scripts/check-sample-tapd-conf.sh "$(RELEASE_TAGS)"

gen-deterministic-test-vectors:
	@$(call print, "Generating deterministic test vectors.")
	make unit gen-test-vectors=true pkg=address case=^TestAddressEncoding$
	make unit gen-test-vectors=true pkg=asset case=^TestAssetEncoding$
	make unit gen-test-vectors=true pkg=asset case=^TestDeriveBurnKey$
	make unit gen-test-vectors=true pkg=mssmt case=^TestProofEncoding$
	make unit gen-test-vectors=true pkg=mssmt case=^TestInsertionOverflow$
	make unit gen-test-vectors=true pkg=mssmt case=^TestReplaceWithEmptyBranch$
	make unit gen-test-vectors=true pkg=mssmt case=^TestReplace$
	make unit gen-test-vectors=true pkg=proof case=^TestGenesisProofVerification$
	make unit gen-test-vectors=true pkg=tappsbt case=^TestEncodingDecoding$
	make unit gen-test-vectors=true pkg=vm case=^TestVM$

gen-itest-test-vectors:
	@$(call print, "Generating test vectors from integration tests.")
	make itest gen-test-vectors=true icase=basic_send_passive_asset
	mv itest/testdata/*.json proof/testdata/
	mv itest/testdata/*proof*.hex proof/testdata/

gen-test-vectors: gen-deterministic-test-vectors gen-itest-test-vectors

test-vector-check: gen-deterministic-test-vectors
	@$(call print, "Checking deterministic test vectors.")
	if test -n "$$(git status | grep -e ".json")"; then echo "Test vectors not updated"; git status; git diff; exit 1; fi

migration-check:
	@$(call print, "Checking migration numbering.")
	./scripts/check-migration-numbering.sh

	@$(call print, "Checking migration version.")
	./scripts/check-migration-latest-version.sh

clean:
	@$(call print, "Cleaning source.$(NC)")
	$(RM) coverage.txt
	$(RM) -r itest/regtest
	$(RM) -r itest/chantools
	$(RM) itest/btcd-itest
	$(RM) itest/lnd-itest
	$(RM) loadtest
	$(RM) tapd-debug
	$(RM) tapcli-debug
	$(RM) -r taproot-assets-v*

.PHONY: all \
	default \
	build \
	install \
	scratch \
	check \
	unit \
	unit-cover \
	unit-race \
	fmt \
	lint \
	list \
	rpc \
	rpc-format \
	rpc-check \
	vendor \
	clean
