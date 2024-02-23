PKG := github.com/lightninglabs/taproot-assets

BTCD_PKG := github.com/btcsuite/btcd
LND_PKG := github.com/lightningnetwork/lnd
GOACC_PKG := github.com/ory/go-acc
GOIMPORTS_PKG := github.com/rinchsan/gosimports/cmd/gosimports
TOOLS_DIR := tools

GO_BIN := ${GOPATH}/bin
GOACC_BIN := $(GO_BIN)/go-acc
GOIMPORTS_BIN := $(GO_BIN)/gosimports
MIGRATE_BIN := $(GO_BIN)/migrate

# VERSION_GO_FILE is the golang file which defines the current project version.
VERSION_GO_FILE := "version.go"

COMMIT := $(shell git describe --tags --dirty)

GOBUILD := GOEXPERIMENT=loopvar GO111MODULE=on go build -v
GOINSTALL := GOEXPERIMENT=loopvar GO111MODULE=on go install -v
GOTEST := GOEXPERIMENT=loopvar GO111MODULE=on go test
GOMOD := GO111MODULE=on go mod

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

DEV_TAGS := $(if ${tags},$(DEV_TAGS) ${tags},$(DEV_TAGS))

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

DOCKER_TOOLS = docker run \
  -v $(shell bash -c "go env GOCACHE || (mkdir -p /tmp/go-cache; echo /tmp/go-cache)"):/tmp/build/.cache \
  -v $(shell bash -c "go env GOMODCACHE || (mkdir -p /tmp/go-modcache; echo /tmp/go-modcache)"):/tmp/build/.modcache \
  -v $$(pwd):/build taproot-assets-tools

GO_VERSION = 1.21.4

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

$(GOACC_BIN):
	@$(call print, "Installing go-acc.")
	cd $(TOOLS_DIR); go install -trimpath $(GOACC_PKG)

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
	@$(call print, "Building itest btcd.")
	CGO_ENABLED=0 $(GOBUILD) -tags="integration" -o itest/btcd-itest $(BTCD_PKG)

	@$(call print, "Building itest lnd.")
	CGO_ENABLED=0 $(GOBUILD) -tags="$(ITEST_TAGS)" -o itest/lnd-itest $(DEV_LDFLAGS) $(LND_PKG)/cmd/lnd

build-loadtest:
	CGO_ENABLED=0 $(GOTEST) -c -tags="$(LOADTEST_TAGS)" -o loadtest $(PKG)/itest/loadtest

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
	./scripts/release.sh build-release "$(VERSION_TAG)" "$(BUILD_SYSTEM)" "$(RELEASE_TAGS)" "$(RELEASE_LDFLAGS)"

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

unit-cover: $(GOACC_BIN)
	@$(call print, "Running unit coverage tests.")
	$(GOACC); $(COVER_HTML)

unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(UNIT_RACE)

itest: build-itest itest-only

itest-trace: build-itest itest-only-trace

itest-only: aperture-dir
	@$(call print, "Running integration tests with ${backend} backend.")
	rm -rf itest/regtest; date
	$(GOTEST) ./itest -v -tags="$(ITEST_TAGS)" $(TEST_FLAGS) $(ITEST_FLAGS) -btcdexec=./btcd-itest -logdir=regtest

itest-only-trace: aperture-dir
	@$(call print, "Running integration tests with ${backend} backend.")
	rm -rf itest/regtest; date
	$(GOTEST) ./itest -v -tags="$(ITEST_TAGS)" $(TEST_FLAGS) $(ITEST_FLAGS) -loglevel=trace -btcdexec=./btcd-itest -logdir=regtest

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
	while [ $$? -eq 0 ]; do env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOLIST) | $(XARGS) env $(GOTEST) -race -test.timeout=20m -count=1; done

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

sqlc-check: sqlc
	@$(call print, "Verifying sql code generation.")
	if test -n "$$(git status --porcelain '*.go')"; then echo "SQL models not properly generated!"; git status --porcelain '*.go'; exit 1; fi

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
	./tools/check-go-version-yaml.sh $(GO_VERSION)

check-go-version-dockerfile:
	@$(call print, "Checking for target Go version (v$(GO_VERSION)) in Dockerfile files (*Dockerfile)")
	./tools/check-go-version-dockerfile.sh $(GO_VERSION)

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

clean:
	@$(call print, "Cleaning source.$(NC)")
	$(RM) coverage.txt

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
