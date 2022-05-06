PKG := github.com/lightninglabs/taro

LINT_PKG := github.com/golangci/golangci-lint/cmd/golangci-lint
GOACC_PKG := github.com/ory/go-acc
GOIMPORTS_PKG := golang.org/x/tools/cmd/goimports

GO_BIN := ${GOPATH}/bin
LINT_BIN := $(GO_BIN)/golangci-lint
GOACC_BIN := $(GO_BIN)/go-acc

LINT_COMMIT := v1.45.2
GOACC_COMMIT := 80342ae2e0fcf265e99e76bcc4efd022c7c3811b
GOIMPORTS_COMMIT := v0.1.10

COMMIT := $(shell git describe --tags --dirty)
COMMIT_HASH := $(shell git rev-parse HEAD)

GOBUILD := GO111MODULE=on go build -v
GOINSTALL := GO111MODULE=on go install -v
GOTEST := GO111MODULE=on go test 

GOVERSION := $(shell go version | awk '{print $$3}')
GOLIST := go list -deps $(PKG)/... | grep '$(PKG)'
GOLIST_COVER := $$(go list -deps $(PKG)/... | grep '$(PKG)')
GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*" -not -name "*pb.go" -not -name "*pb.gw.go" -not -name "*.pb.json.go")

RM := rm -f
CP := cp
MAKE := make
XARGS := xargs -L 1

include make/testing_flags.mk
include make/release_flags.mk
include make/fuzz_flags.mk

DEV_TAGS := $(if ${tags},$(DEV_TAGS) ${tags},$(DEV_TAGS))

# We only return the part inside the double quote here to avoid escape issues
# when calling the external release script. The second parameter can be used to
# add additional ldflags if needed (currently only used for the release).
make_ldflags = $(2) -X $(PKG)/build.Commit=$(COMMIT) \
	-X $(PKG)/build.CommitHash=$(COMMIT_HASH) \
	-X $(PKG)/build.GoVersion=$(GOVERSION) \
	-X $(PKG)/build.RawTags=$(shell echo $(1) | sed -e 's/ /,/g')

DEV_GCFLAGS := -gcflags "all=-N -l"
LDFLAGS := -ldflags "$(call make_ldflags, ${tags}, -s -w)"
DEV_LDFLAGS := -ldflags "$(call make_ldflags, $(DEV_TAGS))"
ITEST_LDFLAGS := -ldflags "$(call make_ldflags, $(ITEST_TAGS))"

# For the release, we want to remove the symbol table and debug information (-s)
# and omit the DWARF symbol table (-w). Also we clear the build ID.
RELEASE_LDFLAGS := $(call make_ldflags, $(RELEASE_TAGS), -s -w -buildid=)

# Linting uses a lot of memory, so keep it under control by limiting the number
# of workers if requested.
ifneq ($(workers),)
LINT_WORKERS = --concurrency=$(workers)
endif

LINT = $(LINT_BIN) run -v $(LINT_WORKERS)

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

$(LINT_BIN):
	@$(call print, "Fetching linter")
	$(GOINSTALL) $(LINT_PKG)@$(LINT_COMMIT)

$(GOACC_BIN):
	@$(call print, "Fetching go-acc")
	$(GOINSTALL) $(GOACC_PKG)@$(GOACC_COMMIT)

goimports:
	@$(call print, "Installing goimports.")
	$(GOINSTALL) $(GOIMPORTS_PKG)@${GOIMPORTS_COMMIT}

# ============
# INSTALLATION
# ============

build:
	@$(call print, "Building debug tarod and tarocli.")
	$(GOBUILD) -tags="$(DEV_TAGS)" -o tarod-debug $(DEV_GCFLAGS) $(DEV_LDFLAGS) $(PKG)/cmd/tarod
	$(GOBUILD) -tags="$(DEV_TAGS)" -o tarocli-debug $(DEV_GCFLAGS) $(DEV_LDFLAGS) $(PKG)/cmd/tarocli

install:
	@$(call print, "Installing tarod and tarocli.")
	$(GOINSTALL) -tags="${tags}" $(LDFLAGS) $(PKG)/cmd/tarod
	$(GOINSTALL) -tags="${tags}" $(LDFLAGS) $(PKG)/cmd/tarocli

scratch: build

# =======
# TESTING
# =======

check: unit

unit:
	@$(call print, "Running unit tests.")
	$(GOLIST) | $(XARGS) env $(GOTEST) -test.timeout=20m

unit-cover: $(GOACC_BIN)
	@$(call print, "Running unit coverage tests.")
	$(GOACC_BIN) $(GOLIST_COVER)

unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" $(GOLIST) | $(XARGS) env $(GOTEST) -race -test.timeout=20m

# =========
# UTILITIES
# =========

rpc:
	@$(call print, "Compiling protos.")
	cd ./tarorpc; ./gen_protos_docker.sh

rpc-format:
	@$(call print, "Formatting protos.")
	cd ./tarorpc; find . -name "*.proto" | xargs clang-format --style=file -i

rpc-check: rpc
	@$(call print, "Verifying protos.")
	cd ./tarorpc; ../scripts/check-rest-annotations.sh
	if test -n "$$(git status --porcelain)"; then echo "Protos not properly formatted or not compiled with v3.4.0"; git status; git diff; exit 1; fi

vendor:
	@$(call print, "Re-creating vendor directory.")
	rm -r vendor/; go mod vendor

fmt: $(GOIMPORTS_BIN)
	@$(call print, "Fixing imports.")
	goimports -w $(GOFILES_NOVENDOR)
	@$(call print, "Formatting source.")
	gofmt -l -w -s $(GOFILES_NOVENDOR)

lint: docker-tools
	@$(call print, "Linting source.")
	$(DOCKER_TOOLS) golangci-lint run -v $(LINT_WORKERS)

list:
	@$(call print, "Listing commands.")
	@$(MAKE) -qp | \
		awk -F':' '/^[a-zA-Z0-9][^$$#\/\t=]*:([^=]|$$)/ {split($$1,A,/ /);for(i in A)print A[i]}' | \
		grep -v Makefile | \
		sort

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
