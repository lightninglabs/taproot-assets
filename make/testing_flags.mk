MONITORING_TAGS = monitoring
DEV_TAGS = dev $(MONITORING_TAGS)
RPC_TAGS = autopilotrpc chainrpc invoicesrpc peersrpc routerrpc signrpc verrpc walletrpc watchtowerrpc wtclientrpc
LOG_TAGS =
TEST_FLAGS =
ITEST_FLAGS = -logoutput
ITEST_COVERAGE = -cover -coverpkg=./... -coverprofile=itest/coverage.txt
COLLECT_ITEST_COVERAGE = go tool covdata textfmt -i=itest/regtest/cover -o itest/coverage.txt
COVER_PKG = $$(go list -deps -tags="$(DEV_TAGS)" ./... | grep '$(PKG)' | grep -v taprpc)
COVER_HTML = go tool cover -html=coverage.txt -o coverage.html
POSTGRES_START_DELAY = 5
NUM_ITEST_TRANCHES = 8
ITEST_PARALLELISM = $(NUM_ITEST_TRANCHES)
SHUFFLE_SEED = 0

GOLIST := go list -tags="$(DEV_TAGS)" -deps $(PKG)/... | grep '$(PKG)'| grep -v '/vendor/'
GOLISTCOVER := $(shell go list -tags="$(DEV_TAGS)" -deps -f '{{.ImportPath}}' ./... | grep '$(PKG)' | sed -e 's/^$(ESCPKG)/./')

# If rpc option is set also add all extra RPC tags to DEV_TAGS
ifneq ($(with-rpc),)
DEV_TAGS += $(RPC_TAGS)
endif

# Scale the number of parallel running itest tranches.
ifneq ($(tranches),)
NUM_ITEST_TRANCHES = $(tranches)
ITEST_PARALLELISM = $(NUM_ITEST_TRANCHES)
endif

# Give the ability to run the same tranche multiple times at the same time.
ifneq ($(parallel),)
ITEST_PARALLELISM = $(parallel)
endif

# Set the seed for shuffling the test cases.
ifneq ($(shuffleseed),)
SHUFFLE_SEED = $(shuffleseed)
endif

# If specific package is being unit tested, construct the full name of the
# subpackage.
ifneq ($(pkg),)
UNITPKG := $(PKG)/$(pkg)
COVER_PKG := $(PKG)/$(pkg)
UNIT_TARGETED = yes
GOLIST = echo '$(PKG)/$(pkg)'
endif

# If a specific unit test case is being target, construct test.run filter.
ifneq ($(case),)
TEST_FLAGS += -test.run=$(case)
UNIT_TARGETED = yes
endif

# Define the integration test.run filter if the icase argument was provided.
ifneq ($(icase),)
TEST_FLAGS += -test.run="TestTaprootAssetsDaemon/tranche.*/.*-of-.*/$(icase)"
endif

# Don't delete the data directories of nodes.
ifneq ($(nodelete),)
ITEST_FLAGS += -nodelete
endif

# Run the optional tests.
ifneq ($(optional),)
ITEST_FLAGS += -optional -postgrestimeout=240m
endif

# Run itests with specified db backend.
ifneq ($(dbbackend),)
ITEST_FLAGS += -dbbackend=$(dbbackend)
endif

ifeq ($(dbbackend),postgres)
DEV_TAGS += test_db_postgres
endif

# Run universe tests with increased scale for performance testing.
ifneq ($(long-tests),)
DEV_TAGS += longtests
endif

ifneq ($(tags),)
DEV_TAGS += ${tags}
endif

# Define the log tags that will be applied only when running unit tests. If none
# are provided, we default to "nolog" which will be silent.
ifneq ($(log),)
LOG_TAGS := ${log}
TEST_FLAGS += -test.v
else
LOG_TAGS := nolog
endif

ifneq ($(gen-test-vectors),)
DEV_TAGS += gen_test_vectors
endif

ifneq ($(nocache),)
TEST_FLAGS += -test.count=1
endif

# If a timeout was requested, construct initialize the proper flag for the go
# test command. If not, we set 60m (up from the default 10m).
ifneq ($(timeout),)
TEST_FLAGS += -test.timeout=$(timeout)
else ifneq ($(optional),)
TEST_FLAGS += -test.timeout=240m
else
TEST_FLAGS += -test.timeout=60m
endif

# UNIT_TARGTED is undefined iff a specific package and/or unit test case is
# not being targeted.
UNIT_TARGETED ?= no

# If a specific package/test case was requested, run the unit test for the
# targeted case. Otherwise, default to running all tests.
ifeq ($(UNIT_TARGETED), yes)
UNIT := $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) $(UNITPKG)
UNIT_COVER := $(GOTEST) -coverprofile=coverage.txt -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) $(UNITPKG)
UNIT_DEBUG := $(GOTEST) -v -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) $(UNITPKG)
UNIT_TRACE := $(GOTEST) -v -tags="$(DEV_TAGS) stdout trace" $(TEST_FLAGS) $(UNITPKG)
UNIT_RACE := $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS) lowscrypt" $(TEST_FLAGS) -race $(UNITPKG)
endif

ifeq ($(UNIT_TARGETED), no)
UNIT := $(GOLIST) | $(XARGS) env $(GOTEST) -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS)
UNIT_COVER := $(GOTEST) -coverprofile=coverage.txt -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS) ./...
UNIT_DEBUG := $(GOLIST) | $(XARGS) env $(GOTEST) -v -tags="$(DEV_TAGS) $(LOG_TAGS)" $(TEST_FLAGS)
UNIT_TRACE := $(GOLIST) | $(XARGS) env $(GOTEST) -v -tags="$(DEV_TAGS) stdout trace" $(TEST_FLAGS)
UNIT_RACE := $(UNIT) -race
endif


# Default to btcd backend if not set.
ifeq ($(backend),)
backend = btcd
endif

# Construct the integration test command with the added build flags.
ITEST_TAGS := $(DEV_TAGS) $(RPC_TAGS) integration itest $(backend)

# Construct the load test command with the added build flags.
LOADTEST_TAGS := $(DEV_TAGS) $(RPC_TAGS) loadtest
