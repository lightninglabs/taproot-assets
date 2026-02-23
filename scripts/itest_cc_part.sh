#!/bin/bash

# itest_cc_part.sh runs a single tranche of custom channel integration tests
# using the pre-compiled test binary. This script is modeled after itest_part.sh
# but adapted for the custom_channels test package.

# Let's work with absolute paths only, we run in the custom_channels directory.
WORKDIR=$(pwd)/itest/custom_channels

TRANCHE=$1
NUM_TRANCHES=$2

# Shift the passed parameters by two, giving us all remaining testing flags in
# the $@ special variable.
shift 2

# Check for --verbose flag in the remaining arguments.
VERBOSE=0
TEST_FLAGS=()
for arg in "$@"; do
  if [ "$arg" == "--verbose" ]; then
    VERBOSE=1
  else
    TEST_FLAGS+=("$arg")
  fi
done

EXEC="$WORKDIR/itest-cc.test"
ITEST_DIR=$(pwd)/itest
LOG_DIR="$WORKDIR/regtest/.logs-tranche$TRANCHE"
mkdir -p "$LOG_DIR"

# The miner package (btctest/rpctest) looks for a 'btcd' binary in PATH.
# Ensure it can find btcd-itest by symlinking it and adding itest/ to PATH.
if [ -f "$ITEST_DIR/btcd-itest" ] && ! command -v btcd &>/dev/null; then
    ln -sf "$ITEST_DIR/btcd-itest" "$ITEST_DIR/btcd"
    export PATH="$ITEST_DIR:$PATH"
fi

echo "$EXEC" "${TEST_FLAGS[@]}" -test.v -test.run=TestCustomChannels -test.timeout=60m -splittranches="$NUM_TRANCHES" -runtranche="$TRANCHE"

# Exit code 255 causes the parallel jobs to abort, so if one part fails the
# other is aborted too.
cd "$WORKDIR" || exit 255

if [ $VERBOSE -eq 1 ]; then
    $EXEC "${TEST_FLAGS[@]}" -test.v -test.run=TestCustomChannels -test.timeout=60m -splittranches="$NUM_TRANCHES" -runtranche="$TRANCHE" 2>&1 | tee "$LOG_DIR/output.log"
    # Capture the exit code of the test run (first command in pipe).
    exit_code=${PIPESTATUS[0]}
else
    $EXEC "${TEST_FLAGS[@]}" -test.v -test.run=TestCustomChannels -test.timeout=60m -splittranches="$NUM_TRANCHES" -runtranche="$TRANCHE" > "$LOG_DIR/output.log" 2>&1
    # Capture the exit code of the test run.
    exit_code=$?
fi
if [ $exit_code -ne 0 ]; then
    echo "CC tranche $TRANCHE failed with exit code $exit_code"
    tail -n 100 "$LOG_DIR/output.log"
    exit 255
else
    echo "CC tranche $TRANCHE completed successfully"
fi
