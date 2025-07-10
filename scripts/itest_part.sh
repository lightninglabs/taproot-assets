#!/bin/bash

# Let's work with absolute paths only, we run in the itest directory itself.
WORKDIR=$(pwd)/itest

TRANCHE=$1
NUM_TRANCHES=$2
SHUFFLE_SEED_PARAM=$3

# Shift the passed parameters by three, giving us all remaining testing flags in
# the $@ special variable.
shift 3

# Windows insists on having the .exe suffix for an executable, we need to add
# that here if necessary.
EXEC="$WORKDIR"/itest.test
BTCD_EXEC="$WORKDIR"/btcd-itest
LOG_DIR="$WORKDIR/regtest/.logs-tranche$TRANCHE"
export GOCOVERDIR="$WORKDIR/regtest/cover"
COVERFILE="$GOCOVERDIR/coverage-tranche$TRANCHE.txt"
mkdir -p "$GOCOVERDIR"
mkdir -p "$LOG_DIR"
echo $EXEC "$@" -test.coverprofile=$COVERFILE -test.gocoverdir=$GOCOVERDIR -logoutput -logdir=$LOG_DIR -btcdexec=$BTCD_EXEC -splittranches=$NUM_TRANCHES -runtranche=$TRANCHE -shuffleseed=$SHUFFLE_SEED_PARAM

# Exit code 255 causes the parallel jobs to abort, so if one part fails the
# other is aborted too.
cd "$WORKDIR" || exit 255
$EXEC "$@" -test.coverprofile=$COVERFILE -test.gocoverdir=$GOCOVERDIR -logoutput -logdir=$LOG_DIR -btcdexec=$BTCD_EXEC -splittranches=$NUM_TRANCHES -runtranche=$TRANCHE -shuffleseed=$SHUFFLE_SEED_PARAM > $LOG_DIR/output.log 2>&1

# Capture the exit code of the test run.
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "Tranche $TRANCHE failed with exit code $exit_code"
    tail -n 100 "$LOG_DIR/output.log"
    exit 255
else
    echo "Tranche $TRANCHE completed successfully"
fi
