#!/bin/bash

set -e -o pipefail

function run_fuzz() {
  PACKAGES=$1
  RUN_TIME=$2
  NUM_WORKERS=$3
  TIMEOUT=$4
  BASE_WORKDIR=$5

  mkdir -p "$BASE_WORKDIR"
  BASE_WORKDIR=$(cd "$BASE_WORKDIR" && pwd)

  for pkg in $PACKAGES; do
    pushd "$pkg"

    go test -list="Fuzz.*" | grep Fuzz | while read -r line; do
        FUZZ_CACHE_DIR="$BASE_WORKDIR/$pkg"
        mkdir -p "$FUZZ_CACHE_DIR"
        echo "----- Fuzz testing $pkg:$line for $RUN_TIME with $NUM_WORKERS workers -----"
        go test -run='^$' -fuzz="^$line\$" -test.timeout="$TIMEOUT" \
          -fuzztime="$RUN_TIME" -parallel="$NUM_WORKERS" \
          -test.fuzzcachedir="$FUZZ_CACHE_DIR"
    done

    popd
  done
}

# usage prints the usage of the whole script.
function usage() {
  echo "Usage: "
  echo "fuzz.sh run <packages> <run_time> <workers> <timeout> <workdir>"
}

# Extract the sub command and remove it from the list of parameters by shifting
# them to the left.
SUBCOMMAND=$1
shift

# Call the function corresponding to the specified sub command or print the
# usage if the sub command was not found.
case $SUBCOMMAND in
run)
  echo "Running fuzzer"
  run_fuzz "$@"
  ;;
*)
  usage
  exit 1
  ;;
esac
