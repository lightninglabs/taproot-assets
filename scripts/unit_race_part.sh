#!/bin/bash
set -euo pipefail

TRANCHE=${1:-}
NUM_TRANCHES=${2:-}

if [[ -z "${TRANCHE}" || -z "${NUM_TRANCHES}" ]]; then
  echo "Usage: $0 <tranche> <num_tranches> [go test flags...]" >&2
  exit 1
fi

if ! [[ "${TRANCHE}" =~ ^[0-9]+$ && "${NUM_TRANCHES}" =~ ^[0-9]+$ ]]; then
  echo "tranche and num_tranches must be non-negative integers" >&2
  exit 1
fi

if (( NUM_TRANCHES <= 0 )); then
  echo "num_tranches must be greater than 0" >&2
  exit 1
fi

if (( TRANCHE < 0 || TRANCHE >= NUM_TRANCHES )); then
  echo "tranche must be in range [0, num_tranches)" >&2
  exit 1
fi

shift 2

PKG_PREFIX=${PKG:-github.com/lightninglabs/taproot-assets}
DEV_TAGS=${DEV_TAGS:-dev monitoring}

mapfile -t all_pkgs < <(go list -tags="${DEV_TAGS}" -deps "${PKG_PREFIX}/..." | \
  grep -F "${PKG_PREFIX}" | grep -v "/vendor/")

selected=()
for i in "${!all_pkgs[@]}"; do
  if (( (i % NUM_TRANCHES) == TRANCHE )); then
    selected+=("${all_pkgs[$i]}")
  fi
done

if (( ${#selected[@]} == 0 )); then
  echo "No packages assigned to tranche ${TRANCHE} of ${NUM_TRANCHES}" >&2
  exit 0
fi

exit_code=0
for pkg in "${selected[@]}"; do
  echo "Running unit race tests for ${pkg}"
  if ! env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" \
    go test "$@" -race "${pkg}"; then
    exit_code=1
  fi
done

if (( exit_code != 0 )); then
  echo "One or more packages failed in tranche ${TRANCHE} of ${NUM_TRANCHES}" >&2
fi

exit ${exit_code}
