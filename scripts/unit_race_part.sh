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

# The dedicated package runs alone in tranche 0. The remaining packages are
# distributed round-robin over the other tranches, heavy packages first.
# Order heavy packages by descending race test duration. Update
# periodically if the profile shifts.
DEDICATED_PKG="${PKG_PREFIX}/tapdb"
HEAVY_PKGS=(
  "${PKG_PREFIX}/tapreorg"
  "${PKG_PREFIX}/authmailbox"
  "${PKG_PREFIX}/mssmt"
  "${PKG_PREFIX}/tapgarden"
  "${PKG_PREFIX}/tapcustody"
  "${PKG_PREFIX}/universe/supplycommit"
  "${PKG_PREFIX}/universe"
  "${PKG_PREFIX}/rpcserver"
)

mapfile -t remaining < <(go list -tags="${DEV_TAGS}" \
  -deps "${PKG_PREFIX}/..." | \
  grep -F "${PKG_PREFIX}" | grep -v "/vendor/" | \
  grep -vxF "$(printf '%s\n' "${DEDICATED_PKG}" "${HEAVY_PKGS[@]}")")

shared_pkgs=("${HEAVY_PKGS[@]}" "${remaining[@]}")

selected=()
if (( NUM_TRANCHES == 1 )); then
  selected=("${DEDICATED_PKG}" "${shared_pkgs[@]}")
elif (( TRANCHE == 0 )); then
  selected=("${DEDICATED_PKG}")
else
  for i in "${!shared_pkgs[@]}"; do
    if (( (i % (NUM_TRANCHES - 1)) + 1 == TRANCHE )); then
      selected+=("${shared_pkgs[$i]}")
    fi
  done
fi

if (( ${#selected[@]} == 0 )); then
  echo "No packages assigned to tranche ${TRANCHE} of ${NUM_TRANCHES}" >&2
  exit 0
fi

echo "Running unit race tests for ${#selected[@]} packages:"
printf '  %s\n' "${selected[@]}"

exit_code=0
if ! env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" \
  go test "$@" -race "${selected[@]}"; then
  exit_code=1
fi

if (( exit_code != 0 )); then
  echo "One or more packages failed in tranche ${TRANCHE} of ${NUM_TRANCHES}" >&2
fi

exit ${exit_code}
