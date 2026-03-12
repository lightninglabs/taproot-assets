# Release Notes

- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)
    - [RPC Updates](#rpc-updates)

# Bug Fixes

* [PR#1981](https://github.com/lightninglabs/taproot-assets/pull/1981)
  fixes a bug where universe leaf keys using the `op` (string-based)
  outpoint field were silently ignored, allowing unauthenticated
  callers to delete universe leaves.

* [PR#1990](https://github.com/lightninglabs/taproot-assets/pull/1990)
  prevents buggy results when comparing quotes encoded using different
  scales.

* [PR#1991](https://github.com/lightninglabs/taproot-assets/pull/1991)
  fixes an issue in which asset invoices could be settled in sats if
  their expiration extended beyond that of the accepted edge node
  quote (or quotes).

* [PR#2008](https://github.com/lightninglabs/taproot-assets/pull/2008)
  fixes a bug where `UniverseFederation.Start()` was called instead
  of `Stop()` during server shutdown.

# Improvements

## RPC Updates

- [PR#2005](https://github.com/lightninglabs/taproot-assets/pull/2005)
  Add a `node_id` field to `QueryAssetRatesRequest` containing the
  local node's 33-byte compressed public key. This allows the price
  oracle to identify which tapd node is querying rates. The field is
  populated by default and can be disabled via
  `experimental.rfq.priceoracledisablenodeid`.

