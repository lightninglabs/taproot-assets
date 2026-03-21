# Release Notes

- [Bug Fixes](#bug-fixes)
- [New Features](#new-features)
    - [RPC Additions](#rpc-additions)
    - [tapcli Additions](#tapcli-additions)
- [Improvements](#improvements)
    - [RPC Updates](#rpc-updates)
- [Technical and Architectural Updates](#technical-and-architectural-updates)
    - [Database](#database)

# Bug Fixes

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

* [PR#2010](https://github.com/lightninglabs/taproot-assets/pull/2010)
  fixes an issue that prevented asset roots from being deleted on
  universes with existing federation sync log entries.

# New Features

## RPC Additions

- [PR#2023](https://github.com/lightninglabs/taproot-assets/pull/2023)
  Add `DeleteAssetLeaf` RPC for removing a single leaf from a
  universe, identified by universe ID and leaf key (outpoint +
  script key). When the last leaf is deleted, the entire universe
  is automatically cleaned up.

## tapcli Additions

- [PR#2023](https://github.com/lightninglabs/taproot-assets/pull/2023)
  Add `tapcli universe delete-leaf` to delete a single leaf from
  a universe by asset ID, outpoint, and script key.

# Improvements

## RPC Updates

- [PR#2005](https://github.com/lightninglabs/taproot-assets/pull/2005)
  Add a `node_id` field to `QueryAssetRatesRequest` containing the
  local node's 33-byte compressed public key. This allows the price
  oracle to identify which tapd node is querying rates. The field is
  populated by default and can be disabled via
  `experimental.rfq.priceoracledisablenodeid`.

# Technical and Architectural Updates

## Database

- [PR#2023](https://github.com/lightninglabs/taproot-assets/pull/2023)
  Add `DeleteUniverseLeaf` SQL query for single-leaf deletion
  from a universe.

