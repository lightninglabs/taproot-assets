# Release Notes
- [Bug Fixes](#bug-fixes)
- [New Features](#new-features)
    - [Functional Enhancements](#functional-enhancements)
    - [RPC Additions](#rpc-additions)
    - [tapcli Additions](#tapcli-additions)
- [Improvements](#improvements)
    - [Functional Updates](#functional-updates)
    - [RPC Updates](#rpc-updates)
    - [tapcli Updates](#tapcli-updates)
    - [Config Changes](#config-changes)
    - [Breaking Changes](#breaking-changes)
    - [Performance Improvements](#performance-improvements)
    - [Deprecations](#deprecations)
- [Technical and Architectural Updates](#technical-and-architectural-updates)
    - [BIP/bLIP Spec Updates](#bipblip-spec-updates)
    - [Testing](#testing)
    - [Database](#database)
    - [Code Health](#code-health)
    - [Tooling and Documentation](#tooling-and-documentation)

# Bug Fixes

* [PR #1920](https://github.com/lightninglabs/taproot-assets/pull/1920)
  addresses a bug in which Neutrino-backed nodes could fail to import
  transfer proofs for remote-initiated force close transactions if they
  were not online to see them broadcast.

# New Features

## Functional Enhancements

## RPC Additions

## tapcli Additions

# Improvements

## Functional Updates

- [Garbage collection of orphaned UTXOs](https://github.com/lightninglabs/taproot-assets/pull/1832)
  by sweeping tombstones and burn outputs when executing onchain transactions.
  Garbage collection will be executed on every burn, transfer or call to
  `AnchorVirtualPsbts`. A new configuration is available to control the sweeping
  via the flag `wallet.sweep-orphan-utxos`.
- [PR](https://github.com/lightninglabs/taproot-assets/pull/1899) tapd now
  treats HTLC interceptor setup failures as fatal during RFQ subsystem startup.
  If the RFQ subsystem cannot install its interceptor, tapd shuts down instead
  of continuing in a degraded state. This ensures that any running tapd
  instance has a fully functional RFQ pipeline and surfaces configuration or
  lnd-level conflicts immediately.

- [RFQ buy/sell accepts are now written to the database](https://github.com/lightninglabs/taproot-assets/pull/1863)
  `rfq_policies` table whenever a policy is agreed, giving us an audit trail
  and keeping quotes alive across restarts.

- [Improve orphan UTXO sweeping](https://github.com/lightninglabs/taproot-assets/pull/1905):
  Fixed two issues with fetching orphan UTXOs for sweeping during transaction
  building:
  - Added filtering to exclude orphan UTXOs with missing signing information
    (KeyFamily=0 and KeyIndex=0). These UTXOs were created in prior versions
    that didn't store this information, causing LND to fail when signing.
  - Added a limit (`MaxOrphanUTXOs = 20`) to prevent transactions from becoming
    too large when sweeping many orphan UTXOs at once.

## RPC Updates

- [PR#1841](https://github.com/lightninglabs/taproot-assets/pull/1841): Remove
  the defaultMacaroonWhitelist map and inline its entries directly
  into the conditional logic within MacaroonWhitelist. This ensures that
  access to previously always-available endpoints is now governed by
  explicit user configuration (read/write/courier), improving permission
  control and aligning with expected access restrictions.

- [PR#1841](https://github.com/lightninglabs/taproot-assets/pull/1841): Add
  default RPC permissions for RPC endpoints universerpc.Universe/Info and
  /authmailboxrpc.Mailbox/MailboxInfo.

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  `NewAddr` now registers a custodian subscriber and waits for the address
  import result (with a timeout) before returning, surfacing mailbox courier
  import failures instead of racing and returning success early.

## tapcli Updates

## Config Changes

- [PR#1870](https://github.com/lightninglabs/taproot-assets/pull/1870)
  The `proofs-per-universe` configuration option is removed. New option
  `max-proof-cache-size` sets the proof cache limit in bytes and accepts
  human-readable values such as `64MB`.

- [Enable orphan UTXO sweeping by default](https://github.com/lightninglabs/taproot-assets/pull/1905):
  The `wallet.sweep-orphan-utxos` configuration option is now enabled by
  default. This automatically sweeps tombstone and burn outputs when executing
  on-chain transactions. Set to `false` to disable.

## Code Health

- [PR#1897](https://github.com/lightninglabs/taproot-assets/pull/1897)
  Fix witness writeback issue when a split commitment is present.

## Breaking Changes

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  Add an integration test that verifies tapd stays running when V2 address
  creation hits an unreachable mailbox courier with the upfront connection
  check skipped, ensuring mailbox subscription failures do not crash tapd.

## Database

## Code Health

## Tooling and Documentation

# Contributors (Alphabetical Order)
