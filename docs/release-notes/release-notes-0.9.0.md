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

# New Features

## Functional Enhancements

## RPC Additions

## tapcli Additions

# Improvements

## Functional Updates

## RPC Updates

* [PR#2094](https://github.com/lightninglabs/taproot-assets/pull/2094)
  The asset listing and balance RPCs (`ListBalances`, `ListAssets`,
  `ListUtxos`) can now show two categories of previously-hidden
  assets via opt-in flags. `--include_channel` surfaces assets
  locked in Lightning channels, including both open and
  pending-close (force-close) channel balances. `--include_pending`
  surfaces unconfirmed outbound transfer balances and pending
  transfer outputs, removing the need to manually filter
  `ListTransfers` for unconfirmed entries. All new fields are
  backward-compatible and empty by default.

## tapcli Updates

* [PR#2094](https://github.com/lightninglabs/taproot-assets/pull/2094)
  Add `--include_channel` and `--include_pending` flags to
  `tapcli assets list`, `tapcli assets balance`, and (channel
  only) `tapcli assets utxos`.

## Config Changes

## Breaking Changes

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

## Tooling and Documentation

# Contributors (Alphabetical Order)
