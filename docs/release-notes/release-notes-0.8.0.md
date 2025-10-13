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

- The `BurnAsset` RPC now supports a 
  [new `AssetSpecifier` field](https://github.com/lightninglabs/taproot-assets/pull/1812)
  that allows the user to  specify the asset to burn by ID or GroupKey.
  The `asset` field is now deprecated.

## tapcli Additions

# Improvements

## Functional Updates

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

## tapcli Updates

- The `tapcli assets burn` command now has a
  [new `--group_key` flag](https://github.com/lightninglabs/taproot-assets/pull/1812)
  that allows users to burn assets by group key.

## Code Health

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
