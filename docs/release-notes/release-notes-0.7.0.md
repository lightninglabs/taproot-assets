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

- A new [address version 2 was introduced that supports grouped assets and
  custom (sender-defined)
  amounts](https://github.com/lightninglabs/taproot-assets/pull/1587). When
  creating an address, the user can now specify `--address_version v2`. The
  amount is optional for V2 addresses, and if it is not specified by the
  receiver, the sender can choose any amount to send. V2 addresses with custom
  amounts work for both simple assets (non-grouped/asset ID only) and grouped
  assets. In addition, V2 addresses also increase on-chain privacy and therefore
  are ideal as re-usable, long-term static addresses (with on-chain privacy
  guarantees similar to BIP-0352 Silent Payments).
  V2 addresses require the use of a proof courier that supports the
  new `authmailbox+universerpc://` protocol. Any `tapd` that runs with version
  `v0.7.0` or later and uses `universe.public-access=rw` automatically supports
  that new protocol. Users running with the default configuration (and therefore
  the default/standard universe servers) will not need to change anything, as
  the default universe servers will be updated after the release of
  `tapd v0.7.0`.

## RPC Additions

- The `SendAsset` RPC has a new field `addresses_with_amounts` that allows the
  user to specify a custom amount to send to a V2 address that doesn't have an
  amount specified.

## tapcli Additions

- The `tapcli assets send` command now has a new flag `--addr_with_amount` that
  allows users to specify the amount to send to a V2 address that allows custom
  amounts (which is the case when a V2 address is created with an amount of 0).

# Improvements

## Functional Updates

## RPC Updates

## tapcli Updates

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

- ffranr
- George Tsagkarelis
- Olaoluwa Osuntokun
- Oliver Gugger
