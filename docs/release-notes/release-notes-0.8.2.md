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

- [PR#2246](https://github.com/lightninglabs/taproot-assets/pull/2246)
  fixes a bug in which a cooperative close never finalized for a channel
  whose funding output merged several asset UTXOs. Only the first input
  proof was fetched when the funding output was imported, leaving the
  virtual transaction impossible to reconstruct, so the channel stayed
  in `waiting_close` and the peer's assets were not swept. Every input
  proof is now fetched and verified.

# New Features

## Functional Enhancements

## RPC Additions

## tapcli Additions

# Improvements

## Functional Updates

## RPC Updates

## tapcli Updates

## Config Changes

## Code Health

## Breaking Changes

## Performance Improvements

- [PR#2183](https://github.com/lightninglabs/taproot-assets/pull/2183)
  dramatically improves the performance of MS-SMT proof verification.

- [PR#2184](https://github.com/lightninglabs/taproot-assets/pull/2184)
  dramatically improves the performance of universe federation proof push.

- [PR#2194](https://github.com/lightninglabs/taproot-assets/pull/2194)
  significantly improves concurrent universe proof ingest on Postgres.

- [PR#2188](https://github.com/lightninglabs/taproot-assets/pull/2188)
  dramatically improves the performance of batched MS-SMT insertions.

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

## Tooling and Documentation

# Contributors (Alphabetical Order)
