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

* [PR#2190](https://github.com/lightninglabs/taproot-assets/pull/2190)
  fixes a bug that could cause minted assets to commit to the wrong
  address.

# New Features

## Functional Enhancements

## RPC Additions

## tapcli Additions

# Improvements

## Functional Updates

- [PR#2202](https://github.com/lightninglabs/taproot-assets/pull/2202)
  adds cursor-based delta sync to the universe federation. Each server
  exposes its insertion-ordered leaf journal via the new `SyncDelta`
  RPC; a peer that remembers the last sequence number it applied can
  fetch exactly the leaves it lacks, instead of enumerating every leaf
  key of every divergent universe to compute a set difference. In the
  fully synced steady state this reduces per-tick sync traffic from
  O(universes + leaves) enumeration to a single round trip carrying
  only the new proofs (measured discovery overhead drops from ~88% of
  transferred bytes at 400 leaves/universe to zero). Convergence is
  still verified by comparing local and remote universe roots after
  each delta; any mismatch falls back to the existing enumeration
  sync, and servers that don't support the new RPC are synced exactly
  as before.

## RPC Updates

## tapcli Updates

## Config Changes

- The new `--universe.no-delta-sync` flag forces the federation syncer
  to always use full enumeration sync, serving as a kill switch for
  the cursor-based delta sync mechanism.

## Code Health

## Breaking Changes

## Performance Improvements

- [PR#2184](https://github.com/lightninglabs/taproot-assets/pull/2184)
  dramatically improves the performance of universe federation proof push.

- [PR#2183](https://github.com/lightninglabs/taproot-assets/pull/2183)
  dramatically improves the performance of MS-SMT proof verification.

- [PR#2188](https://github.com/lightninglabs/taproot-assets/pull/2188)
  dramatically improves the performance of batched MS-SMT insertions.

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

* [PR#2190](https://github.com/lightninglabs/taproot-assets/pull/2190)
  splits out various components of the monolithic tapgarden package
  into their own more focused packages, e.g. tapnode, tapreorg, and
  tapcustody.

## Tooling and Documentation

# Contributors (Alphabetical Order)
