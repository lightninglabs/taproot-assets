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

* [PR#2153](https://github.com/lightninglabs/taproot-assets/pull/2153)
  closes several remaining classes of inconsistent-state bugs in the
  minting flow around persistence atomicity, restart idempotence, and
  the pre-broadcast batch singleton.

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

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

* [PR#2153](https://github.com/lightninglabs/taproot-assets/pull/2153)
  decomposes the `tapgarden` package, moving node-side interfaces and
  proof-verifier helpers into a new `tapnode` package, the receive path
  into `tapcustody`, the re-org watcher into `tapreorg`, and routing
  supply-commit participation and universe publication through new
  `GenesisTxAugmenter` and `MintProofPublisher` interfaces so the two
  concerns evolve independently of the minting state machine.

## Tooling and Documentation

# Contributors (Alphabetical Order)
