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

* [PR#2203](https://github.com/lightninglabs/taproot-assets/pull/2203)
  fixes a bug that could leave invalid minting batch state on disk after
  failure. A database migration now enforces that at most one minting
  batch is in a pre-broadcast (pending or frozen) state; on upgrade, if
  a legacy database holds several such batches, all but the most
  recently created one are automatically cancelled. A new
  `--repair.cancel-duplicate-batches` startup flag applies the same
  repair on demand.

* [PR#2228](https://github.com/lightninglabs/taproot-assets/pull/2228)
  fixes `VerifyProof` failing the whole RPC for an invalid proof when
  decoding the last proof requires unknown asset metadata; it now
  returns `valid=false` as documented.

* [PR#2231](https://github.com/lightninglabs/taproot-assets/pull/2231)
  fixes a bug in which ListPayments returned every Lightning payment, aux
  or otherwise. Non-asset payments are now excluded, as are the
  same payments in SubscribePayments and TrackPayment.

* [PR#2232](https://github.com/lightninglabs/taproot-assets/pull/2232)
  fixes a bug in which accepting an RFQ quote could shut down the daemon
  if the channel selected as the SCID alias base had not negotiated
  the `option_scid_alias` feature.

* [PR#2235](https://github.com/lightninglabs/taproot-assets/pull/2235)
  fixes a bug in which a forwarded HTLC that ends up being resolved on
  chain could shut down the daemon, and prevent it from starting again,
  because `lnd` rejects any resolution the HTLC interceptor sends for
  such an HTLC. It also makes the RFQ order handler act on final HTLC
  events, which `lnd` sends without an event type and which were
  therefore dropped, and makes the quote accounting idempotent for HTLCs
  that `lnd` offers more than once.

# New Features

## Functional Enhancements

## RPC Additions

## tapcli Additions

# Improvements

## Functional Updates

## RPC Updates

* [PR#2226](https://github.com/lightninglabs/taproot-assets/pull/2226)
  lets `CommitVirtualPsbts` select the transition proof version and adds
  BIP-371 tapscript sibling exclusion proofs for version 1 proofs.

## tapcli Updates

## Config Changes

## Code Health

* [PR#2245](https://github.com/lightninglabs/taproot-assets/pull/2245)
  bumps `google.golang.org/grpc` from v1.82.1 to v1.83.1 in the main,
  `taprpc`, and basic price oracle example modules, mirroring the bump
  done in `lnd`.

## Breaking Changes

## Performance Improvements

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
