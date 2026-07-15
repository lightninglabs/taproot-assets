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

- [PR#2159](https://github.com/lightninglabs/taproot-assets/pull/2159)
  fixes several failure modes in the handling of force-close sweep
  transactions that could leave transfers stuck in a pending state.

- [PR#2180](https://github.com/lightninglabs/taproot-assets/pull/2180)
  fixes a proof cache issue that could cause universe sync to fail for
  groups receiving new issuances.

# New Features

## Functional Enhancements

## RPC Additions

- [PR#2150](https://github.com/lightninglabs/taproot-assets/pull/2150)
  Add `ListInvoices` and `ListPayments` RPCs to the `TaprootAssetChannels`
  service. Each request embeds the corresponding `lnrpc` list request so
  callers pass the same arguments they would pass to lnd. Responses embed
  the full `lnrpc.Invoice` / `lnrpc.Payment` alongside an `AssetAmount`
  summary (`asset_id`, `amount`, and tweaked `group_key`) decoded from
  the HTLCs' custom records. Results are filtered to records that involve
  a Taproot Asset; lnd's pagination offsets are passed through unchanged.

- [PR#2195](https://github.com/lightninglabs/taproot-assets/pull/2195)
  adds `SubscribeInvoices`, `SubscribePayments`, and `TrackPayment` RPCs to
  the `TaprootAssetChannels` service. The new streaming RPCs wrap the
  corresponding lnd invoice/payment streams, preserve lnd's request semantics
  and index handling, and filter updates down to those involving Taproot
  Assets while returning decoded `AssetAmount` summaries.

## tapcli Additions

# Improvements

## Functional Updates

- [PR#2187](https://github.com/lightninglabs/taproot-assets/pull/2187)
  substantially improves the reliability and performance of universe
  sync.

## RPC Updates

## tapcli Updates

## Config Changes

## Code Health

## Breaking Changes

## Performance Improvements

- [PR#2192](https://github.com/lightninglabs/taproot-assets/pull/2192)
  keeps the universe root node page cache warm across proof inserts.
  Previously, every inserted proof leaf wiped the whole page cache,
  leaving `AssetRoots` pagination permanently cold on a busy server.

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

- [PR#2186](https://github.com/lightninglabs/taproot-assets/pull/2186)
  updates the project dependencies for btcd v2 compatibility.

## Tooling and Documentation
