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

## Tooling and Documentation

