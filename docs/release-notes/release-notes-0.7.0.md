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

- [Two new configuration values were added to improve privacy when using public
  or untrusted third-party price
  oracles](https://github.com/lightninglabs/taproot-assets/pull/1677):
  `experimental.rfq.sendpricehint` controls whether a price hint is queried
  from the local price oracle and sent to the peer when requesting a price
  quote (opt-in, default `false`). `experimental.rfq.priceoraclesendpeerid`
  controls whether the peer's identity public key is sent to the local price
  oracle when querying asset price rates.

## RPC Additions

- The [price oracle RPC calls now have an intent, optional peer ID and metadata
  field](https://github.com/lightninglabs/taproot-assets/pull/1677) for more
  context to help the oracle return an optimal asset price rate. The intent
  distinguishes between paying an asset invoice vs. creating an asset invoice
  and the three distinct phases of those two processes: Asking for a price hint
  before creating the request, requesting an actual price for a swap and
  validating a price returned from a peer. See `priceoraclerpc.Intent` in the
  [API
  docs](https://lightning.engineering/api-docs/api/taproot-assets/price-oracle/query-asset-rates/#priceoraclerpcintent)
  for more information on the different values and their meaning.
- The `SendPayment`, `AddInvoice` and `DecodeAssetPayReq` RPCs now have a [new
  `price_oracle_metadata` field the user can specify to send additional metadata
  to a price oracle](https://github.com/lightninglabs/taproot-assets/pull/1677)
  when requesting quotes. The field can contain optional user or authentication
  information that helps the price oracle to decide on the optimal price rate to
  return.

## tapcli Additions

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

- [Two new sequence diagrams were
  added](https://github.com/lightninglabs/taproot-assets/pull/1677) to the [RFQ
  section of the RFQ and decimal display
  document](https://github.com/lightninglabs/taproot-assets/blob/main/docs/rfq-and-decimal-display.md#rfq)
  that show the interaction between `tapd` and its price oracle for the two
  different flows.

# Contributors (Alphabetical Order)

- Oliver Gugger
