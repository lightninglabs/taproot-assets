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

- A bug in the [syncer was fixed where IDs were compared
  incorrectly](https://github.com/lightninglabs/taproot-assets/pull/1610).

- [An integration test flake was
  fixed](https://github.com/lightninglabs/taproot-assets/pull/1651).

# New Features

## Functional Enhancements

- A series of PRs added support for creating and verifying grouped asset supply
  commitments:
   - https://github.com/lightninglabs/taproot-assets/pull/1602
   - https://github.com/lightninglabs/taproot-assets/pull/1464
   - https://github.com/lightninglabs/taproot-assets/pull/1589
   - https://github.com/lightninglabs/taproot-assets/pull/1507
   - https://github.com/lightninglabs/taproot-assets/pull/1508
   - https://github.com/lightninglabs/taproot-assets/pull/1638
   - https://github.com/lightninglabs/taproot-assets/pull/1643
   - https://github.com/lightninglabs/taproot-assets/pull/1655
   - https://github.com/lightninglabs/taproot-assets/pull/1554

- Assets burned before `v0.6.0` were not yet added to the table that contains
  all burn events (which can be listed with the `ListBurns` RPC). A [database
  migration](https://github.com/lightninglabs/taproot-assets/pull/1612) was
  added that retroactively inserts all burned assets into that table.

- Sending a payment now supports multi-rfq. This new feature allows for multiple
  quotes to be used in order to carry out a payment. With multiple quotes, we
  can use liquidity that is spread across different channels and also use
  multiple rates. See
  [related PR](https://github.com/lightninglabs/taproot-assets/pull/1613) for
  more info.

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
- [Rename](https://github.com/lightninglabs/taproot-assets/pull/1682) the
  `MintAsset` RPC message field from `universe_commitments` to
  `enable_supply_commitments`.

## tapcli Additions

- [Rename](https://github.com/lightninglabs/taproot-assets/pull/1682) the mint
  asset command flag from `--universe_commitments` to
  `--enable_supply_commitments` for consistency with the updated terminology.

# Improvements

## Functional Updates

## RPC Updates

## tapcli Updates

## Code Health

- A series of PRs was created that refactored the send and funding logic in
  preparation for supporting grouped asset on-chain TAP addresses:
   - https://github.com/lightninglabs/taproot-assets/pull/1502
   - https://github.com/lightninglabs/taproot-assets/pull/1611
   - https://github.com/lightninglabs/taproot-assets/pull/1512
   - https://github.com/lightninglabs/taproot-assets/pull/1614
   - https://github.com/lightninglabs/taproot-assets/pull/1621
   - https://github.com/lightninglabs/taproot-assets/pull/1658

- The compile time dependency version of `lnd` was bumped to `v0.19.2-beta` in
  [#1657](https://github.com/lightninglabs/taproot-assets/pull/1657).

- All [`lndclient` wrapper services were moved to their own `lndservices` sub
  package](https://github.com/lightninglabs/taproot-assets/pull/1668).

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

- Integration tests can [now run in
  parallel](https://github.com/lightninglabs/taproot-assets/pull/1641) which
  saves a lot of cumulative CI minutes in GitHub Actions.

# Contributors (Alphabetical Order)

- Oliver Gugger
