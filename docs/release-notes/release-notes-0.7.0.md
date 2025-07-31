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
   - https://github.com/lightninglabs/taproot-assets/pull/1587

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
- The `SubscribeSendEvents` RPC now supports [historical event replay of 
  completed sends with efficient database-level
  filtering](https://github.com/lightninglabs/taproot-assets/pull/1685).
- [Add universe RPC endpoint FetchSupplyLeaves](https://github.com/lightninglabs/taproot-assets/pull/1693)
  that allows users to fetch the supply leaves of a universe supply commitment.
  This is useful for verification.

- A [new field `unconfirmed_transfers` was added to the response of the 
  `ListBalances` RPC
  method](https://github.com/lightninglabs/taproot-assets/pull/1691) to indicate
  that unconfirmed asset-related transactions don't count toward the balance.

- The `SendAsset` RPC has a new field `addresses_with_amounts` that allows the
  user to specify a custom amount to send to a V2 address that doesn't have an
  amount specified.

## tapcli Additions

- [Rename](https://github.com/lightninglabs/taproot-assets/pull/1682) the mint
  asset command flag from `--universe_commitments` to
  `--enable_supply_commitments` for consistency with the updated terminology.

- The [CLI command `tapcli assets removelease` was added to give access to the
  `RemoveUTXOLease` RPC method on the command line as
  well](https://github.com/lightninglabs/taproot-assets/pull/1690).

- The `tapcli assets send` command now has a new flag `--addr_with_amount` that
  allows users to specify the amount to send to a V2 address that allows custom
  amounts (which is the case when a V2 address is created with an amount of 0).

# Improvements

## Functional Updates

- The output of `lncli channelbalance` [now also shows the local and remote
  balances of asset channels grouped by group key (if grouped assets were used
  in a channel)](https://github.com/lightninglabs/taproot-assets/pull/1691).

- When sending a payment or adding an invoice any failed RFQ negotiations will
  now fail immediately, instead of causing a long timeout (30s). This was due
  to the RPC endpoint ignoring the RFQ rejection response. This
  [PR](https://github.com/lightninglabs/taproot-assets/pull/1640) addresses the
  issue.

## RPC Updates

## tapcli Updates

- The default script key type in the `tapcli assets list`,
  `tapcli assets balance` and `tapcli assets utxos` commands was changed from
  the default "all script key types" [to the value
  `bip86`](https://github.com/lightninglabs/taproot-assets/pull/1690) to match
  the default value of the RPC interface.
- [Add universe supply commit subcommand fetchleaves](https://github.com/lightninglabs/taproot-assets/pull/1693)
  that allows users to fetch the supply leaves of a universe supply commitment.
  This is useful for verification.

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

- [Simplify](https://github.com/lightninglabs/taproot-assets/pull/1696)
  `ChainPorter` state machine by removing a goroutine and simplifying
  event emission. Fixes an itest flake.

## Breaking Changes

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

- [The Golang version used was bumped to `v1.23.12` to fix a potential issue
  with the SQL API](https://github.com/lightninglabs/taproot-assets/pull/1713).

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

- ffranr
- George Tsagkarelis
- Olaoluwa Osuntokun
- Oliver Gugger
