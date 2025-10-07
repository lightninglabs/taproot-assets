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

- Fixed two send related bugs that would lead to either a `invalid transfer 
  asset witness` or `unable to fund address send: error funding packet: unable 
  to list eligible coins: unable to query commitments: mismatch of managed utxo
  and constructed tap commitment root` error when sending assets.
  The [PR that fixed the two
  bugs](https://github.com/lightninglabs/taproot-assets/pull/1741) also
  optimized sending to V2 TAP addresses by removing the need for creating
  tombstone outputs on a full-value send (by using interactive transfers for V2
  addresses).

- [Updated](https://github.com/lightninglabs/taproot-assets/pull/1774) 
  `BuyOrderRequest` and `SellOrderRequest` proto docs to mark `peer_pub_key` as
  required. Previously, the field was incorrectly documented as optional.
  This change corrects the documentation to match the current implementation.

- [Invoice tolerance calculations were fixed to properly account for per-HTLC
  conversion errors](https://github.com/lightninglabs/taproot-assets/pull/1673).
  This improves the accuracy of asset payment acceptance by correctly modeling
  rounding errors that accumulate when converting between asset units and
  millisatoshis across multiple HTLCs.

- [Fixed a blocking startup issue where the server would hang during
  initialization](https://github.com/lightninglabs/taproot-assets/pull/1780).
  The `ExtraBudgetForInputs` function was refactored to be callable without
  requiring a fully initialized AuxSweeper, allowing sweep operations to proceed
  during server startup.

- [Ensure that tapd won't start if the latest db migration errors and sets the
  db to a dirty state for sqlite database
  backends](https://github.com/lightninglabs/taproot-assets/pull/1826).
  If the latest migration errors and sets the db to a dirty state, startup of
  tapd will now be prevented for all database backend types. Previously, this
  safeguard did not work correctly for SQLite backends if the most recent
  migration failed. Tapd could then still start even though the database was
  dirty. This issue has been resolved, and the behavior is now consistent across
  all database backend types.

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
   - https://github.com/lightninglabs/taproot-assets/pull/1716
   - https://github.com/lightninglabs/taproot-assets/pull/1675
   - https://github.com/lightninglabs/taproot-assets/pull/1674
   - https://github.com/lightninglabs/taproot-assets/pull/1784
   - https://github.com/lightninglabs/taproot-assets/pull/1777
   - https://github.com/lightninglabs/taproot-assets/pull/1796
   - https://github.com/lightninglabs/taproot-assets/pull/1797
   - https://github.com/lightninglabs/taproot-assets/pull/1823
   - https://github.com/lightninglabs/taproot-assets/pull/1822
   - https://github.com/lightninglabs/taproot-assets/pull/1820

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

- Asset HTLCs that are received or sent do not shift the satoshi balance of the
  channel. This is because now the default behavior is to use
  [Noop HTLCs](https://github.com/lightninglabs/taproot-assets/pull/1567) which
  lock some above-dust sats amount with the HTLC as long as it's in-flight, but
  nullifies it upon settlement. This is currently hidden behind the dev build
  tag and also needs to be toggled on via the `channel.noop-htlcs` configuration
  option.

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
- [Rename](https://github.com/lightninglabs/taproot-assets/pull/1682) the
  `MintAsset` RPC message field from `universe_commitments` to
  `enable_supply_commitments`.
- [Enhanced RFQ accepted quote messages with asset identification fields](https://github.com/lightninglabs/taproot-assets/pull/1805):
  The `PeerAcceptedBuyQuote` and `PeerAcceptedSellQuote` proto messages
  now include asset ID and asset group pub key fields (via the `AssetSpecBytes`
  message), allowing clients to directly associate quotes with their
  corresponding assets without manual tracking.

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

- The `AddrReceives` RPC now supports timestamp filtering with
  [new `StartTimestamp` and `EndTimestamp` fields](https://github.com/lightninglabs/taproot-assets/pull/1794).

- The [FetchSupplyLeaves RPC endpoint](https://github.com/lightninglabs/taproot-assets/pull/1829)  
  is now accessible without authentication when the universe server is  
  configured with public read access. This matches the behavior of the  
  existing FetchSupplyCommit RPC endpoint.

- [PR#1839](https://github.com/lightninglabs/taproot-assets/pull/1839) The
  `FetchSupplyLeaves` and `FetchSupplyCommit` RPC endpoints now
  include a new `block_headers` field. This field is a map from block
  height to a `SupplyLeafBlockHeader` message, which provides the block
  header timestamp (in seconds since the Unix epoch) and the 32-byte
  block header hash. This allows clients to obtain block timing and hash
  information directly from the RPC response without performing separate
  blockchain queries.

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

- CLI JSON output [now](https://github.com/lightninglabs/taproot-assets/pull/1821)
  includes unset and zero-valued proto fields (e.g. transaction output indexes).
  This ensures consistent output shape across all proto messages.

- The `tapcli addrs receives` command now supports 
  [new `--start_timestamp` and `--end_timestamp` flags](https://github.com/lightninglabs/taproot-assets/pull/1794).

- The `fetchsupplycommit` command [now supports](https://github.com/lightninglabs/taproot-assets/pull/1823)
  a `--first` flag to fetch the very first supply commitment; if no flag is
  provided, it defaults to fetching the latest. Only one of `--first`,
  `--outpoint`, or `--spent_outpoint` may be set.

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

- A new configuration is now available which controls the max ratio of fees that
  each anchor transaction pays. This is important because given the nature of
  the small taproot-assets anchors we might want to allow for fees to be greater
  than the anchor amount itself, which is helpful in high fee environment where
  pulling in extra inputs might not be preferred. It is exposed via the flag
  `wallet.psbt-max-fee-ratio` and is introduced by
  [PR #1545](https://github.com/lightninglabs/taproot-assets/pull/1545).

- Enable [burning the full amount of an asset](https://github.com/lightninglabs/taproot-assets/pull/1791)
  when it is the sole one anchored to a Bitcoin UTXO.

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

- [The Golang version used was bumped to `v1.23.12` to fix a potential issue
  with the SQL API](https://github.com/lightninglabs/taproot-assets/pull/1713).

- [The Golang version used was bumped to `v1.24.6` in order to keep up with the
  dependencies (LND).](https://github.com/lightninglabs/taproot-assets/pull/1815)

## Breaking Changes

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

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
