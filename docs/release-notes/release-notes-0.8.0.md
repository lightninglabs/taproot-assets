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

- [PR#1897](https://github.com/lightninglabs/taproot-assets/pull/1897)
  Fix witness writeback issue when a split commitment is present.
  `UpdateTxWitness` was mutating a pointer into a copied root asset when a
  split commitment was present, causing the updated witness to never propagate
  back into `SplitCommitment.RootAsset`. This left the root witness empty and
  produced invalid split proofs and transactions.

- [PR#1898](https://github.com/lightninglabs/taproot-assets/pull/1898)
  The funding output proofs are now always imported during force close handling
  for both channel initiator and responder. Previously, proofs were only
  imported for the responder, which could lead to issues if the initiator
  failed to properly import funding proofs after the funding transaction
  confirmed. This ensures both parties can properly recognize and spend funding
  outputs regardless of any prior import failures.

- [PR#1920](https://github.com/lightninglabs/taproot-assets/pull/1920)
  addresses a bug in which Neutrino-backed nodes could fail to import
  transfer proofs for remote-initiated force close transactions if they
  were not online to see them broadcast.

- [PR#1941](https://github.com/lightninglabs/taproot-assets/pull/1941)
  `tapgarden` now avoids a full `tapd` shutdown when the `Custodian` encounters
  non-critical errors during its operation. Errors occurring during proof
  availability checks, proof retrieval, or initial wallet transaction
  inspections are now logged instead of being treated as fatal, allowing the
  daemon to remain operational and continue processing other events.

* [PR#1943](https://github.com/lightninglabs/taproot-assets/pull/1943)
  addresses a bug in which passive assets would incorrectly be included in
  channel funding proofs.

* [PR#1990](https://github.com/lightninglabs/taproot-assets/pull/1990)
  prevents buggy results when comparing quotes encoded using different
  scales.

* [PR#1985](https://github.com/lightninglabs/taproot-assets/pull/1985)
  adds a basic health check for TLS cert expiry which allows for more effective
  autonomous renewals.

* [PR#1991](https://github.com/lightninglabs/taproot-assets/pull/1991)
  fixes an issue in which asset invoices could be settled in sats if
  their expiration extended beyond that of the accepted edge node
  quote (or quotes).

* [PR#2044](https://github.com/lightninglabs/taproot-assets/pull/2044)
  fixes a bug in `AssertAnchorTimeLocks` that prevented asset-level
  timelocks from being enforced at the consensus level.

* [PR#2009](https://github.com/lightninglabs/taproot-assets/pull/2009)
  fixes SCID resolution for asset invoices when the peer-accepted buy
  quote has expired from memory or the node has restarted. Peer-accepted
  buy quotes are now persisted to the database and resolved via a 3-tier
  lookup (active map, LRU cache, DB fallback). On startup, persisted
  quotes are restored into the active map so payment flows survive
  restarts.

* [PR#2010](https://github.com/lightninglabs/taproot-assets/pull/2010)
  fixes an issue that prevented asset roots from being deleted on
  universes with existing federation sync log entries.

* [PR#2035](https://github.com/lightninglabs/taproot-assets/pull/2035)
  fixes a bug by which which the connection with an authmailbox server
  could be lost after encountering a non-graceful error.

* [PR#2039](https://github.com/lightninglabs/taproot-assets/pull/2039)
  fixes `DecodeAssetPayReq` so `GenesisInfo` is populated consistently,
  including group-key invoice decodes.

# New Features

## Functional Enhancements

- [Auth Mailbox Cleanup](https://github.com/lightninglabs/taproot-assets/pull/2020):
  The auth mailbox server now periodically checks claimed outpoints against the
  chain and deletes messages whose outpoints have been spent. Receivers can also
  explicitly remove their own messages via the new `RemoveMessage` RPC. The
  custodian automatically removes mailbox messages after successfully receiving
  proofs.

- [Forwarding History Tracking](https://github.com/lightninglabs/taproot-assets/pull/1921):
  Routing nodes can now track and query historical asset forwarding events.
  When a node successfully routes an asset payment, the forward event is logged.
  This provides edge nodes with an audit trail of their swap activity.
  **Note:** For full functionality, it is highly recommended to start LND with
  the `--store-final-htlc-resolutions` flag enabled, which is disabled by default.

- [Limit-Order Constraints](https://github.com/lightninglabs/taproot-assets/pull/2048):
  RFQ buy and sell orders can now carry explicit limit-price bounds
  (`asset_rate_limit`) and minimum fill sizes (`asset_min_amt` /
  `payment_min_amt`). Quotes that violate these constraints are rejected
  with machine-readable reasons (`RATE_BOUND_MISS`, `MIN_FILL_NOT_MET`).
  New fields are optional and backward-compatible; constraint validation
  only activates when they are present.

## Functional Enhancements

- [Wallet Backup/Restore](https://github.com/lightninglabs/taproot-assets/pull/1980):
  Add wallet backup and restore functionality with three modes: **raw** (v1)
  exports complete proof files, **compact** (v2) strips blockchain-derivable
  fields from proofs for significantly smaller backups (fields are reconstructed
  from the blockchain on import), and **optimistic** (v3) omits proofs entirely
  and fetches them from a universe federation server on import, producing the
  smallest possible backup. On import, stale assets whose anchor outpoints have
  already been spent are automatically detected and skipped. Note that backup
  files contain asset key derivation paths (similar to exporting a descriptor)
  and should be stored securely. A full restore still requires access to the
  corresponding LND wallet; the backup only covers the Taproot Assets layer.
  See [docs/backup.md](../backup.md) for the full format specification.

## RPC Additions

- [Wallet Backup RPCs](https://github.com/lightninglabs/taproot-assets/pull/1980):
  Add `ExportAssetWalletBackup` and `ImportAssetsFromBackup` RPCs to the
  `assetwalletrpc` service. Export accepts a `mode` field (`RAW`, `COMPACT`,
  `OPTIMISTIC`) for selecting the backup format. Import returns the count of
  newly imported assets.

- [PR#1960](https://github.com/lightninglabs/taproot-assets/pull/1960)
  Add `BakeMacaroon` to mint custom macaroons with scoped permissions.

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add the PortfolioPilot RPC service for RFQ quote resolution, verification,
  and asset rate queries.

- [PR#2023](https://github.com/lightninglabs/taproot-assets/pull/2023)
  Add `DeleteAssetLeaf` RPC for removing a single leaf from a universe,
  identified by universe ID and leaf key (outpoint + script key). When
  the last leaf is deleted, the entire universe is automatically cleaned
  up.

- [PR#2014](https://github.com/lightninglabs/taproot-assets/pull/2014)
  Add `FetchAsset` RPC for fetching assets by asset ID or group key using an
  `AssetSpecifier`. Supports filters for `include_spent`, `include_leased`,
  `include_unconfirmed_mints`, `with_witness`, and `script_key_type`.

- [PR#2020](https://github.com/lightninglabs/taproot-assets/pull/2020)
  Add `RemoveMessage` RPC to the auth mailbox service. Receivers can
  authenticate with a Schnorr signature to delete their own messages by ID.

- [PR#2048](https://github.com/lightninglabs/taproot-assets/pull/2048):
  Add `asset_rate_limit` to `AddAssetBuyOrder` and `AddAssetSellOrder`
  requests. Add `asset_min_amt` to buy orders and `payment_min_amt`
  to sell orders. Add `asset_rate_limit` and min fill fields to
  `PortfolioPilot.ResolveRequest` for constraint forwarding. Add
  `RATE_BOUND_MISS` and `MIN_FILL_NOT_MET` to `QuoteRespStatus`.

## tapcli Additions

- [Wallet Backup CLI](https://github.com/lightninglabs/taproot-assets/pull/1980):
  Add `tapcli assets backup export` and `tapcli assets backup import` commands
  exposing the wallet backup RPCs. Export supports `--mode` (`raw`, `compact`,
  `optimistic`) and `--output_file` flags. Import reads a backup blob from
  `--backup_file` and restores assets.

- [PR#1960](https://github.com/lightninglabs/taproot-assets/pull/1960)
  Add `tapcli bakemacaroon` to bake custom macaroons with offline caveats.

- [PR#2023](https://github.com/lightninglabs/taproot-assets/pull/2023)
  Add `tapcli universe delete-leaf` to delete a single leaf from a
  universe by asset ID, outpoint, and script key.

- [PR#2014](https://github.com/lightninglabs/taproot-assets/pull/2014)
  Add `tapcli assets fetch` command for fetching assets by `--asset_id` or
  `--group_key`, with optional filter flags.

- [ForwardingHistory RPC](https://github.com/lightninglabs/taproot-assets/pull/1921):
  New RPC endpoint `rfqrpc.ForwardingHistory` allows querying historical
  forwarding events with filtering and pagination support. Filters include:
  timestamp range (min/max), peer public key, asset ID, and asset group key.

## tapcli Additions

- [tapcli rfq forwardinghistory](https://github.com/lightninglabs/taproot-assets/pull/1921):
  New CLI command `tapcli rfq forwardinghistory` (alias: `f`) to query forwarding event
  history. Supports flags for filtering by timestamp (`--min-timestamp`,
  `--max-timestamp`), peer (`--peer`), asset ID (`--asset-id`), and asset
  group key (`--group-key`). Includes pagination support via `--limit` and
  `--offset` flags.

# Improvements

## Functional Updates

- [PR#1884](https://github.com/lightninglabs/taproot-assets/pull/1884)
  Introduce pre-broadcast validation state in the ChainPorter state machine.
  A new `SendStateVerifyPreBroadcast` state performs validation checks on send
  packages before broadcasting transactions. This validates input proofs and
  provides infrastructure for additional pre-broadcast checks.

- [PR#1904](https://github.com/lightninglabs/taproot-assets/pull/1904)
  Enforce split root witness validation before broadcasting transactions.
  Split leaf outputs must now embed a split root that carries a valid witness.
  Split leaves intentionally keep their own `TxWitness` empty and rely on the
  embedded root witness for validation. This check prevents invalid split
  transactions from being broadcast.

- [Garbage collection of orphaned UTXOs](https://github.com/lightninglabs/taproot-assets/pull/1832)
  by sweeping tombstones and burn outputs when executing onchain transactions.
  Garbage collection will be executed on every burn, transfer or call to
  `AnchorVirtualPsbts`. Sweeping is enabled by default and can be disabled via
  the flag `wallet.disable-sweep-orphan-utxos`.
- [PR](https://github.com/lightninglabs/taproot-assets/pull/1899) tapd now
  treats HTLC interceptor setup failures as fatal during RFQ subsystem startup.
  If the RFQ subsystem cannot install its interceptor, tapd shuts down instead
  of continuing in a degraded state. This ensures that any running tapd
  instance has a fully functional RFQ pipeline and surfaces configuration or
  lnd-level conflicts immediately.

- [RFQ buy/sell accepts are now written to the database](https://github.com/lightninglabs/taproot-assets/pull/1863)
  `rfq_policies` table whenever a policy is agreed, giving us an audit trail
  and keeping quotes alive across restarts.

- [Improve orphan UTXO sweeping](https://github.com/lightninglabs/taproot-assets/pull/1905):
  Fixed two issues with fetching orphan UTXOs for sweeping during transaction
  building:
  - Added filtering to exclude orphan UTXOs with missing signing information
    (KeyFamily=0 and KeyIndex=0). These UTXOs were created in prior versions
    that didn't store this information, causing LND to fail when signing.
  - Added a limit (`MaxOrphanUTXOs = 20`) to prevent transactions from becoming
    too large when sweeping many orphan UTXOs at once.

- [PR#1775](https://github.com/lightninglabs/taproot-assets/pull/1775):
  Price oracle connections now verify TLS certificates by
  default, using the OS root CA list. New config options under
  `experimental.rfq.priceoracle*` allow disabling TLS, skipping
  verification, or specifying custom certificates.

- [PR#1978](https://github.com/lightninglabs/taproot-assets/pull/1978)
  also augments price oracle connections with support for macaroon
  authentication. A macaroon path can be specified via the
  `experimental.rfq.priceoraclemacaroonpath` config option.

## RPC Updates

- [PR#2005](https://github.com/lightninglabs/taproot-assets/pull/2005)
  Add a `node_id` field to `QueryAssetRatesRequest` containing the local
  node's 33-byte compressed public key. This allows the price oracle to
  identify which tapd node is querying rates. The field is populated by
  default and can be disabled via
  `experimental.rfq.priceoracledisablenodeid`.

- [PR#1766](https://github.com/lightninglabs/taproot-assets/pull/1766):
  Introduces structured price oracle errors that allow oracles to return
  specific error codes. Also, adds a new error code that oracles can use
  to indicate that an asset is unsupported.

- [PR#1841](https://github.com/lightninglabs/taproot-assets/pull/1841): Remove
  the defaultMacaroonWhitelist map and inline its entries directly
  into the conditional logic within MacaroonWhitelist. This ensures that
  access to previously always-available endpoints is now governed by
  explicit user configuration (read/write/courier), improving permission
  control and aligning with expected access restrictions.

- [PR#1841](https://github.com/lightninglabs/taproot-assets/pull/1841): Add
  default RPC permissions for RPC endpoints universerpc.Universe/Info and
  /authmailboxrpc.Mailbox/MailboxInfo.

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  `NewAddr` now registers a custodian subscriber and waits for the address
  import result (with a timeout) before returning, surfacing mailbox courier
  import failures instead of racing and returning success early.

- [PR#1995](https://github.com/lightninglabs/taproot-assets/pull/1995)
  Add pagination support (offset, limit, direction) to the `ListAssets` RPC
  endpoint.

## tapcli Updates

- [PR#1995](https://github.com/lightninglabs/taproot-assets/pull/1995)
  Add `--limit`, `--offset`, and `--direction` flags to `tapcli assets list`
  for pagination support. The direction defaults to descending order.

## Config Changes

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add `experimental.rfq.portfoliopilotaddress` to configure an external
  PortfolioPilot RPC server.

- [PR#1870](https://github.com/lightninglabs/taproot-assets/pull/1870)
  The `proofs-per-universe` configuration option is removed. New option
  `max-proof-cache-size` sets the proof cache limit in bytes and accepts
  human-readable values such as `64MB`.

- [Enable orphan UTXO sweeping by default](https://github.com/lightninglabs/taproot-assets/pull/1905):
  Orphan UTXO sweeping is now enabled by default. This automatically sweeps
  tombstone and burn outputs when executing on-chain transactions. Set
  `wallet.disable-sweep-orphan-utxos` to disable.

- [PR#2020](https://github.com/lightninglabs/taproot-assets/pull/2020)
  Add `universe.mbox-cleanup-interval` and
  `universe.mbox-cleanup-check-timeout` to configure periodic cleanup of
  auth mailbox messages whose claimed outpoints have been spent on chain.

## Breaking Changes

- [PR#1935](https://github.com/lightninglabs/taproot-assets/pull/1935)
  Renamed the RFQ configuration option `experimental.rfq.skipacceptquotepricecheck`
  to `experimental.rfq.skipquoteacceptverify` for improved clarity.
  Update your configuration files to use the new option name.

- [PR#2054](https://github.com/lightninglabs/taproot-assets/pull/2054)
  ([#1661](https://github.com/lightninglabs/taproot-assets/issues/1661))
  Adds `sat_per_vbyte` as the new optional manual fee field on
  `SendAssetRequest` and deprecates the legacy `fee_rate` field. For backward
  compatibility, `sat_per_vbyte` is preferred when set; otherwise `fee_rate` is
  still accepted with sat/kw semantics during the transition period.

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

- [Wallet Backup Integration Tests](https://github.com/lightninglabs/taproot-assets/pull/1980):
  Add two integration tests for wallet backup covering genesis backup/restore,
  idempotent import, all three backup modes with size comparison, post-restore
  spendability via multi-hop transfer, and stale backup detection. Also includes
  unit tests for TLV encoding roundtrips, checksum verification, and proof
  strip/rehydrate cycles.

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add an integration test that exercises the PortfolioPilot RPC flow.

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  Add an integration test that verifies tapd stays running when V2 address
  creation hits an unreachable mailbox courier with the upfront connection
  check skipped, ensuring mailbox subscription failures do not crash tapd.

- [Forwarding History Integration Test](https://github.com/lightninglabs/taproot-assets/pull/1921):
  New integration test `testForwardingEventHistory` verifies that forwarding events are
  properly logged when routing asset payments.

- [PR#2048](https://github.com/lightninglabs/taproot-assets/pull/2048):
  Add unit, property-based, and integration tests for limit-order
  constraint fields.

## Database

- [forwards table](https://github.com/lightninglabs/taproot-assets/pull/1921):
  New database table `forwards` stores historical forwarding events.

- [PR#2023](https://github.com/lightninglabs/taproot-assets/pull/2023)
  Add `DeleteUniverseLeaf` SQL query for single-leaf deletion from a
  universe.

## Code Health

## Tooling and Documentation

- [Wallet Backup Format Spec](https://github.com/lightninglabs/taproot-assets/pull/1980):
  Add `docs/backup.md` documenting the binary backup format, TLV schema,
  compact strip/rehydrate mechanism, stale detection flow, and RPC interface.

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add a basic PortfolioPilot RPC example under `docs/examples`.

# Contributors (Alphabetical Order)
