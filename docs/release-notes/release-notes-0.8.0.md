# Release Notes
- [Breaking Changes](#breaking-changes)
- [New Features](#new-features)
    - [Functional Enhancements](#functional-enhancements)
    - [tapcli Additions](#tapcli-additions)
    - [RPC Additions](#rpc-additions)
- [Improvements](#improvements)
    - [Bug Fixes](#bug-fixes)
    - [Functional Updates](#functional-updates)
    - [RPC Updates](#rpc-updates)
    - [tapcli Updates](#tapcli-updates)
    - [Config Changes](#config-changes)
- [Tooling and Documentation](#tooling-and-documentation)

# Breaking Changes

- **(RFQ Configuration)**:
  [PR#1935](https://github.com/lightninglabs/taproot-assets/pull/1935)
  renames the RFQ configuration option
  `experimental.rfq.skipacceptquotepricecheck` to
  `experimental.rfq.skipquoteacceptverify` for improved clarity.

- **(BurnAsset RPC changes)**:
  via [PR#2062](https://github.com/lightninglabs/taproot-assets/pull/2062),
  `BurnAssetRequest` now uses an `AssetSpecifier` field to identify the
  asset to burn, supporting both asset ID and group key. The old `oneof
  asset` fields (`asset_id`, `asset_id_str`) are deprecated.
  `BurnAssetResponse` adds a repeated `burn_proofs` field; the singular
  `burn_proof` field is deprecated.

# New Features

## Functional Enhancements

- [Orphan UTXO Garbage Collection](https://github.com/lightninglabs/taproot-assets/pull/1832):
  tapd now garbage-collects orphaned UTXOs by sweeping tombstone and
  burn outputs when executing on-chain transactions. Collection runs
  on every burn, transfer, or call to `AnchorVirtualPsbts`. Sweeping
  is enabled by default and can be disabled via the
  `wallet.disable-sweep-orphan-utxos` config flag.

- [Forwarding History Tracking](https://github.com/lightninglabs/taproot-assets/pull/1921):
  Routing nodes can now track and query historical asset forwarding events.
  When a node successfully routes an asset payment, the forward event is logged.
  This provides edge nodes with an audit trail of their swap activity.
  **Note:** For full functionality, it is highly recommended to start LND with
  the `--store-final-htlc-resolutions` flag enabled, which is disabled by default.

- [PortfolioPilot RPC Service](https://github.com/lightninglabs/taproot-assets/pull/1962):
  introduces a new RPC service contract that lets operators delegate RFQ
  orchestration to an external engine, allowing e.g. pricing, hedging,
  and acceptance policy to live in a single external service rather
  than being baked into tapd. An external server is wired up via the
  new `experimental.rfq.portfoliopilotaddress` config option, and a
  reference implementation is provided under `docs/examples`.

- [Wallet Backup/Restore](https://github.com/lightninglabs/taproot-assets/pull/1980):
  Adds wallet backup and restore functionality with three modes: **raw** (v1)
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

- [Auth Mailbox Cleanup](https://github.com/lightninglabs/taproot-assets/pull/2020):
  The auth mailbox server now periodically checks claimed outpoints against the
  chain and deletes messages whose outpoints have been spent. Receivers can also
  explicitly remove their own messages via the new `RemoveMessage` RPC. The
  custodian automatically removes mailbox messages after successfully receiving
  proofs.

- [Limit-Order Constraints](https://github.com/lightninglabs/taproot-assets/pull/2048):
  RFQ buy and sell orders can now carry explicit limit-price bounds
  (`asset_rate_limit`) and minimum fill sizes (`asset_min_amt` /
  `payment_min_amt`). Quotes that violate these constraints are
  rejected. New fields are optional and backward-compatible; constraint
  validation only activates when they are present.

- [Execution Policy](https://github.com/lightninglabs/taproot-assets/pull/2049):
  RFQ buy and sell orders can now specify an execution policy: IOC
  (Immediate-Or-Cancel, the default) allows partial fills above the
  minimum, while FOK (Fill-Or-Kill) requires the full requested amount
  or rejects the quote. New fields are optional and backward-compatible.

- [Fill Quantity Negotiation](https://github.com/lightninglabs/taproot-assets/pull/2050):
  RFQ accept messages now carry an optional fill quantity, allowing
  the responder to signal the maximum amount it is willing to fill.
  The negotiated fill caps HTLC policies so forwarding never exceeds
  the agreed amount.

- [Burns Assets by Group Key](https://github.com/lightninglabs/taproot-assets/pull/2062):
  Assets can now be burned by specifying a group key instead of a specific
  asset ID. When burning by group key, the daemon automatically selects
  and burns units across all issuances in the group, producing multiple
  burn outputs if needed. The `tapcli assets burn` command now accepts a
  `--group_key` flag.

## tapcli Additions

- [tapcli rfq forwardinghistory](https://github.com/lightninglabs/taproot-assets/pull/1921):
  adds `tapcli rfq forwardinghistory` (alias: `f`) to query forwarding event
  history. Supports flags for filtering by timestamp (`--min-timestamp`,
  `--max-timestamp`), peer (`--peer`), asset ID (`--asset-id`), and asset
  group key (`--group-key`). Includes pagination support via `--limit` and
  `--offset` flags.

- [tapcli bakemacaroon](https://github.com/lightninglabs/taproot-assets/pull/1960):
  adds `tapcli bakemacaroon` to bake custom macaroons with offline caveats.

- [tapcli assets backup](https://github.com/lightninglabs/taproot-assets/pull/1980):
  adds `tapcli assets backup export` and `tapcli assets backup import` commands
  exposing the wallet backup RPCs. Export supports `--mode` (`raw`, `compact`,
  `optimistic`) and `--output_file` flags. Import reads a backup blob from
  `--backup_file` and restores assets.

- [tapcli assets fetch](https://github.com/lightninglabs/taproot-assets/pull/2014):
  adds `tapcli assets fetch` command for fetching assets by `--asset_id` or
  `--group_key`, with optional filter flags.

## RPC Additions

- [Forwarding History](https://github.com/lightninglabs/taproot-assets/pull/1921): PR#1921 adds a new `rfqrpc.ForwardingHistory` RPC endpoint that allows
  querying historical forwarding events with filtering and pagination
  support. Filters include: timestamp range (min/max), peer public key,
  asset ID, and asset group key.

- [BakeMacaroon](https://github.com/lightninglabs/taproot-assets/pull/1960):
  PR#1960 adds `BakeMacaroon` to mint custom macaroons with scoped permissions.

- [Wallet Backup](https://github.com/lightninglabs/taproot-assets/pull/1980):
  PR#1980 adds `ExportAssetWalletBackup` and `ImportAssetsFromBackup`
  RPCs to the `assetwalletrpc` service. Export accepts a `mode` field
  (`RAW`, `COMPACT`, `OPTIMISTIC`) for selecting the backup format.
  Import returns the count of newly imported assets.

- [FetchAsset](https://github.com/lightninglabs/taproot-assets/pull/2014):
  PR#2014 adds the `FetchAsset` RPC for fetching assets by asset
  ID or group key using an `AssetSpecifier`. Supports filters for
  `include_spent`, `include_leased`, `include_unconfirmed_mints`,
  `with_witness`, and `script_key_type`.

- [RemoveMessage](https://github.com/lightninglabs/taproot-assets/pull/2020):
  PR#2020 adds the `RemoveMessage` RPC to the auth mailbox service.
  Receivers can authenticate with a Schnorr signature to delete their
  own messages by ID.

- [Limit Constraints](https://github.com/lightninglabs/taproot-assets/pull/2048):
  PR#2048 adds `asset_rate_limit` to `AddAssetBuyOrder` and
  `AddAssetSellOrder` requests. Adds `asset_min_amt` to buy orders and
  `payment_min_amt` to sell orders. Adds `asset_rate_limit` and min fill
  fields to `PortfolioPilot.ResolveRequest` for constraint forwarding.
  Adds `RATE_BOUND_MISS` and `MIN_FILL_NOT_MET` to `QuoteRespStatus`.

- [Execution Policy](https://github.com/lightninglabs/taproot-assets/pull/2049):
  PR#2049 adds `execution_policy` enum (`EXECUTION_POLICY_IOC`,
  `EXECUTION_POLICY_FOK`) to `AddAssetBuyOrder` and `AddAssetSellOrder`
  requests, and to `PortfolioPilot.ResolveRequest` for constraint
  forwarding. Adds `FOK_NOT_VIABLE` to `QuoteRespStatus`.

# Improvements

## Bug Fixes

- [PR#1898](https://github.com/lightninglabs/taproot-assets/pull/1898)
  ensures that funding output proofs are now always imported during
  force close handling for both channel initiator and responder.
  Previously, proofs were only imported for the responder, which could
  lead to issues if the initiator failed to properly import funding
  proofs after the funding transaction confirmed.

* [PR#2009](https://github.com/lightninglabs/taproot-assets/pull/2009)
  fixes SCID resolution for asset invoices when the peer-accepted buy
  quote has expired from memory or the node has restarted.

* [PR#2035](https://github.com/lightninglabs/taproot-assets/pull/2035)
  fixes a bug by which which the connection with an authmailbox server
  could be lost after encountering a non-graceful error.

* [PR#2039](https://github.com/lightninglabs/taproot-assets/pull/2039)
  ensures that useful asset information is propagated in payment
  requests.

* [PR#2044](https://github.com/lightninglabs/taproot-assets/pull/2044)
  fixes a bug that prevented asset-level timelocks from being enforced
  at the consensus level.

* [PR#2051](https://github.com/lightninglabs/taproot-assets/pull/2051)
  ensures that sell-side payment flows survive restarts.

* [PR#2100](https://github.com/lightninglabs/taproot-assets/pull/2100)
  fixes inverted sort direction in `AssetRoots`, `AssetLeafKeys`, and
  `QueryEvents` universe RPCs.

* [PR#2115](https://github.com/lightninglabs/taproot-assets/pull/2115)
  fixes a bug by which grouped assets could remain invisible to
  ListGroups after import, remaining visible only in ListAssets.

## Functional Updates

- [PR#1775](https://github.com/lightninglabs/taproot-assets/pull/1775):
  ensures that price oracle connections now verify TLS certificates
  by default, using the OS root CA list. New config options under
  `experimental.rfq.priceoracle*` allow disabling TLS, skipping
  verification, or specifying custom certificates.

- [PR#1863](https://github.com/lightninglabs/taproot-assets/pull/1863)
  ensures taht RFQ buy/sell accepts are now written to the database
  `rfq_policies` table whenever a policy is agreed, giving us an audit
  trail and keeping quotes alive across restarts.

- [PR#1884](https://github.com/lightninglabs/taproot-assets/pull/1884)
  introduces pre-broadcast validation state in the ChainPorter state
  machine. This validates input proofs and provides infrastructure for
  additional pre-broadcast checks.

- [PR#1904](https://github.com/lightninglabs/taproot-assets/pull/1904)
  enforces split root witness validation before broadcasting
  transactions. This check prevents invalid split transactions from
  being broadcast.

- [PR#1905](https://github.com/lightninglabs/taproot-assets/pull/1905):
  improves orphan UTXO sweeping, fixing two issues with fetching orphan
  UTXOs for sweeping during transaction building:
  - Adds filtering to exclude orphan UTXOs with missing signing information
    (KeyFamily=0 and KeyIndex=0). These UTXOs were created in prior versions
    that didn't store this information, causing LND to fail when signing.
  - Adds a limit (`MaxOrphanUTXOs = 20`) to prevent transactions from becoming
    too large when sweeping many orphan UTXOs at once.

- [PR#1978](https://github.com/lightninglabs/taproot-assets/pull/1978)
  also augments price oracle connections with support for macaroon
  authentication. A macaroon path can be specified via the
  `experimental.rfq.priceoraclemacaroonpath` config option.

* [PR#1985](https://github.com/lightninglabs/taproot-assets/pull/1985)
  adds a basic health check for TLS cert expiry which allows for more effective
  autonomous renewals.

- [PR#2070](https://github.com/lightninglabs/taproot-assets/pull/2070)
  ensures that non-critical custodian errors are now surfaced to RPC
  clients subscribed via `SubscribeReceiveEvents`. Errors during proof
  availability checks, proof retrieval, wallet transaction inspection,
  and mailbox message handling now publish `AssetReceiveErrorEvent`
  notifications, allowing clients to monitor and react to failures
  without requiring log parsing.

* [PR#2104](https://github.com/lightninglabs/taproot-assets/pull/2104)
  dramatically improves block header verification performance during
  proof receipt. Header verification RPCs are now deduplicated
  and executed in parallel, replacing the previous sequential per-proof
  approach. Benchmarks show a ~7x speedup for files with many unique
  headers.

## RPC Updates

- [PR#1766](https://github.com/lightninglabs/taproot-assets/pull/1766):
  introduces structured price oracle errors that allow oracles to return
  specific error codes. Also, adds a new error code that oracles can use
  to indicate that an asset is unsupported.

- [PR#1841](https://github.com/lightninglabs/taproot-assets/pull/1841) removes
  the defaultMacaroonWhitelist map and inlines its entries directly into
  the conditional logic within MacaroonWhitelist. This ensures that
  access to previously always-available endpoints is now governed by
  explicit user configuration (read/write/courier), improving permission
  control and aligning with expected access restrictions.

- [PR#1841](https://github.com/lightninglabs/taproot-assets/pull/1841) adds
  default RPC permissions for RPC endpoints universerpc.Universe/Info and
  /authmailboxrpc.Mailbox/MailboxInfo.

- [PR#1995](https://github.com/lightninglabs/taproot-assets/pull/1995)
  adds pagination support (offset, limit, direction) to the `ListAssets` RPC
  endpoint.

- [PR#2100](https://github.com/lightninglabs/taproot-assets/pull/2100)
  adds pagination support (offset, limit, direction) to the `AssetLeaves`
  RPC endpoint, and adds `MaxPageSize` validation to `AssetRoots`.
  Standardizes pagination validation across `AssetRoots`,
  `AssetLeafKeys`, `AssetLeaves`, and `QueryAssetStats` via a shared
  `validatePage` helper, and adds a `has_more` field to all four
  response types. Defaults `limit=0` to `MaxPageSize` instead of
  `RequestPageSize`.

- [PR#2122](https://github.com/lightninglabs/taproot-assets/pull/2122)
  adds a `group_key` field to `TransferInput` and `TransferOutput`.
  Affects `ListTransfers` and the `transfer` field embedded in
  `SendEvent`.

- [PR#2125](https://github.com/lightninglabs/taproot-assets/pull/2125)
  adds an `asset_type` field to `TransferInput` and `TransferOutput`.
  Affects `ListTransfers` and the `transfer` field embedded in
  `SendEvent`, allowing clients to distinguish grouped fungible assets from
  grouped collectible assets.

- [PR#2126](https://github.com/lightninglabs/taproot-assets/pull/2126)
  adds an `asset_type` field to `AssetBurn`. Affects `ListBurns`, allowing
  clients to distinguish grouped fungible burns from grouped collectible
  burns.

## tapcli Updates

- [PR#1995](https://github.com/lightninglabs/taproot-assets/pull/1995)
  adds `--limit`, `--offset`, and `--direction` flags to `tapcli assets list`
  for pagination support. The direction defaults to descending order.

- [PR#2100](https://github.com/lightninglabs/taproot-assets/pull/2100):
  `tapcli universe leaves` now paginates automatically, fetching all
  pages instead of silently truncating at 512 results.

## Config Changes

- [PR#1870](https://github.com/lightninglabs/taproot-assets/pull/1870)
  removes the `proofs-per-universe` configuration option. A new option
  `max-proof-cache-size` sets the proof cache limit in bytes and accepts
  human-readable values such as `64MB`.

- [PR#1905](https://github.com/lightninglabs/taproot-assets/pull/1905)
  enables orphan UTXO sweeping by default. This automatically sweeps
  tombstone and burn outputs when executing on-chain transactions. Set
  `wallet.disable-sweep-orphan-utxos` to disable.

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  adds `experimental.rfq.portfoliopilotaddress` to configure an external
  PortfolioPilot RPC server.

- [PR#2020](https://github.com/lightninglabs/taproot-assets/pull/2020)
  adds `universe.mbox-cleanup-interval` and
  `universe.mbox-cleanup-check-timeout` to configure periodic cleanup of
  auth mailbox messages whose claimed outpoints have been spent on chain.

# Tooling and Documentation

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  adds a basic PortfolioPilot RPC example under `docs/examples`.

- [PR#1980](https://github.com/lightninglabs/taproot-assets/pull/1980)
  adds `docs/backup.md` documenting the binary backup format, TLV schema,
  compact strip/rehydrate mechanism, stale detection flow, and RPC interface.

- [PR#2056](https://github.com/lightninglabs/taproot-assets/pull/2056)
  expands the example portfolio pilot with constraint enforcement,
  configurable fill caps, and live CoinGecko pricing.
