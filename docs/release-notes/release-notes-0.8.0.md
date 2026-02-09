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

# New Features

## Functional Enhancements

- [Forwarding History Tracking](https://github.com/lightninglabs/taproot-assets/pull/1921):
  Routing nodes can now track and query historical asset forwarding events.
  When a node successfully routes an asset payment, the forward event is logged.
  This provides edge nodes with an audit trail of their swap activity.
  **Note:** For full functionality, it is highly recommended to start LND with
  the `--store-final-htlc-resolutions` flag enabled, which is disabled by default.

## RPC Additions

- [PR#1960](https://github.com/lightninglabs/taproot-assets/pull/1960)
  Add `BakeMacaroon` to mint custom macaroons with scoped permissions.

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add the PortfolioPilot RPC service for RFQ quote resolution, verification,
  and asset rate queries.

## tapcli Additions

- [PR#1960](https://github.com/lightninglabs/taproot-assets/pull/1960)
  Add `tapcli bakemacaroon` to bake custom macaroons with offline caveats.

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
  `AnchorVirtualPsbts`. A new configuration is available to control the sweeping
  via the flag `wallet.sweep-orphan-utxos`.
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

## RPC Updates

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

## tapcli Updates

## Config Changes

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add `experimental.rfq.portfoliopilotaddress` to configure an external
  PortfolioPilot RPC server.

- [PR#1870](https://github.com/lightninglabs/taproot-assets/pull/1870)
  The `proofs-per-universe` configuration option is removed. New option
  `max-proof-cache-size` sets the proof cache limit in bytes and accepts
  human-readable values such as `64MB`.

- [Enable orphan UTXO sweeping by default](https://github.com/lightninglabs/taproot-assets/pull/1905):
  The `wallet.sweep-orphan-utxos` configuration option is now enabled by
  default. This automatically sweeps tombstone and burn outputs when executing
  on-chain transactions. Set to `false` to disable.

## Breaking Changes

- [PR#1935](https://github.com/lightninglabs/taproot-assets/pull/1935)
  Renamed the RFQ configuration option `experimental.rfq.skipacceptquotepricecheck` 
  to `experimental.rfq.skipquoteacceptverify` for improved clarity.
  Update your configuration files to use the new option name.

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add an integration test that exercises the PortfolioPilot RPC flow.

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  Add an integration test that verifies tapd stays running when V2 address
  creation hits an unreachable mailbox courier with the upfront connection
  check skipped, ensuring mailbox subscription failures do not crash tapd.

- [Forwarding History Integration Test](https://github.com/lightninglabs/taproot-assets/pull/1921):
  New integration test `testForwardingEventHistory` verifies that forwarding events are
  properly logged when routing asset payments.

## Database

- [forwards table](https://github.com/lightninglabs/taproot-assets/pull/1921):
  New database table `forwards` stores historical forwarding events.

## Code Health

## Tooling and Documentation

- [PR#1962](https://github.com/lightninglabs/taproot-assets/pull/1962)
  Add a basic PortfolioPilot RPC example under `docs/examples`.

# Contributors (Alphabetical Order)
