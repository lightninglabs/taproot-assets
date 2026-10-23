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

- [Asset hold invoices now preserve the requested final CLTV
  delta](https://github.com/lightninglabs/taproot-assets/pull/2360) instead of
  always using LND's default. A zero value still uses the configured default,
  and LND rejects values outside its supported range.

- [Importing an asset wallet
  backup](https://github.com/lightninglabs/taproot-assets/pull/2277) into a
  node whose database was wiped but whose proofs directory survived no longer
  skips every asset as already present. The existence check now consults the
  wallet database only. Backups also record the script key type, so assets
  received on V2 addresses (unique Pedersen script keys) stay visible and
  spendable after a restore instead of being filed as external script path
  keys.

- [Backup entries of grouped assets now record the asset
  group](https://github.com/lightninglabs/taproot-assets/pull/2298) (the
  group anchor's genesis and the group key parameters), and the import makes
  the recorded groups known to the wallet before verifying any proof. Assets
  minted into an existing group carry no group key reveal in their proofs, so
  a restore onto a fresh node previously skipped every such asset with `group
  key not known` while the import still reported success.

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

* [PR#2247](https://github.com/lightninglabs/taproot-assets/pull/2247)
  fixes several latent bugs in asset minting. Note for operators:
  database migration 65 deduplicates the supply-update event log.
  Duplicate rows produced by a now-fixed double-counting bug are
  deleted, and any pending supply-commit transition left empty by that
  cleanup is removed, with its state machine reset to the default
  state. The next supply update for the affected asset group simply
  starts a fresh commitment cycle.

* [PR#2259](https://github.com/lightninglabs/taproot-assets/pull/2259)
  makes supply-commit mint event emission atomic with mint
  confirmation: on a failed augmenter call the batch stays in
  Broadcast and the confirmation is retried, in place and across
  restarts, instead of completing the mint while still owing the
  supply-commit event. A failed delegation-key lookup is likewise an
  error rather than a silent drop of the asset from emission. The
  `event_key` dedup index (migration 64) keeps retries idempotent.
  Note for operators: database migration 66 enforces that a minting
  batch has at most one supply pre-commitment output.

* [PR#2259](https://github.com/lightninglabs/taproot-assets/pull/2259)
  closes several deadlock and race hazards in the minting pipeline: a
  batch cancellation request arriving after the batch's worker has
  already finished no longer hangs the planter until shutdown; a mint
  request arriving while an earlier batch is still in a pre-broadcast
  state -- resumed at startup, or left orphaned on disk -- is refused
  with a clear error before any wallet inputs are leased, instead of
  tripping the batch singleton index with a raw SQL error; wallet
  inputs leased while funding a batch are released again when a later
  funding step fails; and the confirmation path no longer mutates the
  in-memory batch ahead of the corresponding database writes, so a
  concurrent batch snapshot can never observe state that disk does
  not yet hold.

* [PR#2255](https://github.com/lightninglabs/taproot-assets/pull/2255)
  fixes a bug in which registering a proof leaf the universe already
  held was still logged as a new proof, so `num_total_proofs` in the
  universe stats counted insert attempts rather than proofs held, and
  the `universe_events` table grew with sync traffic rather than with
  universe size.

  Database migration 67 redefines the `universe_stats` view to derive
  the proof count from the universe leaves actually held instead of
  from the event log, so a database that already accumulated duplicate
  events reports the correct figure from the upgrade onwards. No event
  rows are deleted, as the per-day statistics still read them. Note
  that the count can now decrease when a proof leaf is deleted, which
  it previously did not.

  This also changes the meaning of `new_proof_events` in `QueryEvents`,
  which is fed by the event rows: it now counts leaves newly acquired
  per day rather than registration attempts per day, so on a
  long-running node the series steps down. The per-day `sync_events`
  series is unchanged and still reflects sync traffic volume.

* [PR#2323](https://github.com/lightninglabs/taproot-assets/pull/2323)
  fixes a bug in which a batch minting the anchor of a version 1 asset
  group, such as one with an external group key, never finished if the
  daemon restarted after the batch was committed but before it
  confirmed. The group key read back from disk lacked its version and
  custom tapscript root, so building the anchor's minting proof failed
  with `group key reveal doesn't match group key` on every retry.

* [PR#2334](https://github.com/lightninglabs/taproot-assets/pull/2334)
  makes the auth mailbox answer a resent message with its original ID even
  after the receiver has removed it. Removing a message deleted its row but
  kept the claim on its outpoint, so a sender retrying after delivery was
  refused with `tx merkle proof already exists`. As the proof courier resends
  its send fragment before every proof upload, such a sender retried forever.
  Removing a message now only discards its payload. Database migration 73
  drops the outpoint claims already left without a message, so senders stuck
  this way succeed on their next retry. Senders now send the fragment once,
  after uploading all the proofs it announces, and receivers also remove a
  message for a transfer they already completed instead of leaving it on the
  server. No operator action is required.

* [PR#2327](https://github.com/lightninglabs/taproot-assets/pull/2327)
  fixes the check of an asset's relative lock time against an input
  whose proof carries no block height. Measured from the resulting zero
  height, a block-based relative lock was satisfied at any height. The
  input's height now comes from the local asset store when its proof
  carries none, and a relative lock on an input of unknown height is
  rejected.

* [PR#2329](https://github.com/lightninglabs/taproot-assets/pull/2329)
  fixes asset channel force-close sweeps that combine pre-signed
  second-level HTLC claims with direct asset sweeps, or that claim
  several HTLCs via pre-signed transactions without a change output.
  The aux sweeper assumed a fixed layout for the sweep transaction lnd
  builds, so the asset proofs it produced failed verification, the
  sweep was never broadcast, and lnd retried it on every block, which
  could let an HTLC claim miss its deadline. Output positions are now
  derived from the final sweep transaction. Fixes
  [#2205](https://github.com/lightninglabs/taproot-assets/issues/2205).

* [PR#2362](https://github.com/lightninglabs/taproot-assets/pull/2362)
  makes asset hold invoices created with pre-existing RFQ route hints
  carry those hints.

- [Universe servers no longer reject supply commitments that carry
  burns](https://github.com/lightninglabs/taproot-assets/pull/2331). A
  burn leaf's proof is a bare state transition, with no provenance for the
  input it consumes, and was verified as if it were self-contained, so
  every such commitment failed with `missing asset input(s)` and the group
  stopped publishing supply commitments. The verifier now checks the burn
  against its input's provenance: a universe server takes it from its own
  universe, and a node syncing supply commitments from the servers it pulls
  from. The issuer publishes that provenance to each server before pushing
  the commitment. A server accepts a commitment burning an output whose
  provenance it doesn't already hold only if it allows proof inserts, via
  `--universe.sync-all-assets` or `tapcli universe federation config`.

# New Features

## Functional Enhancements

* [PR#2266](https://github.com/lightninglabs/taproot-assets/pull/2266)
  adds the 'watcher': a daemon-wide service that records each
  act of staking local state on a chain outcome as a durable
  "anchoring", senses the chain into per-anchoring evidence, derives
  phases from that evidence, and converges the owning subsystem
  through handlers that run atomically with the registry advance.

* [PR#2287](https://github.com/lightninglabs/taproot-assets/pull/2287)
  moves the transfer, receive, minting, auxiliary-sweep, and
  supply-commit paths onto the watcher: each registers its
  chain-dependent state as an anchoring and converges it from the
  phases the watcher delivers.
  When a shallow re-org removes a transaction, the watcher withdraws
  its confirmation state and refreshes the stored chain and proof
  context when it reconfirms. If a competing transaction reaches the
  configured re-org-safe depth, the watcher abandons the original
  anchoring and compensates the local state tied to the losing
  transaction.

  A received proof is imported and registered with the watcher in one
  transaction, so the receiver never holds an asset the watcher does
  not: a registration that fails rolls the import back with it. The
  receive's triggers are derived from the anchor transaction's own
  inputs, so a verified proof file cannot be refused, and a file that
  cannot be watched at all is rejected rather than imported.

  Irreversible effects now wait until the winning transaction reaches
  `--reorgsafedepth`. These include mint universe publication, mint
  and burn supply-update events, and supply-commit finalization and
  publication. The default is six confirmations, or 120 on testnet
  unless overridden. Operators should therefore expect new issuance
  and supply updates to become externally visible only after that
  threshold; lowering it reduces the corresponding re-org protection.

- [`tapd` now keeps an encrypted asset wallet backup
  file](https://github.com/lightninglabs/taproot-assets/pull/2277)
  (`assets.backup`, see [backup-file.md](../backup-file.md)) on disk that is updated
  whenever the wallet state changes, in the same spirit as lnd's
  `channel.backup`. The file holds a compact backup of every confirmed,
  unspent asset and is encrypted with a key derived from the connected lnd
  wallet. `ImportAssetsFromBackup` accepts the encrypted file directly, so a
  fresh `tapd` connected to an lnd restored from the same seed can recover
  its assets with `tapcli assets backup import`.

## RPC Additions

* [PR#2266](https://github.com/lightninglabs/taproot-assets/pull/2266)
  adds a `ListAnchorings` RPC (with REST binding) exposing the
  anchoring watcher's registry: each anchoring's site, sensed and
  delivered phase (stable names that round-trip through the phase
  filter, with evidence renderings in companion detail fields),
  burial threshold, current witness, delivery bookkeeping including
  the last delivery error and terminal timestamp, filterable by
  site, phase and stuckness, and paged (100 anchorings per page by
  default, 1000 at most). A new Prometheus collector exports live
  anchorings by site and phase, plus stuck and lagging deliveries
  counted over live and terminal anchorings alike.

* The `Anchoring` message of `ListAnchorings` gains a `stuck_reason`
  field carrying the last delivery error once the anchoring is
  flagged stuck, so an operator can see why delivery keeps failing
  without reading the daemon's log.

## tapcli Additions

# Improvements

## Functional Updates

- [PR#2278](https://github.com/lightninglabs/taproot-assets/pull/2278)
  derives the initial (height zero) commitment of an asset channel from
  the negotiated local and remote channel configs (dust limit, CSV
  delay), which makes it consistent with the commitment that is
  re-derived on an immediate force close. A new aux channel feature bit,
  `negotiated-chan-cfg`, is advertised as optional. When a peer doesn't
  signal it, the previous derivation from zeroed configs is used so that
  channels can still be opened with older versions. The next release
  will make the feature required, at which point peers that don't signal
  it are rejected.

- [PR#2202](https://github.com/lightninglabs/taproot-assets/pull/2202)
  adds cursor-based delta sync to the universe federation. Each server
  exposes its insertion-ordered leaf journal via the new `SyncDelta`
  RPC; a peer that remembers the last sequence number it applied can
  fetch exactly the leaves it lacks, instead of enumerating every leaf
  key of every divergent universe to compute a set difference. In the
  fully synced steady state this reduces per-tick sync traffic from
  O(universes + leaves) enumeration to a single round trip carrying
  only the new proofs (measured enumeration overhead drops from ~88%
  of transferred bytes at 400 leaves/universe to zero, with the delta
  page's own root and inclusion-proof framing taking its place).
  Convergence is still verified by comparing local and remote universe
  roots after each delta; any mismatch falls back to the existing
  enumeration sync, and servers that don't support the new RPC are
  synced exactly as before. A full enumeration sync also runs against
  each server periodically as an audit, bounding any divergence the
  delta path cannot observe, and a server whose journal has been
  rewound or replaced (e.g. restored from a backup) is detected and
  reconciled by resetting the sync cursor.

## RPC Updates

* [PR#2287](https://github.com/lightninglabs/taproot-assets/pull/2287)
  makes `RegisterTransfer` safe to retry. It previously failed with
  "proof already exists for this transfer" when the proof was already
  in the local archive, which left no way to re-drive a call that had
  imported the proof but failed before registering the transfer with
  the re-org watcher. The RPC now imports the proof and registers the
  transfer in one transaction: a failed call leaves nothing behind, and
  a repeated call finds the proof held, imports nothing twice, and
  attaches to the existing registration. A proof file the watcher
  cannot stake is rejected.

## tapcli Updates

## Config Changes

- The new [`--backup.filepath`
  flag](https://github.com/lightninglabs/taproot-assets/pull/2277) sets the
  location of the encrypted asset wallet backup file (default: `assets.backup` in the network data
  directory) and `--backup.disable` turns the file off.

- The new `--universe.no-delta-sync` flag forces the federation syncer
  to always use full enumeration sync, serving as a kill switch for
  the cursor-based delta sync mechanism.

- The new `--universe.sync-audit-interval` flag controls how long the
  federation syncer will rely on cursor-based delta sync against a
  server before forcing a full enumeration sync as an audit (default:
  24h).

- The `--disable-anchoring-watcher` flag is removed along with the
  legacy proof watcher it fell back to: every chain-dependent path now
  runs through the anchoring watcher only. A configuration file that
  still carries the flag is refused at startup as an unknown option;
  delete the line before upgrading.

- [PR#2287](https://github.com/lightninglabs/taproot-assets/pull/2287)
  validates `--reorgsafedepth` at startup. It must be at least
  one and at most 144, the chain notifier's maximum confirmation
  depth, since the depth doubles as every anchoring's confirmation
  threshold. A larger value previously passed startup and then failed
  every registration after its transaction had already broadcast.
  Nodes configured above 144 will refuse to start; lower the value
  before upgrading.

## Code Health

## Breaking Changes

* [PR#2259](https://github.com/lightninglabs/taproot-assets/pull/2259)
  changes the exported Go API of `tapgarden`; RPC and database
  interfaces are unaffected. The `Planter` interface is removed, and
  configuration structs that previously held a `tapgarden.Planter`
  (the `AssetMinter` fields in `tapconfig` and `monitoring`) now hold
  the concrete `*tapgarden.ChainPlanter`. `FundBatch` returns
  `*VerboseBatch` directly instead of the former `FundBatchResp`
  wrapper, and `PendingAssetGroup`'s embedded `asset.GroupKeyRequest`
  and `asset.GroupVirtualTx` are now the named fields `KeyRequest`
  and `VirtualTx`.

* The `--disable-anchoring-watcher` flag is removed. The supply-commit
  state machine loses its finalize state: rows persisted in that state
  by an earlier release load as the broadcast state, whose resume path
  re-derives what it needs from the durable record, so no migration is
  required.

* The legacy proof watcher is deleted from the exported Go API:
  `proof.Watcher` and `proof.UpdateCallback`, `tapreorg.LegacyWatcher`
  with `LegacyConfig` and `NewLegacyWatcher`, the
  `tapconfig.Config.ReOrgWatcher` field, and `tapgarden.MockProofWatcher`
  are gone.

## Performance Improvements

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

* [PR#2177](https://github.com/lightninglabs/taproot-assets/pull/2177)
  adds an integration test that force closes an asset channel right after
  the funding transaction confirms, before any commitment update, and
  asserts the swept assets remain spendable.

## Database

* [PR#2287](https://github.com/lightninglabs/taproot-assets/pull/2287)
  adds database migration 69, an opaque per-site match key and a
  unique partial index on the anchoring registry. This lets subsystems recover
  their anchorings by transaction identity across every phase without
  scanning the registry history. Existing rows retain a null key and
  remain valid; no backfill or operator action is required.

* [PR#2287](https://github.com/lightninglabs/taproot-assets/pull/2287)
  adds database migration 70, an `abandoned` column on
  `asset_transfers` recording that a transfer was superseded because
  a buried foreign transaction claimed its inputs, as opposed to
  losing a race against a rival local form. Only the latter is
  revivable when the winning transfer is itself abandoned. The two
  were previously indistinguishable, so abandoning one transfer could
  revive a permanently dead sibling that shared an input, which was
  then resumed at startup and rebroadcast an anchor that can never
  confirm. Existing rows default to `false`; no backfill or operator
  action is required.

* [PR#2315](https://github.com/lightninglabs/taproot-assets/pull/2315)
  updates the SQLite driver to v1.59.0, embedding SQLite 3.53.4, which
  fixes the WAL-reset data-corruption bug affecting SQLite versions
  through 3.51.2 when concurrent connections write and checkpoint a
  WAL-mode database, and updates the PostgreSQL driver to v5.11.0,
  bringing in its security hardening and correctness fixes. No migration
  or operator action is required.

## Code Health

* [PR#2190](https://github.com/lightninglabs/taproot-assets/pull/2190)
  splits out various components of the monolithic tapgarden package
  into their own more focused packages, e.g. tapnode, tapreorg, and
  tapcustody.

* [PR#2247](https://github.com/lightninglabs/taproot-assets/pull/2247)
  simplifies the internals of the minting state machine.

* [PR#2259](https://github.com/lightninglabs/taproot-assets/pull/2259)
  routes supply-commit participation and universe publication
  through new `GenesisTxAugmenter` and `MintProofPublisher`
  interfaces so the two concerns evolve independently of the minting
  state machine. The group-verifier generators similarly move out of
  `tapgarden` into `tapnode`, alongside the rest of the
  proof-verifier code.

## Tooling and Documentation

# Contributors (Alphabetical Order)

* Vandit Singh
