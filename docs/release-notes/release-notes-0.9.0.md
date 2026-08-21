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

* [PR#2228](https://github.com/lightninglabs/taproot-assets/pull/2228)
  fixes `VerifyProof` failing the whole RPC for an invalid proof when
  decoding the last proof requires unknown asset metadata; it now
  returns `valid=false` as documented.

* [PR#2231](https://github.com/lightninglabs/taproot-assets/pull/2231)
  fixes a bug in which ListPayments returned every Lightning payment, aux
  or otherwise. Non-asset payments are now excluded, as are the
  same payments in SubscribePayments and TrackPayment.

* [PR#2232](https://github.com/lightninglabs/taproot-assets/pull/2232)
  fixes a bug in which accepting an RFQ quote could shut down the daemon
  if the channel selected as the SCID alias base had not negotiated
  the `option_scid_alias` feature.

* [PR#2235](https://github.com/lightninglabs/taproot-assets/pull/2235)
  fixes a bug in which a forwarded HTLC that ends up being resolved on
  chain could shut down the daemon, and prevent it from starting again,
  because `lnd` rejects any resolution the HTLC interceptor sends for
  such an HTLC. It also makes the RFQ order handler act on final HTLC
  events, which `lnd` sends without an event type and which were
  therefore dropped, and makes the quote accounting idempotent for HTLCs
  that `lnd` offers more than once.

* [PR#2247](https://github.com/lightninglabs/taproot-assets/pull/2247)
  fixes several latent bugs in asset minting. Note for operators:
  database migration 63 deduplicates the supply-update event log.
  Duplicate rows produced by a now-fixed double-counting bug are
  deleted, and any pending supply-commit transition left empty by that
  cleanup is removed, with its state machine reset to the default
  state. The next supply update for the affected asset group simply
  starts a fresh commitment cycle.

# New Features

## Functional Enhancements

## RPC Additions

## tapcli Additions

# Improvements

## Functional Updates

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

* [PR#2226](https://github.com/lightninglabs/taproot-assets/pull/2226)
  lets `CommitVirtualPsbts` select the transition proof version and adds
  BIP-371 tapscript sibling exclusion proofs for version 1 proofs.

## tapcli Updates

## Config Changes

- The new `--universe.no-delta-sync` flag forces the federation syncer
  to always use full enumeration sync, serving as a kill switch for
  the cursor-based delta sync mechanism.

- The new `--universe.sync-audit-interval` flag controls how long the
  federation syncer will rely on cursor-based delta sync against a
  server before forcing a full enumeration sync as an audit (default:
  24h).

## Code Health

* [PR#2245](https://github.com/lightninglabs/taproot-assets/pull/2245)
  bumps `google.golang.org/grpc` from v1.82.1 to v1.83.1 in the main,
  `taprpc`, and basic price oracle example modules, mirroring the bump
  done in `lnd`.

## Breaking Changes

## Performance Improvements

* [PR#2251](https://github.com/lightninglabs/taproot-assets/pull/2251)
  batches the per-asset witness and proof queries issued when loading
  assets from the database. Loading assets previously issued one witness
  query per asset, and reconstructing input commitments issued one proof
  query per asset, which dominated every path that materialises assets
  on nodes holding many assets
  ([#2249](https://github.com/lightninglabs/taproot-assets/issues/2249)).

* [PR#2252](https://github.com/lightninglabs/taproot-assets/pull/2252)
  bounds input selection when funding a send. Eligible coins are now
  listed in pages of descending amounts and listing stops as soon as the
  accumulated amount covers the send target, instead of loading every
  eligible coin the node holds
  ([#2250](https://github.com/lightninglabs/taproot-assets/issues/2250)).
  Sends that request specific inputs keep listing every eligible coin, as
  the requested inputs are filtered for after the listing. A send that
  cannot be funded is somewhat slower than before, as the listing is
  repeated unbounded before reporting insufficient funds, so that a coin
  the paged listing may have missed can't be mistaken for missing funds.

## Deprecations

# Technical and Architectural Updates

## BIP/bLIP Spec Updates

## Testing

## Database

## Code Health

* [PR#2190](https://github.com/lightninglabs/taproot-assets/pull/2190)
  splits out various components of the monolithic tapgarden package
  into their own more focused packages, e.g. tapnode, tapreorg, and
  tapcustody.

* [PR#2247](https://github.com/lightninglabs/taproot-assets/pull/2247)
  simplifies the internals of the minting state machine.

## Tooling and Documentation

# Contributors (Alphabetical Order)
