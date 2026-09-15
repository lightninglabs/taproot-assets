# Release Notes
- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)
- [Performance Improvements](#performance-improvements)

# Bug Fixes

* [PR#2283](https://github.com/lightninglabs/taproot-assets/pull/2283)
  fixes force-close resolution of an asset channel whose resolved
  commitment output holds no assets, as when the whole asset balance
  sits with the remote party. The aux sweeper tried to build sweep
  packets from an empty input set, failed with `no inputs provided`,
  and lnd treated that as a hard error, leaving the channel in
  `pending_force_closing` and re-running the failing resolution on
  every block. The sweeper now returns an empty resolution for such
  outputs, so lnd sweeps them as plain BTC outputs.

* [PR#2294](https://github.com/lightninglabs/taproot-assets/pull/2294)
  fixes a bug in which a grouped receive holding several assets under
  one script key at one outpoint could be imported but never completed.
  Completing the address event looked each output's proof up by script
  key and outpoint alone, so the lookup returned every asset's proof at
  once and the event failed with `ErrMultipleProofs` on every attempt.
  The proof is now looked up by asset as well.

# Improvements

* [PR#2112](https://github.com/lightninglabs/taproot-assets/pull/2112)
  `DecodeAddr`, `DecodeProof`, and `ExportProof` now return
  `codes.InvalidArgument` for request validation errors instead of
  `codes.Unknown`. This enables clients to programmatically distinguish
  bad input from internal errors.

# Performance Improvements

* [PR#2251](https://github.com/lightninglabs/taproot-assets/pull/2251)
  batches the per-asset witness and proof queries issued when loading
  assets from the database. Loading assets previously issued one witness
  query per asset, and reconstructing input commitments issued one proof
  query per asset, which dominated every path that materialises assets
  on nodes holding many assets.

* [PR#2252](https://github.com/lightninglabs/taproot-assets/pull/2252)
  bounds input selection when funding a send. Eligible coins are now
  listed in pages of descending amounts and listing stops as soon as the
  accumulated amount covers the send target, instead of loading every
  eligible coin the node holds.

* [PR#2264](https://github.com/lightninglabs/taproot-assets/pull/2264)
  bounds pinned input coin selection to the requested anchor UTXOs
  instead of materializing all eligible wallet assets.

* [PR#2265](https://github.com/lightninglabs/taproot-assets/pull/2265)
  reduces orphan UTXO scan work by filtering normal funded anchors in a
  single database query instead of materializing assets once per managed
  UTXO.

* [PR#2300](https://github.com/lightninglabs/taproot-assets/pull/2300)
  avoids deep-copying the split commitment proof when the VM validates
  a split asset, cutting the allocations of split validation by roughly
  three quarters.

* [PR#2299](https://github.com/lightninglabs/taproot-assets/pull/2299)
  encodes nested TLV records once. The TLV stream asks each record for
  its size before writing it, and the size functions of nested records
  serialized their value to measure it, so every level of nesting
  doubled the encoding work below it. Encoding a single proof is now
  roughly seven times faster, and encoding a channel commitment blob
  carrying proofs for a dozen outputs roughly nineteen times faster.
