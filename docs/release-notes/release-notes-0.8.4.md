# Release Notes
- [Improvements](#improvements)
- [Performance Improvements](#performance-improvements)

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
