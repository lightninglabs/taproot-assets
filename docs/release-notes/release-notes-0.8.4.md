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
