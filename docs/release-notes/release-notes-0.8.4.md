# Release Notes
- [Improvements](#improvements)

# Improvements

* [PR#2112](https://github.com/lightninglabs/taproot-assets/pull/2112)
  `DecodeAddr`, `DecodeProof`, and `ExportProof` now return
  `codes.InvalidArgument` for request validation errors instead of
  `codes.Unknown`. This enables clients to programmatically distinguish
  bad input from internal errors.
