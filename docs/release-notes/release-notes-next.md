# Next release

## Breaking Changes

* Provide a btcd v2 compatibility branch for the fixed v0.8.6 code. Exported
  Bitcoin Go types move to the v2 packages, and source builds require Go 1.26.
  The released RFQ, address, proof, and TLV fixes are retained.
  [PR #2366](https://github.com/lightninglabs/taproot-assets/pull/2366)
