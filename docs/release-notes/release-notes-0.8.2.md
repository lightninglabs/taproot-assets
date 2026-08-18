# Release Notes
- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)
    - [RPC Updates](#rpc-updates)

# Bug Fixes

- [PR#2228](https://github.com/lightninglabs/taproot-assets/pull/2228)
  fixes `VerifyProof` failing the whole RPC for an invalid proof when
  decoding the last proof requires unknown asset metadata; it now
  returns `valid=false` as documented.

# Improvements

## RPC Updates

* [PR#2226](https://github.com/lightninglabs/taproot-assets/pull/2226)
  lets `CommitVirtualPsbts` select the transition proof version and adds
  BIP-371 tapscript sibling exclusion proofs for version 1 proofs.

