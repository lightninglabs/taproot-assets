# Release Notes
- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)
    - [RPC Updates](#rpc-updates)

# Bug Fixes

- [PR#2228](https://github.com/lightninglabs/taproot-assets/pull/2228)
  fixes `VerifyProof` failing the whole RPC for an invalid proof when
  decoding the last proof requires unknown asset metadata; it now
  returns `valid=false` as documented.

- [PR#2246](https://github.com/lightninglabs/taproot-assets/pull/2246)
  fixes a bug in which a cooperative close never finalized for a channel
  whose funding output merged several asset UTXOs. Only the first input
  proof was fetched when the funding output was imported, leaving the
  virtual transaction impossible to reconstruct, so the channel stayed
  in `waiting_close` and the peer's assets were not swept. Every input
  proof is now fetched and verified.

# Improvements

## RPC Updates

* [PR#2226](https://github.com/lightninglabs/taproot-assets/pull/2226)
  lets `CommitVirtualPsbts` select the transition proof version and adds
  BIP-371 tapscript sibling exclusion proofs for version 1 proofs.

