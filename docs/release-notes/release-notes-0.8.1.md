# Release Notes
- [New Features](#new-features)
    - [RPC Additions](#rpc-additions)
- [Improvements](#improvements)
    - [Bug Fixes](#bug-fixes)
    - [Functional Updates](#functional-updates)

# New Features

## RPC Additions

- [ListInvoices and ListPayments](https://github.com/lightninglabs/taproot-assets/pull/2150):
  PR#2150 adds `ListInvoices` and `ListPayments` RPCs, mirroring lnd's
  invoice and payment listing endpoints on the assets side.

- [Invoice and Payment Streaming](https://github.com/lightninglabs/taproot-assets/pull/2195):
  PR#2195 adds `SubscribeInvoices`, `SubscribePayments`, and
  `TrackPayment` RPCs to the `TaprootAssetChannels` service, mirroring
  lnd's corresponding streaming endpoints analogously.

# Improvements

## Bug Fixes

- [PR#2159](https://github.com/lightninglabs/taproot-assets/pull/2159)
  fixes several failure modes in the handling of force-close sweep
  transactions that could leave transfers stuck in a pending state.

- [PR#2180](https://github.com/lightninglabs/taproot-assets/pull/2180)
  fixes a proof cache issue that could cause universe sync to fail for
  groups receiving new issuances.

- [PR#2232](https://github.com/lightninglabs/taproot-assets/pull/2232)
  fixes a bug in which accepting an RFQ quote could shut down the daemon
  if the channel selected as the SCID alias base had not negotiated
  the `option_scid_alias` feature.

## Functional Updates

- [PR#2183](https://github.com/lightninglabs/taproot-assets/pull/2183)
  dramatically improves the performance of MS-SMT proof verification.

- [PR#2188](https://github.com/lightninglabs/taproot-assets/pull/2188)
  dramatically improves the performance of batched MS-SMT insertions.
