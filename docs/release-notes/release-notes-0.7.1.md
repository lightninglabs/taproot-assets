# Release Notes

- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)
    - [Functional Updates](#functional-updates)
    - [RPC Updates](#rpc-updates)
- [Technical and Architectural Updates](#technical-and-architectural-updates)
    - [Code Health](#code-health)
    - [Testing](#testing)

# Bug Fixes

* [PR#1920](https://github.com/lightninglabs/taproot-assets/pull/1920)
  addresses a bug in which Neutrino-backed nodes could fail to import
  transfer proofs for remote-initiated force close transactions if they
  were not online to see them broadcast.

- [PR#1941](https://github.com/lightninglabs/taproot-assets/pull/1941)
  `tapgarden` now avoids a full `tapd` shutdown when the `Custodian` encounters
  non-critical errors during its operation. Errors occurring during proof
  availability checks, proof retrieval, or initial wallet transaction
  inspections are now logged instead of being treated as fatal, allowing the
  daemon to remain operational and continue processing other events.

* [PR#1943](https://github.com/lightninglabs/taproot-assets/pull/1943)
  addresses a bug in which passive assets would incorrectly be included in
  channel funding proofs.

# Improvements

## Functional Updates

- [PR#1899](https://github.com/lightninglabs/taproot-assets/pull/1899) tapd now
  treats HTLC interceptor setup failures as fatal during RFQ subsystem startup.
  If the RFQ subsystem cannot install its interceptor, tapd shuts down instead
  of continuing in a degraded state. This ensures that any running tapd
  instance has a fully functional RFQ pipeline and surfaces configuration or
  lnd-level conflicts immediately.

## RPC Updates

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  `NewAddr` now registers a custodian subscriber and waits for the address
  import result (with a timeout) before returning, surfacing mailbox courier
  import failures instead of racing and returning success early.

# Technical and Architectural Updates

## Code Health

- [PR#1897](https://github.com/lightninglabs/taproot-assets/pull/1897)
  Fix witness writeback issue when a split commitment is present.

## Testing

- [PR#1915](https://github.com/lightninglabs/taproot-assets/pull/1915)
  Add an integration test that verifies tapd stays running when V2 address
  creation hits an unreachable mailbox courier with the upfront connection
  check skipped, ensuring mailbox subscription failures do not crash tapd.

