# Release Notes
- [Bug Fixes](#bug-fixes)

# Bug Fixes

* [PR#2317](https://github.com/lightninglabs/taproot-assets/pull/2317)
  updates RFQ quote accounting to track settled amounts separately from
  pending HTLC reservations and restore settled usage from forwarding records
  on startup. Failed HTLCs continue to release their reservations.
