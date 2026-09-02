# Release Notes
- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)

# Bug Fixes

* [PR#2235](https://github.com/lightninglabs/taproot-assets/pull/2235)
  fixes a bug in which a forwarded HTLC that ends up being resolved on
  chain could shut down the daemon, and prevent it from starting again,
  because `lnd` rejects any resolution the HTLC interceptor sends for
  such an HTLC. It also makes the RFQ order handler act on final HTLC
  events, which `lnd` sends without an event type and which were
  therefore dropped, and makes the quote accounting idempotent for HTLCs
  that `lnd` offers more than once.

* [PR#2239](https://github.com/lightninglabs/taproot-assets/pull/2239)
  fixes a check-then-track race in the RFQ order policies by which
  concurrently intercepted HTLCs could collectively exceed the agreed
  maximum amount of an accepted quote.

* [PR#2267](https://github.com/lightninglabs/taproot-assets/pull/2267)
  rejects a negative `expiry` when adding a Taproot Asset channel
  invoice. A negative expiry previously skipped the default and was
  passed through to lnd, which treated it as unset and applied its own
  86400 second default instead of returning an error. Fixes
  [#2261](https://github.com/lightninglabs/taproot-assets/issues/2261).

# Improvements

* [PR#2091](https://github.com/lightninglabs/taproot-assets/pull/2091)
  bumps the `lnd` dependency to `v0.21.3-beta` and implements the new
  `AuxCloseShape` interface method, which lets `lnd` account for the
  auxiliary asset outputs when estimating the fee of a cooperative
  close transaction.
