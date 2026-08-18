# Release Notes
- [Bug Fixes](#bug-fixes)

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
