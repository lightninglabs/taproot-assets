# Release Notes
- [Bug Fixes](#bug-fixes)
- [Improvements](#improvements)
    - [Performance Improvements](#performance-improvements)
- [Technical and Architectural Updates](#technical-and-architectural-updates)
    - [Code Health](#code-health)

# Bug Fixes

- Database errors are now [sanitized before being
  returned](https://github.com/lightninglabs/taproot-assets/pull/1630).

- [A potential deadlock in combination with `lnd`'s code hooks was fixed by
  making the message router
  non-blocking](https://github.com/lightninglabs/taproot-assets/pull/1652).

- [A bug in the multi-RFQ send logic was fixed that could previously lead to
  a panic](https://github.com/lightninglabs/taproot-assets/pull/1627).

- [An extra asset unit of tolerance was added to the invoice acceptor to fix
  MPP sharding
  issues](https://github.com/lightninglabs/taproot-assets/pull/1639).

# Improvements

## Performance Improvements

- A new cache for [asset meta information was
  added](https://github.com/lightninglabs/taproot-assets/pull/1650) that greatly
  improves the performance of the universe asset statistics call.

# Technical and Architectural Updates

## Code Health

- The compile time dependency version of `lnd` was bumped to `v0.19.2-beta` in
  [#1644](https://github.com/lightninglabs/taproot-assets/pull/1644).

# Contributors (Alphabetical Order)

- George Tsagkarelis
- Oliver Gugger
