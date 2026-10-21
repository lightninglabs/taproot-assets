# Taproot Assets v0.8.7

## Tooling and Documentation

- [Raise the minimum Go version and the build toolchain to 1.27.3](https://github.com/lightninglabs/taproot-assets/pull/2364). Go 1.27.3 carries the fix for CVE-2026-111943, which distrusts a set of
  intermediate certificates in `crypto/x509`. Release binaries are statically
  linked, so they only pick up the new trust decision when rebuilt with a
  patched toolchain.
