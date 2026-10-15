# Taproot Assets v0.8.6 security refresh

In this release, we update the existing v0.8.6 distribution with four fixes for asset-channel and proof validation.

- Asset invoice HTLCs credit only the value of the assets in that HTLC. Canceled shards no longer contribute to settlement, and a rounding allowance cannot fill an asset shortfall.
- Asset invoice credit is bounded by the rate offered in the invoice's matching route hints, even if the payer uses a newer accepted quote with a more favorable rate.
- Standalone asset sale policies reject a Bitcoin HTLC carrying the asset no-op marker. Asset forwards continue to use their incoming asset value.
- Address decoding requires both script and internal public keys. Proof verification also rejects an invalid internal key.

The v0.8.6 tag and release artifacts are refreshed at the same version. Operators should replace previously downloaded archives and compare their hashes with the refreshed manifest before deployment.
