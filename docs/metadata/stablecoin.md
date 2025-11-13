# Taproot Assets Stablecoin Metadata Standard

> Version 1

## Summary

This document describes the metadata specification for stablecoins minted on
the [Taproot Assets Protocol](https://docs.lightning.engineering/the-lightning-network/taproot-assets).
When minting assets, issuers can include additional metadata about the asset
which will be stored and synchronized with universes. Specifying the metadata
using this standard allows applications like
[Terminal](https://terminal.lightning.engineering) to pull in rich data and
display them in the UI. The specification outlined below focuses solely on
stablecoin assets that will not have a fixed supply. It is expected that
there will be multiple issuance and burn events using the same Group Key to
ensure fungibility between asset tranches.

## Motivation

In the Taproot Asset Protocol, every asset has a name defined at the time of
mint. It is common in the digital asset industry for assets to also have
additional information, such as a ticker (acronym), long name, logo image, and
description. The asset `metadata` field is the intended place to store this
kind of information. The Taproot Assets Protocol does not prescribe any
structure to the data stored here other than a 1MB size limit. The goal of
this document is to provide a specification that will allow asset issuers and
app developers to coalesce around a single metadata structure to maximize
compatibility throughout the industry.

## Metadata Structure

The metadata should be a JSON encoded string containing the additional
information about the asset.

### Sample

```json
{
  "spec": "stablecoin",
  "version": 1,
  "ticker": "USDT",
  "long_name": "Tether",
  "description": "All USDT tokens are pegged at 1-to-1 with a matching fiat currency and are backed 100% by Tether's Reserves. Information about Tether Tokens in circulation is typically published daily.",
  "logo_image": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCA0OCA0OCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgaWQ9IkZyYW1lIDUyNjAiPgo8cmVjdCB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHJ4PSIyNCIgZmlsbD0iIzI2QTE3QiIvPgo8cGF0aCBpZD0iVmVjdG9yIiBkPSJNMjYuNTcwOSAyNS44MThDMjYuNDI4NiAyNS44MTggMjUuODE2NiAyNS44NzYzIDI0LjAyNzcgMjUuODc2M0MyMi41OTM3IDI1Ljg3NjMgMjEuNzgyOSAyNS44MzM0IDIxLjQyOCAyNS44MThDMTUuOTA1NCAyNS41NzI5IDExLjU3NjkgMjQuNjA0MyAxMS41NzY5IDIzLjQzMzRDMTEuNTc2OSAyMi4yNjI2IDE1LjkwNTQgMjEuMjc5NCAyMS40MjggMjEuMDMzNFYyNC44NTAzSDI2LjU3MDlWMjEuMDM0M0MzMi4wNzg5IDIxLjI3OTQgMzYuNDA3NCAyMi4yNjI2IDM2LjQwNzQgMjMuNDMzNEMzNi40MDc0IDI0LjU4OTcgMzIuMDc4OSAyNS41NzI5IDI2LjU3MDkgMjUuODE4Wk0yNi41NzA5IDIwLjYyOTdWMTcuMTQyOUgzNC4yODUyVjEySDEzLjcxMzdWMTcuMTQyOUgyMS40MjhWMjAuNjI4OUMxNS4xODEyIDIwLjkxODYgMTAuMjg1MiAyMi4xOTA2IDEwLjI4NTIgMjMuNjkzMUwxMC4yODUyIDI1LjE5NjYgMTUuMTgxMiAyNi40Njg2IDIxLjQyOCAyNi43NTgzVjM3LjcxNDNIMjYuNTcwOVYyNi43NTgzQzMyLjgxNzcgMjYuNDY4NiAzNy43MTM3IDI1LjE5NjYgMzcuNzEzNyAyMy42OTMxQzM3LjcxMzcgMjIuMTkwNiAzMi44MTc3IDIwLjkzMzEgMjYuNTcwOSAyMC42Mjg5VjIwLjYyOTdaIiBmaWxsPSJ3aGl0ZSIvPgo8L2c+Cjwvc3ZnPgo="
}
```

### Fields

#### `spec`

| Data Type | Values       | Required |
| --------- | ------------ | -------- |
| enum      | `stablecoin` | True     |

A discriminator field that declares the specification used for the metadata.
Having this field allows for other specifications to exist in the future (ex:
fixed supply, collectible, etc.) without introducing potential conflicts in
the field names. When using the standard described in this document, the
value “stablecoin” should always be used.

#### `version`

| Data Type | Required |
| --------- | -------- |
| `number`  | True     |

Declares the version of the above spec that the content in the metadata
adheres to. The additional fields in each spec may evolve over time. This
field should be used to allow applications to easily determine which fields
are expected to be defined based on the version number.

#### `ticker`

| Data Type | Required |
| --------- | -------- |
| `string`  | False    |

The ticker symbol commonly used on exchanges and financial platforms to
uniquely identify this asset. (ex: BTC, USDT, USDC). If this field is not
provided, the native TAP asset name should be used in its place.

#### `long_name`

| Data Type | Required |
| --------- | -------- |
| `string`  | False    |

A more user-friendly name for the asset. (ex: Bitcoin, Tether, USD Coin). If
this field is not provided, the ticker may be used in its place.

#### `description`

| Data Type | Required |
| --------- | -------- |
| `string`  | False    |

A description of the asset provided by the issuer.

#### `logo_image`

| Data Type                                                                                 | Required |
| ----------------------------------------------------------------------------------------- | -------- |
| [data:image URL](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/data) | False    |

The URL to use for the logo image. The value must be a
[data:image URL](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/data)
which contains the base64 encoded bytes as a string within the content of the
JSON metadata. This ensures the image will persist without reliance on any
third-party hosting. It is recommended to use a square image no larger than
128x128 pixels.

## Minting with Metadata

The simplest way to mint an asset with JSON metadata is to use the
`--meta_file_path` parameter as this eliminates the need to properly escape
the special characters included in the JSON content in the shell or script.

First, create the JSON file containing the fields above with the values
specific to your asset. Then run the `tapcli assets mint` command with the
appropriate arguments.

### Example

```bash
tapcli assets mint --type=normal --name=TEST --supply=100000 --decimal_display=2 --meta_file_path=/path/to/metadata.json --new_grouped_asset
```

### Minting Additional Assets

When minting additional units of the same asset, be sure to include the
metadata each time. If you’d like to update the `long_name`, `description`, or
`logo_image`, you may change those values in subsequent mints. It is
recommended for app developers to use the values from the most recent mint to
display in their apps.

### Decimal Display

When minting assets with the --decimal_display parameter, the value specified
will be merged into the resulting JSON alongside the content you provide. You
should not include this field in your JSON file as it will be overwritten by
the CLI parameter.

If we ran the example command above, when applications decode the metadata it
will look like this:

```json
{
  "spec": "stablecoin",
  "version": 1,
  "ticker": "TEST",
  "long_name": "Test Asset",
  "description": "Test description of the asset",
  "logo_image": "data:image/svg+xml;base64,PHN2Zy...3ZnPgo=",
  "decimal_display": 2
}
```

Check out the
[docs](https://github.com/lightninglabs/taproot-assets/blob/main/docs/rfq-and-decimal-display.md)
to learn more about how the decimal display field should be used.

### Viewing Metadata

After minting an asset, you can see the embedded metadata by running the
following CLI command:

```bash
tapcli assets --asset_id <id>  | jq -r '.data' | xxd -p -r | jq
```
