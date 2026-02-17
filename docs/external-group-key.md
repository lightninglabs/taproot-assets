# Initial and subsequent mints using an external group key

This document illustrates how to mint an asset with a group key that
is external to the lnd node/wallet that tapd is connected to, using
[chantools](https://github.com/lightninglabs/chantools) to create
signatures for use on a *regtest* network.

You'll need a basic regtest network running (i.e. with a Bitcoin
backend, and with lnd and tapd nodes connected). In particular, to go
through the full flow, you'll need to be able to both run 'tapcli'
commands and mine blocks with your Bitcoin backend. We'll assume you
have environment variables TAPCLI and BITCOIN configured for your
particular setup; e.g., on a Docker regtest network, these might look
like:

```
TAPCLI="docker exec -it tapd-alice tapcli --network regtest ""$@"
BITCOIN="docker exec -it -u bitcoin bitcoind bitcoin-cli -regtest -rpcuser=lightning -rpcpassword=lightning ""$@"
```

You can then use this convenience shell function to mine blocks:

```
mine() {
    local blocks="${1:-6}"
    $BITCOIN generatetoaddress "$blocks" \
        "$($BITCOIN getnewaddress "" legacy)" > /dev/null
}
```

We'll also use a couple of standard utilities, e.g. 'awk' and 'jq'.

## Step 1: Create example wallet

We'll use a persistent wallet for this example. Create it like so:

```
chantools --regtest createwallet --bip39 --walletdbdir /tmp
```

and use the following 12-word mnemonic, with no seed or wallet
passphrase:

```
dismiss sugar enhance impose unique treat message party list throw blame field
```

Derive an xpub and master root key at the path *m/86'/1'/0'* as follows:

```
chantools --regtest derivekey --walletdb /tmp/wallet.db \
  --path "m/86'/1'/0'" --neuter
```

You should see the following:

```
Path:                           m/86'/1'/0'
Network:                        regtest
Master Fingerprint:             10608bb9
Public key:                     039186e157f8b7a8a56fb5f4c0b679d8a883aa8f84f01420e6606b2b1be2ffdadb
Extended public key (xpub):     tpubDD2EgfmrtDs51w46DHDa87yiwiidEYC3ECXXyFp72ESAt5SV661R19kGAMiQMPm8No438YmW5yeYLKUJYuDByAkJvfxA13n2u79ZeDvryHb
Address:                        bcrt1quqynp6q9lusp48f0lx0sdt8ygaacfmdcqwccd4
Legacy address:                 n1wYfdRFwi5123ELa37eeMX5KkxMSQWTos
Taproot address:                bcrt1pymsfzl8rxxx6uq2a88pgtlatfn4ztwlaaxc9eh3hcnmf5d4ku85sq8ksaj
Private key (WIF):              n/a
Extended private key (xprv):    n/a
```

Save some of this information (xpub, path suffixed with /0/0, master
fingerprint) in environment variables, like so:

```
GROUP_KEY_XPUB="tpubDD2EgfmrtDs51w46DHDa87yiwiidEYC3ECXXyFp72ESAt5SV661R19kGAMiQMPm8No438YmW5yeYLKUJYuDByAkJvfxA13n2u79ZeDvryHb"
GROUP_KEY_PATH="m/86'/1'/0'/0/0"
GROUP_KEY_FINGERPRINT="10608bb9"
```

We'll use this information going forward.

## Step 2: Mint an asset

With a basic regtest network of your choice set up, use the following to
mint an initial asset tranche:

```
$TAPCLI assets mint \
  --type normal \
  --name "asset-tranche1" \
  --supply 500000000 \
  --new_grouped_asset \
  --group_key_xpub "$GROUP_KEY_XPUB" \
  --group_key_derivation_path "$GROUP_KEY_PATH" \
  --group_key_fingerprint "$GROUP_KEY_FINGERPRINT"
```

You should see a JSON response like the following:

```json
{
  "pending_batch": {
    "batch_key": "02beae4dedfbe4d343d097fc3a7a88e48adc90d47325c57d937b0a308cc44ff06d",
    "batch_txid": "",
    "state": "BATCH_STATE_PENDING",
    "assets": [
      {
        "asset_version": "ASSET_VERSION_V0",
        "asset_type": "NORMAL",
        "name": "asset-tranche1",
        "asset_meta": {
          "data": "",
          "type": "META_TYPE_OPAQUE",
          "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd"
        },
        "amount": "500000000",
        "new_grouped_asset": true,
        "group_key": "",
        "group_anchor": "",
        "group_internal_key": {
          "raw_key_bytes": "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
          "key_loc": {
            "key_family": 0,
            "key_index": 0
          }
        },
        "group_tapscript_root": "",
        "script_key": {
          "pub_key": "e2418043baac7932919382edc47fe51596db6bccb5cb6c7d31a921ef9e81ceba",
          "key_desc": {
            "raw_key_bytes": "0347105089b0d12a4edb429ac8afd486fc9fefea2f0a73364ee55af9f1123ea711",
            "key_loc": {
              "key_family": 212,
              "key_index": 0
            }
          },
          "tap_tweak": "",
          "type": "SCRIPT_KEY_BIP86"
        }
      }
    ],
    "created_at": "1771289998",
    "height_hint": 119,
    "batch_psbt": ""
  }
}
```

This represents a pending batch with a single asset. More assets can be
added now, if desired.

## Step 3: Fund the batch

Funding the batch means reserving a BTC on-chain output that will be
used to fund the minting transaction. The very first input used will
also serve as the unique randomness to the asset ID of each asset in the
batch.

Fund the batch and save the result to the `FUND_RESP_1` environment
variable:

```shell
FUND_RESP_1=$($TAPCLI assets mint fund --sat_per_vbyte 10)
```

If you want to take a look at the response, use 'jq' to get a pretty
render of it:

```
echo $FUND_RESP_1 | jq .
```

It should look like this:

```json
{
  "batch": {
    "batch": {
      "batch_key": "02beae4dedfbe4d343d097fc3a7a88e48adc90d47325c57d937b0a308cc44ff06d",
      "batch_txid": "",
      "state": "BATCH_STATE_PENDING",
      "assets": [],
      "created_at": "1771289998",
      "height_hint": 119,
      "batch_psbt": "70736274ff0100890200000001b83cb9105a6eb01e6e551e52dbbe113649c0f7a77a1eab58ef2f5c93d15c3ce901000000000000000002e80300000000000022512000000000000000000000000000000000000000000000000000000000000000007478031c000000002251206fd19ca2786daccbeb7cab937f5107d6dbad6f69c7ba8ff86e637f63bdfeba8d000000000001012b6082031c00000000225120411d85513e1c8c8e357d571c07c83f7ec3e4b061bfc57831942355e5a21b45872206035a2449d4a51cbb3fbccb59f6bb8f0ab863a390d26e7e4a23414ff389209416b21800000000560000800000008000000080010000000100000021165a2449d4a51cbb3fbccb59f6bb8f0ab863a390d26e7e4a23414ff389209416b219000000000056000080000000800000008001000000010000000000220203ef54421ac7b69197a9501b7db4083949bbbffecf1ecc140941ad498d7dcac5a218000000005600008000000080000000800100000002000000010520ef54421ac7b69197a9501b7db4083949bbbffecf1ecc140941ad498d7dcac5a22107ef54421ac7b69197a9501b7db4083949bbbffecf1ecc140941ad498d7dcac5a2190000000000560000800000008000000080010000000200000000"
    },
    "unsealed_assets": [
      {
        "asset": {
          "asset_version": "ASSET_VERSION_V0",
          "asset_type": "NORMAL",
          "name": "asset-tranche1",
          "asset_meta": {
            "data": "",
            "type": "META_TYPE_OPAQUE",
            "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd"
          },
          "amount": "500000000",
          "new_grouped_asset": true,
          "group_key": "",
          "group_anchor": "",
          "group_internal_key": {
            "raw_key_bytes": "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
            "key_loc": {
              "key_family": 0,
              "key_index": 0
            }
          },
          "group_tapscript_root": "",
          "script_key": {
            "pub_key": "e2418043baac7932919382edc47fe51596db6bccb5cb6c7d31a921ef9e81ceba",
            "key_desc": {
              "raw_key_bytes": "0347105089b0d12a4edb429ac8afd486fc9fefea2f0a73364ee55af9f1123ea711",
              "key_loc": {
                "key_family": 212,
                "key_index": 0
              }
            },
            "tap_tweak": "",
            "type": "SCRIPT_KEY_BIP86"
          }
        },
        "group_key_request": {
          "raw_key": null,
          "anchor_genesis": {
            "genesis_point": "e93c5cd1935c2fef58ab1e7aa7f7c0493611bedb521e556e1eb06e5a10b93cb8:1",
            "name": "asset-tranche1",
            "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd",
            "asset_id": "bab2f9995a1c46a9550ac49404ae0f3db7ada3bc42d80cefbd6f6338a6e5e4fc",
            "asset_type": "NORMAL",
            "output_index": 0
          },
          "tapscript_root": "7d7a8748f0f4abdbce183f02dccbf4db607acfbca973cdc7b62b1f12a4a0ed50",
          "new_asset": "0001000258b83cb9105a6eb01e6e551e52dbbe113649c0f7a77a1eab58ef2f5c93d15c3ce9000000010e61737365742d7472616e63686531f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd00000000000401000605fe1dcd65000b690167016500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e020000102102e2418043baac7932919382edc47fe51596db6bccb5cb6c7d31a921ef9e81ceba",
          "external_key": {
            "xpub": "tpubDD2EgfmrtDs51w46DHDa87yiwiidEYC3ECXXyFp72ESAt5SV661R19kGAMiQMPm8No438YmW5yeYLKUJYuDByAkJvfxA13n2u79ZeDvryHb",
            "master_fingerprint": "10608bb9",
            "derivation_path": "m/86'/1'/0'/0/0"
          }
        },
        "group_virtual_tx": {
          "transaction": "02000000010b8bba61193aa9512a86f2b965227801275bf49c511849c6764052d1b3c3940b000000000000000000010065cd1d000000002251209c599bf9f39dcb3e3d9257e2fe18ea3da4cea55a31c1a185f80e49d959acd77200000000",
          "prev_out": {
            "value": "500000000",
            "pk_script": "5120b283955acc482b1a1712b5628a082fc036ab540cb7c6cdea193d96228b0bcc09"
          },
          "genesis_id": "bab2f9995a1c46a9550ac49404ae0f3db7ada3bc42d80cefbd6f6338a6e5e4fc",
          "tweaked_key": "02b283955acc482b1a1712b5628a082fc036ab540cb7c6cdea193d96228b0bcc09"
        },
        "group_virtual_psbt": "cHNidP8BAF4CAAAAAQuLumEZOqlRKobyuWUieAEnW/ScURhJxnZAUtGzw5QLAAAAAAAAAAAAAQBlzR0AAAAAIlEgnFmb+fOdyz49klfi/hjqPaTOpVoxwaGF+A5J2Vms13IAAAAATwEENYfPA4er6h2AAAAALGhINzvEPLXWuCFxp02C9aQjgemKj+QY0XAegOagP/UDkYbhV/i3qKVvtfTAtnnYqIOqj4TwFCDmYGsrG+L/2tsQEGCLuVYAAIABAACAAAAAgE8BBDWHzwMAAAAAAAAAAB236w4+ddCuzh3QIu5DKtnjtqjsYts3J/YVP4iflKNHAx236w4+ddCuzh3QIu5DKtnjtqjsYts3J/YVP4iflKNHEHqaVedWAACAAQAAgAAAAIAAAQErAGXNHQAAAAAiUSCyg5VazEgrGhcStWKKCC/ANqtUDLfGzeoZPZYiiwvMCSIGAwpsUtmN4LGta8sBYVnnx+IsehkTg2G7+AL0o5/CYPFGGHqaVedWAACAAQAAgAAAAIAAAAAAAAAAACIGA6ZVP/Gqi7HckbNeH4Qo+Z5t/Dpm45lFrZwMIv/+xnf/GBBgi7lWAACAAQAAgAAAAIAAAAAAAAAAACEWCmxS2Y3gsa1rywFhWefH4ix6GRODYbv4AvSjn8Jg8UYZAHqaVedWAACAAQAAgAAAAIAAAAAAAAAAACEWplU/8aqLsdyRs14fhCj5nm38OmbjmUWtnAwi//7Gd/8ZABBgi7lWAACAAQAAgAAAAIAAAAAAAAAAAAEXIKZVP/Gqi7HckbNeH4Qo+Z5t/Dpm45lFrZwMIv/+xnf/ARggfXqHSPD0q9vOGD8C3Mv022B6z7ypc83HtisfEqSg7VAAAA=="
      }
    ]
  }
}
```

## Step 4: Sign the group PSBT

The batch funding response contains `group_virtual_psbt`, which is the
Taproot Assets VM transaction that we'll sign to prove ownership of the
group key. Save that to another environment variable, like so:

```
GROUP_VIRTUAL_PSBT_1=$(echo "$FUND_RESP_1" | \
  jq -r '.batch.unsealed_assets[0].group_virtual_psbt')
```

Then sign it using chantools as follows, saving the result to a new
environment variable, `SIGNED_PSBT_1`:

```
SIGN_OUTPUT_1=$(WALLET_PASSWORD=- AEZEED_PASSPHRASE=- \
  chantools --regtest signpsbt --walletdb "/tmp/wallet.db" \
  --psbt "$GROUP_VIRTUAL_PSBT_1" 2>&1)

SIGNED_PSBT_1=$(echo "$SIGN_OUTPUT_1" | \
  awk '/Successfully signed PSBT:/{getline;getline;print;exit}')
```

## Step 5: Seal and finalize the batch

Now use the signed group PSBT to seal the batch:

```
$TAPCLI assets mint seal --signed_group_psbt "$SIGNED_PSBT_1"
$TAPCLI assets mint finalize
```

The result should be:

```json
{
  "batch": {
    "batch_key": "02beae4dedfbe4d343d097fc3a7a88e48adc90d47325c57d937b0a308cc44ff06d",
    "batch_txid": "d4d3c57c7e62b6a8fa35b7c178e366b5b1bda03462c323cdcf05d08a469fcce2",
    "state": "BATCH_STATE_BROADCAST",
    "assets": [
      {
        "asset_version": "ASSET_VERSION_V0",
        "asset_type": "NORMAL",
        "name": "asset-tranche1",
        "asset_meta": {
          "data": "",
          "type": "META_TYPE_OPAQUE",
          "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd"
        },
        "amount": "500000000",
        "new_grouped_asset": false,
        "group_key": "02b283955acc482b1a1712b5628a082fc036ab540cb7c6cdea193d96228b0bcc09",
        "group_anchor": "",
        "group_internal_key": {
          "raw_key_bytes": "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
          "key_loc": {
            "key_family": 0,
            "key_index": 0
          }
        },
        "group_tapscript_root": "7d7a8748f0f4abdbce183f02dccbf4db607acfbca973cdc7b62b1f12a4a0ed50",
        "script_key": {
          "pub_key": "e2418043baac7932919382edc47fe51596db6bccb5cb6c7d31a921ef9e81ceba",
          "key_desc": {
            "raw_key_bytes": "0347105089b0d12a4edb429ac8afd486fc9fefea2f0a73364ee55af9f1123ea711",
            "key_loc": {
              "key_family": 212,
              "key_index": 0
            }
          },
          "tap_tweak": "",
          "type": "SCRIPT_KEY_BIP86"
        }
      }
    ],
    "created_at": "1771289998",
    "height_hint": 119,
    "batch_psbt": "70736274ff0100890200000001b83cb9105a6eb01e6e551e52dbbe113649c0f7a77a1eab58ef2f5c93d15c3ce901000000000000000002e8030000000000002251202e71ef194febe0aef63839b9f3aa3908f18cb0d9483017ecd8899596fefdbc887478031c000000002251206fd19ca2786daccbeb7cab937f5107d6dbad6f69c7ba8ff86e637f63bdfeba8d000000000001012b6082031c00000000225120411d85513e1c8c8e357d571c07c83f7ec3e4b061bfc57831942355e5a21b4587010842014084b692adbd38e0ec093df57f1eb24e52b45973debd78a97ac83062f351c20c5b4c4a9e49f95ee22fcbfa36974fc965b6ad71249a31942b1f4b5d22d4d1b38fb60000220203ef54421ac7b69197a9501b7db4083949bbbffecf1ecc140941ad498d7dcac5a218000000005600008000000080000000800100000002000000010520ef54421ac7b69197a9501b7db4083949bbbffecf1ecc140941ad498d7dcac5a22107ef54421ac7b69197a9501b7db4083949bbbffecf1ecc140941ad498d7dcac5a2190000000000560000800000008000000080010000000200000000"
  }
}
```

## Step 6: Subsequent issuance

First, mine some blocks:

```
mine 6
```

You'll then need to get the *tweaked* group key as follows:

```
ASSET_1=$($TAPCLI assets list | jq -r \
  ".assets[] | select(.asset_genesis.name == \"asset-tranche1\")")

TWEAKED_GROUP_KEY=$(echo "$ASSET_1" | jq -r '.asset_group.tweaked_group_key')
```

Now, issuing another tranche is a matter of repeating the same steps
(mint, fund, sign, seal & finalize) with only a couple of differences.
You'll want to use `--grouped_asset` instead of `--new_grouped_asset`
in the mint command, and also pass the tweaked group key via the
`--group_key` argument.

First, the mint step:

```
$TAPCLI assets mint \
  --type normal \
  --name "asset-tranche2" \
  --supply 100000000  \
  --grouped_asset \
  --group_key "$TWEAKED_GROUP_KEY" \
  --group_key_xpub "$GROUP_KEY_XPUB" \
  --group_key_derivation_path "$GROUP_KEY_PATH" \
  --group_key_fingerprint "$GROUP_KEY_FINGERPRINT"
```

This will give something like the following response:

```json
{
  "pending_batch": {
    "batch_key": "024a93d7b547311cef82fcd6320c034a79e78e6e8308f9969814d0845128138adf",
    "batch_txid": "",
    "state": "BATCH_STATE_PENDING",
    "assets": [
      {
        "asset_version": "ASSET_VERSION_V0",
        "asset_type": "NORMAL",
        "name": "asset-tranche2",
        "asset_meta": {
          "data": "",
          "type": "META_TYPE_OPAQUE",
          "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd"
        },
        "amount": "100000000",
        "new_grouped_asset": false,
        "group_key": "02b283955acc482b1a1712b5628a082fc036ab540cb7c6cdea193d96228b0bcc09",
        "group_anchor": "",
        "group_internal_key": {
          "raw_key_bytes": "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
          "key_loc": {
            "key_family": 0,
            "key_index": 0
          }
        },
        "group_tapscript_root": "",
        "script_key": {
          "pub_key": "e0fbb9f650d6bceec5f72da396628d432d95312973e6921841bbac7ec4f9bab6",
          "key_desc": {
            "raw_key_bytes": "026864a8edfd20a09b31fe6618f603bb91143f2cbd6486dc85c232d66e93c50d0f",
            "key_loc": {
              "key_family": 212,
              "key_index": 2
            }
          },
          "tap_tweak": "",
          "type": "SCRIPT_KEY_BIP86"
        }
      }
    ],
    "created_at": "1771291485",
    "height_hint": 125,
    "batch_psbt": ""
  }
}
```

Then fund:

```
FUND_RESP_2=$($TAPCLI assets mint fund --sat_per_vbyte 10)
```

and sign:

```
GROUP_VIRTUAL_PSBT_2=$(echo "$FUND_RESP_2" | \
  jq -r '.batch.unsealed_assets[0].group_virtual_psbt')

SIGN_OUTPUT_2=$(WALLET_PASSWORD=- AEZEED_PASSPHRASE=- \
  chantools --regtest signpsbt --walletdb "/tmp/wallet.db" \
  --psbt "$GROUP_VIRTUAL_PSBT_2" 2>&1)

SIGNED_PSBT_2=$(echo "$SIGN_OUTPUT_2" | \
  awk '/Successfully signed PSBT:/{getline;getline;print;exit}')
```

Then seal:

```
$TAPCLI assets mint seal --signed_group_psbt "$SIGNED_PSBT_2"
```

and finalize:

```
$TAPCLI assets mint finalize
```

To verify the issuance, first mine some more blocks:

```
mine 6
```

Now you should be able to see both tranches issued under the group key via:

```
$TAPCLI assets list | jq \
  "[.assets[] | select(.asset_group.tweaked_group_key == \"$TWEAKED_GROUP_KEY\")]"
```

which should yield a JSON response like the following:

```json
[
  {
    "version": "ASSET_VERSION_V0",
    "asset_genesis": {
      "genesis_point": "e93c5cd1935c2fef58ab1e7aa7f7c0493611bedb521e556e1eb06e5a10b93cb8:1",
      "name": "asset-tranche1",
      "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd",
      "asset_id": "bab2f9995a1c46a9550ac49404ae0f3db7ada3bc42d80cefbd6f6338a6e5e4fc",
      "asset_type": "NORMAL",
      "output_index": 0
    },
    "amount": "500000000",
    "lock_time": 0,
    "relative_lock_time": 0,
    "script_version": 0,
    "script_key": "02e2418043baac7932919382edc47fe51596db6bccb5cb6c7d31a921ef9e81ceba",
    "script_key_is_local": true,
    "asset_group": {
      "raw_group_key": "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
      "tweaked_group_key": "02b283955acc482b1a1712b5628a082fc036ab540cb7c6cdea193d96228b0bcc09",
      "asset_witness": "01407e5bac4684525cc30d663d41f6f21357371b65ddbff91e7b5371d2a5825a0c9983f5c3e558a77bbb2651045e75e91e6f4caff60b58c930a93e1635e5937b2545",
      "tapscript_root": "7d7a8748f0f4abdbce183f02dccbf4db607acfbca973cdc7b62b1f12a4a0ed50"
    },
    "chain_anchor": {
      "anchor_tx": "02000000000101b83cb9105a6eb01e6e551e52dbbe113649c0f7a77a1eab58ef2f5c93d15c3ce901000000000000000002e8030000000000002251202e71ef194febe0aef63839b9f3aa3908f18cb0d9483017ecd8899596fefdbc887478031c000000002251206fd19ca2786daccbeb7cab937f5107d6dbad6f69c7ba8ff86e637f63bdfeba8d014084b692adbd38e0ec093df57f1eb24e52b45973debd78a97ac83062f351c20c5b4c4a9e49f95ee22fcbfa36974fc965b6ad71249a31942b1f4b5d22d4d1b38fb600000000",
      "anchor_block_hash": "589d2b70f154868555f1937e03f865e4c6e0c5aaefd18eccc66554fcabdd8464",
      "anchor_outpoint": "d4d3c57c7e62b6a8fa35b7c178e366b5b1bda03462c323cdcf05d08a469fcce2:0",
      "internal_key": "02beae4dedfbe4d343d097fc3a7a88e48adc90d47325c57d937b0a308cc44ff06d",
      "merkle_root": "84d664678aa45f212a40e616cbcaee1b63ede70815931d0f48a759ad15b219e9",
      "tapscript_sibling": "",
      "block_height": 120,
      "block_timestamp": "1771291104"
    },
    "prev_witnesses": [],
    "is_spent": false,
    "lease_owner": "",
    "lease_expiry": "0",
    "is_burn": false,
    "script_key_declared_known": true,
    "script_key_has_script_path": false,
    "decimal_display": {
      "decimal_display": 0
    },
    "script_key_type": "SCRIPT_KEY_BIP86"
  },
  {
    "version": "ASSET_VERSION_V0",
    "asset_genesis": {
      "genesis_point": "d4d3c57c7e62b6a8fa35b7c178e366b5b1bda03462c323cdcf05d08a469fcce2:1",
      "name": "asset-tranche2",
      "meta_hash": "f19bbf25df2e3f02ef33bd8edfdea2a176f38f608065f920aeef077644a268bd",
      "asset_id": "9257183ed959d0c29ac21a3818c11212b057d0428934f26c1c62e260bb6eced2",
      "asset_type": "NORMAL",
      "output_index": 0
    },
    "amount": "100000000",
    "lock_time": 0,
    "relative_lock_time": 0,
    "script_version": 0,
    "script_key": "02e0fbb9f650d6bceec5f72da396628d432d95312973e6921841bbac7ec4f9bab6",
    "script_key_is_local": true,
    "asset_group": {
      "raw_group_key": "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
      "tweaked_group_key": "02b283955acc482b1a1712b5628a082fc036ab540cb7c6cdea193d96228b0bcc09",
      "asset_witness": "014078cffb66e3bb40feab6c69478dc8f941764ad3e8dc78d93ebdba4e8d8e1eb1d326f5f76d52b64cfcd56cc08d0f29457e63386eb675e9dd860933d9c962082e59",
      "tapscript_root": "7d7a8748f0f4abdbce183f02dccbf4db607acfbca973cdc7b62b1f12a4a0ed50"
    },
    "chain_anchor": {
      "anchor_tx": "02000000000101e2cc9f468ad005cfcd23c36234a0bdb1b566e378c1b735faa8b6627e7cc5d3d401000000000000000002e80300000000000022512029209d824f2da5790d8bd92ef0606f95393754fa10f5f5703a96449e28fc9934886e031c00000000225120fc395bd3971d614495ded6d439833ded5c39b784da44ab5f152523fdc679a9a80140d7ebd7528ba332e4bfba84bc3a934410a2b762795a2383a5b4cf6cd6a12fbf87d57f8ab8dd4f5ad217d6c63e560210605aa6d61ab0845c43a266e37e835754b700000000",
      "anchor_block_hash": "777f50a658aecd2221bdcb2a18705e0fd28231ad9d957707b9b9302263e78936",
      "anchor_outpoint": "9cc9e40f766031eee75f6d7d5f5157dd872624cc4b58984b655b0022634df097:0",
      "internal_key": "024a93d7b547311cef82fcd6320c034a79e78e6e8308f9969814d0845128138adf",
      "merkle_root": "013fa16bbe3ac2c0e87edc988768d27d07f57cb05325f49e7e340b9fdcb1b681",
      "tapscript_sibling": "",
      "block_height": 126,
      "block_timestamp": "1771291736"
    },
    "prev_witnesses": [],
    "is_spent": false,
    "lease_owner": "",
    "lease_expiry": "0",
    "is_burn": false,
    "script_key_declared_known": true,
    "script_key_has_script_path": false,
    "decimal_display": {
      "decimal_display": 0
    },
    "script_key_type": "SCRIPT_KEY_BIP86"
  }
]
```

