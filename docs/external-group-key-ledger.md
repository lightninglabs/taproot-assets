# How to use an external group key with a Ledger

This document describes how we can mint an asset with a group key that is
external to the `lnd` node/wallet that `tapd` is connected to.

This guide shows how to use a Ledger (in this example specifically a Leder
Nano S with the latest firmware).

## Step 1: Set up the Ledger device

First, you need to set up the Ledger device. This only needs to be done once for
a new device. If a device that already has a seed is being used, some steps can
potentially be skipped.

1. Initialize the device with a seed, following the manufacturer's instructions.
2. Using the "Ledger Live" software, make sure the device runs the latest
   available firmware (`v1.3.1` at time of writing this).
3. Using the "Ledger Live" software, make sure you install the "Bitcoin" app
   or update it to the latest version (`v2.3.0` at time of writing this).
4. If you plan to experiment on regtest or testnet first, you also need to
   install the "Bitcoin Test" app with the same version (the "Ledger Live" app
   needs to be changed to "developer mode" for test apps to appear).

## Step 2: Install HWI and derive the xpub for the group key

We will be using a
[custom version](https://github.com/lightninglabs/HWI/tree/tapd-v0.6.0-cold-minting)
of the [HWI](https://github.com/bitcoin-core/HWI) library to talk with the
Ledger device from the command line.

```shell
$ git clone --branch tapd-v0.6.0-cold-minting https://github.com/lightninglabs/HWI.git
$ cd HWI
```

Depending on your environment, you need to install the Python dependencies of
the HWI application:

```shell
$ python3 setup.py install # or 'poetry install' or 'pip3 install .'
```

Next, you need to unlock the device and open the "Bitcoin Test" (or "Bitcoin"
for mainnet) on the device. Then the command below should return some JSON:
```shell
$ ./hwi.py enumerate
[{"type": "ledger", "model": "ledger_nano_s_plus", "label": null, "path": "5-3.2.2.1:1.0", "fingerprint": "e5bf06e8", "needs_pin_sent": false, "needs_passphrase_sent": false}]
```

With the above command we now know the device is in the correct state.
Make sure to change the "path" variable in all future HWI commands with the one
shown for your device, not the one from the example above.
We'll need the value of "fingerprint" later when minting an asset.

Now we can derive the xpub for the Taproot path. Make sure to replace the path
`m/86h/1h/0'` with `m/86h/0h/0'` on **mainnet** (and remove the `--chain test`
part from the command)!

```shell
./hwi.py --chain test -t ledger -d "5-3.2.2.1:1.0" getxpub m/86h/1h/0h                                                                       ─╯
{"xpub": "tpubDDZhuaRUHh84uonNw5GiWiienwiAABcYKpoFSJkjs8nBvTDXNLuYj98yeyhjiHGRRMQZRFiBLvj6VFJdg5jHGNXDX8bcEZFcrzZE53xjSc6"}
```

## Step 3: Mint an asset

With the `xpub`, derivation path and master fingerprint obtained, we can now
start the mint process. **NOTE** that we're adding `/0/0` to the derivation
path, as the key that should be used for the actual group internal key should
be the key at index `0` of the external (`0`) branch.
When creating more, distinct asset groups from the same key, the last number can
be incremented to derive/use a different key.

```shell
$ tapcli assets mint --type normal --name usdt --supply 500000000 --new_grouped_asset \
  --group_key_xpub tpubDDZhuaRUHh84uonNw5GiWiienwiAABcYKpoFSJkjs8nBvTDXNLuYj98yeyhjiHGRRMQZRFiBLvj6VFJdg5jHGNXDX8bcEZFcrzZE53xjSc6 \
  --group_key_derivation_path "m/86'/1'/0'/0/0" --group_key_fingerprint e5bf06e8

{
    "pending_batch":  {
        "batch_key":  "031cad33f9c2d11ba1955c86d30e99414010a3d8db3cf005cdfd7b5947884d152b",
        "batch_txid":  "",
        "state":  "BATCH_STATE_PENDING",
        "assets":  [
            {
                "asset_version":  "ASSET_VERSION_V0",
                "asset_type":  "NORMAL",
                "name":  "usdt",
                "asset_meta":  null,
                "amount":  "500000000",
                "new_grouped_asset":  true,
                "group_key":  "",
                "group_anchor":  "",
                "group_internal_key":  {
                    "raw_key_bytes":  "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
                    "key_loc":  {
                        "key_family":  0,
                        "key_index":  0
                    }
                },
                "group_tapscript_root":  "",
                "script_key":  {
                    "pub_key":  "ff3608f3e5e608317011201b104bf87352655f4ea47c14edad0cabe6d69ff5b4",
                    "key_desc":  {
                        "raw_key_bytes":  "03a0fc40fd7d5ecbc34cfd479aa44320af064a9df7a3c9d1940ebe2fc9bcd8f1a9",
                        "key_loc":  {
                            "key_family":  212,
                            "key_index":  15
                        }
                    },
                    "tap_tweak":  ""
                }
            }
        ],
        "created_at":  "1735303474",
        "height_hint":  157,
        "batch_psbt":  ""
    }
}
```

This creates a pending batch with a single asset. More assets can be added now,
if desired.

## Step 4: Fund the batch

Funding the batch means reserving a BTC on-chain output that will be used to
fund the minting transaction. The very first input used will also serve as the
unique randomness to the asset ID of each asset in the batch. So this step is
necessary to obtain the asset IDs in the first place.

```shell
$ tapcli assets mint fund --sat_per_vbyte 20

{
    "batch":  {
        "batch":  {
            "batch_key":  "031cad33f9c2d11ba1955c86d30e99414010a3d8db3cf005cdfd7b5947884d152b",
            "batch_txid":  "",
            "state":  "BATCH_STATE_PENDING",
            "assets":  [],
            "created_at":  "1735303474",
            "height_hint":  157,
            "batch_psbt":  "70736274ff010089020000000193267bc4203fbcd503f52ebf10e57cb1bea854617ac27b07df36d6feae38407100000000000000000002e803000000000000225120000000000000000000000000000000000000000000000000000000000000000039d0f50500000000225120b57e85d54f10ff813207ebb49e0c1a174813946516ca0e1c0b06191ba6b2667400000000000100de02000000000101049ea356718188c25b111a07f293158e6fbff2c0780643aa8731d392ac3b5b180100000000fdffffff0200e1f50500000000160014dd2f53994b70a2c43b72bb7f66b63d8b8e629a5cd05b93d600000000160014c10699dfa395cc2d48d7ed5fc697c5efddd18fe60247304402202d46b3fc55d7ca7140ac38a3847c1c1df9984f8c2abbdbcdb8779208810199b00220134869b61fee2a09fcbd4a5bc6b2ce813f1f785b692d8971ee30f6dd2a172ce20121028a0bda7fde65fc310d5a2540aee5f20c2693faab85331c3161063b842611e2d98c00000001011f00e1f50500000000160014dd2f53994b70a2c43b72bb7f66b63d8b8e629a5c010304010000002206020b76f7e4cb9de0a39697e085815ec8c32ad3124f693bf6cfe2ae44477f4c23ed180000000054000080000000800000008000000000010000000000220203b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f21718000000005600008000000080000000800100000007000000010520b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f2172107b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f217190000000000560000800000008000000080010000000700000000"
        },
        "unsealed_assets":  [
            {
                "asset":  {
                    "asset_version":  "ASSET_VERSION_V0",
                    "asset_type":  "NORMAL",
                    "name":  "usdt",
                    "asset_meta":  null,
                    "amount":  "500000000",
                    "new_grouped_asset":  true,
                    "group_key":  "",
                    "group_anchor":  "",
                    "group_internal_key":  {
                        "raw_key_bytes":  "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
                        "key_loc":  {
                            "key_family":  0,
                            "key_index":  0
                        }
                    },
                    "group_tapscript_root":  "",
                    "script_key":  {
                        "pub_key":  "ff3608f3e5e608317011201b104bf87352655f4ea47c14edad0cabe6d69ff5b4",
                        "key_desc":  {
                            "raw_key_bytes":  "03a0fc40fd7d5ecbc34cfd479aa44320af064a9df7a3c9d1940ebe2fc9bcd8f1a9",
                            "key_loc":  {
                                "key_family":  212,
                                "key_index":  15
                            }
                        },
                        "tap_tweak":  ""
                    }
                },
                "group_key_request":  {
                    "raw_key":  {
                        "raw_key_bytes":  "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
                        "key_loc":  {
                            "key_family":  0,
                            "key_index":  0
                        }
                    },
                    "anchor_genesis":  {
                        "genesis_point":  "714038aefed636df077bc27a6154a8beb17ce510bf2ef503d5bc3f20c47b2693:0",
                        "name":  "usdt",
                        "meta_hash":  "0000000000000000000000000000000000000000000000000000000000000000",
                        "asset_id":  "c4b0771c1bd1334bf20df5204c162702a6dc765a9cb15b1bc9e3c91e0282061b",
                        "asset_type":  "NORMAL",
                        "output_index":  0
                    },
                    "tapscript_root":  "93ece4efce6d317e9ecb74d1bfc26c2eadb43080ff38aa21069dc81379defd8d",
                    "new_asset":  "000100024e93267bc4203fbcd503f52ebf10e57cb1bea854617ac27b07df36d6feae384071000000000475736474000000000000000000000000000000000000000000000000000000000000000000000000000401000605fe1dcd65000b690167016500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e020000102102ff3608f3e5e608317011201b104bf87352655f4ea47c14edad0cabe6d69ff5b4",
                    "external_key":  {
                        "xpub":  "tpubDD2EgfmrtDs51w46DHDa87yiwiidEYC3ECXXyFp72ESAt5SV661R19kGAMiQMPm8No438YmW5yeYLKUJYuDByAkJvfxA13n2u79ZeDvryHb",
                        "master_fingerprint":  "10608bb9",
                        "derivation_path":  "m/86'/1'/0'/0/0"
                    }
                },
                "group_virtual_tx":  {
                    "transaction":  "02000000013299ae8f8a4a3aa0e1842f1346ea0426d6ba28b77a428076e7ce1a8e7b2fc970000000000000000000010065cd1d00000000225120c684a933ce8fcaefdb0912a139cebfd932d70c65e75275e7ebd150a83f20c3b700000000",
                    "prev_out":  {
                        "value":  "500000000",
                        "pk_script":  "5120a947e56ec036b80fcfdaa61eeaa725b14a31ee4a05091de1d71930878f8cd704"
                    },
                    "genesis_id":  "c4b0771c1bd1334bf20df5204c162702a6dc765a9cb15b1bc9e3c91e0282061b",
                    "tweaked_key":  "02a947e56ec036b80fcfdaa61eeaa725b14a31ee4a05091de1d71930878f8cd704"
                },
                "group_virtual_psbt":  "cHNidP8BAF4CAAAAATKZro+KSjqg4YQvE0bqBCbWuii3ekKAdufOGo57L8lwAAAAAAAAAAAAAQBlzR0AAAAAIlEgxoSpM86Pyu/bCRKhOc6/2TLXDGXnUnXn69FQqD8gw7cAAAAAAAEBKwBlzR0AAAAAIlEgqUflbsA2uA/P2qYe6qclsUox7koFCR3h1xkwh4+M1wQiBgOmVT/xqoux3JGzXh+EKPmebfw6ZuOZRa2cDCL//sZ3/xgQYIu5VgAAgAEAAIAAAACAAAAAAAAAAAAhFqZVP/Gqi7HckbNeH4Qo+Z5t/Dpm45lFrZwMIv/+xnf/GQAQYIu5VgAAgAEAAIAAAACAAAAAAAAAAAABFyCmVT/xqoux3JGzXh+EKPmebfw6ZuOZRa2cDCL//sZ3/wEYIJPs5O/ObTF+nst00b/CbC6ttDCA/ziqIQadyBN53v2NAAA="
            }
        ]
    }
}
```

We now got the `group_virtual_psbt`, which is the Taproot Asset VM transaction
that is going to be signed in the next step to prove ownership of the group key.

## Step 5: Sign the group PSBT

We now copy the `group_virtual_psbt` from the previous step and sign it with
the HWI script (make sure to remove the `--chain test` for mainnet):

```shell
$ ./hwi.py --chain test -t ledger -d "5-3.2.2.1:1.0" signtx \
  cHNidP8BAF4CAAAAATKZro+KSjqg4YQvE0bqBCbWuii3ekKAdufOGo57L8lwAAAAAAAAAAAAAQBlzR0AAAAAIlEgxoSpM86Pyu/bCRKhOc6/2TLXDGXnUnXn69FQqD8gw7cAAAAAAAEBKwBlzR0AAAAAIlEgqUflbsA2uA/P2qYe6qclsUox7koFCR3h1xkwh4+M1wQiBgOmVT/xqoux3JGzXh+EKPmebfw6ZuOZRa2cDCL//sZ3/xgQYIu5VgAAgAEAAIAAAACAAAAAAAAAAAAhFqZVP/Gqi7HckbNeH4Qo+Z5t/Dpm45lFrZwMIv/+xnf/GQAQYIu5VgAAgAEAAIAAAACAAAAAAAAAAAABFyCmVT/xqoux3JGzXh+EKPmebfw6ZuOZRa2cDCL//sZ3/wEYIJPs5O/ObTF+nst00b/CbC6ttDCA/ziqIQadyBN53v2NAAA=
  
{"psbt": "cHNidP8BAF4CAAAAAS8MN0redQjReGudiMzpiKf6ct1qMQl9icuuIjcZtSnYAAAAAAAAAAAAAQBlzR0AAAAAIlEglXtLW++uNjRdN9NB2aOsfLuJ844QeNqiQzpE8CZcHGoAAAAATwEENYfPAwAAAAAAAAAAagOaCdw2+wARrnK9pOPR46VRMtekL1E3mQz6DPkcNMgDagOaCdw2+wARrnK9pOPR46VRMtekL1E3mQz6DPkcNMgQAAAAAFYAAIABAACAAAAAgE8BBIiyHgPRfU1CgAAAAC3h3pSGuqHmKGgim3acdnIfRKCxP/sVHr6h9HtwZMD6AlrgAdQbK0B6qT3PBQKoDZ1ZUR1yWoNKH1ml05PGQ9n4EOW/BuhWAACAAQAAgAAAAIAAAQErAGXNHQAAAAAiUSCUQAq8agPlNkDnrfQQfNAGByNbTIq+mKxY52GRqK2yXSIGAqEj9s2g9LHZE2Mm2zYxPR3ZnOYrGnvCg6vAiNpay5LJGOW/BuhWAACAAQAAgAAAAIAAAAAAAAAAAAETQOTfRBGyQqNUTI7oSmr4peWAjMig1Uwk/XZvpypzSNMcH7/GCDWH4qunWb1ecsHplpkfZOXnKhqu0wnhMO+lSlkhFqEj9s2g9LHZE2Mm2zYxPR3ZnOYrGnvCg6vAiNpay5LJGQDlvwboVgAAgAEAAIAAAACAAAAAAAAAAAABFyChI/bNoPSx2RNjJts2MT0d2ZzmKxp7woOrwIjaWsuSyQEYIOWeffQlExiltUlKYws1t7IY4MVI+bnldZMwlsfcdQQQAAA=", "signed": true}
```

If all goes well, the device should ask you to register/approve the policy, then
sign the transaction.

## Step 6: Seal the batch with the signature

```shell
$ tapcli assets mint seal --signed_group_psbt "cHNidP8BAF4CAAAAAS8MN0redQjReGudiMzpiKf6ct1qMQl9icuuIjcZtSnYAAAAAAAAAAAAAQBlzR0AAAAAIlEglXtLW++uNjRdN9NB2aOsfLuJ844QeNqiQzpE8CZcHGoAAAAATwEENYfPAwAAAAAAAAAAagOaCdw2+wARrnK9pOPR46VRMtekL1E3mQz6DPkcNMgDagOaCdw2+wARrnK9pOPR46VRMtekL1E3mQz6DPkcNMgQAAAAAFYAAIABAACAAAAAgE8BBIiyHgPRfU1CgAAAAC3h3pSGuqHmKGgim3acdnIfRKCxP/sVHr6h9HtwZMD6AlrgAdQbK0B6qT3PBQKoDZ1ZUR1yWoNKH1ml05PGQ9n4EOW/BuhWAACAAQAAgAAAAIAAAQErAGXNHQAAAAAiUSCUQAq8agPlNkDnrfQQfNAGByNbTIq+mKxY52GRqK2yXSIGAqEj9s2g9LHZE2Mm2zYxPR3ZnOYrGnvCg6vAiNpay5LJGOW/BuhWAACAAQAAgAAAAIAAAAAAAAAAAAETQOTfRBGyQqNUTI7oSmr4peWAjMig1Uwk/XZvpypzSNMcH7/GCDWH4qunWb1ecsHplpkfZOXnKhqu0wnhMO+lSlkhFqEj9s2g9LHZE2Mm2zYxPR3ZnOYrGnvCg6vAiNpay5LJGQDlvwboVgAAgAEAAIAAAACAAAAAAAAAAAABFyChI/bNoPSx2RNjJts2MT0d2ZzmKxp7woOrwIjaWsuSyQEYIOWeffQlExiltUlKYws1t7IY4MVI+bnldZMwlsfcdQQQAAA=

{
    "batch":  {
        "batch_key":  "031cad33f9c2d11ba1955c86d30e99414010a3d8db3cf005cdfd7b5947884d152b",
        "batch_txid":  "",
        "state":  "BATCH_STATE_PENDING",
        "assets":  [
            {
                "asset_version":  "ASSET_VERSION_V0",
                "asset_type":  "NORMAL",
                "name":  "usdt",
                "asset_meta":  null,
                "amount":  "500000000",
                "new_grouped_asset":  true,
                "group_key":  "02a947e56ec036b80fcfdaa61eeaa725b14a31ee4a05091de1d71930878f8cd704",
                "group_anchor":  "",
                "group_internal_key":  {
                    "raw_key_bytes":  "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
                    "key_loc":  {
                        "key_family":  0,
                        "key_index":  0
                    }
                },
                "group_tapscript_root":  "",
                "script_key":  {
                    "pub_key":  "ff3608f3e5e608317011201b104bf87352655f4ea47c14edad0cabe6d69ff5b4",
                    "key_desc":  {
                        "raw_key_bytes":  "03a0fc40fd7d5ecbc34cfd479aa44320af064a9df7a3c9d1940ebe2fc9bcd8f1a9",
                        "key_loc":  {
                            "key_family":  212,
                            "key_index":  15
                        }
                    },
                    "tap_tweak":  ""
                }
            }
        ],
        "created_at":  "1735303474",
        "height_hint":  157,
        "batch_psbt":  "70736274ff010089020000000193267bc4203fbcd503f52ebf10e57cb1bea854617ac27b07df36d6feae38407100000000000000000002e803000000000000225120000000000000000000000000000000000000000000000000000000000000000039d0f50500000000225120b57e85d54f10ff813207ebb49e0c1a174813946516ca0e1c0b06191ba6b2667400000000000100de02000000000101049ea356718188c25b111a07f293158e6fbff2c0780643aa8731d392ac3b5b180100000000fdffffff0200e1f50500000000160014dd2f53994b70a2c43b72bb7f66b63d8b8e629a5cd05b93d600000000160014c10699dfa395cc2d48d7ed5fc697c5efddd18fe60247304402202d46b3fc55d7ca7140ac38a3847c1c1df9984f8c2abbdbcdb8779208810199b00220134869b61fee2a09fcbd4a5bc6b2ce813f1f785b692d8971ee30f6dd2a172ce20121028a0bda7fde65fc310d5a2540aee5f20c2693faab85331c3161063b842611e2d98c00000001011f00e1f50500000000160014dd2f53994b70a2c43b72bb7f66b63d8b8e629a5c010304010000002206020b76f7e4cb9de0a39697e085815ec8c32ad3124f693bf6cfe2ae44477f4c23ed180000000054000080000000800000008000000000010000000000220203b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f21718000000005600008000000080000000800100000007000000010520b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f2172107b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f217190000000000560000800000008000000080010000000700000000"
    }
}
```

## Step 7: Finalize the batch

If the step above didn't result in an error, the minting batch is ready to be
finalized:

```shell
$ tapcli assets mint finalize

{
    "batch":  {
        "batch_key":  "031cad33f9c2d11ba1955c86d30e99414010a3d8db3cf005cdfd7b5947884d152b",
        "batch_txid":  "07be90fa33795ddb4d20c397ddfb07827c898b8096df75a12871e25ae8f7653a",
        "state":  "BATCH_STATE_BROADCAST",
        "assets":  [
            {
                "asset_version":  "ASSET_VERSION_V0",
                "asset_type":  "NORMAL",
                "name":  "usdt",
                "asset_meta":  null,
                "amount":  "500000000",
                "new_grouped_asset":  false,
                "group_key":  "02a947e56ec036b80fcfdaa61eeaa725b14a31ee4a05091de1d71930878f8cd704",
                "group_anchor":  "",
                "group_internal_key":  {
                    "raw_key_bytes":  "03a6553ff1aa8bb1dc91b35e1f8428f99e6dfc3a66e39945ad9c0c22fffec677ff",
                    "key_loc":  {
                        "key_family":  0,
                        "key_index":  0
                    }
                },
                "group_tapscript_root":  "93ece4efce6d317e9ecb74d1bfc26c2eadb43080ff38aa21069dc81379defd8d",
                "script_key":  {
                    "pub_key":  "ff3608f3e5e608317011201b104bf87352655f4ea47c14edad0cabe6d69ff5b4",
                    "key_desc":  {
                        "raw_key_bytes":  "03a0fc40fd7d5ecbc34cfd479aa44320af064a9df7a3c9d1940ebe2fc9bcd8f1a9",
                        "key_loc":  {
                            "key_family":  212,
                            "key_index":  15
                        }
                    },
                    "tap_tweak":  ""
                }
            }
        ],
        "created_at":  "1735303474",
        "height_hint":  157,
        "batch_psbt":  "70736274ff010089020000000193267bc4203fbcd503f52ebf10e57cb1bea854617ac27b07df36d6feae38407100000000000000000002e8030000000000002251208e7e9e413a2ed27bee7bd378720589005d310e24814449e16f39d0a3087eba5439d0f50500000000225120b57e85d54f10ff813207ebb49e0c1a174813946516ca0e1c0b06191ba6b2667400000000000100de02000000000101049ea356718188c25b111a07f293158e6fbff2c0780643aa8731d392ac3b5b180100000000fdffffff0200e1f50500000000160014dd2f53994b70a2c43b72bb7f66b63d8b8e629a5cd05b93d600000000160014c10699dfa395cc2d48d7ed5fc697c5efddd18fe60247304402202d46b3fc55d7ca7140ac38a3847c1c1df9984f8c2abbdbcdb8779208810199b00220134869b61fee2a09fcbd4a5bc6b2ce813f1f785b692d8971ee30f6dd2a172ce20121028a0bda7fde65fc310d5a2540aee5f20c2693faab85331c3161063b842611e2d98c00000001011f00e1f50500000000160014dd2f53994b70a2c43b72bb7f66b63d8b8e629a5c01086b02473044022004d32c69c7fbb54d2f4278d0f2b2f3506dc1d273a252b8b487c8a425693240a502203e2682d58292fc1339857fd0321b1c8555e63ce4f117dfdded8b8b418333b0d50121020b76f7e4cb9de0a39697e085815ec8c32ad3124f693bf6cfe2ae44477f4c23ed0000220203b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f21718000000005600008000000080000000800100000007000000010520b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f2172107b59023dd9a58fb64dad00948ad44fe5c194cf2e36b2e104bd8ef255bc480f217190000000000560000800000008000000080010000000700000000"
    }
}

```
