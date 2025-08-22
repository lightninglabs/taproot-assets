# How to add Hardware Wallet support

With `v0.7.0`, `tapd` uses four different forms of scripts/tweaks for anchoring
commitment roots into Bitcoin transactions that can be relevant for hardware
signing devices:
 - The "Taproot Asset Root Commitment": The pseudo-leaf that's placed in the
   Taproot merkle tree to commit to asset mints and transfers.
   - Relevant when signing any asset mint or transfer transaction. The Taproot
     internal key used for the mint or transfer output(s) would be a key that
     belongs to the signing device. And the Taproot Asset Root Commitment pseudo
     leaf would be the single leaf in the tree (unless there are more
     user-defined script leaves added, as would be the case for Lightning
     Channel outputs)
 - The V0 group key scheme that tweaks the group internal key twice.
    - Deprecated, should not be used when targeting Hardware Wallet support. The
      commitment is a simple double tweak to arrive at the final ("tweaked")
      group key:
      ```go
      //	internalKey = rawKey + singleTweak * G
      //	tweakedGroupKey = TapTweak(internalKey, tapscriptRoot)
      ```
      Where `singleTweak` is the asset ID of the group anchor and the
      `tapscriptRoot` is either an empty byte slice or the root of a custom
      script tapscript tree.
 - The `OP_RETURN` commitment scheme for signing minting events with the group
   key.
    - Currently only relevant as an option to choose from when defining a group
      key V1. Relevant for signing new tranches of assets only: A single
      `OP_RETURN` leaf would be present in the group key's tapscript tree that
      commits to the group anchor's asset ID.
 - The Pedersen commitment scheme for signing minting events with the group key
   and for generating unique script keys in V2 TAP address sends.
     - Relevant as an option to choose from when defining a group
       key V1. Relevant for signing new tranches of assets: A single
       `<pedersen_key> OP_CHECKSIG` leaf would be present in the group key's
       tapscript tree that commits to the group anchor's asset ID through a
       Pedersen commitment key.
     - This is also relevant for outputs created for sends to V2 TAP addresses.
       The receiver script keys are constructed with a Pedersen commitment, so
       if the internal key of the script key is held in a signing device, then
       authorizing the spend of such an output would require the signing device
       to be able to deal with such a leaf being present.

## On-chain Taproot Asset Root Commitment Structure

The Taproot Asset commitment is what is placed in a tap leaf of a transaction
output's tapscript tree. The exact structure of the leaf script depends on the
commitment version.

### V0 and V1 Commitments

For `TapCommitmentV0` and `TapCommitmentV1`, the tap leaf script is constructed
as follows:

`version (1 byte) || TaprootAssetsMarker (32 bytes) || root_hash (32 bytes) || 
root_sum (8 bytes)`

Where:
- `version`: The `TapCommitmentVersion`, which is `0` for V0 and `1` for V1.
- `TaprootAssetsMarker`: A static marker to identify the leaf as a Taproot Asset
  commitment. It is the `sha256` hash of the string `taproot-assets`.
- `root_hash`: The MS-SMT root of the `TapCommitment`, which commits to all the
  asset commitments within it.
- `root_sum`: The sum of all asset amounts under that `TapCommitment` root.

### V2 Commitments

For `TapCommitmentV2`, the tap leaf script is constructed as follows:

`tag (32 bytes) || version (1 byte) || root_hash (32 bytes) || 
root_sum (8 bytes)`

Where:
- `tag`: A tagged hash to uniquely identify this as a V2+ Taproot Asset
  commitment. It is the `sha256` hash of the string `taproot-assets:194243`.
- `version`: The `TapCommitmentVersion`, which is `2` for V2.
- `root_hash`: The MS-SMT root of the `TapCommitment`, which commits to all the
  asset commitments within it.
- `root_sum`: The sum of all asset amounts under that `TapCommitment` root.

## Group Key Commitment Schemes

To commit to a group key, two main schemes are used to create non-spendable
tapscript leaves. These leaves are used to commit to the genesis asset ID within
the group key's tapscript tree and therefore a signing device signing a new
asset tranche needs to be able to deal with such a leaf being present in the
tapscript tree.

### OP_RETURN Commitment

This scheme creates a non-spendable script by using the `OP_RETURN` opcode.
The script is constructed as follows:

`OP_RETURN || <data>`

Where:
- `data`: The data to be committed to, which is typically the genesis asset ID.

This creates a script that will terminate execution early, making it provably
unspendable.

### Pedersen Commitment

This scheme uses a normal `OP_CHECKSIG` operator with a public key that cannot
be signed for. This special public key is generated using a Pedersen
commitment. The script is constructed as follows:

`<tweaked_nums_key> OP_CHECKSIG`

Where:
- `tweaked_nums_key`: A public key derived from a Pedersen commitment. The
  message for the commitment is the asset ID (or 32 zero bytes if no data is
  provided). To achieve hardware wallet support, this key is turned into an
  extended key (xpub), and a child key at path `0/0` is used as the actual
  public key that goes into the `OP_CHECKSIG` script.

