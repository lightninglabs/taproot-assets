# Driving Asset Sends with an External Signer (PSBT + vPSBT)

This guide shows how to send Taproot Assets while a hardware wallet or any
PSBT/descriptor-based signer (for example, a Coldcard or a wallet built on
[BDK](https://bitcoindevkit.org/)) produces the final Bitcoin signature. The
idea is a division of labor: `tapd` does all of the asset-protocol work it
already knows how to do — coin-selecting asset inputs, building and signing
the virtual transaction, computing commitments and proofs — and hands back a
standard Bitcoin PSBT for an external party to sign and broadcast.

The companion document
[`hardware-wallet-support.md`](./hardware-wallet-support.md) describes the
tweaks and tapscript leaves a signing device must understand. This guide
describes the RPC workflow that produces the PSBT carrying those tweaks.

The audience is a developer integrating `tapd` with an external signer. We
assume you already know what a PSBT is and have a working `tapd` connected to
`lnd`. Code references are pinned to commit
[`3d9d3f2e`](https://github.com/lightninglabs/taproot-assets/tree/3d9d3f2e).

## Two signing layers

A Taproot Asset transfer commits to two transactions, and each is signed
separately.

The **virtual transaction** (the "vPSBT") lives at the asset layer. It spends
asset inputs to asset outputs and carries the asset witness — a signature over
the virtual transaction made with the asset's *script key*. This witness is
what authorizes the asset to move.

The **anchor transaction** lives at the Bitcoin layer. It is an ordinary
on-chain transaction whose outputs commit to the asset state through a Taproot
output-key tweak, and whose inputs spend the previous on-chain outputs that
held the assets (plus any inputs added to pay fees). This is the transaction
that gets mined.

The two layers are independent. `tapd` can own the asset layer entirely while
an external party signs the Bitcoin layer, because signing the vPSBT and
signing the anchor PSBT use different keys and happen at different steps. That
independence is what lets an external device sign the Bitcoin layer without
learning anything about the asset protocol beyond the output tweak.

> **Minting is different.** Issuing a grouped asset needs a signature at the
> *asset* layer — the group key must sign the genesis. That signature can also
> be externalized, but through a separate mechanism (see
> [`external-group-key.md`](./external-group-key.md)). This guide covers sends,
> where the asset-layer signing stays inside `tapd`.

## The RPC sequence

All of the RPCs below live in the `AssetWallet` service
(`taprpc/assetwalletrpc/assetwallet.proto`). The full send runs in five steps:

```
1. FundVirtualPsbt           tapd selects asset inputs, builds the vPSBT
2. SignVirtualPsbt           tapd signs the asset layer
3. PrepareAnchoringTemplate  build the BTC anchor PSBT skeleton
4. CommitVirtualPsbts        tapd funds + commits, returns an UNSIGNED anchor PSBT
   ──  external signer signs the anchor PSBT here  ──
5. PublishAndLogTransfer     tapd logs the transfer and (optionally) broadcasts
```

Steps 1, 2, 4, and 5 are RPC calls. Step 3 is a helper,
`tapsend.PrepareAnchoringTemplate`, that you can call in-process or reproduce
in your own client; it just assembles a PSBT skeleton from the funded virtual
packets.

### Step 1 — FundVirtualPsbt

`FundVirtualPsbt` takes a template describing what you want to send — either a
raw `TxTemplate` (recipients and optional explicit asset inputs) or an existing
virtual PSBT — and selects asset inputs to cover it. It returns:

- `funded_psbt`: the funded but unsigned virtual transaction.
- `change_output_index`: the asset change output, or `-1` if the send is
  full-value.
- `passive_asset_psbts`: the *passive* assets that happen to share a Bitcoin
  anchor UTXO with the asset you are sending. They are not the target of the
  send, but they must be re-anchored alongside it, so you carry them through
  the rest of the flow.

### Step 2 — SignVirtualPsbt

`SignVirtualPsbt` signs the asset layer. It looks up the script key for each
input, populates the derivation paths, and signs with the key `tapd` controls
through `lnd`. This is where the asset witness is produced; no external party
is involved, because the script keys belong to `tapd`.

Sign the active asset and every passive asset returned in step 1. Both must be
signed before they can be committed.

### Step 3 — PrepareAnchoringTemplate

`tapsend.PrepareAnchoringTemplate` turns the signed virtual packets into a
Bitcoin PSBT skeleton. For each distinct asset anchor UTXO being spent, it adds
one input and fills in the fields a signer needs:

- `WitnessUtxo` — the value and `pkScript` of the output being spent.
- `TaprootInternalKey` — the internal key of the anchor output.
- `TaprootMerkleRoot` — the Taproot Asset commitment root, which sits in the
  BIP-341 merkle-root position and therefore acts as the Taproot tweak.
- `TaprootBip32Derivation` and `Bip32Derivation` — the BIP-371 and legacy
  derivation info (master fingerprint plus path) that lets a descriptor wallet
  recognize the key as its own.

These are exactly the fields a BIP-371 signer reads to sign a Taproot key-path
spend. We return to that in [The external signing
boundary](#the-external-signing-boundary).

The template starts with only the asset inputs and the asset outputs. It does
not yet pay fees. Funding is the next step.

### Step 4 — CommitVirtualPsbts

`CommitVirtualPsbts` is the heart of the flow. It maps the virtual packets onto
the anchor template, computes the output commitments and the state-transition
proofs, writes the committed Taproot output keys into the anchor PSBT, and —
unless you opt out — funds the transaction so it is ready to sign.

The request carries the active `virtual_psbts`, the `passive_asset_psbts`, the
`anchor_psbt` template, a fee setting (`target_conf` or `sat_per_vbyte`), and a
change instruction (`add` a new P2TR change output, or reuse an
`existing_output_index`). It returns:

- `anchor_psbt`: the funded anchor transaction, **ready to be signed**. The
  proto comment states the one exception precisely: it is ready to sign
  "unless some of the asset inputs don't belong to this daemon, in which case
  the anchor input derivation info must be added to those inputs first."
- `virtual_psbts` and `passive_asset_psbts`: now updated with their proofs.
- `change_output_index`: the BTC change output, or `-1`.
- `lnd_locked_utxos`: the UTXO leases `lnd` took for any inputs it added during
  funding.

`CommitVirtualPsbts` does not sign the anchor transaction. That is the seam
where the external signer takes over.

### External signing

Sign the `anchor_psbt` returned by step 4 however you like — with `lnd`'s
`SignPsbt`, with a BDK-based wallet, or by exporting the PSBT to a hardware
device and importing the signed result. The next section covers what the
signer must be able to do.

### Step 5 — PublishAndLogTransfer

`PublishAndLogTransfer` takes the fully signed `anchor_psbt`, the proof-bearing
`virtual_psbts` and `passive_asset_psbts`, the `change_output_index`, and the
`lnd_locked_utxos` from step 4. It extracts the final transaction, logs the
transfer to the database, and ships the outgoing proofs to the counterparty.

Set `skip_anchor_tx_broadcast` if an external system handles broadcasting;
`tapd` then logs the transfer and distributes proofs without publishing the
transaction itself. Set `label` to track the transfer through the logs or a
`SubscribeSendEvents` stream.

## The external signing boundary

The anchor transaction can spend two kinds of inputs, and they have different
signing requirements.

**The asset anchor input** is the previous on-chain output that held the assets
being spent. It is a P2TR output whose output key is the internal key tweaked
by the Taproot Asset commitment root. Spending it through the key path means
signing with the internal key plus that tweak. Because
`PrepareAnchoringTemplate` writes the internal key into `TaprootInternalKey`
and the commitment root into `TaprootMerkleRoot`, any BIP-371 signer can do
this: it matches the master fingerprint in `TaprootBip32Derivation` against its
descriptor, derives the key, applies the merkle-root tweak, and produces a
Schnorr signature. This is a BIP-86-style key-path spend, except the tweak is
the asset commitment rather than an empty root.

**Fee inputs** are whatever inputs pay for the transaction. They are ordinary
outputs of the signing wallet — P2TR or P2WPKH — and need nothing
asset-specific to sign.

A descriptor wallet such as BDK therefore signs the anchor PSBT the same way it
would sign any other: it walks each input, finds the ones whose derivation
fingerprint matches a descriptor it holds, and signs them. The asset input is
special only in that it carries a non-empty Taproot tweak, which BIP-371
already accounts for. If your asset outputs were created with a tapscript
sibling (for example, an asset held under a Lightning channel script), the
device must instead sign the matching script path; see
[`hardware-wallet-support.md`](./hardware-wallet-support.md) for the leaf
structures involved.

### Which keys live where

Who can sign the anchor transaction depends entirely on who holds the keys for
its inputs.

In a stock `tapd` plus `lnd` deployment, both kinds of input belong to `lnd`.
The asset anchor input's internal key was derived from `lnd`'s keyring when the
asset was received, and any fee inputs `tapd` adds during funding are `lnd`'s
UTXOs. So `lnd` can sign the whole anchor transaction, which is what the
simpler `AnchorVirtualPsbts` RPC does in one call.

To move Bitcoin signing to an external device, that device must hold the keys
for the inputs it signs. This yields two integration shapes.

**Shape A — external wallet pays the fees.** The external wallet contributes
the fee UTXOs and signs them; `lnd` still signs the asset anchor input. A
single PSBT can carry signatures from more than one signer, so each party signs
only the inputs it owns. This works on stock `tapd` today and is the direct
path for "let a Coldcard fund and co-sign the on-chain transaction." Funding
the fees from external UTXOs is covered next under [External coin
selection](#external-coin-selection).

**Shape B — the device signs everything.** The device holds the asset anchor
input's internal key too, so it signs the entire Bitcoin layer and `tapd` never
touches a Bitcoin key. This requires the asset to have been *received* into an
anchor whose internal key the device controls, and `tapd` must recognize that
key so it can populate the input's derivation info. Standard receive addresses
derive the anchor internal key from `lnd` (`NewAddr` has no field for supplying
an external internal key), so Shape B is not yet a turnkey path: it needs
custom key provisioning on the receive side. When the asset inputs don't belong
to the daemon, you also fill in the anchor input derivation info yourself before
signing, as the `CommitVirtualPsbts` response comment notes.

## External coin selection

Fees can come from `lnd` or from an external wallet. The `skip_funding` flag on
`CommitVirtualPsbts` chooses between them.

**`lnd`-funded (default, `skip_funding = false`).** `tapd` calls `lnd`'s
`FundPsbt` to add inputs and a P2TR change output, sizing them to the
`target_conf` or `sat_per_vbyte` you set. `lnd` locks the inputs it selects and
returns them as `lnd_locked_utxos`, which you pass on to
`PublishAndLogTransfer`. Use this when `lnd` holds the funds and you only want
to externalize signing of the asset input (or when `lnd` itself is the signer).

**Externally funded (`skip_funding = true`).** `tapd` skips funding entirely.
You are responsible for adding the fee inputs and the change output to the
anchor PSBT *before* calling `CommitVirtualPsbts`, drawing on UTXOs the external
wallet controls. `tapd` then only computes the commitments and proofs and
updates the Taproot output keys; it adds no inputs and locks nothing. This is
the path for genuine external coin selection: select coins in BDK (or the
device's host software), add them to the template, commit, sign, and publish.

A practical pattern for Shape A with external fees:

1. Fund and sign the virtual packets (steps 1–2).
2. Build the anchor template (step 3).
3. Run coin selection in your external wallet and add the chosen fee inputs and
   a change output to the template.
4. Call `CommitVirtualPsbts` with `skip_funding = true`.
5. Sign the fee inputs with the external wallet and the asset input with `lnd`
   (or both with the device under Shape B).
6. Call `PublishAndLogTransfer`.

## Worked example

The integration test `testPsbtExternalCommit` (`itest/psbt_test.go`) exercises
this exact send flow end to end. It signs the anchor PSBT with `lnd` in-test,
but the signer is interchangeable: any party holding the input keys can sign
the same PSBT. A separate test, `testMintExternalGroupKeyChantools`
(`itest/mint_fund_seal_test.go`), shows that a real offline signer
([chantools](https://github.com/lightninglabs/chantools)) can be driven over
`tapd`'s PSBT flows — there at the minting layer rather than the send anchor,
but it demonstrates the same export-sign-import round trip a hardware device
would use.

The example below calls the `AssetWallet` RPCs directly through a generated
`assetwalletrpc.AssetWalletClient`. It uses three helpers from the
`taproot-assets` module: `tappsbt.Encode`/`tappsbt.Decode` to (de)serialize
virtual packets, `tapsend.PrepareAnchoringTemplate` to build the anchor
skeleton, and the standard `psbt` package to serialize the Bitcoin PSBT. For
connection and macaroon setup, either dial directly with `grpc.Dial` plus the
`assetwalletrpc.NewAssetWalletClient` constructor, or reuse `tap-sdk`'s
`grpc.NewClient` (see [Connecting and the tap-sdk
wrappers](#connecting-and-the-tap-sdk-wrappers)).

```go
// aw is an assetwalletrpc.AssetWalletClient connected to tapd.

// Step 1 — Fund: tapd selects asset inputs for the send.
fundResp, err := aw.FundVirtualPsbt(ctx, &assetwalletrpc.FundVirtualPsbtRequest{
        Template: &assetwalletrpc.FundVirtualPsbtRequest_Raw{
                Raw: &assetwalletrpc.TxTemplate{
                        AddressesWithAmounts: []*taprpc.AddressWithAmount{{
                                TapAddr: destAddr,
                                Amount:  amount,
                        }},
                },
        },
})

// Step 2 — Sign the asset layer: the active packet and every passive packet.
activeSigned, err := aw.SignVirtualPsbt(ctx, &assetwalletrpc.SignVirtualPsbtRequest{
        FundedPsbt: fundResp.FundedPsbt,
})
signedActive := [][]byte{activeSigned.SignedPsbt}

signedPassive := make([][]byte, len(fundResp.PassiveAssetPsbts))
for i, p := range fundResp.PassiveAssetPsbts {
        resp, err := aw.SignVirtualPsbt(ctx, &assetwalletrpc.SignVirtualPsbtRequest{
                FundedPsbt: p,
        })
        // handle err
        signedPassive[i] = resp.SignedPsbt
}

// Step 3 — Build the BTC anchor template. Decode each signed vPSBT with
// tappsbt.Decode, then call tapsend.PrepareAnchoringTemplate.
var vPackets []*tappsbt.VPacket
for _, b := range append(signedActive, signedPassive...) {
        vp, err := tappsbt.Decode(b)
        // handle err
        vPackets = append(vPackets, vp)
}
anchorTemplate, err := tapsend.PrepareAnchoringTemplate(vPackets)

var templateBuf bytes.Buffer
err = anchorTemplate.Serialize(&templateBuf)

// Step 4 — Commit: tapd funds via lnd and returns an UNSIGNED anchor PSBT.
commitResp, err := aw.CommitVirtualPsbts(ctx, &assetwalletrpc.CommitVirtualPsbtsRequest{
        VirtualPsbts:      signedActive,
        PassiveAssetPsbts: signedPassive,
        AnchorPsbt:        templateBuf.Bytes(),
        AnchorChangeOutput: &assetwalletrpc.CommitVirtualPsbtsRequest_Add{
                Add: true,
        },
        Fees: &assetwalletrpc.CommitVirtualPsbtsRequest_SatPerVbyte{
                SatPerVbyte: satPerVByte,
        },
        // For external coin selection instead, set SkipFunding: true and add
        // your own fee inputs and change output to AnchorPsbt before this call.
})

// --- external signing happens here on commitResp.AnchorPsbt ---
// Hand the PSBT to your hardware wallet or BDK signer, collect the fully
// signed result, then finalize and extract it. lnd's walletrpc SignPsbt and
// FinalizePsbt are one option if lnd holds the keys.
signedAnchorPsbt := externalSign(commitResp.AnchorPsbt)

// Step 5 — Publish + log. Pass back the proof-bearing vPSBTs, the change
// index, and the lease handles that step 4 returned.
sendResp, err := aw.PublishAndLogTransfer(ctx, &assetwalletrpc.PublishAndLogRequest{
        AnchorPsbt:            signedAnchorPsbt,
        VirtualPsbts:          commitResp.VirtualPsbts,
        PassiveAssetPsbts:     commitResp.PassiveAssetPsbts,
        ChangeOutputIndex:     commitResp.ChangeOutputIndex,
        LndLockedUtxos:        commitResp.LndLockedUtxos,
        SkipAnchorTxBroadcast: true,
        Label:                 "external-signed-send",
})
```

Note that step 5 passes `commitResp.VirtualPsbts` and
`commitResp.PassiveAssetPsbts`, not the pre-commit packets: committing is what
attaches the state-transition proofs, so the post-commit packets are the ones
to publish.

### Connecting and the tap-sdk wrappers

The [`tap-sdk`](https://github.com/lightninglabs/tap-sdk) module wraps a running
`tapd` with typed Go clients and removes much of the boilerplate above. Its
`grpc` package handles connection and macaroon setup (`grpc.NewClient`), and
`grpc.NewWalletKitClient` exposes the four steps as typed methods —
`FundTransfer`, `SignVirtualPsbt`, `CommitVirtualPsbts`, and
`PublishAndLogTransfer` — building the anchor template for you. The SDK also
ships a
[`remote-signing-coordinator`](https://github.com/lightninglabs/tap-sdk/tree/main/demos/remote-signing-coordinator)
demo that drives an external signer end to end, though at the minting layer.

The connection setup and the first two steps — `FundTransfer` and
`SignVirtualPsbt` — are directly reusable for the external-signing flow.

The commit and publish steps are not, and the reason is more than missing
fields. The SDK's `CommitVirtualPsbts` wrapper always funds through `lnd`: it
builds the anchor template internally, adds a P2TR change output, and takes the
fee as sat/vByte, with no `skip_funding`, lock fields, or way to pass your own
fee inputs. When `lnd` funds the anchor, every input belongs to `lnd` — the
asset input and the fee inputs alike — so `lnd` must sign the whole
transaction, and no input is left for an external device to sign. Putting an
external signer (or external UTXOs) on any input requires `skip_funding = true`
plus inputs you add yourself, which the wrapper doesn't expose; its
`PublishAndLogTransfer` likewise omits the change index and lease handles. So
the commit and publish steps of the external-signing flow need the raw
`assetwalletrpc` client shown above. This gap is tracked in
[tap-sdk#157](https://github.com/lightninglabs/tap-sdk/issues/157).

Note also that `grpc.Client` keeps its connection and macaroons private, so you
can't borrow them for a raw client. A hybrid integration opens a second gRPC
connection to the same `tapd` for the raw `assetwalletrpc` calls.

## Caveats

- **Sign passive assets too.** Every asset sharing a spent anchor UTXO must be
  re-anchored, so sign the passive packets from step 1 alongside the active
  one.
- **Custom-script assets can't be passive.** `tapd`'s automatic re-anchoring
  signs only normal BIP-86 keys, so if a spent UTXO holds custom-script assets,
  the external application must sign all of them — passive ones included.
- **`ASSET_VERSION_V1` can sign after committing.** For V1 assets with a
  segregated witness, you may commit first and add the asset witness afterward;
  in that case the proofs are only valid once the witness is filled in.
- **Match the fingerprint to the descriptor.** The external signer recognizes
  its inputs by the master fingerprint in `TaprootBip32Derivation`. If the
  device's descriptor fingerprint doesn't match what `tapd` recorded for the
  anchor key, it will silently skip the input rather than sign it.
