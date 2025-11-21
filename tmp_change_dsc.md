TestTaprootAssetsDaemon/tranche00/83-of-98/anchor_multiple_virtual_transactions was failing inside ValidateAnchorInputs
with “anchor input script mismatch”. The mismatch appeared whenever we executed the PublishAndLogTransfer (pre‑anchored)
path: the RPC would validate the user-supplied PSBT/vpkts,
but once ChainPorter picked up the resulting parcel it no longer had the full tap trees needed to recreate each anchor
input, so the final pre-broadcast check failed.

Root cause

ValidateAnchorInputs needs all assets that were committed in the original anchor input:

1. active + passive assets (present in the virtual packets), and
2. “purged assets” (tombstones/burns) that were part of the commitment but are not recreated.

When ChainPorter orchestrates a send from scratch it keeps the original InputCommitments in memory, so in
SendStateVerifyPreBroadcast we can call tapsend.ExtractUnSpendable on those commitments and hand the pruned leaves to
ValidateAnchorInputs. However, in the pre‑anchored RPC flow we never stored
those commitments—InputCommitments is empty—and although rpcServer.validateInputAssets fetched and used the purged
leaves to check the user’s PSBT, it didn’t persist them anywhere. By the time ChainPorter ran, the only data left were
the active/passive assets; the tombstones/burns were gone, so the
reconstructed tap tree didn’t match the on-chain script.

What changed

1. rpcServer.validateInputAssets now returns the pruned assets it discovers while validating a PSBT’s inputs. The helper
   still performs all prior checks (version validation, local key derivation, commitment lookups, supply conservation),
   but it also hands the tombstones/burns back to the caller.
2. PublishAndLogTransfer captures that map and passes it down to ChainPorter by storing it in the PreAnchoredParcel.
3. sendPackage and ChainPorter gain a PrunedAssets field. When we reach SendStateVerifyPreBroadcast, we merge any
   pre-supplied pruned leaves with the ones we can still derive from InputCommitments and feed the combined set into
   ValidateAnchorInputs.
4. Existing internal callers of NewPreAnchoredParcel (aux funding controller, aux closer) pass nil because they still
   have full commitments in memory; nothing changes for those flows.

This ensures that every code path which validated a PSBT against the full tap tree can supply the same tombstones/burns
later, so the final pre-broadcast check reconstructs the exact script that is committed on chain.

Why not just populate InputCommitments?

For pre-anchored flows we often cannot build the full InputCommitments map:

- Inputs might belong to another party; we can’t fetch or persist their entire tap commitments.
- Even for local inputs the full commitment can be large, and we’d only be storing it to re-derive a small subset (the
  unspendable leaves). That’s heavyweight and redundant.

Passing just the pruned leaves is the minimal data we need to satisfy ValidateAnchorInputs, and it works even when the
full commitments aren’t available.

Is rpcServer.validateInputAssets redundant now?

No. It serves as the early validation barrier at the RPC boundary:

- It decorates the PSBT with local derivation info (so later signing works).
- It fetches whatever commitments the node knows about to enforce supply conservation and collect pruned leaves.
- It ensures malformed PSBTs are rejected before we ask the wallet to fund/sign or modify any state.

ChainPorter’s validateReadyForPublish is the final gate after coin selection and passive re-anchoring. Both stages call
into ValidateAnchorInputs/Outputs, but at different points in the lifecycle and with different responsibilities.
Removing either would either expose us to malformed user input (if
we removed the RPC check) or allow inconsistencies to slip through right before broadcast (if we removed the ChainPorter
check). The new change simply lets the early-stage information flow to the late stage so both checks see the same
complete data.

Summary

- Returning pruned assets from the RPC-layer validation and carrying them through the parcel keeps tombstones/burns
  alive for the final validation step.
- ChainPorter still gathers unspendables from InputCommitments when it has them; the new field only matters for
  pre‑anchored workflows that previously had no way to reproduce the missing leaves.
- validateInputAssets remains necessary as the RPC boundary guard; the additional return value just makes its work
  reusable later.
