# Proof activation

tapd v0.8.5 adds requirements to transition proofs. They apply to proofs
anchored at or past an activation height. Proofs anchored before it
verify as they did, so existing assets and their histories are
unaffected.

## Activation heights

- Mainnet: block 971,750, expected around 2026-10-17 12:00 UTC.
- Signet, with the default challenge: block 326,200, expected around
  2026-10-13 12:00 UTC.
- Testnet3, testnet4, regtest, simnet and custom signets: none. For
  testing, the hidden `--proofactivationheight` option sets one. It is
  rejected on mainnet.

The expected times assume ten-minute blocks.

## The requirements

From the activation height, a transition proof must:

- be of transition version 1;
- carry the root locator proof, if its transition splits an asset;
- carry the STXO proofs of the split root, if it is the proof of a split
  asset;
- carry the spender proofs of its transfer's root asset. tapd v0.8.5
  commits to a spender leaf next to the STXO leaf of each input it
  spends, and proves it.

A proof is subject to the requirements if the block confirming its
anchor transaction is at or past the activation height. An unconfirmed
proof is subject to them once the next block would be. Issuance proofs
are not.

## Before the activation height

1. Upgrade every node to v0.8.5, including universe servers. tapd
   v0.8.5 creates proofs that meet the requirements for every transfer
   it anchors, before and after the activation height.
2. Make sure every transfer anchored by an earlier version confirms
   before the activation height. A transaction's asset commitments are
   fixed once it is signed: the outputs of a transfer that confirms at
   or past the activation height without spender leaves can't be proven
   to an upgraded node, and so can't be spent with a valid history.
   Don't send from an earlier version close to or past the activation
   height.

## Asset channels

Commitment transactions are signed ahead of time, so the asset outputs
of a commitment commit to the leaves chosen when it was created. A
commitment carries spender leaves only if both peers support them, as
the `stxo-spender` feature that v0.8.5 advertises. Commitments created
before both peers run v0.8.5 carry none. Existing commitments are not
migrated on disk: a channel moves to spender leaves with its next
commitment update.

The outputs of a commitment without spender leaves that confirm at or
past the activation height can't be proven. That covers:

- a force close from such a commitment;
- the second-level HTLC transactions of such a commitment, which are
  signed along with it;
- a revoked state of the channel broadcast by a peer (see below).

A cooperative close between two v0.8.5 peers builds its closing
transaction with spender leaves, whatever the state of the commitments.

### Migrating a channel

For each asset channel, before the activation height:

1. Upgrade both peers to v0.8.5.
2. Let the peers reconnect, so that they negotiate the `stxo-spender`
   feature. Peers with a channel reconnect on their own after a
   restart.
3. Make at least one commitment update and let it complete, such as a
   small keysend or asset payment that settles. Both peers' current
   commitments then carry spender leaves. An idle channel is not
   migrated.
4. Check the channel on both peers. The custom channel data of an
   asset channel, as `lncli listchannels` shows it, reports whether the
   node's current commitment carries spender leaves:

       "spender_leaves": true

   While an activation height is set, tapd also logs a warning, once per
   channel and process, when it loads a commitment that carries no
   spender leaves:

       Asset channel <channel point>: its commitment carries no spender
       leaves. ...

The `TestSpenderLeafUpgrade` itest, run by `make itest-cc-compat`, takes
a channel through these steps from v0.8.4: it opens the channel,
upgrades both peers, reconnects them, updates the channel once and
checks that both peers report spender leaves, then force closes it past
the activation height and verifies the proofs of the swept outputs.

### Channels that can't be migrated in time

If a peer won't run v0.8.5 before the activation height, the feature is
not negotiated, and the channel stays on commitments without spender
leaves. Close the channel so that the closing transaction confirms, not
merely broadcasts, before the activation height. Before a force close,
settle or fail any HTLCs on the channel, as their second-level
transactions would have to confirm before the activation height too.

### Revoked states

Commitment states revoked before a channel moved to spender leaves stay
without them. If a peer broadcasts such a state at or past the
activation height, the justice transaction still sweeps its outputs, but
the swept assets can't be proven, as the revoked commitment's asset
outputs lack spender leaves. To remove this exposure, close a channel
opened before v0.8.5 cooperatively, and reopen it on v0.8.5, before the
activation height. A channel with a peer trusted not to broadcast a
revoked state can be migrated as above instead.

## After the activation height

Upgraded nodes reject proofs anchored at or past the activation height
that don't meet the requirements. Transfers that earlier versions anchor
past the activation height can't be proven to them.
