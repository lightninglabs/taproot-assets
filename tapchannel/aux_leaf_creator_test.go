package tapchannel

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestPopulateSecondLevelLeaves asserts that second-level HTLC aux leaves are
// derived from a revocation log for exactly the HTLCs that carry assets: an
// incoming asset HTLC gets a second-level leaf with a CLTV timeout, an
// outgoing asset HTLC gets one without, HTLCs without asset outputs are
// skipped, and revocation log entries without an HTLC index are ignored.
func TestPopulateSecondLevelLeaves(t *testing.T) {
	t.Parallel()

	commitTx := randProof(t).AnchorTx
	keyRing := test.RandCommitmentKeyRing(t)

	groupKey := &asset.GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}

	newHtlcOutputs := func() []*cmsg.AssetOutput {
		assetID, p := htlcGroupProof(t, groupKey, commitTx)
		return []*cmsg.AssetOutput{
			cmsg.NewAssetOutput(assetID, p.Asset.Amount, *p),
		}
	}

	const (
		incomingIdx = uint64(1)
		outgoingIdx = uint64(2)
		btcOnlyIdx  = uint64(3)
	)

	incomingHtlcs := map[input.HtlcIndex][]*cmsg.AssetOutput{
		incomingIdx: newHtlcOutputs(),
	}
	outgoingHtlcs := map[input.HtlcIndex][]*cmsg.AssetOutput{
		outgoingIdx: newHtlcOutputs(),
	}

	commitment := cmsg.NewCommitment(
		nil, nil, outgoingHtlcs, incomingHtlcs,
		lnwallet.CommitAuxLeaves{}, false, cmsg.SigHashAll,
	)

	newEntry := func(idx uint64, incoming bool) *channeldb.HTLCEntry {
		entry, err := channeldb.NewHTLCEntryFromHTLC(channeldb.HTLC{
			RHash:         [32]byte{byte(idx)},
			RefundTimeout: 800_000 + uint32(idx),
			Incoming:      incoming,
			Amt: lnwire.NewMSatFromSatoshis(
				354,
			),
			HtlcIndex: idx,
		})
		require.NoError(t, err)

		return entry
	}

	revLog := &channeldb.RevocationLog{
		HTLCEntries: []*channeldb.HTLCEntry{
			newEntry(incomingIdx, true),
			newEntry(outgoingIdx, false),
			// A BTC-only HTLC: present in the log, but carries no
			// asset outputs in the commitment.
			newEntry(btcOnlyIdx, true),
			// An entry without an HTLC index must be skipped.
			{},
		},
	}

	leaves := lnwallet.CommitAuxLeaves{
		IncomingHtlcLeaves: make(input.HtlcAuxLeaves),
		OutgoingHtlcLeaves: make(input.HtlcAuxLeaves),
	}

	err := populateSecondLevelLeaves(
		revLog, commitment, chanState, keyRing, &commitTx,
		testChainParams, &leaves,
	)
	require.NoError(t, err)

	// The incoming asset HTLC must have produced a second-level leaf.
	incomingLeaf, ok := leaves.IncomingHtlcLeaves[incomingIdx]
	require.True(t, ok, "incoming asset HTLC missing second-level leaf")
	require.True(t, incomingLeaf.SecondLevelLeaf.IsSome())

	// Same for the outgoing asset HTLC.
	outgoingLeaf, ok := leaves.OutgoingHtlcLeaves[outgoingIdx]
	require.True(t, ok, "outgoing asset HTLC missing second-level leaf")
	require.True(t, outgoingLeaf.SecondLevelLeaf.IsSome())

	// The incoming and outgoing leaves must differ: the incoming path
	// commits to a CLTV timeout while the outgoing one does not.
	require.NotEqual(
		t,
		incomingLeaf.SecondLevelLeaf.UnwrapOrFail(t).Script,
		outgoingLeaf.SecondLevelLeaf.UnwrapOrFail(t).Script,
	)

	// The BTC-only HTLC and the index-less entry must not have produced
	// any leaves.
	require.NotContains(t, leaves.IncomingHtlcLeaves, btcOnlyIdx)
	require.Len(t, leaves.IncomingHtlcLeaves, 1)
	require.Len(t, leaves.OutgoingHtlcLeaves, 1)
}
