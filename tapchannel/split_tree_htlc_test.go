package tapchannel

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// TestNextCommitSplitTreeV0 tests that the next commitment of a channel with a
// peer that doesn't signal the split-tree-v1 feature is reported to have
// BranchV0 split trees once the block after the chain tip reaches the split
// tree activation height, and that of a channel with a peer that does is not.
// The mock chain tip is at height 0. The test changes the default split tree
// activation height, so it must not run in parallel with other tests.
func TestNextCommitSplitTreeV0(t *testing.T) {
	defer proof.SetDefaultSplitTreeActivationHeight(
		proof.DefaultSplitTreeActivationHeight(),
	)

	negotiator := tapfeatures.NewAuxChannelNegotiator()
	v0Peer, v1Peer := route.Vertex{0x01}, route.Vertex{0x02}
	require.NoError(t, negotiator.ProcessInitRecords(
		v0Peer, auxInitRecords(
			t, tapfeatures.STXOOptional,
			tapfeatures.STXOSpenderOptional,
		),
	))
	require.NoError(t, negotiator.ProcessInitRecords(
		v1Peer, auxInitRecords(
			t, tapfeatures.STXOOptional,
			tapfeatures.STXOSpenderOptional,
			tapfeatures.SplitTreeV1Optional,
		),
	))

	shaper := NewAuxTrafficShaper(&TrafficShaperConfig{
		AuxChanNegotiator: negotiator,
		ChainBridge:       tapgarden.NewMockChainBridge(),
	})

	testCases := []struct {
		name            string
		splitTreeHeight lfn.Option[uint32]
		peer            route.Vertex
		want            bool
	}{{
		name:            "no activation height",
		splitTreeHeight: lfn.None[uint32](),
		peer:            v0Peer,
	}, {
		name:            "below activation height",
		splitTreeHeight: lfn.Some(uint32(2)),
		peer:            v0Peer,
	}, {
		name:            "at activation height",
		splitTreeHeight: lfn.Some(uint32(1)),
		peer:            v0Peer,
		want:            true,
	}, {
		name:            "at activation height, peer with feature",
		splitTreeHeight: lfn.Some(uint32(1)),
		peer:            v1Peer,
	}}
	for _, tc := range testCases {
		proof.SetDefaultSplitTreeActivationHeight(tc.splitTreeHeight)

		got, err := shaper.nextCommitSplitTreeV0(tc.peer)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}
