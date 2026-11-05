package tapchannel

import (
	"bytes"
	"context"
	"testing"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// auxInitRecords returns the init message records of a peer that advertises
// the given aux feature bits.
func auxInitRecords(t *testing.T,
	bits ...lnwire.FeatureBit) lnwire.CustomRecords {

	var buf bytes.Buffer
	err := lnwire.NewRawFeatureVector(bits...).Encode(&buf)
	require.NoError(t, err)

	return lnwire.CustomRecords{
		uint64(tapfeatures.AuxFeatureBitsTLV): buf.Bytes(),
	}
}

// TestChannelAcceptorSplitTreeV1 tests that the channel acceptor rejects an
// asset channel from a peer that doesn't signal the split-tree-v1 feature, and
// accepts one from a peer that does.
func TestChannelAcceptorSplitTreeV1(t *testing.T) {
	t.Parallel()

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

	f := &FundingController{
		cfg: FundingControllerCfg{AuxChanNegotiator: negotiator},
	}
	commitType := lnwallet.CommitmentTypeSimpleTaprootOverlay

	resp, err := f.channelAcceptor(
		context.Background(), &lndclient.AcceptorRequest{
			NodePubkey:     v0Peer,
			CommitmentType: &commitType,
		},
	)
	require.NoError(t, err)
	require.False(t, resp.Accept)
	require.Contains(t, resp.Error, ErrSplitTreeV1Required.Error())

	resp, err = f.channelAcceptor(
		context.Background(), &lndclient.AcceptorRequest{
			NodePubkey:     v1Peer,
			CommitmentType: &commitType,
		},
	)
	require.NoError(t, err)
	require.True(t, resp.Accept)
}
