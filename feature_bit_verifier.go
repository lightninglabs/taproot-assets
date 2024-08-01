package taprootassets

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// LndFeatureBitVerifier is a struct that verifies that the feature bits of a
// target connected peer, using our registered lnd node.
type LndFeatureBitVerifier struct {
	lnd *lndclient.LndServices
}

// NewLndFeatureBitVerifier creates a new LndFeatureBitVerifier instance.
func NewLndFeatureBitVerifier(
	lnd *lndclient.LndServices) *LndFeatureBitVerifier {

	return &LndFeatureBitVerifier{
		lnd: lnd,
	}
}

// HasFeature returns true if the peer has the given feature bit set. If the
// peer can't be found, then ErrNoPeer is returned.
func (l *LndFeatureBitVerifier) HasFeature(ctx context.Context,
	peerPub btcec.PublicKey, bit lnwire.FeatureBit) (bool, error) {

	peerBytes := route.NewVertex(&peerPub)

	peers, err := l.lnd.Client.ListPeers(ctx)
	if err != nil {
		return false, err
	}

	for _, peer := range peers {
		if peer.Pubkey != peerBytes {
			continue
		}

		return peer.Features.HasFeature(bit), nil
	}

	// If we get to this point, we weren't able to find the peer.
	return false, tapchannel.ErrNoPeer
}

// A compile-time check to ensure that LndFeatureBitVerifier implements the
// FeatureBitVerifier interface.
var _ tapchannel.FeatureBitVerifer = (*LndFeatureBitVerifier)(nil)
