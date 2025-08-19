package tapfeatures

import (
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

// AuxChannelNegotiator is responsible for producing the extra tlv blob that is
// encapsulated in the init and reestablish peer messages. This helps us
// communicate custom feature bits with our peer.
type AuxChannelNegotiator struct {
	peerFeatures map[route.Vertex]CustomChannelType
}

// NewAuxChannelNegotiator returns a new instance of the aux channel negotiator.
func NewAuxChannelNegotiator() *AuxChannelNegotiator {
	return &AuxChannelNegotiator{
		peerFeatures: make(map[route.Vertex]CustomChannelType),
	}
}

// GetInitFeatures is called when sending an init message to a peer. It returns
// custom feature bits to include in the init message TLVs. The implementation
// can decide which features to advertise based on the peer's identity.
func (n *AuxChannelNegotiator) GetInitFeatures(
	peer [33]byte) (tlv.Blob, error) {

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(getCustomChannelType()))

	return buf, nil
}

// ProcessInitFeatures handles received init feature TLVs from a peer. The
// implementation can store state internally to affect future channel operations
// with this peer.
func (n *AuxChannelNegotiator) ProcessInitFeatures(peer [33]byte,
	features tlv.Blob) error {

	if len(features) != 8 {
		return fmt.Errorf("expected 8 bytes in features blob, got %v",
			len(features))
	}

	peerChanType := CustomChannelType(binary.BigEndian.Uint64(features))
	n.peerFeatures[peer] = getCustomChannelType() & peerChanType

	return nil
}

// GetReestablishFeatures is called when sending a channel_reestablish message.
// It returns feature bits based on the specific channel identified by its
// funding outpoint and aux channel blob.
func (n *AuxChannelNegotiator) GetReestablishFeatures(
	fundingPoint wire.OutPoint, auxChanBlob tlv.Blob) (tlv.Blob, error) {

	return nil, nil
}

// ProcessReestablishFeatures handles received channel_reestablish feature TLVs.
// This is a blocking call - the channel link will wait for this method to
// complete before continuing channel operations. The implementation can modify
// aux channel behavior based on the negotiated features.
func (n *AuxChannelNegotiator) ProcessReestablishFeatures(
	fundingPoint wire.OutPoint, features tlv.Blob,
	auxChanBlob tlv.Blob) error {

	return nil
}

// GetPeerFeatures returns the negotiated custom channel type that was
// established with the given peer.
func (n *AuxChannelNegotiator) GetPeerFeatures(
	peer route.Vertex) CustomChannelType {

	return n.peerFeatures[peer]
}
