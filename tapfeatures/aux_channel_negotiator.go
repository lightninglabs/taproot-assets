package tapfeatures

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

// AuxChannelNegotiator is responsible for producing the extra tlv blob that is
// encapsulated in the init and reestablish peer messages. This helps us
// communicate custom feature bits with our peer.
type AuxChannelNegotiator struct {
	// peerFeatures keeps track of the supported features of our peers. This
	// map will be used for lookups by other subsystems, when some features
	// need to be supported by both parties to take effect.
	peerFeatures lnutils.SyncMap[route.Vertex, *lnwire.RawFeatureVector]

	// chanFeatures keeps track of the supported features of each channel.
	// This map will be used for lookups by other subsystems to check
	// whether certain custom channel features are supported.
	chanFeatures lnutils.SyncMap[wire.OutPoint, *lnwire.RawFeatureVector]
}

// NewAuxChannelNegotiator returns a new instance of the aux channel negotiator.
func NewAuxChannelNegotiator() *AuxChannelNegotiator {
	return &AuxChannelNegotiator{}
}

// GetInitFeatures is called when sending an init message to a peer. It returns
// custom feature bits to include in the init message TLVs. The implementation
// can decide which features to advertise based on the peer's identity.
func (n *AuxChannelNegotiator) GetInitFeatures(
	peer route.Vertex) (tlv.Blob, error) {

	var buf bytes.Buffer

	// Grab the "static" feature vector that denotes the supported features
	// of our node. If our peer can read this message they will keep track
	// of our features just like we do below in `ProcessInitFeatures`.
	features := getLocalFeatureVec()
	err := features.Encode(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ProcessInitFeatures handles received init feature TLVs from a peer. The
// implementation can store state internally to affect future channel operations
// with this peer.
func (n *AuxChannelNegotiator) ProcessInitFeatures(peer route.Vertex,
	features tlv.Blob) error {

	buf := bytes.NewBuffer(features)
	peerVec := lnwire.NewRawFeatureVector()
	err := peerVec.Decode(buf)
	if err != nil {
		return err
	}

	// Before we store this peer's supported features we need to first check
	// if our required features are supported by that peer. If a locally
	// required feature is not supported by the remote peer we have to
	// return an error and drop the connection. Whether we support all of
	// the remote required features is a responsibility of the remote peer.
	// If we fail to support a remotely required feature they are the ones
	// to drop the connection (by returning an error right here).
	err = checkRequiredBits(getLocalFeatureVec(), peerVec)
	if err != nil {
		return err
	}

	// Store this peer's features.
	n.peerFeatures.Store(peer, peerVec)

	return nil
}

// GetReestablishFeatures is called when sending a channel_reestablish message.
// It returns feature bits based on the specific channel identified by its
// funding outpoint and aux channel blob.
func (n *AuxChannelNegotiator) GetReestablishFeatures(
	_ wire.OutPoint, _ tlv.Blob) (tlv.Blob, error) {

	var buf bytes.Buffer

	// We could store per-channel features, but currently there's no need to
	// support that. We report the same feature vector over all of our
	// custom channels.
	features := getLocalFeatureVec()
	err := features.Encode(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ProcessReestablishFeatures handles received channel_reestablish feature TLVs.
// This is a blocking call - the channel link will wait for this method to
// complete before continuing channel operations. The implementation can modify
// aux channel behavior based on the negotiated features.
func (n *AuxChannelNegotiator) ProcessReestablishFeatures(
	fundingPoint wire.OutPoint, features tlv.Blob,
	auxChanBlob tlv.Blob) error {

	buf := bytes.NewBuffer(features)
	peerVec := lnwire.NewRawFeatureVector()
	err := peerVec.Decode(buf)
	if err != nil {
		return err
	}

	// Before we store this channel's supported features we need to first
	// check if our required features are supported by the remote party. If
	// a locally required feature is not supported we have to return an
	// error and drop the connection. Whether we support all of the remote
	// required features is a responsibility of the remote peer. If we fail
	// to support a remotely required feature they are the ones to drop the
	// connection (by returning an error right here).
	err = checkRequiredBits(getLocalFeatureVec(), peerVec)
	if err != nil {
		return err
	}

	n.chanFeatures.Store(fundingPoint, peerVec)

	return nil
}

// GetPeerFeatures returns the negotiated custom channel type that was
// established with the given peer.
func (n *AuxChannelNegotiator) GetPeerFeatures(
	peer route.Vertex) *lnwire.FeatureVector {

	rawfeatures, ok := n.peerFeatures.Load(peer)
	if !ok {
		rawfeatures = lnwire.NewRawFeatureVector()
	}

	return lnwire.NewFeatureVector(rawfeatures, featureNames)
}

// checkRequiredBits is a helper method that checks if all of the required bits
// of the first vector are supported by the second vector.
func checkRequiredBits(a, b *lnwire.RawFeatureVector) error {
	featuresA, featuresB :=
		lnwire.NewFeatureVector(a, featureNames),
		lnwire.NewFeatureVector(b, featureNames)

	for _, f := range ourFeatures() {
		if featuresA.RequiresFeature(f) && !featuresB.HasFeature(f) {
			return fmt.Errorf("peer does not support required "+
				"feature: %v", featuresA.Name(f))
		}
	}

	return nil
}
