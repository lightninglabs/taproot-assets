package tapfeatures

import (
	"bytes"
	"fmt"

	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// AuxFeatureBitsTLV is the TLV type used to encode auxiliary feature
	// bits in the init message. These feature bits allow aux channel
	// implementations to negotiate custom channel behavior.
	AuxFeatureBitsTLV tlv.Type = 65545
)

// AuxFeatureBits is a type alias for a TLV blob that contains custom feature
// bits for auxiliary channel negotiation.
type AuxFeatureBits = tlv.Blob

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
	chanFeatures lnutils.SyncMap[lnwire.ChannelID, *lnwire.RawFeatureVector]
}

// NewAuxChannelNegotiator returns a new instance of the aux channel negotiator.
func NewAuxChannelNegotiator() *AuxChannelNegotiator {
	return &AuxChannelNegotiator{}
}

// GetInitRecords is called when sending an init message to a peer. It returns
// custom feature bits to include in the init message TLVs. The implementation
// can decide which features to advertise based on the peer's identity.
func (n *AuxChannelNegotiator) GetInitRecords(
	_ route.Vertex) (lnwire.CustomRecords, error) {

	var buf bytes.Buffer

	// Grab the "static" feature vector that denotes the supported features
	// of our node. If our peer can read this message they will keep track
	// of our features just like we do below in `ProcessInitFeatures`.
	features := getLocalFeatureVec()
	err := features.Encode(&buf)
	if err != nil {
		return nil, err
	}

	tlvMap := make(tlv.TypeMap, 1)
	tlvMap[AuxFeatureBitsTLV] = buf.Bytes()

	return lnwire.NewCustomRecords(tlvMap)
}

// ProcessInitRecords handles received init feature TLVs from a peer. The
// implementation can store state internally to affect future channel operations
// with this peer.
func (n *AuxChannelNegotiator) ProcessInitRecords(peer route.Vertex,
	customRecords lnwire.CustomRecords) error {

	auxRecord, ok := customRecords[uint64(AuxFeatureBitsTLV)]
	if !ok {
		// If the entry was not present, delete the previous entry. Our
		// peer did not provide a custom feature bit vector this time.
		n.peerFeatures.Delete(peer)
		return nil
	}

	buf := bytes.NewBuffer(auxRecord)
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

// ProcessChannelReady handles the reception of the ChannelReady message, which
// signals that a newly established channel is now ready to use. This helps us
// correlate a peer's features with a channel outpoint
func (n *AuxChannelNegotiator) ProcessChannelReady(cid lnwire.ChannelID,
	peer route.Vertex) {

	features, ok := n.peerFeatures.Load(peer)
	if ok {
		n.chanFeatures.Store(cid, features)
	}
}

// ProcessReestablish handles the reception of the ChannelReestablish message,
// which signals that a previously established channel is now ready to use. This
// helps us correlate a peer's features with a channel outpoint.
func (n *AuxChannelNegotiator) ProcessReestablish(
	cid lnwire.ChannelID, peer route.Vertex) {

	features, ok := n.peerFeatures.Load(peer)
	if ok {
		n.chanFeatures.Store(cid, features)
	}
}

// GetPeerFeatures returns the negotiated feature bit vector that was
// established with the given peer.
func (n *AuxChannelNegotiator) GetPeerFeatures(
	peer route.Vertex) lnwire.FeatureVector {

	rawfeatures, ok := n.peerFeatures.Load(peer)
	if !ok {
		rawfeatures = lnwire.NewRawFeatureVector()
	}

	return *lnwire.NewFeatureVector(rawfeatures, featureNames)
}

// GetChannelFeatures returns the negotiated feature bits vector for the channel
// identified by the given channelID.
func (n *AuxChannelNegotiator) GetChannelFeatures(
	cid lnwire.ChannelID) lnwire.FeatureVector {

	rawfeatures, ok := n.chanFeatures.Load(cid)
	if !ok {
		rawfeatures = lnwire.NewRawFeatureVector()
	}

	return *lnwire.NewFeatureVector(rawfeatures, featureNames)
}

// checkRequiredBits is a helper method that checks if all of the required bits
// of the first vector are supported by the second vector.
func checkRequiredBits(local, remote *lnwire.RawFeatureVector) error {
	localBits, remoteBits :=
		lnwire.NewFeatureVector(local, featureNames),
		lnwire.NewFeatureVector(remote, featureNames)

	for _, f := range ourFeatures() {
		if localBits.RequiresFeature(f) && !remoteBits.HasFeature(f) {
			return fmt.Errorf("peer does not support required "+
				"feature: %v", localBits.Name(f))
		}
	}

	return nil
}
