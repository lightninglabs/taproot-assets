package tapfeatures

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestFeatureBits tests that the behavior of the feature vector matches our
// expectations when using the custom feature bits for taproot asset channels.
func TestFeatureBits(t *testing.T) {
	featuresA := lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(NoOpHTLCsOptional), featureNames,
	)

	featuresB := lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(STXOOptional), featureNames,
	)

	require.True(t, featuresA.HasFeature(NoOpHTLCsOptional))
	require.True(t, featuresB.HasFeature(STXOOptional))

	require.False(t, featuresA.HasFeature(STXOOptional))
	require.False(t, featuresB.HasFeature(NoOpHTLCsOptional))

	require.False(t, featuresA.RequiresFeature(NoOpHTLCsOptional))
	require.False(t, featuresB.RequiresFeature(STXOOptional))

	err := checkRequiredBits(
		featuresA.RawFeatureVector, featuresB.RawFeatureVector,
	)

	require.NoError(t, err)

	featuresA = lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(NoOpHTLCsRequired), featureNames,
	)

	featuresB = lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(STXORequired), featureNames,
	)

	require.True(t, featuresA.HasFeature(NoOpHTLCsOptional))
	require.True(t, featuresB.HasFeature(STXOOptional))

	require.False(t, featuresA.HasFeature(STXOOptional))
	require.False(t, featuresB.HasFeature(NoOpHTLCsOptional))

	require.True(t, featuresA.RequiresFeature(NoOpHTLCsOptional))
	require.True(t, featuresB.RequiresFeature(STXOOptional))

	err = checkRequiredBits(
		featuresA.RawFeatureVector, featuresB.RawFeatureVector,
	)

	require.Error(t, err)
}

// TestNegotiatedChanCfgFeature asserts that we advertise the negotiated channel
// config feature as optional. Flipping it to required is a deliberate,
// separate step, as it rejects every peer that doesn't signal the feature.
func TestNegotiatedChanCfgFeature(t *testing.T) {
	local := LocalFeatures()

	require.True(t, local.HasFeature(NegotiatedChanCfgOptional))
	require.False(t, local.RequiresFeature(NegotiatedChanCfgOptional))

	// A peer that doesn't know the feature at all must still pass our
	// required bits check while the feature is optional.
	peer := lnwire.NewRawFeatureVector(NoOpHTLCsOptional, STXOOptional)
	require.NoError(t, checkRequiredBits(getLocalFeatureVec(), peer))

	// Once we require it, such a peer is rejected at init.
	required := lnwire.NewRawFeatureVector(NegotiatedChanCfgRequired)
	require.Error(t, checkRequiredBits(required, peer))

	peer.Set(NegotiatedChanCfgOptional)
	require.NoError(t, checkRequiredBits(required, peer))
}

// TestRbfCoopCloseFeature asserts that we advertise the RBF co-op close
// feature as optional, and that a peer only counts as supporting it when it
// signals the bit itself.
func TestRbfCoopCloseFeature(t *testing.T) {
	local := LocalFeatures()

	require.True(t, local.HasFeature(RbfCoopCloseOptional))
	require.False(t, local.RequiresFeature(RbfCoopCloseOptional))

	// A peer that doesn't know the feature still passes our required
	// bits check, it just won't use the RBF flow for asset channels.
	peer := lnwire.NewRawFeatureVector(NoOpHTLCsOptional, STXOOptional)
	require.NoError(t, checkRequiredBits(getLocalFeatureVec(), peer))

	negotiator := NewAuxChannelNegotiator()
	peerVertex := route.Vertex{1, 2, 3}

	// Without any init records from the peer, the feature is unknown.
	peerFeatures := negotiator.GetPeerFeatures(peerVertex)
	require.False(t, peerFeatures.HasFeature(RbfCoopCloseOptional))

	// Process init records without the bit, it stays unsupported.
	records, err := initRecordsFor(peer)
	require.NoError(t, err)
	require.NoError(t, negotiator.ProcessInitRecords(peerVertex, records))
	peerFeatures = negotiator.GetPeerFeatures(peerVertex)
	require.False(t, peerFeatures.HasFeature(RbfCoopCloseOptional))

	// Once the peer signals the bit, it's supported.
	peer.Set(RbfCoopCloseOptional)
	records, err = initRecordsFor(peer)
	require.NoError(t, err)
	require.NoError(t, negotiator.ProcessInitRecords(peerVertex, records))
	peerFeatures = negotiator.GetPeerFeatures(peerVertex)
	require.True(t, peerFeatures.HasFeature(RbfCoopCloseOptional))
}

// initRecordsFor encodes the given feature vector the way a peer would put it
// into its init message.
func initRecordsFor(features *lnwire.RawFeatureVector) (lnwire.CustomRecords,
	error) {

	var buf bytes.Buffer
	if err := features.Encode(&buf); err != nil {
		return nil, err
	}

	tlvMap := make(tlv.TypeMap, 1)
	tlvMap[AuxFeatureBitsTLV] = buf.Bytes()

	return lnwire.NewCustomRecords(tlvMap)
}
