package tapfeatures

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
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
