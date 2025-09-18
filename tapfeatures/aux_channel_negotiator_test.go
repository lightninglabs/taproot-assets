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
