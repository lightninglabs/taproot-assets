package tapfeatures

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
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

// TestRequiredSTXOFeatures tests that the negotiator advertises the
// stxo-proofs and stxo-spender features as required, and rejects a peer that
// doesn't support both of them.
func TestRequiredSTXOFeatures(t *testing.T) {
	t.Parallel()

	negotiator := NewAuxChannelNegotiator()

	records, err := negotiator.GetInitRecords(route.Vertex{})
	require.NoError(t, err)

	local := lnwire.NewRawFeatureVector()
	err = local.Decode(bytes.NewReader(records[uint64(AuxFeatureBitsTLV)]))
	require.NoError(t, err)
	require.True(t, local.IsSet(STXORequired))
	require.True(t, local.IsSet(STXOSpenderRequired))
	require.False(t, local.IsSet(STXOOptional))
	require.False(t, local.IsSet(STXOSpenderOptional))

	testCases := []struct {
		name  string
		bits  []lnwire.FeatureBit
		valid bool
	}{{
		name: "no stxo features",
		bits: []lnwire.FeatureBit{NoOpHTLCsOptional},
	}, {
		name: "stxo-proofs only",
		bits: []lnwire.FeatureBit{NoOpHTLCsOptional, STXOOptional},
	}, {
		name: "stxo-spender only",
		bits: []lnwire.FeatureBit{
			NoOpHTLCsOptional, STXOSpenderOptional,
		},
	}, {
		name: "optional stxo features",
		bits: []lnwire.FeatureBit{
			NoOpHTLCsOptional, STXOOptional, STXOSpenderOptional,
		},
		valid: true,
	}, {
		name: "required stxo features",
		bits: []lnwire.FeatureBit{
			NoOpHTLCsOptional, STXORequired, STXOSpenderRequired,
		},
		valid: true,
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := lnwire.NewRawFeatureVector(tc.bits...).Encode(
				&buf,
			)
			require.NoError(t, err)

			err = negotiator.ProcessInitRecords(
				route.Vertex{0x01}, lnwire.CustomRecords{
					uint64(AuxFeatureBitsTLV): buf.Bytes(),
				},
			)
			if !tc.valid {
				require.ErrorContains(
					t, err, "does not support required",
				)
				return
			}

			require.NoError(t, err)
		})
	}
}
