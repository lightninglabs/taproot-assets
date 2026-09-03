package tapchannel

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestUseNegotiatedChanCfg asserts the decision of whether the initial
// commitment is derived from the negotiated channel configs, depending on what
// we and our peer signal.
func TestUseNegotiatedChanCfg(t *testing.T) {
	t.Parallel()

	// The negotiator hands out vectors that know the feature names, which
	// is what makes the required and optional bit a pair.
	names := map[lnwire.FeatureBit]string{
		tapfeatures.NegotiatedChanCfgRequired: "negotiated-chan-cfg",
		tapfeatures.NegotiatedChanCfgOptional: "negotiated-chan-cfg",
	}
	vec := func(bits ...lnwire.FeatureBit) lnwire.FeatureVector {
		return *lnwire.NewFeatureVector(
			lnwire.NewRawFeatureVector(bits...), names,
		)
	}

	testCases := []struct {
		name   string
		local  lnwire.FeatureVector
		peer   lnwire.FeatureVector
		useCfg bool
		err    error
	}{{
		name:   "peer optional, we optional",
		local:  vec(tapfeatures.NegotiatedChanCfgOptional),
		peer:   vec(tapfeatures.NegotiatedChanCfgOptional),
		useCfg: true,
	}, {
		name:   "peer required, we optional",
		local:  vec(tapfeatures.NegotiatedChanCfgOptional),
		peer:   vec(tapfeatures.NegotiatedChanCfgRequired),
		useCfg: true,
	}, {
		name:   "peer optional, we required",
		local:  vec(tapfeatures.NegotiatedChanCfgRequired),
		peer:   vec(tapfeatures.NegotiatedChanCfgOptional),
		useCfg: true,
	}, {
		name:   "peer lacks feature, we optional",
		local:  vec(tapfeatures.NegotiatedChanCfgOptional),
		peer:   vec(tapfeatures.STXOOptional),
		useCfg: false,
	}, {
		name:   "peer lacks feature, no feature bits at all",
		local:  vec(tapfeatures.NegotiatedChanCfgOptional),
		peer:   vec(),
		useCfg: false,
	}, {
		name:  "peer lacks feature, we required",
		local: vec(tapfeatures.NegotiatedChanCfgRequired),
		peer:  vec(tapfeatures.STXOOptional),
		err:   ErrNegotiatedChanCfgRequired,
	}, {
		name:  "peer has no feature bits at all, we required",
		local: vec(tapfeatures.NegotiatedChanCfgRequired),
		peer:  vec(),
		err:   ErrNegotiatedChanCfgRequired,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			useCfg, err := useNegotiatedChanCfg(tc.local, tc.peer)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.False(t, useCfg)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.useCfg, useCfg)
		})
	}

	// The feature vector we actually advertise must lead to the fallback,
	// not a rejection, for peers that don't know the feature yet.
	useCfg, err := useNegotiatedChanCfg(tapfeatures.LocalFeatures(), vec())
	require.NoError(t, err)
	require.False(t, useCfg)
}
