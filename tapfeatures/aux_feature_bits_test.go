package tapfeatures

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestReleasedSpenderFeatureBits preserves the wire assignments of v0.8.5
// independently of mainline's negotiated channel configuration feature.
func TestReleasedSpenderFeatureBits(t *testing.T) {
	t.Parallel()

	require.Equal(t, lnwire.FeatureBit(4), STXOSpenderRequired)
	require.Equal(t, lnwire.FeatureBit(5), STXOSpenderOptional)
	require.Equal(t, lnwire.FeatureBit(6), NegotiatedChanCfgRequired)
	require.Equal(t, lnwire.FeatureBit(7), NegotiatedChanCfgOptional)

	features := LocalFeatures()
	require.True(t, features.HasFeature(STXOSpenderRequired))
	require.True(t, features.HasFeature(NegotiatedChanCfgRequired))
}
