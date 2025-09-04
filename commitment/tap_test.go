package commitment

import (
	"crypto/sha256"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

var (
	// markerV2 is the marker tag for Taproot Assets used in V2 commitments.
	markerV2 = []byte(taprootAssetsMarkerTag + ":194243")
)

// randTapCommitment generates a random Taproot commitment for the given
// assetVersion.
func randTapCommitment(t *testing.T, commitVersion *TapCommitmentVersion,
	assetVersion asset.Version) *TapCommitment {

	t.Helper()
	randAssetType := test.RandFlip(asset.Normal, asset.Collectible)
	randGenesis := asset.RandGenesis(t, randAssetType)
	randAsset := randAsset(t, randGenesis, nil)

	randAsset.Version = assetVersion

	tapCommitment, err := FromAssets(commitVersion, randAsset)
	require.NoError(t, err)

	return tapCommitment
}

// TestTaprootAssetsMarkerV0 tests if it can find the TaprootAssetsMarker V0 at
// the correct spot according to the legacy MarkerV0 digest with assetVersion 0
// and 1.
func TestTaprootAssetsMarkerV0(t *testing.T) {
	t.Parallel()

	assetVersions := []asset.Version{asset.V0, asset.V1}
	for _, assetVersion := range assetVersions {
		// Create a random Taproot commitment, and extract the tapLeaf
		// script.
		randTapCommitment := randTapCommitment(t, nil, assetVersion)
		tapLeaf := randTapCommitment.TapLeaf()
		script := tapLeaf.Script

		require.Equal(t, byte(assetVersion), script[0])
		require.Equal(t, TaprootAssetsMarker[:], script[1:33])
	}
}

// TestTaprootAssetsMarkerV1 tests if it can find the TaprootAssetsMarker V2 at
// the correct spot according to the MarkerV1 digest with assetVersion 0 and 1.
func TestTaprootAssetsMarkerV1(t *testing.T) {
	t.Parallel()

	assetVersions := []asset.Version{asset.V0, asset.V1}
	for _, assetVersion := range assetVersions {
		// Create a random Taproot commitment, and extract the tapLeaf
		// script.
		randTapCommitment := randTapCommitment(
			t, fn.Ptr(TapCommitmentV2), assetVersion,
		)

		// Check if MarkerVersion is set to MarkerV2, which should be
		// the default.
		require.Equal(t, randTapCommitment.Version, TapCommitmentV2)

		tapLeaf := randTapCommitment.TapLeaf()
		script := tapLeaf.Script

		tag := sha256.Sum256(markerV2)
		require.Equal(t, tag[:], script[:32])
		require.Equal(t, byte(TapCommitmentV2), script[32])
	}
}
