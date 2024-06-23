package commitment

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// RandSplitCommit creates a random split commitment for testing.
func RandSplitCommit(t testing.TB, a asset.Asset) *asset.SplitCommitment {
	// 50/50 chance there's no commitment at all.
	if test.RandBool() {
		return nil
	}

	rootLoc := commitment.SplitLocator{
		OutputIndex: uint32(test.RandInt[int32]()),
		AssetID:     assetmock.RandID(t),
		Amount:      a.Amount / 2,
		ScriptKey:   asset.ToSerialized(test.RandPubKey(t)),
	}
	splitLoc := commitment.SplitLocator{
		OutputIndex: uint32(test.RandInt[int32]()),
		AssetID:     assetmock.RandID(t),
		Amount:      a.Amount / 2,
		ScriptKey:   asset.ToSerialized(test.RandPubKey(t)),
	}

	split, err := commitment.NewSplitCommitment(
		context.Background(), []commitment.SplitCommitmentInput{{
			Asset:    &a,
			OutPoint: test.RandOp(t),
		}}, &rootLoc, &splitLoc,
	)
	require.NoError(t, err)

	assetSplit := split.SplitAssets[splitLoc].PrevWitnesses[0]

	return assetSplit.SplitCommitment
}
