package commitment

import (
	"testing"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/stretchr/testify/require"
)

// RandSplitCommit creates a random split commitment for testing.
func RandSplitCommit(t testing.TB, a asset.Asset) *asset.SplitCommitment {
	// 50/50 chance there's no commitment at all.
	if test.RandBool() {
		return nil
	}

	rootLoc := SplitLocator{
		OutputIndex: uint32(test.RandInt[int32]()),
		AssetID:     asset.RandID(t),
		Amount:      a.Amount / 2,
		ScriptKey:   asset.ToSerialized(test.RandPubKey(t)),
	}
	splitLoc := SplitLocator{
		OutputIndex: uint32(test.RandInt[int32]()),
		AssetID:     asset.RandID(t),
		Amount:      a.Amount / 2,
		ScriptKey:   asset.ToSerialized(test.RandPubKey(t)),
	}

	split, err := NewSplitCommitment(
		&a, test.RandOp(t), &rootLoc, &splitLoc,
	)
	require.NoError(t, err)

	assetSplit := split.SplitAssets[splitLoc].PrevWitnesses[0]

	return assetSplit.SplitCommitment
}
