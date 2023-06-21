package commitment

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
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
		context.Background(), []SplitCommitmentInput{{
			Asset:    &a,
			OutPoint: test.RandOp(t),
		}}, &rootLoc, &splitLoc,
	)
	require.NoError(t, err)

	assetSplit := split.SplitAssets[splitLoc].PrevWitnesses[0]

	return assetSplit.SplitCommitment
}

func HexTapscriptSibling(t testing.TB, ts *TapscriptPreimage) string {
	if ts.IsEmpty() {
		return ""
	}

	siblingBytes, _, err := MaybeEncodeTapscriptPreimage(ts)
	require.NoError(t, err)

	return hex.EncodeToString(siblingBytes)
}

func ParseTapscriptSibling(t testing.TB, ts string) *TapscriptPreimage {
	if ts == "" {
		return nil
	}

	siblingHex, _, err := MaybeDecodeTapscriptPreimage(test.ParseHex(t, ts))
	require.NoError(t, err)

	return siblingHex
}
