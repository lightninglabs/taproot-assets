package commitment

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
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

func NewTestFromProof(t testing.TB, p *Proof) *TestProof {
	t.Helper()

	tp := &TestProof{
		TaprootAssetProof: &TestTaprootAssetProof{
			Proof:   mssmt.HexProof(t, &p.TaprootAssetProof.Proof),
			Version: uint8(p.TaprootAssetProof.Version),
		},
	}
	if p.AssetProof != nil {
		tp.AssetProof = &TestAssetProof{
			Proof:   mssmt.HexProof(t, &p.AssetProof.Proof),
			Version: uint8(p.AssetProof.Version),
			AssetID: hex.EncodeToString(p.AssetProof.AssetID[:]),
		}
	}

	return tp
}

type TestProof struct {
	AssetProof        *TestAssetProof        `json:"asset_proof"`
	TaprootAssetProof *TestTaprootAssetProof `json:"taproot_asset_proof"`
}

func (tp *TestProof) ToProof(t testing.TB) *Proof {
	t.Helper()

	p := &Proof{
		TaprootAssetProof: TaprootAssetProof{
			Proof: mssmt.ParseProof(
				t, tp.TaprootAssetProof.Proof,
			),
			Version: asset.Version(tp.AssetProof.Version),
		},
	}
	if tp.AssetProof != nil {
		p.AssetProof = &AssetProof{
			Proof:   mssmt.ParseProof(t, tp.AssetProof.Proof),
			Version: asset.Version(tp.AssetProof.Version),
		}
		assetID, err := hex.DecodeString(tp.AssetProof.AssetID)
		require.NoError(t, err)
		copy(p.AssetProof.AssetID[:], assetID)
	}

	return p
}

type TestAssetProof struct {
	Proof   string `json:"proof"`
	Version uint8  `json:"version"`
	AssetID string `json:"asset_id"`
}

type TestTaprootAssetProof struct {
	Proof   string `json:"proof"`
	Version uint8  `json:"version"`
}
