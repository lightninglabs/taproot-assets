package commitment

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
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
			TapKey:  hex.EncodeToString(p.AssetProof.TapKey[:]),
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
			Version: asset.Version(tp.TaprootAssetProof.Version),
		},
	}
	if tp.AssetProof != nil {
		p.AssetProof = &AssetProof{
			Proof:   mssmt.ParseProof(t, tp.AssetProof.Proof),
			Version: asset.Version(tp.AssetProof.Version),
		}
		assetID, err := hex.DecodeString(tp.AssetProof.TapKey)
		require.NoError(t, err)
		copy(p.AssetProof.TapKey[:], assetID)
	}

	return p
}

type TestAssetProof struct {
	Proof   string `json:"proof"`
	Version uint8  `json:"version"`
	TapKey  string `json:"tap_key"`
}

type TestTaprootAssetProof struct {
	Proof   string `json:"proof"`
	Version uint8  `json:"version"`
}

func NewTestFromSplitSet(t testing.TB, s SplitSet) TestSplitSet {
	t.Helper()

	ts := make([]*TestSplitEntry, 0, len(s))

	// We want stable ordering for the test vectors, so we loop over the
	// sorted keys.
	keys := maps.Keys(s)
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].OutputIndex < keys[j].OutputIndex
	})
	for keyIndex := range keys {
		key := keys[keyIndex]
		ts = append(ts, &TestSplitEntry{
			Locator: &TestSplitLocator{
				OutputIndex: key.OutputIndex,
				AssetID:     key.AssetID.String(),
				ScriptKey: hex.EncodeToString(
					key.ScriptKey[:],
				),
				Amount: key.Amount,
			},
			Asset: &TestSplitAsset{
				Asset: asset.NewTestFromAsset(
					t, &s[key].Asset,
				),
				OutputIndex: s[key].OutputIndex,
			},
		})
	}

	return ts
}

type TestSplitSet []*TestSplitEntry

func (ts TestSplitSet) ToSplitSet(t testing.TB) SplitSet {
	t.Helper()

	s := make(SplitSet, len(ts))
	for idx := range ts {
		e := ts[idx]
		key := SplitLocator{
			OutputIndex: e.Locator.OutputIndex,
			AssetID:     test.Parse32Byte(t, e.Locator.AssetID),
			ScriptKey:   test.Parse33Byte(t, e.Locator.ScriptKey),
			Amount:      e.Locator.Amount,
		}

		// We'll allow empty assets here.
		var (
			parsedAsset asset.Asset
			emptyAsset  = asset.NewTestFromAsset(t, &asset.Asset{})
		)
		if !reflect.DeepEqual(e.Asset.Asset, emptyAsset) {
			parsedAsset = *e.Asset.Asset.ToAsset(t)
		}

		s[key] = &SplitAsset{
			Asset:       parsedAsset,
			OutputIndex: e.Asset.OutputIndex,
		}
	}

	return s
}

type TestSplitEntry struct {
	Locator *TestSplitLocator `json:"key"`
	Asset   *TestSplitAsset   `json:"value"`
}

type TestSplitLocator struct {
	OutputIndex uint32 `json:"output_index"`
	AssetID     string `json:"asset_id"`
	ScriptKey   string `json:"script_key"`
	Amount      uint64 `json:"amount"`
}

type TestSplitAsset struct {
	Asset       *asset.TestAsset `json:"asset"`
	OutputIndex uint32           `json:"output_index"`
}

func NewTestFromInputSet(t testing.TB, i InputSet) TestInputSet {
	t.Helper()

	ts := make([]*TestInputEntry, 0, len(i))

	// We want stable ordering for the test vectors, so we loop over the
	// sorted keys.
	keys := maps.Keys(i)
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(
			keys[i].ScriptKey[:], keys[j].ScriptKey[:],
		) < 0
	})
	for keyIndex := range keys {
		key := keys[keyIndex]
		ts = append(ts, &TestInputEntry{
			PrevID: asset.NewTestFromPrevID(&key),
			Asset:  asset.NewTestFromAsset(t, i[key]),
		})
	}

	return ts
}

type TestInputSet []*TestInputEntry

func (ts TestInputSet) ToInputSet(t testing.TB) InputSet {
	t.Helper()

	i := make(InputSet, len(ts))
	for idx := range ts {
		e := ts[idx]
		key := e.PrevID.ToPrevID(t)
		i[*key] = e.Asset.ToAsset(t)
	}

	return i
}

type TestInputEntry struct {
	PrevID *asset.TestPrevID `json:"prev_id"`
	Asset  *asset.TestAsset  `json:"asset"`
}
