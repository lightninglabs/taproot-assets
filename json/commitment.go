package json

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func ParseProof(proofHex string) (mssmt.Proof, error) {
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return mssmt.Proof{}, err
	}

	var compressedProof mssmt.CompressedProof
	err = compressedProof.Decode(bytes.NewReader(proofBytes))
	if err != nil {
		return mssmt.Proof{}, err
	}

	proof, err := compressedProof.Decompress()
	if err != nil {
		return mssmt.Proof{}, err
	}

	return *proof, nil
}

func HexProof(proof *mssmt.Proof) (string, error) {
	compressedProof := proof.Compress()

	var buf bytes.Buffer
	err := compressedProof.Encode(&buf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func HexTapscriptSibling(ts *commitment.TapscriptPreimage) (string, error) {
	if ts.IsEmpty() {
		return "", nil
	}

	siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(ts)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(siblingBytes), nil
}

func ParseTapscriptSibling(t testing.TB,
	ts string) *commitment.TapscriptPreimage {

	if ts == "" {
		return nil
	}

	siblingHex, _, err := commitment.MaybeDecodeTapscriptPreimage(
		test.ParseHex(t, ts),
	)
	require.NoError(t, err)

	return siblingHex
}

func NewCommitmentProof(p *commitment.Proof) (*CommitmentProof, error) {
	tapProof, err := HexProof(&p.TaprootAssetProof.Proof)
	if err != nil {
		return nil, err
	}

	tp := &CommitmentProof{
		TaprootAssetProof: &TaprootAssetProof{
			Proof:   tapProof,
			Version: uint8(p.TaprootAssetProof.Version),
		},
	}
	if p.AssetProof != nil {
		assetProof, err := HexProof(&p.AssetProof.Proof)
		if err != nil {
			return nil, err
		}

		tp.AssetProof = &AssetProof{
			Proof:   assetProof,
			Version: uint8(p.AssetProof.Version),
			TapKey:  hex.EncodeToString(p.AssetProof.TapKey[:]),
		}
	}

	return tp, nil
}

type CommitmentProof struct {
	AssetProof        *AssetProof        `json:"asset_proof"`
	TaprootAssetProof *TaprootAssetProof `json:"taproot_asset_proof"`
}

func (tp *CommitmentProof) ToProof(t testing.TB) *commitment.Proof {
	t.Helper()

	tapProof, err := ParseProof(tp.TaprootAssetProof.Proof)
	require.NoError(t, err)

	p := &commitment.Proof{
		TaprootAssetProof: commitment.TaprootAssetProof{
			Proof: tapProof,
			Version: commitment.TapCommitmentVersion(
				tp.TaprootAssetProof.Version,
			),
		},
	}
	if tp.AssetProof != nil {
		assetProof, err := ParseProof(tp.AssetProof.Proof)
		require.NoError(t, err)

		p.AssetProof = &commitment.AssetProof{
			Proof:   assetProof,
			Version: asset.Version(tp.AssetProof.Version),
		}
		assetID, err := hex.DecodeString(tp.AssetProof.TapKey)
		require.NoError(t, err)
		copy(p.AssetProof.TapKey[:], assetID)
	}

	return p
}

type AssetProof struct {
	Proof   string `json:"proof"`
	Version uint8  `json:"version"`
	TapKey  string `json:"tap_key"`
}

type TaprootAssetProof struct {
	Proof   string `json:"proof"`
	Version uint8  `json:"version"`
}

func NewSplitSet(s commitment.SplitSet) (SplitSet, error) {
	ts := make([]*SplitEntry, 0, len(s))

	// We want stable ordering for the test vectors, so we loop over the
	// sorted keys.
	keys := maps.Keys(s)
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].OutputIndex < keys[j].OutputIndex
	})
	for keyIndex := range keys {
		key := keys[keyIndex]
		a, err := NewAsset(&s[key].Asset)
		if err != nil {
			return nil, err
		}

		ts = append(ts, &SplitEntry{
			Locator: &SplitLocator{
				OutputIndex: key.OutputIndex,
				AssetID:     key.AssetID.String(),
				ScriptKey: hex.EncodeToString(
					key.ScriptKey[:],
				),
				Amount: key.Amount,
			},
			Asset: &SplitAsset{
				Asset:       a,
				OutputIndex: s[key].OutputIndex,
			},
		})
	}

	return ts, nil
}

type SplitSet []*SplitEntry

func (ts SplitSet) ToSplitSet(t testing.TB) commitment.SplitSet {
	t.Helper()

	s := make(commitment.SplitSet, len(ts))
	for idx := range ts {
		e := ts[idx]
		key := commitment.SplitLocator{
			OutputIndex: e.Locator.OutputIndex,
			AssetID:     test.Parse32Byte(t, e.Locator.AssetID),
			ScriptKey:   test.Parse33Byte(t, e.Locator.ScriptKey),
			Amount:      e.Locator.Amount,
		}

		// We'll allow empty assets here.
		var (
			parsedAsset   asset.Asset
			emptyAsset, _ = NewAsset(&asset.Asset{})
		)
		if !reflect.DeepEqual(e.Asset.Asset, emptyAsset) {
			parsedAsset = *e.Asset.Asset.ToAsset(t)
		}

		s[key] = &commitment.SplitAsset{
			Asset:       parsedAsset,
			OutputIndex: e.Asset.OutputIndex,
		}
	}

	return s
}

type SplitEntry struct {
	Locator *SplitLocator `json:"key"`
	Asset   *SplitAsset   `json:"value"`
}

type SplitLocator struct {
	OutputIndex uint32 `json:"output_index"`
	AssetID     string `json:"asset_id"`
	ScriptKey   string `json:"script_key"`
	Amount      uint64 `json:"amount"`
}

type SplitAsset struct {
	Asset       *Asset `json:"asset"`
	OutputIndex uint32 `json:"output_index"`
}

func NewInputSet(i commitment.InputSet) (InputSet, error) {
	ts := make([]*InputEntry, 0, len(i))

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
		a, err := NewAsset(i[key])
		if err != nil {
			return nil, err
		}

		ts = append(ts, &InputEntry{
			PrevID: NewPrevID(&key),
			Asset:  a,
		})
	}

	return ts, nil
}

type InputSet []*InputEntry

func (ts InputSet) ToInputSet(t testing.TB) commitment.InputSet {
	t.Helper()

	i := make(commitment.InputSet, len(ts))
	for idx := range ts {
		e := ts[idx]
		key := e.PrevID.ToPrevID(t)
		i[*key] = e.Asset.ToAsset(t)
	}

	return i
}

type InputEntry struct {
	PrevID *PrevID `json:"prev_id"`
	Asset  *Asset  `json:"asset"`
}
