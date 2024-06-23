package json

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

func NewAsset(a *asset.Asset) (*Asset, error) {
	ja := &Asset{
		Version:             uint8(a.Version),
		GenesisFirstPrevOut: a.Genesis.FirstPrevOut.String(),
		GenesisTag:          a.Genesis.Tag,
		GenesisMetaHash:     hex.EncodeToString(a.Genesis.MetaHash[:]),
		GenesisOutputIndex:  a.Genesis.OutputIndex,
		GenesisType:         uint8(a.Genesis.Type),
		Amount:              a.Amount,
		LockTime:            a.LockTime,
		RelativeLockTime:    a.RelativeLockTime,
		ScriptVersion:       uint16(a.ScriptVersion),
		ScriptKey:           test.HexPubKey(a.ScriptKey.PubKey),
	}

	for _, w := range a.PrevWitnesses {
		jsonWitness, err := NewWitness(w)
		if err != nil {
			return nil, err
		}

		ja.PrevWitnesses = append(ja.PrevWitnesses, jsonWitness)
	}

	if a.SplitCommitmentRoot != nil {
		ja.SplitCommitmentRoot = NewNode(a.SplitCommitmentRoot)
	}

	if a.GroupKey != nil {
		ja.GroupKey = NewGroupKey(a.GroupKey)
	}

	return ja, nil
}

type Asset struct {
	Version             uint8      `json:"version"`
	GenesisFirstPrevOut string     `json:"genesis_first_prev_out"`
	GenesisTag          string     `json:"genesis_tag"`
	GenesisMetaHash     string     `json:"genesis_meta_hash"`
	GenesisOutputIndex  uint32     `json:"genesis_output_index"`
	GenesisType         uint8      `json:"genesis_type"`
	Amount              uint64     `json:"amount"`
	LockTime            uint64     `json:"lock_time"`
	RelativeLockTime    uint64     `json:"relative_lock_time"`
	PrevWitnesses       []*Witness `json:"prev_witnesses"`
	SplitCommitmentRoot *Node      `json:"split_commitment_root"`
	ScriptVersion       uint16     `json:"script_version"`
	ScriptKey           string     `json:"script_key"`
	GroupKey            *GroupKey  `json:"group_key"`
}

func (ta *Asset) ToAsset(t testing.TB) *asset.Asset {
	t.Helper()

	// Validate minimum fields are set. We use panic, so we can actually
	// interpret the error message in the error test cases.
	if ta.GenesisFirstPrevOut == "" || ta.GenesisMetaHash == "" {
		panic("missing genesis fields")
	}

	if ta.ScriptKey == "" {
		panic("missing script key")
	}

	if len(ta.ScriptKey) != test.HexCompressedPubKeyLen {
		panic("invalid script key length")
	}

	if ta.GroupKey != nil {
		if ta.GroupKey.GroupKey == "" {
			panic("missing group key")
		}

		if len(ta.GroupKey.GroupKey) != test.HexCompressedPubKeyLen {
			panic("invalid group key length")
		}
	}

	a := &asset.Asset{
		Version: asset.Version(ta.Version),
		Genesis: asset.Genesis{
			FirstPrevOut: test.ParseOutPoint(
				t, ta.GenesisFirstPrevOut,
			),
			Tag:         ta.GenesisTag,
			MetaHash:    test.Parse32Byte(t, ta.GenesisMetaHash),
			OutputIndex: ta.GenesisOutputIndex,
			Type:        asset.Type(ta.GenesisType),
		},
		Amount:           ta.Amount,
		LockTime:         ta.LockTime,
		RelativeLockTime: ta.RelativeLockTime,
		ScriptVersion:    asset.ScriptVersion(ta.ScriptVersion),
		ScriptKey: asset.ScriptKey{
			PubKey: test.ParsePubKey(t, ta.ScriptKey),
		},
	}

	for _, tw := range ta.PrevWitnesses {
		a.PrevWitnesses = append(
			a.PrevWitnesses, tw.ToWitness(t),
		)
	}

	if ta.SplitCommitmentRoot != nil {
		a.SplitCommitmentRoot = ta.SplitCommitmentRoot.ToNode(t)
	}

	if ta.GroupKey != nil {
		a.GroupKey = ta.GroupKey.ToGroupKey(t)
	}

	return a
}

func NewWitness(w asset.Witness) (*Witness, error) {
	tw := &Witness{}

	if w.PrevID != nil {
		tw.PrevID = NewPrevID(w.PrevID)
	}

	for _, witness := range w.TxWitness {
		tw.TxWitness = append(tw.TxWitness, hex.EncodeToString(witness))
	}

	if w.SplitCommitment != nil {
		var err error
		tw.SplitCommitment, err = NewSplitCommitment(
			w.SplitCommitment,
		)
		if err != nil {
			return nil, err
		}
	}

	return tw, nil
}

type Witness struct {
	PrevID          *PrevID          `json:"prev_id"`
	TxWitness       []string         `json:"tx_witness"`
	SplitCommitment *SplitCommitment `json:"split_commitment"`
}

func (tw *Witness) ToWitness(t testing.TB) asset.Witness {
	t.Helper()

	w := asset.Witness{}
	if tw.PrevID != nil {
		w.PrevID = tw.PrevID.ToPrevID(t)
	}

	for _, witness := range tw.TxWitness {
		w.TxWitness = append(w.TxWitness, test.ParseHex(t, witness))
	}

	if tw.SplitCommitment != nil {
		w.SplitCommitment = tw.SplitCommitment.ToSplitCommitment(t)
	}

	return w
}

func NewPrevID(prevID *asset.PrevID) *PrevID {
	return &PrevID{
		OutPoint:  prevID.OutPoint.String(),
		AssetID:   hex.EncodeToString(prevID.ID[:]),
		ScriptKey: hex.EncodeToString(prevID.ScriptKey[:]),
	}
}

type PrevID struct {
	OutPoint  string `json:"out_point"`
	AssetID   string `json:"asset_id"`
	ScriptKey string `json:"script_key"`
}

func (tpv *PrevID) ToPrevID(t testing.TB) *asset.PrevID {
	if tpv.OutPoint == "" || tpv.AssetID == "" || tpv.ScriptKey == "" {
		return nil
	}

	return &asset.PrevID{
		OutPoint:  test.ParseOutPoint(t, tpv.OutPoint),
		ID:        test.Parse32Byte(t, tpv.AssetID),
		ScriptKey: test.Parse33Byte(t, tpv.ScriptKey),
	}
}

func NewSplitCommitment(sc *asset.SplitCommitment) (*SplitCommitment, error) {
	var buf bytes.Buffer
	err := sc.Proof.Compress().Encode(&buf)
	if err != nil {
		return nil, err
	}

	ra, err := NewAsset(&sc.RootAsset)
	if err != nil {
		return nil, err
	}

	return &SplitCommitment{
		Proof:     hex.EncodeToString(buf.Bytes()),
		RootAsset: ra,
	}, nil
}

type SplitCommitment struct {
	Proof     string `json:"proof"`
	RootAsset *Asset `json:"root_asset"`
}

func (tsc *SplitCommitment) ToSplitCommitment(
	t testing.TB) *asset.SplitCommitment {

	t.Helper()

	p, err := ParseProof(tsc.Proof)
	require.NoError(t, err)

	sc := &asset.SplitCommitment{
		Proof: p,
	}
	if tsc.RootAsset != nil {
		sc.RootAsset = *tsc.RootAsset.ToAsset(t)
	}

	return sc
}

func NewGroupKey(gk *asset.GroupKey) *GroupKey {
	return &GroupKey{
		GroupKey: test.HexPubKey(&gk.GroupPubKey),
	}
}

type GroupKey struct {
	GroupKey string `json:"group_key"`
}

func (tgk *GroupKey) ToGroupKey(t testing.TB) *asset.GroupKey {
	t.Helper()

	return &asset.GroupKey{
		GroupPubKey: *test.ParsePubKey(t, tgk.GroupKey),
	}
}

func NewGenesisReveal(g *asset.Genesis) *GenesisReveal {
	return &GenesisReveal{
		FirstPrevOut: g.FirstPrevOut.String(),
		Tag:          g.Tag,
		MetaHash:     hex.EncodeToString(g.MetaHash[:]),
		OutputIndex:  g.OutputIndex,
		Type:         uint8(g.Type),
	}
}

type GenesisReveal struct {
	FirstPrevOut string `json:"first_prev_out"`
	Tag          string `json:"tag"`
	MetaHash     string `json:"meta_hash"`
	OutputIndex  uint32 `json:"output_index"`
	Type         uint8  `json:"type"`
}

func (tgr *GenesisReveal) ToGenesisReveal(t testing.TB) *asset.Genesis {
	t.Helper()

	return &asset.Genesis{
		FirstPrevOut: test.ParseOutPoint(
			t, tgr.FirstPrevOut,
		),
		Tag:         tgr.Tag,
		MetaHash:    test.Parse32Byte(t, tgr.MetaHash),
		OutputIndex: tgr.OutputIndex,
		Type:        asset.Type(tgr.Type),
	}
}

func NewGroupKeyReveal(gkr *asset.GroupKeyReveal) *GroupKeyReveal {
	return &GroupKeyReveal{
		RawKey:        hex.EncodeToString(gkr.RawKey[:]),
		TapscriptRoot: hex.EncodeToString(gkr.TapscriptRoot),
	}
}

type GroupKeyReveal struct {
	RawKey        string `json:"raw_key"`
	TapscriptRoot string `json:"tapscript_root"`
}

func (gkr *GroupKeyReveal) ToGroupKeyReveal(
	t testing.TB) *asset.GroupKeyReveal {

	t.Helper()

	rawKey := test.ParsePubKey(t, gkr.RawKey)
	tapscriptRoot, err := hex.DecodeString(gkr.TapscriptRoot)
	require.NoError(t, err)

	return &asset.GroupKeyReveal{
		RawKey:        asset.ToSerialized(rawKey),
		TapscriptRoot: tapscriptRoot,
	}
}
