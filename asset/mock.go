package asset

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// RandGenesis creates a random genesis for testing.
func RandGenesis(t testing.TB, assetType Type) Genesis {
	t.Helper()

	var metaHash [32]byte
	test.RandRead(t, metaHash[:])

	return Genesis{
		FirstPrevOut: test.RandOp(t),
		Tag:          hex.EncodeToString(metaHash[:]),
		MetaHash:     metaHash,
		OutputIndex:  uint32(test.RandInt[int32]()),
		Type:         assetType,
	}
}

// RandGroupKey creates a random group key for testing.
func RandGroupKey(t testing.TB, genesis Genesis) *GroupKey {
	privateKey := test.RandPrivKey(t)

	genSigner := NewRawKeyGenesisSigner(privateKey)

	groupKey, err := DeriveGroupKey(
		genSigner, test.PubToKeyDesc(privateKey.PubKey()),
		genesis, nil,
	)
	require.NoError(t, err)
	return groupKey
}

// RandGroupKeyWithSigner creates a random group key for testing, and provides
// the signer for reissuing assets into the same group.
func RandGroupKeyWithSigner(t testing.TB, genesis Genesis) (*GroupKey, []byte) {
	privateKey := test.RandPrivKey(t)

	genSigner := NewRawKeyGenesisSigner(privateKey)
	groupKey, err := DeriveGroupKey(
		genSigner, test.PubToKeyDesc(privateKey.PubKey()),
		genesis, nil,
	)
	require.NoError(t, err)

	return groupKey, privateKey.Serialize()
}

// RandScriptKey creates a random script key for testing.
func RandScriptKey(t testing.TB) ScriptKey {
	return NewScriptKey(test.RandPrivKey(t).PubKey())
}

// RandSerializedKey creates a random serialized key for testing.
func RandSerializedKey(t testing.TB) SerializedKey {
	return ToSerialized(test.RandPrivKey(t).PubKey())
}

// RandID creates a random asset ID.
func RandID(t testing.TB) ID {
	var a ID
	test.RandRead(t, a[:])

	return a
}

// RandAsset creates a random asset of the given type for testing.
func RandAsset(t testing.TB, assetType Type) *Asset {
	t.Helper()

	genesis := RandGenesis(t, assetType)
	familyKey := RandGroupKey(t, genesis)
	scriptKey := RandScriptKey(t)

	return RandAssetWithValues(t, genesis, familyKey, scriptKey)
}

// RandAssetWithValues creates a random asset with the given genesis and keys
// for testing.
func RandAssetWithValues(t testing.TB, genesis Genesis, groupKey *GroupKey,
	scriptKey ScriptKey) *Asset {

	t.Helper()

	units := test.RandInt[uint64]() + 1

	switch genesis.Type {
	case Normal:

	case Collectible:
		units = 1

	default:
		t.Fatal("unhandled asset type", genesis.Type)
	}

	a, err := New(genesis, units, 0, 0, scriptKey, groupKey)
	require.NoError(t, err)

	return a
}

type ValidTestCase struct {
	Asset    *TestAsset `json:"asset"`
	Expected string     `json:"expected"`
	Comment  string     `json:"comment"`
}

type ErrorTestCase struct {
	Asset   *TestAsset `json:"asset"`
	Error   string     `json:"error"`
	Comment string     `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func NewTestFromAsset(t testing.TB, a *Asset) *TestAsset {
	ta := &TestAsset{
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
		ta.PrevWitnesses = append(
			ta.PrevWitnesses, NewTestFromWitness(t, w),
		)
	}

	if a.SplitCommitmentRoot != nil {
		ta.SplitCommitmentRoot = mssmt.NewTestFromNode(
			t, a.SplitCommitmentRoot,
		)
	}

	if a.GroupKey != nil {
		ta.GroupKey = NewTestFromGroupKey(t, a.GroupKey)
	}

	return ta
}

type TestAsset struct {
	Version             uint8           `json:"version"`
	GenesisFirstPrevOut string          `json:"genesis_first_prev_out"`
	GenesisTag          string          `json:"genesis_tag"`
	GenesisMetaHash     string          `json:"genesis_meta_hash"`
	GenesisOutputIndex  uint32          `json:"genesis_output_index"`
	GenesisType         uint8           `json:"genesis_type"`
	Amount              uint64          `json:"amount"`
	LockTime            uint64          `json:"lock_time"`
	RelativeLockTime    uint64          `json:"relative_lock_time"`
	PrevWitnesses       []*TestWitness  `json:"prev_witnesses"`
	SplitCommitmentRoot *mssmt.TestNode `json:"split_commitment_root"`
	ScriptVersion       uint16          `json:"script_version"`
	ScriptKey           string          `json:"script_key"`
	GroupKey            *TestGroupKey   `json:"group_key"`
}

func (ta *TestAsset) ToAsset(t testing.TB) *Asset {
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

	a := &Asset{
		Version: Version(ta.Version),
		Genesis: Genesis{
			FirstPrevOut: test.ParseOutPoint(
				t, ta.GenesisFirstPrevOut,
			),
			Tag:         ta.GenesisTag,
			MetaHash:    test.Parse32Byte(t, ta.GenesisMetaHash),
			OutputIndex: ta.GenesisOutputIndex,
			Type:        Type(ta.GenesisType),
		},
		Amount:           ta.Amount,
		LockTime:         ta.LockTime,
		RelativeLockTime: ta.RelativeLockTime,
		ScriptVersion:    ScriptVersion(ta.ScriptVersion),
		ScriptKey: ScriptKey{
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

func NewTestFromWitness(t testing.TB, w Witness) *TestWitness {
	t.Helper()

	tw := &TestWitness{}

	if w.PrevID != nil {
		tw.PrevID = NewTestFromPrevID(w.PrevID)
	}

	for _, witness := range w.TxWitness {
		tw.TxWitness = append(tw.TxWitness, hex.EncodeToString(witness))
	}

	if w.SplitCommitment != nil {
		tw.SplitCommitment = NewTestFromSplitCommitment(
			t, w.SplitCommitment,
		)
	}

	return tw
}

type TestWitness struct {
	PrevID          *TestPrevID          `json:"prev_id"`
	TxWitness       []string             `json:"tx_witness"`
	SplitCommitment *TestSplitCommitment `json:"split_commitment"`
}

func (tw *TestWitness) ToWitness(t testing.TB) Witness {
	t.Helper()

	w := Witness{}
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

func NewTestFromPrevID(prevID *PrevID) *TestPrevID {
	return &TestPrevID{
		OutPoint:  prevID.OutPoint.String(),
		AssetID:   hex.EncodeToString(prevID.ID[:]),
		ScriptKey: hex.EncodeToString(prevID.ScriptKey[:]),
	}
}

type TestPrevID struct {
	OutPoint  string `json:"out_point"`
	AssetID   string `json:"asset_id"`
	ScriptKey string `json:"script_key"`
}

func (tpv *TestPrevID) ToPrevID(t testing.TB) *PrevID {
	if tpv.OutPoint == "" || tpv.AssetID == "" || tpv.ScriptKey == "" {
		return nil
	}

	return &PrevID{
		OutPoint:  test.ParseOutPoint(t, tpv.OutPoint),
		ID:        test.Parse32Byte(t, tpv.AssetID),
		ScriptKey: test.Parse33Byte(t, tpv.ScriptKey),
	}
}

func NewTestFromSplitCommitment(t testing.TB,
	sc *SplitCommitment) *TestSplitCommitment {

	t.Helper()

	var buf bytes.Buffer
	err := sc.Proof.Compress().Encode(&buf)
	require.NoError(t, err)

	return &TestSplitCommitment{
		Proof:     hex.EncodeToString(buf.Bytes()),
		RootAsset: NewTestFromAsset(t, &sc.RootAsset),
	}
}

type TestSplitCommitment struct {
	Proof     string     `json:"proof"`
	RootAsset *TestAsset `json:"root_asset"`
}

func (tsc *TestSplitCommitment) ToSplitCommitment(
	t testing.TB) *SplitCommitment {

	t.Helper()

	sc := &SplitCommitment{
		Proof: mssmt.ParseProof(t, tsc.Proof),
	}
	if tsc.RootAsset != nil {
		sc.RootAsset = *tsc.RootAsset.ToAsset(t)
	}

	return sc
}

func NewTestFromGroupKey(t testing.TB, gk *GroupKey) *TestGroupKey {
	t.Helper()

	return &TestGroupKey{
		GroupKey:    test.HexPubKey(&gk.GroupPubKey),
		GroupKeySig: test.HexSignature(&gk.Sig),
	}
}

type TestGroupKey struct {
	GroupKey    string `json:"group_key"`
	GroupKeySig string `json:"group_key_sig"`
}

func (tgk *TestGroupKey) ToGroupKey(t testing.TB) *GroupKey {
	t.Helper()

	return &GroupKey{
		GroupPubKey: *test.ParsePubKey(t, tgk.GroupKey),
		Sig:         *test.ParseSchnorrSig(t, tgk.GroupKeySig),
	}
}

type TestScriptKey struct {
}

type ValidBurnTestCase struct {
	PrevID   *TestPrevID `json:"prev_id"`
	Expected string      `json:"expected"`
	Comment  string      `json:"comment"`
}

type BurnTestVectors struct {
	ValidTestCases []*ValidBurnTestCase `json:"valid_test_cases"`
}
