package tappsbt

import (
	"bytes"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	testParams = &address.MainNetTap

	// Block 100002 with 9 transactions on bitcoin mainnet.
	oddTxBlockHexFileName = filepath.Join(
		testDataFileName, "odd-block.hex",
	)
)

// RandPacket generates a random virtual packet for testing purposes.
func RandPacket(t testing.TB) *VPacket {
	testPubKey := test.RandPubKey(t)
	op := test.RandOp(t)
	keyDesc := keychain.KeyDescriptor{
		PubKey: testPubKey,
		KeyLocator: keychain.KeyLocator{
			Family: 123,
			Index:  456,
		},
	}
	inputScriptKey := asset.ScriptKey{
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keyDesc,
			Tweak:  []byte("merkle root"),
		},
	}
	inputScriptKey.PubKey = txscript.ComputeTaprootOutputKey(
		keyDesc.PubKey, inputScriptKey.Tweak,
	)

	bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
		keyDesc, testParams.HDCoinType,
	)
	bip32Derivations := []*psbt.Bip32Derivation{bip32Derivation}
	trBip32Derivations := []*psbt.TaprootBip32Derivation{trBip32Derivation}
	testAsset := asset.RandAsset(t, asset.Normal)
	testAsset.ScriptKey = inputScriptKey

	testOutputAsset := asset.RandAsset(t, asset.Normal)
	testOutputAsset.ScriptKey = asset.NewScriptKeyBip86(keyDesc)

	// The raw key won't be serialized within the asset, so let's blank it
	// out here to get a fully, byte-by-byte comparable PSBT.
	testAsset.GroupKey.RawKey = keychain.KeyDescriptor{}
	testAsset.GroupKey.Witness = nil
	testOutputAsset.GroupKey.RawKey = keychain.KeyDescriptor{}
	testOutputAsset.GroupKey.Witness = nil
	testOutputAsset.ScriptKey.TweakedScriptKey = nil
	leaf1 := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      []byte("not a valid script"),
	}
	testPreimage1, err := commitment.NewPreimageFromLeaf(leaf1)
	require.NoError(t, err)
	testPreimage2 := commitment.NewPreimageFromBranch(
		txscript.NewTapBranch(leaf1, leaf1),
	)

	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	inputProof := proof.RandProof(
		t, testAsset.Genesis, inputScriptKey.PubKey, oddTxBlock, 1, 0,
	)

	courierAddress, err := url.Parse("https://example.com")
	require.NoError(t, err)

	vPacket := &VPacket{
		Inputs: []*VInput{{
			PrevID: asset.PrevID{
				OutPoint:  op,
				ID:        asset.RandID(t),
				ScriptKey: asset.RandSerializedKey(t),
			},
			Anchor: Anchor{
				Value:             777,
				PkScript:          []byte("anchor pkscript"),
				SigHashType:       txscript.SigHashSingle,
				InternalKey:       testPubKey,
				MerkleRoot:        []byte("merkle root"),
				TapscriptSibling:  []byte("sibling"),
				Bip32Derivation:   bip32Derivations,
				TrBip32Derivation: trBip32Derivations,
			},
			Proof: &inputProof,
		}, {
			// Empty input.
		}},
		Outputs: []*VOutput{{
			Amount: 123,
			AssetVersion: asset.Version(
				test.RandIntn(2),
			),
			Type:                               TypeSplitRoot,
			Interactive:                        true,
			AnchorOutputIndex:                  0,
			AnchorOutputInternalKey:            testPubKey,
			AnchorOutputBip32Derivation:        bip32Derivations,
			AnchorOutputTaprootBip32Derivation: trBip32Derivations,
			Asset:                              testOutputAsset,
			ScriptKey:                          testOutputAsset.ScriptKey,
			SplitAsset:                         testOutputAsset,
			AnchorOutputTapscriptSibling:       testPreimage1,
			ProofDeliveryAddress:               courierAddress,
			ProofSuffix:                        &inputProof,
		}, {
			Amount: 345,
			AssetVersion: asset.Version(
				test.RandIntn(2),
			),
			Type:                               TypeSplitRoot,
			Interactive:                        false,
			AnchorOutputIndex:                  1,
			AnchorOutputInternalKey:            testPubKey,
			AnchorOutputBip32Derivation:        bip32Derivations,
			AnchorOutputTaprootBip32Derivation: trBip32Derivations,
			Asset:                              testOutputAsset,
			ScriptKey:                          testOutputAsset.ScriptKey,
			AnchorOutputTapscriptSibling:       &testPreimage2,
		}},
		ChainParams: testParams,
	}
	vPacket.SetInputAsset(0, testAsset)

	return vPacket
}

type ValidTestCase struct {
	Packet   *TestVPacket `json:"packet"`
	Expected string       `json:"expected"`
	Comment  string       `json:"comment"`
}

type ErrorTestCase struct {
	Packet  *TestVPacket `json:"packet"`
	Error   string       `json:"error"`
	Comment string       `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func NewTestFromVPacket(t testing.TB, p *VPacket) *TestVPacket {
	tp := &TestVPacket{
		Version:        p.Version,
		ChainParamsHRP: p.ChainParams.TapHRP,
	}

	for idx := range p.Inputs {
		tp.Inputs = append(
			tp.Inputs, NewTestFromVInput(t, p.Inputs[idx]),
		)
	}

	for idx := range p.Outputs {
		tp.Outputs = append(tp.Outputs, NewTestFromVOutput(
			t, p.Outputs[idx], p.ChainParams.HDCoinType,
		))
	}

	return tp
}

type TestVPacket struct {
	Inputs         []*TestVInput  `json:"inputs"`
	Outputs        []*TestVOutput `json:"outputs"`
	Version        uint8          `json:"version"`
	ChainParamsHRP string         `json:"chain_params_hrp"`
}

func (tp *TestVPacket) ToVPacket(t testing.TB) *VPacket {
	t.Helper()

	// Validate minimum fields are set. We use panic, so we can actually
	// interpret the error message in the error test cases.
	if tp.ChainParamsHRP == "" {
		panic("missing chain params HRP")
	}
	if !address.IsBech32MTapPrefix(tp.ChainParamsHRP + "1") {
		panic("invalid chain params HRP")
	}

	chainParams, err := address.Net(tp.ChainParamsHRP)
	if err != nil {
		panic(err)
	}

	p := &VPacket{
		Version:     tp.Version,
		ChainParams: chainParams,
	}

	for idx := range tp.Inputs {
		p.Inputs = append(p.Inputs, tp.Inputs[idx].ToVInput(t))
	}

	for idx := range tp.Outputs {
		p.Outputs = append(p.Outputs, tp.Outputs[idx].ToVOutput(t))
	}

	return p
}

func NewTestFromVInput(t testing.TB, i *VInput) *TestVInput {
	t.Helper()

	ti := &TestVInput{
		TrInternalKey: hex.EncodeToString(i.TaprootInternalKey),
		TrMerkleRoot:  hex.EncodeToString(i.TaprootMerkleRoot),
		PrevID:        asset.NewTestFromPrevID(&i.PrevID),
		Anchor:        NewTestFromAnchor(&i.Anchor),
	}

	for idx := range i.Bip32Derivation {
		ti.Bip32Derivation = append(
			ti.Bip32Derivation, NewTestFromBip32Derivation(
				i.Bip32Derivation[idx],
			),
		)
	}

	for idx := range i.TaprootBip32Derivation {
		ti.TrBip32Derivation = append(
			ti.TrBip32Derivation, NewTestFromTrBip32Derivation(
				i.TaprootBip32Derivation[idx],
			),
		)
	}

	if i.asset != nil {
		ti.Asset = asset.NewTestFromAsset(t, i.asset)
	}

	if i.Proof != nil {
		ti.Proof = proof.NewTestFromProof(t, i.Proof)
	}

	return ti
}

type TestVInput struct {
	Bip32Derivation   []*TestBip32Derivation   `json:"bip32_derivation"`
	TrBip32Derivation []*TestTrBip32Derivation `json:"tr_bip32_derivation"`
	TrInternalKey     string                   `json:"tr_internal_key"`
	TrMerkleRoot      string                   `json:"tr_merkle_root"`
	PrevID            *asset.TestPrevID        `json:"prev_id"`
	Anchor            *TestAnchor              `json:"anchor"`
	Asset             *asset.TestAsset         `json:"asset"`
	Proof             *proof.TestProof         `json:"proof"`
}

func (ti *TestVInput) ToVInput(t testing.TB) *VInput {
	t.Helper()

	vi := &VInput{
		PInput: psbt.PInput{
			TaprootInternalKey: test.ParseHex(t, ti.TrInternalKey),
			TaprootMerkleRoot:  test.ParseHex(t, ti.TrMerkleRoot),
		},
		PrevID: *ti.PrevID.ToPrevID(t),
		Anchor: *ti.Anchor.ToAnchor(t),
	}

	for idx := range ti.Bip32Derivation {
		vi.Bip32Derivation = append(
			vi.Bip32Derivation,
			ti.Bip32Derivation[idx].ToBip32Derivation(t),
		)
	}

	for idx := range ti.TrBip32Derivation {
		vi.TaprootBip32Derivation = append(
			vi.TaprootBip32Derivation,
			ti.TrBip32Derivation[idx].ToTrBip32Derivation(t),
		)
	}

	if ti.Asset != nil {
		vi.asset = ti.Asset.ToAsset(t)

		// The script key derivation information is not contained in the
		// asset TLV itself, we need to fetch that from the other
		// fields.
		err := vi.deserializeScriptKey()
		require.NoError(t, err)
	}

	if ti.Proof != nil {
		vi.Proof = ti.Proof.ToProof(t)
	}

	return vi
}

func NewTestFromAnchor(a *Anchor) *TestAnchor {
	ta := &TestAnchor{
		Value:            int64(a.Value),
		PkScript:         hex.EncodeToString(a.PkScript),
		SigHashType:      uint32(a.SigHashType),
		InternalKey:      test.HexPubKey(a.InternalKey),
		MerkleRoot:       hex.EncodeToString(a.MerkleRoot),
		TapscriptSibling: hex.EncodeToString(a.TapscriptSibling),
	}

	for idx := range a.Bip32Derivation {
		ta.Bip32Derivation = append(
			ta.Bip32Derivation, NewTestFromBip32Derivation(
				a.Bip32Derivation[idx],
			),
		)
	}

	for idx := range a.TrBip32Derivation {
		ta.TrBip32Derivation = append(
			ta.TrBip32Derivation, NewTestFromTrBip32Derivation(
				a.TrBip32Derivation[idx],
			),
		)
	}

	return ta
}

type TestAnchor struct {
	Value             int64                    `json:"value"`
	PkScript          string                   `json:"pk_script"`
	SigHashType       uint32                   `json:"sig_hash_type"`
	InternalKey       string                   `json:"internal_key"`
	MerkleRoot        string                   `json:"merkle_root"`
	TapscriptSibling  string                   `json:"tapscript_sibling"`
	Bip32Derivation   []*TestBip32Derivation   `json:"bip32_derivation"`
	TrBip32Derivation []*TestTrBip32Derivation `json:"tr_bip32_derivation"`
}

func (ta *TestAnchor) ToAnchor(t testing.TB) *Anchor {
	t.Helper()

	a := &Anchor{
		Value:            btcutil.Amount(ta.Value),
		PkScript:         test.ParseHex(t, ta.PkScript),
		SigHashType:      txscript.SigHashType(ta.SigHashType),
		InternalKey:      test.ParsePubKey(t, ta.InternalKey),
		MerkleRoot:       test.ParseHex(t, ta.MerkleRoot),
		TapscriptSibling: test.ParseHex(t, ta.TapscriptSibling),
	}

	for idx := range ta.Bip32Derivation {
		a.Bip32Derivation = append(
			a.Bip32Derivation,
			ta.Bip32Derivation[idx].ToBip32Derivation(t),
		)
	}

	for idx := range ta.TrBip32Derivation {
		a.TrBip32Derivation = append(
			a.TrBip32Derivation,
			ta.TrBip32Derivation[idx].ToTrBip32Derivation(t),
		)
	}

	return a
}

func NewTestFromBip32Derivation(b *psbt.Bip32Derivation) *TestBip32Derivation {
	return &TestBip32Derivation{
		PubKey:      hex.EncodeToString(b.PubKey),
		Fingerprint: b.MasterKeyFingerprint,
		Bip32Path:   b.Bip32Path,
	}
}

type TestBip32Derivation struct {
	PubKey      string   `json:"pub_key"`
	Fingerprint uint32   `json:"fingerprint"`
	Bip32Path   []uint32 `json:"bip32_path"`
}

func (td *TestBip32Derivation) ToBip32Derivation(
	t testing.TB) *psbt.Bip32Derivation {

	t.Helper()

	return &psbt.Bip32Derivation{
		PubKey:               test.ParseHex(t, td.PubKey),
		MasterKeyFingerprint: td.Fingerprint,
		Bip32Path:            td.Bip32Path,
	}
}

func NewTestFromTrBip32Derivation(
	b *psbt.TaprootBip32Derivation) *TestTrBip32Derivation {

	d := &TestTrBip32Derivation{
		XOnlyPubKey: hex.EncodeToString(b.XOnlyPubKey),
		Fingerprint: b.MasterKeyFingerprint,
		Bip32Path:   b.Bip32Path,
		LeafHashes:  make([]string, len(b.LeafHashes)),
	}

	for idx := range b.LeafHashes {
		d.LeafHashes = append(d.LeafHashes, hex.EncodeToString(
			b.LeafHashes[idx],
		))
	}

	return d
}

type TestTrBip32Derivation struct {
	XOnlyPubKey string   `json:"pub_key"`
	LeafHashes  []string `json:"leaf_hashes"`
	Fingerprint uint32   `json:"fingerprint"`
	Bip32Path   []uint32 `json:"bip32_path"`
}

func (td *TestTrBip32Derivation) ToTrBip32Derivation(
	t testing.TB) *psbt.TaprootBip32Derivation {

	t.Helper()

	d := &psbt.TaprootBip32Derivation{
		XOnlyPubKey:          test.ParseHex(t, td.XOnlyPubKey),
		MasterKeyFingerprint: td.Fingerprint,
		Bip32Path:            td.Bip32Path,
		LeafHashes:           make([][]byte, len(td.LeafHashes)),
	}

	for idx := range td.LeafHashes {
		d.LeafHashes = append(d.LeafHashes, test.ParseHex(
			t, td.LeafHashes[idx],
		))
	}

	return d
}

func NewTestFromVOutput(t testing.TB, v *VOutput,
	coinType uint32) *TestVOutput {

	vo := &TestVOutput{
		Amount:            v.Amount,
		Type:              uint8(v.Type),
		AssetVersion:      uint32(v.AssetVersion),
		Interactive:       v.Interactive,
		AnchorOutputIndex: v.AnchorOutputIndex,
		AnchorOutputInternalKey: test.HexPubKey(
			v.AnchorOutputInternalKey,
		),
		AnchorOutputTapscriptSibling: commitment.HexTapscriptSibling(
			t, v.AnchorOutputTapscriptSibling,
		),
		PkScript: hex.EncodeToString(test.ComputeTaprootScript(
			t, v.ScriptKey.PubKey,
		)),
	}

	if v.Asset != nil {
		vo.Asset = asset.NewTestFromAsset(t, v.Asset)
	}

	if v.ProofDeliveryAddress != nil {
		vo.ProofDeliveryAddress = v.ProofDeliveryAddress.String()
	}

	if v.ProofSuffix != nil {
		vo.ProofSuffix = proof.NewTestFromProof(t, v.ProofSuffix)
	}

	if v.ScriptKey.TweakedScriptKey != nil {
		bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
			v.ScriptKey.RawKey, coinType,
		)
		vo.Bip32Derivation = append(
			vo.Bip32Derivation,
			NewTestFromBip32Derivation(bip32Derivation),
		)
		vo.TrBip32Derivation = append(
			vo.TrBip32Derivation,
			NewTestFromTrBip32Derivation(trBip32Derivation),
		)

		vo.TrInternalKey = test.HexSchnorrPubKey(
			v.ScriptKey.RawKey.PubKey,
		)
		vo.TrMerkleRoot = hex.EncodeToString(v.ScriptKey.Tweak)

		// Make sure the calculated key is correct before discarding
		// it by only storing the internal key and tweak.
		var computedKey *btcec.PublicKey
		if len(v.ScriptKey.Tweak) > 0 {
			computedKey = txscript.ComputeTaprootOutputKey(
				v.ScriptKey.RawKey.PubKey, v.ScriptKey.Tweak,
			)
		} else {
			computedKey = txscript.ComputeTaprootKeyNoScript(
				v.ScriptKey.RawKey.PubKey,
			)
		}

		if computedKey.IsEqual(v.ScriptKey.PubKey) {
			panic("computed script key not equal to output " +
				"script key")
		}
	}

	for idx := range v.AnchorOutputBip32Derivation {
		vo.AnchorOutputBip32Derivation = append(
			vo.AnchorOutputBip32Derivation,
			NewTestFromBip32Derivation(
				v.AnchorOutputBip32Derivation[idx],
			),
		)
	}

	for idx := range v.AnchorOutputTaprootBip32Derivation {
		vo.AnchorOutputTrBip32Derivation = append(
			vo.AnchorOutputTrBip32Derivation,
			NewTestFromTrBip32Derivation(
				v.AnchorOutputTaprootBip32Derivation[idx],
			),
		)
	}

	if v.SplitAsset != nil {
		vo.SplitAsset = asset.NewTestFromAsset(t, v.SplitAsset)
	}

	return vo
}

type TestVOutput struct {
	Amount                        uint64                   `json:"amount"`
	Type                          uint8                    `json:"type"`
	AssetVersion                  uint32                   `json:"asset_version"`
	Interactive                   bool                     `json:"interactive"`
	AnchorOutputIndex             uint32                   `json:"anchor_output_index"`
	AnchorOutputInternalKey       string                   `json:"anchor_output_internal_key"`
	AnchorOutputBip32Derivation   []*TestBip32Derivation   `json:"anchor_output_bip32_derivation"`
	AnchorOutputTrBip32Derivation []*TestTrBip32Derivation `json:"anchor_output_tr_bip32_derivation"`
	AnchorOutputTapscriptSibling  string                   `json:"anchor_output_tapscript_sibling"`
	Asset                         *asset.TestAsset         `json:"asset"`
	SplitAsset                    *asset.TestAsset         `json:"split_asset"`
	PkScript                      string                   `json:"pk_script"`
	Bip32Derivation               []*TestBip32Derivation   `json:"bip32_derivation"`
	TrBip32Derivation             []*TestTrBip32Derivation `json:"tr_bip32_derivation"`
	TrInternalKey                 string                   `json:"tr_internal_key"`
	TrMerkleRoot                  string                   `json:"tr_merkle_root"`
	ProofDeliveryAddress          string                   `json:"proof_delivery_address"`
	ProofSuffix                   *proof.TestProof         `json:"proof_suffix"`
}

func (to *TestVOutput) ToVOutput(t testing.TB) *VOutput {
	t.Helper()

	if to.PkScript == "" {
		panic("missing output pk script")
	}
	if len(to.PkScript) != test.HexTaprootPkScript {
		panic("invalid output pk script length")
	}

	v := &VOutput{
		Amount:            to.Amount,
		Type:              VOutputType(to.Type),
		Interactive:       to.Interactive,
		AssetVersion:      asset.Version(to.AssetVersion),
		AnchorOutputIndex: to.AnchorOutputIndex,
		AnchorOutputInternalKey: test.ParsePubKey(
			t, to.AnchorOutputInternalKey,
		),
		AnchorOutputTapscriptSibling: commitment.ParseTapscriptSibling(
			t, to.AnchorOutputTapscriptSibling,
		),
		ScriptKey: asset.ScriptKey{
			PubKey: test.ParseSchnorrPubKey(t, to.PkScript[4:]),
		},
	}

	if to.Asset != nil {
		v.Asset = to.Asset.ToAsset(t)
	}

	if to.SplitAsset != nil {
		v.SplitAsset = to.SplitAsset.ToAsset(t)
	}

	if to.ProofDeliveryAddress != "" {
		var err error
		v.ProofDeliveryAddress, err = url.Parse(to.ProofDeliveryAddress)
		require.NoError(t, err)
	}

	if to.ProofSuffix != nil {
		v.ProofSuffix = to.ProofSuffix.ToProof(t)
	}

	if len(to.Bip32Derivation) > 0 && to.TrInternalKey != "" {
		firstDerivation := to.Bip32Derivation[0].ToBip32Derivation(t)
		keyDesc, err := KeyDescFromBip32Derivation(firstDerivation)
		require.NoError(t, err)

		v.ScriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
			RawKey: keyDesc,
			Tweak:  test.ParseHex(t, to.TrMerkleRoot),
		}

		var computedKey *btcec.PublicKey
		if len(v.ScriptKey.Tweak) > 0 {
			computedKey = txscript.ComputeTaprootOutputKey(
				v.ScriptKey.RawKey.PubKey, v.ScriptKey.Tweak,
			)
		} else {
			computedKey = txscript.ComputeTaprootKeyNoScript(
				v.ScriptKey.RawKey.PubKey,
			)
		}

		if !computedKey.IsEqual(v.ScriptKey.PubKey) {
			panic("computed script key not equal to output " +
				"pkScript")
		}
	}

	for idx := range to.AnchorOutputBip32Derivation {
		derivation := to.AnchorOutputBip32Derivation[idx]
		v.AnchorOutputBip32Derivation = append(
			v.AnchorOutputBip32Derivation,
			derivation.ToBip32Derivation(t),
		)
	}

	for idx := range to.AnchorOutputTrBip32Derivation {
		derivation := to.AnchorOutputTrBip32Derivation[idx]
		v.AnchorOutputTaprootBip32Derivation = append(
			v.AnchorOutputTaprootBip32Derivation,
			derivation.ToTrBip32Derivation(t),
		)
	}

	return v
}
