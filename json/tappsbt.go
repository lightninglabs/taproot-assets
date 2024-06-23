package json

import (
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

func NewVPacket(p *tappsbt.VPacket) (*VPacket, error) {
	tp := &VPacket{
		Version:        uint8(p.Version),
		ChainParamsHRP: p.ChainParams.TapHRP,
	}

	for idx := range p.Inputs {
		vIn, err := NewVInput(p.Inputs[idx])
		if err != nil {
			return nil, err
		}

		tp.Inputs = append(tp.Inputs, vIn)
	}

	for idx := range p.Outputs {
		vOut, err := NewVOutput(
			p.Outputs[idx], p.ChainParams.HDCoinType,
		)
		if err != nil {
			return nil, err
		}

		tp.Outputs = append(tp.Outputs, vOut)
	}

	return tp, nil
}

type VPacket struct {
	Inputs         []*VInput  `json:"inputs"`
	Outputs        []*VOutput `json:"outputs"`
	Version        uint8      `json:"version"`
	ChainParamsHRP string     `json:"chain_params_hrp"`
}

func (tp *VPacket) ToVPacket(t testing.TB) *tappsbt.VPacket {
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

	p := &tappsbt.VPacket{
		Version:     tappsbt.VPacketVersion(tp.Version),
		ChainParams: chainParams,
	}

	for idx := range tp.Inputs {
		ti := tp.Inputs[idx].ToVInput(t)
		p.Inputs = append(p.Inputs, ti)

		if tp.Inputs[idx].Asset != nil {
			p.SetInputAsset(idx, tp.Inputs[idx].Asset.ToAsset(t))

			// The script key derivation information is not
			// contained in the asset TLV itself, we need to fetch
			// that from the other fields.
			err := p.Inputs[idx].DeserializeScriptKey()
			require.NoError(t, err)
		}
	}

	for idx := range tp.Outputs {
		p.Outputs = append(p.Outputs, tp.Outputs[idx].ToVOutput(t))
	}

	return p
}

func NewVInput(i *tappsbt.VInput) (*VInput, error) {
	ti := &VInput{
		TrInternalKey: hex.EncodeToString(i.TaprootInternalKey),
		TrMerkleRoot:  hex.EncodeToString(i.TaprootMerkleRoot),
		PrevID:        NewPrevID(&i.PrevID),
		Anchor:        NewAnchor(&i.Anchor),
	}

	for idx := range i.Bip32Derivation {
		ti.Bip32Derivation = append(
			ti.Bip32Derivation, NewBip32Derivation(
				i.Bip32Derivation[idx],
			),
		)
	}

	for idx := range i.TaprootBip32Derivation {
		ti.TrBip32Derivation = append(
			ti.TrBip32Derivation, NewTaprootBip32Derivation(
				i.TaprootBip32Derivation[idx],
			),
		)
	}

	var err error
	if i.Asset() != nil {
		ti.Asset, err = NewAsset(i.Asset())
		if err != nil {
			return nil, err
		}
	}

	if i.Proof != nil {
		ti.Proof, err = NewProof(i.Proof)
		if err != nil {
			return nil, err
		}
	}

	return ti, nil
}

type VInput struct {
	Bip32Derivation   []*Bip32Derivation        `json:"bip32_derivation"`
	TrBip32Derivation []*TaprootBip32Derivation `json:"tr_bip32_derivation"`
	TrInternalKey     string                    `json:"tr_internal_key"`
	TrMerkleRoot      string                    `json:"tr_merkle_root"`
	PrevID            *PrevID                   `json:"prev_id"`
	Anchor            *Anchor                   `json:"anchor"`
	Asset             *Asset                    `json:"asset"`
	Proof             *Proof                    `json:"proof"`
}

func (ti *VInput) ToVInput(t testing.TB) *tappsbt.VInput {
	t.Helper()

	vi := &tappsbt.VInput{
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

	if ti.Proof != nil {
		vi.Proof = ti.Proof.ToProof(t)
	}

	return vi
}

func NewAnchor(a *tappsbt.Anchor) *Anchor {
	ta := &Anchor{
		Value:            int64(a.Value),
		PkScript:         hex.EncodeToString(a.PkScript),
		SigHashType:      uint32(a.SigHashType),
		InternalKey:      test.HexPubKey(a.InternalKey),
		MerkleRoot:       hex.EncodeToString(a.MerkleRoot),
		TapscriptSibling: hex.EncodeToString(a.TapscriptSibling),
	}

	for idx := range a.Bip32Derivation {
		ta.Bip32Derivation = append(
			ta.Bip32Derivation, NewBip32Derivation(
				a.Bip32Derivation[idx],
			),
		)
	}

	for idx := range a.TrBip32Derivation {
		ta.TrBip32Derivation = append(
			ta.TrBip32Derivation, NewTaprootBip32Derivation(
				a.TrBip32Derivation[idx],
			),
		)
	}

	return ta
}

type Anchor struct {
	Value             int64                     `json:"value"`
	PkScript          string                    `json:"pk_script"`
	SigHashType       uint32                    `json:"sig_hash_type"`
	InternalKey       string                    `json:"internal_key"`
	MerkleRoot        string                    `json:"merkle_root"`
	TapscriptSibling  string                    `json:"tapscript_sibling"`
	Bip32Derivation   []*Bip32Derivation        `json:"bip32_derivation"`
	TrBip32Derivation []*TaprootBip32Derivation `json:"tr_bip32_derivation"`
}

func (ta *Anchor) ToAnchor(t testing.TB) *tappsbt.Anchor {
	t.Helper()

	a := &tappsbt.Anchor{
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

func NewBip32Derivation(b *psbt.Bip32Derivation) *Bip32Derivation {
	return &Bip32Derivation{
		PubKey:      hex.EncodeToString(b.PubKey),
		Fingerprint: b.MasterKeyFingerprint,
		Bip32Path:   b.Bip32Path,
	}
}

type Bip32Derivation struct {
	PubKey      string   `json:"pub_key"`
	Fingerprint uint32   `json:"fingerprint"`
	Bip32Path   []uint32 `json:"bip32_path"`
}

func (td *Bip32Derivation) ToBip32Derivation(
	t testing.TB) *psbt.Bip32Derivation {

	t.Helper()

	return &psbt.Bip32Derivation{
		PubKey:               test.ParseHex(t, td.PubKey),
		MasterKeyFingerprint: td.Fingerprint,
		Bip32Path:            td.Bip32Path,
	}
}

func NewTaprootBip32Derivation(
	b *psbt.TaprootBip32Derivation) *TaprootBip32Derivation {

	d := &TaprootBip32Derivation{
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

type TaprootBip32Derivation struct {
	XOnlyPubKey string   `json:"pub_key"`
	LeafHashes  []string `json:"leaf_hashes"`
	Fingerprint uint32   `json:"fingerprint"`
	Bip32Path   []uint32 `json:"bip32_path"`
}

func (td *TaprootBip32Derivation) ToTrBip32Derivation(
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

func NewVOutput(v *tappsbt.VOutput, coinType uint32) (*VOutput, error) {
	sibling, err := HexTapscriptSibling(
		v.AnchorOutputTapscriptSibling,
	)
	if err != nil {
		return nil, err
	}

	pkScript, err := test.ComputeTaprootScriptErr(
		schnorr.SerializePubKey(v.ScriptKey.PubKey),
	)
	if err != nil {
		return nil, err
	}

	vo := &VOutput{
		Amount:            v.Amount,
		Type:              uint8(v.Type),
		AssetVersion:      uint32(v.AssetVersion),
		Interactive:       v.Interactive,
		AnchorOutputIndex: v.AnchorOutputIndex,
		AnchorOutputInternalKey: test.HexPubKey(
			v.AnchorOutputInternalKey,
		),
		AnchorOutputTapscriptSibling: sibling,
		PkScript:                     hex.EncodeToString(pkScript),
		RelativeLockTime:             v.RelativeLockTime,
		LockTime:                     v.LockTime,
	}

	if v.Asset != nil {
		vo.Asset, err = NewAsset(v.Asset)
		if err != nil {
			return nil, err
		}
	}

	if v.ProofDeliveryAddress != nil {
		vo.ProofDeliveryAddress = v.ProofDeliveryAddress.String()
	}

	if v.ProofSuffix != nil {
		vo.ProofSuffix, err = NewProof(v.ProofSuffix)
		if err != nil {
			return nil, err
		}
	}

	if v.ScriptKey.TweakedScriptKey != nil {
		bip32Derivation, trBip32Derivation := tappsbt.Bip32DerivationFromKeyDesc(
			v.ScriptKey.RawKey, coinType,
		)
		vo.Bip32Derivation = append(
			vo.Bip32Derivation,
			NewBip32Derivation(bip32Derivation),
		)
		vo.TrBip32Derivation = append(
			vo.TrBip32Derivation,
			NewTaprootBip32Derivation(trBip32Derivation),
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
			NewBip32Derivation(
				v.AnchorOutputBip32Derivation[idx],
			),
		)
	}

	for idx := range v.AnchorOutputTaprootBip32Derivation {
		vo.AnchorOutputTrBip32Derivation = append(
			vo.AnchorOutputTrBip32Derivation,
			NewTaprootBip32Derivation(
				v.AnchorOutputTaprootBip32Derivation[idx],
			),
		)
	}

	if v.SplitAsset != nil {
		vo.SplitAsset, err = NewAsset(v.SplitAsset)
		if err != nil {
			return nil, err
		}
	}

	return vo, nil
}

//nolint:lll
type VOutput struct {
	Amount                        uint64                    `json:"amount"`
	Type                          uint8                     `json:"type"`
	AssetVersion                  uint32                    `json:"asset_version"`
	Interactive                   bool                      `json:"interactive"`
	AnchorOutputIndex             uint32                    `json:"anchor_output_index"`
	AnchorOutputInternalKey       string                    `json:"anchor_output_internal_key"`
	AnchorOutputBip32Derivation   []*Bip32Derivation        `json:"anchor_output_bip32_derivation"`
	AnchorOutputTrBip32Derivation []*TaprootBip32Derivation `json:"anchor_output_tr_bip32_derivation"`
	AnchorOutputTapscriptSibling  string                    `json:"anchor_output_tapscript_sibling"`
	Asset                         *Asset                    `json:"asset"`
	SplitAsset                    *Asset                    `json:"split_asset"`
	PkScript                      string                    `json:"pk_script"`
	Bip32Derivation               []*Bip32Derivation        `json:"bip32_derivation"`
	TrBip32Derivation             []*TaprootBip32Derivation `json:"tr_bip32_derivation"`
	TrInternalKey                 string                    `json:"tr_internal_key"`
	TrMerkleRoot                  string                    `json:"tr_merkle_root"`
	ProofDeliveryAddress          string                    `json:"proof_delivery_address"`
	ProofSuffix                   *Proof                    `json:"proof_suffix"`
	RelativeLockTime              uint64                    `json:"relative_lock_time"`
	LockTime                      uint64                    `json:"lock_time"`
}

func (to *VOutput) ToVOutput(t testing.TB) *tappsbt.VOutput {
	t.Helper()

	if to.PkScript == "" {
		panic("missing output pk script")
	}
	if len(to.PkScript) != test.HexTaprootPkScript {
		panic("invalid output pk script length")
	}

	v := &tappsbt.VOutput{
		Amount:            to.Amount,
		Type:              tappsbt.VOutputType(to.Type),
		Interactive:       to.Interactive,
		AssetVersion:      asset.Version(to.AssetVersion),
		AnchorOutputIndex: to.AnchorOutputIndex,
		AnchorOutputInternalKey: test.ParsePubKey(
			t, to.AnchorOutputInternalKey,
		),
		AnchorOutputTapscriptSibling: ParseTapscriptSibling(
			t, to.AnchorOutputTapscriptSibling,
		),
		ScriptKey: asset.ScriptKey{
			PubKey: test.ParseSchnorrPubKey(t, to.PkScript[4:]),
		},
		RelativeLockTime: to.RelativeLockTime,
		LockTime:         to.LockTime,
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
		keyDesc, err := tappsbt.KeyDescFromBip32Derivation(firstDerivation)
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
