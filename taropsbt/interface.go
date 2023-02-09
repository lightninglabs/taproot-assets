package taropsbt

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightningnetwork/lnd/keychain"
)

// We define a set of Taro specific global, input and output PSBT key types here
// that correspond to the custom types defined in the VPacket below. We start at
// 0x70 because that is sufficiently high to not conflict with any of the keys
// specified in BIP174. Also, 7 is leet speak for "t" as in Taro.
// It would perhaps make sense to wrap these values in the BIP174 defined
// proprietary types to make 100% sure that no parser removes them. But the BIP
// also mentions to not remove unknown keys, so we should be fine like this as
// well.
var (
	PsbtKeyTypeGlobalTaroIsVirtualTx    = []byte{0x70}
	PsbtKeyTypeGlobalTaroChainParamsHRP = []byte{0x71}

	PsbtKeyTypeInputTaroPrevID                             = []byte{0x70}
	PsbtKeyTypeInputTaroAnchorValue                        = []byte{0x71}
	PsbtKeyTypeInputTaroAnchorPkScript                     = []byte{0x72}
	PsbtKeyTypeInputTaroAnchorSigHashType                  = []byte{0x73}
	PsbtKeyTypeInputTaroAnchorInternalKey                  = []byte{0x74}
	PsbtKeyTypeInputTaroAnchorMerkleRoot                   = []byte{0x75}
	PsbtKeyTypeInputTaroAnchorOutputBip32Derivation        = []byte{0x76}
	PsbtKeyTypeInputTaroAnchorOutputTaprootBip32Derivation = []byte{0x77}
	PsbtKeyTypeInputTaroAnchorTapscriptSibling             = []byte{0x78}
	PsbtKeyTypeInputTaroAsset                              = []byte{0x79}
	PsbtKeyTypeInputTaroAssetProof                         = []byte{0x7a}

	PsbtKeyTypeOutputTaroIsChange                           = []byte{0x70}
	PsbtKeyTypeOutputTaroIsInteractive                      = []byte{0x71}
	PsbtKeyTypeOutputTaroAnchorOutputIndex                  = []byte{0x72}
	PsbtKeyTypeOutputTaroAnchorOutputInternalKey            = []byte{0x73}
	PsbtKeyTypeOutputTaroAnchorOutputBip32Derivation        = []byte{0x74}
	PsbtKeyTypeOutputTaroAnchorOutputTaprootBip32Derivation = []byte{0x75}
	PsbtKeyTypeOutputTaroAsset                              = []byte{0x76}
)

// VPacket is a PSBT extension packet for a virtual transaction. It represents
// the virtual asset state transition as it will be validated by the Taro VM.
// Some elements within the virtual packet may refer to on-chain elements (such
// as the anchor BTC transaction that was used to anchor the input that is
// spent). But in general a virtual transaction does NOT directly map onto a BTC
// transaction. It is entirely possible that multiple virtual transactions will
// be merged into a single BTC transaction. Thus, each asset state transfer is
// represented in a virtual TX and multiple asset state transfers can be
// anchored within a single BTC transaction.
//
// NOTE: A virtual transaction only carries the asset state transition for a
// single asset ID. If multiple inputs are given, they must all belong to the
// same asset ID (which means those asset UTXOs are being merged and possibly
// split again in this virtual transaction). Therefore, if an anchor output
// carries commitments for multiple assets, a virtual transaction needs to be
// created, signed and then anchored for each asset ID separately.
//
// TODO(guggero): Actually support merging multiple virtual transactions into a
// single BTC transaction.
type VPacket struct {
	// Inputs is the list of asset inputs that are being spent.
	Inputs []*VInput

	// Outputs is the list of new asset outputs that are created by the
	// virtual transaction. By convention the output at index 0 is the
	// change output for asset change or the asset tombstone in case of a
	// non-interactive full value send. If this is an interactive full value
	// send, then there is only one output with Change being set to false
	// and Interactive being set to true.
	Outputs []*VOutput

	// ChainParams are the Taro chain parameters that are used to encode and
	// decode certain contents of the virtual packet.
	ChainParams *address.ChainParams
}

// SetInputAsset sets the input asset that is being spent.
func (p *VPacket) SetInputAsset(index int, a *asset.Asset,
	proof *commitment.Proof) {

	if index >= len(p.Inputs) {
		p.Inputs = append(p.Inputs, &VInput{})
	}
	p.Inputs[index].asset = a.Copy()
	p.Inputs[index].assetProof = proof
	p.Inputs[index].serializeScriptKey(
		a.ScriptKey, p.ChainParams.HDCoinType,
	)
}

// HasSplitCommitment determines if this transaction results in an asset split.
// This is either the case if the value of the input asset is split or if one of
// the outputs is non-interactive (in which case we need to have a zero value
// tombstone asset in the change output).
func (p *VPacket) HasSplitCommitment() (bool, error) {
	for i := 0; i < len(p.Outputs); i++ {
		// If any of the recipient asset is nil, this virtual
		// transaction hasn't been prepared correctly, and we cannot
		// determine if there is a split commitment.
		if p.Outputs[i].Asset == nil {
			return false, fmt.Errorf("recipient asset %d is nil", i)
		}

		// If there is a split commitment witness present, we know there
		// is a split going on.
		if p.Outputs[i].Asset.HasSplitCommitmentWitness() {
			return true, nil
		}
	}

	return false, nil
}

// Anchor is a struct that contains all the information about an anchor output.
type Anchor struct {
	// Value is output value of the anchor output.
	Value btcutil.Amount

	// PkScript is the output script of the anchor output.
	PkScript []byte

	// SigHashType is the signature hash type that should be used to sign
	// the anchor output spend.
	SigHashType txscript.SigHashType

	// InternalKey is the internal key of the anchor output that the input
	// is spending the asset from.
	InternalKey *btcec.PublicKey

	// MerkleRoot is the root of the tap script merkle tree that also
	// contains the Taro commitment of the anchor output.
	MerkleRoot []byte

	// TapscriptSibling is the tapscript sibling of the Taro commitment.
	TapscriptSibling []byte

	// Bip32Derivation is the BIP32 derivation of the anchor output's
	// internal key.
	//
	// TODO(guggero): Do we also want to allow multiple derivations to be
	// specified here? That would allow us to specify multiple keys involved
	// in MuSig2 for example. Same for the Taproot derivation below.
	Bip32Derivation *psbt.Bip32Derivation

	// TrBip32Derivation is the Taproot BIP32 derivation of the anchor
	// output's internal key.
	TrBip32Derivation *psbt.TaprootBip32Derivation
}

// VInput represents an input to a virtual asset state transition transaction.
type VInput struct {
	// PInput is the embedded default PSBT input struct that is used for
	// asset related input data.
	psbt.PInput

	// PrevID is the asset previous ID of the asset being spent.
	PrevID asset.PrevID

	// Anchor contains the information about the BTC level anchor
	// transaction that committed to the asset being spent.
	Anchor Anchor

	// asset is the full instance of the asset being spent. It is not
	// exported because the assets script key must be encoded in the PSBT
	// input struct for the signing to work correctly.
	asset *asset.Asset

	// assetProof is the proof that the asset being spent was committed to
	// in the anchor transaction above.
	assetProof *commitment.Proof
}

// Asset returns the input's asset that's being spent.
func (i *VInput) Asset() *asset.Asset {
	return i.asset
}

// AssetProof returns the proof that the asset being spent was committed to in
// the anchor transaction.
func (i *VInput) AssetProof() *commitment.Proof {
	return i.assetProof
}

// serializeScriptKey serializes the input asset's script key as the PSBT
// derivation information on the virtual input.
func (i *VInput) serializeScriptKey(key asset.ScriptKey, coinType uint32) {
	if key.TweakedScriptKey == nil {
		return
	}

	bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
		key.RawKey, coinType,
	)

	i.Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	i.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trBip32Derivation,
	}
	i.TaprootInternalKey = trBip32Derivation.XOnlyPubKey
	i.TaprootMerkleRoot = key.Tweak
}

// deserializeScriptKey deserializes the PSBT derivation information on the
// input into the input asset's script key.
func (i *VInput) deserializeScriptKey() error {
	if i.asset == nil || len(i.TaprootInternalKey) == 0 ||
		len(i.Bip32Derivation) == 0 {

		return nil
	}

	bip32Derivation := i.Bip32Derivation[0]
	rawKeyDesc, err := KeyDescFromBip32Derivation(bip32Derivation)
	if err != nil {
		return fmt.Errorf("error decoding script key derivation info: "+
			"%w", err)
	}

	i.asset.ScriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
		RawKey: rawKeyDesc,
		Tweak:  i.TaprootMerkleRoot,
	}

	return nil
}

// VOutput represents an output of a virtual asset state transition.
type VOutput struct {
	// Amount is the amount of units of the asset that this output is
	// creating. This can be zero in case of an asset tombstone in a
	// non-interactive full value send scenario. When serialized, this will
	// be stored as the value of the wire.TxOut of the PSBT's unsigned TX.
	Amount uint64

	// IsChange indicates whether this output is the change output for the
	// virtual transaction. By convention the first output of a virtual
	// asset transaction is the change output, unless it is an interactive
	// full value send where there is no change.
	IsChange bool

	// Interactive, when set to true, indicates that the receiver of the
	// output is aware of the asset transfer and can therefore receive a
	// full value send directly and without a tombstone in the change
	// output.
	Interactive bool

	// AnchorOutputIndex indicates in which output index of the BTC
	// transaction this asset output should be committed to. Multiple asset
	// outputs can be committed to within the same BTC transaction output.
	AnchorOutputIndex uint32

	// AnchorOutputInternalKey is the internal key of the anchor output that
	// will be used to create the anchor Taproot output key to which this
	// asset output will be committed to.
	AnchorOutputInternalKey *btcec.PublicKey

	// AnchorOutputBip32Derivation is the BIP32 derivation of the anchor
	// output's internal key.
	AnchorOutputBip32Derivation *psbt.Bip32Derivation

	// AnchorOutputTaprootBip32Derivation is the Taproot BIP32 derivation of
	// the anchor output's internal key.
	AnchorOutputTaprootBip32Derivation *psbt.TaprootBip32Derivation

	// Asset is the actual asset (including witness or split commitment
	// data) that this output will commit to on chain. This asset will be
	// included in the proof sent to the recipient of this output.
	Asset *asset.Asset

	// ScriptKey is the new script key of the recipient of the asset. When
	// serialized, this will be stored in the TaprootInternalKey and
	// TaprootDerivationPath fields of the PSBT output.
	ScriptKey asset.ScriptKey
}

// SplitLocator creates a split locator from the output. The asset ID is passed
// in for cases in which the asset is not yet set on the output.
func (o *VOutput) SplitLocator(assetID asset.ID) commitment.SplitLocator {
	return commitment.SplitLocator{
		OutputIndex: o.AnchorOutputIndex,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(o.ScriptKey.PubKey),
		Amount:      o.Amount,
	}
}

// SetAnchorInternalKey sets the internal key and derivation path of the anchor
// output based on the given key descriptor and coin type.
func (o *VOutput) SetAnchorInternalKey(keyDesc keychain.KeyDescriptor,
	coinType uint32) {

	bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
		keyDesc, coinType,
	)
	o.AnchorOutputInternalKey = keyDesc.PubKey
	o.AnchorOutputBip32Derivation = bip32Derivation
	o.AnchorOutputTaprootBip32Derivation = trBip32Derivation
}

// AnchorKeyToDesc attempts to extract the key descriptor of the anchor output
// from the anchor output BIP32 derivation information.
func (o *VOutput) AnchorKeyToDesc() (keychain.KeyDescriptor, error) {
	if o.AnchorOutputBip32Derivation == nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("anchor output " +
			"bip32 derivation is missing")
	}

	return KeyDescFromBip32Derivation(o.AnchorOutputBip32Derivation)
}

// KeyDescFromBip32Derivation attempts to extract the key descriptor from the
// given public key and BIP32 derivation information.
func KeyDescFromBip32Derivation(
	bip32Derivation *psbt.Bip32Derivation) (keychain.KeyDescriptor, error) {

	if len(bip32Derivation.PubKey) == 0 {
		return keychain.KeyDescriptor{}, fmt.Errorf("pubkey is missing")
	}

	pubKey, err := btcec.ParsePubKey(bip32Derivation.PubKey)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("error parsing "+
			"pubkey: %w", err)
	}

	keyLocator, err := extractLocatorFromPath(bip32Derivation.Bip32Path)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"extract locator from path: %w", err)
	}

	return keychain.KeyDescriptor{
		PubKey:     pubKey,
		KeyLocator: keyLocator,
	}, nil
}

// Bip32DerivationFromKeyDesc returns the default and Taproot BIP32 key
// derivation information from the given key descriptor information.
func Bip32DerivationFromKeyDesc(keyDesc keychain.KeyDescriptor,
	coinType uint32) (*psbt.Bip32Derivation, *psbt.TaprootBip32Derivation) {

	bip32Derivation := &psbt.Bip32Derivation{
		PubKey: keyDesc.PubKey.SerializeCompressed(),
		Bip32Path: []uint32{
			keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
			coinType + hdkeychain.HardenedKeyStart,
			uint32(keyDesc.Family) +
				uint32(hdkeychain.HardenedKeyStart),
			0,
			keyDesc.Index,
		},
	}

	return bip32Derivation, &psbt.TaprootBip32Derivation{
		XOnlyPubKey:          bip32Derivation.PubKey[1:],
		MasterKeyFingerprint: bip32Derivation.MasterKeyFingerprint,
		Bip32Path:            bip32Derivation.Bip32Path,
		LeafHashes:           make([][]byte, 0),
	}
}

// extractLocatorFromPath extracts the key family and index from the given BIP32
// derivation path. The derivation path is expected to be of the form:
// 	m/1017'/coin_type'/key_family'/0/index.
func extractLocatorFromPath(path []uint32) (keychain.KeyLocator, error) {
	loc := keychain.KeyLocator{}
	if len(path) != 5 {
		return loc, fmt.Errorf("invalid bip32 derivation path length: "+
			"%d", len(path))
	}

	if path[0] != keychain.BIP0043Purpose+hdkeychain.HardenedKeyStart {
		return loc, fmt.Errorf("invalid purpose, expected internal "+
			"purpose, got %d", path[0])
	}

	if path[2] < hdkeychain.HardenedKeyStart {
		return loc, fmt.Errorf("key family must be hardened")
	}

	loc.Family = keychain.KeyFamily(path[2] - hdkeychain.HardenedKeyStart)
	loc.Index = path[4]

	return loc, nil
}

// serializeTweakedScriptKey serializes a script key as the PSBT derivation
// information on the PSBT output.
func serializeTweakedScriptKey(key *asset.TweakedScriptKey,
	coinType uint32) psbt.POutput {

	pOut := psbt.POutput{}
	if key == nil {
		return pOut
	}

	bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
		key.RawKey, coinType,
	)

	// If we have a non-empty tweak of the script key, it means we don't
	// have a BIP-86 key, so we need to add the tweak to the derivation path
	// as a leaf hash (since the tweak will represent the root hash of the
	// script tree). Unfortunately outputs don't have the TaprootMerkleRoot
	// field as inputs have.
	if len(key.Tweak) > 0 {
		trBip32Derivation.LeafHashes = [][]byte{key.Tweak}
	}

	pOut.Bip32Derivation = []*psbt.Bip32Derivation{bip32Derivation}
	pOut.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trBip32Derivation,
	}
	pOut.TaprootInternalKey = trBip32Derivation.XOnlyPubKey

	return pOut
}

// deserializeTweakedScriptKey deserializes the PSBT derivation information on
// the PSBT output into the script key.
func deserializeTweakedScriptKey(pOut psbt.POutput) (*asset.TweakedScriptKey,
	error) {

	// The fields aren't mandatory.
	if len(pOut.TaprootInternalKey) == 0 || len(pOut.Bip32Derivation) == 0 {
		return nil, nil
	}

	bip32Derivation := pOut.Bip32Derivation[0]
	rawKeyDesc, err := KeyDescFromBip32Derivation(bip32Derivation)
	if err != nil {
		return nil, fmt.Errorf("error decoding script key derivation "+
			"info: %w", err)
	}

	var tweak []byte
	if len(pOut.TaprootBip32Derivation) > 0 &&
		len(pOut.TaprootBip32Derivation[0].LeafHashes) > 0 {

		tweak = pOut.TaprootBip32Derivation[0].LeafHashes[0]
	}

	return &asset.TweakedScriptKey{
		RawKey: rawKeyDesc,
		Tweak:  tweak,
	}, nil
}
