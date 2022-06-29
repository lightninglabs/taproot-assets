package address

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrUnsupportedHRP is an error returned when we attempt to encode a Taro
	// address with an HRP for a network without Taro support.
	ErrUnsupportedHRP = errors.New(
		"address: Unsupported HRP value",
	)

	// ErrInvalidBech32m is an error returned when we attempt to decode
	// a Taro address from a string that is not a valid bech32m string.
	ErrInvalidBech32m = errors.New(
		"address: Invalid bech32m string",
	)

	// ErrMissingInputAsset is an error returned when we attempt to spend to a
	// Taro address from an input that does not contain the matching asset.
	ErrMissingInputAsset = errors.New(
		"address: Input does not contain requested asset",
	)

	// ErrInsufficientInputAsset is an error returned when we attempt to spend
	// to a Taro address from an input that contains insufficient asset funds.
	ErrInsufficientInputAsset = errors.New(
		"address: Input asset value is insufficient",
	)
)

// Human-readable prefixes for bech32m encoded addresses for each network.
const (
	Bech32HRPTaroMainnet = "taro"
	Bech32HRPTaroTestnet = "tarot"
)

// Highest version of Taro script supported.
const (
	TaroScriptVersion uint8 = 0
)

// Set of all supported prefixes for bech32m encoded addresses.
var (
	bech32TaroPrefixes = map[string]struct{}{
		Bech32HRPTaroMainnet + "1": {},
		Bech32HRPTaroTestnet + "1": {},
	}
)

// IsBech32TaroPrefix returns whether the prefix is a known prefix for Taro
// addresses on any supported network.  This is used when decoding an address
// string into a TLV.
func IsBech32TaroPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32TaroPrefixes[prefix]
	return ok
}

type AddressTaro struct {
	hrp     string
	payload AddressTLV
}

type AddressTLV struct {
	// Version is the Taro version of the asset.
	Version asset.Version

	// ID is the hash that uniquely identifies the asset requested by the receiver.
	ID asset.ID

	// FamilyKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	FamilyKey *btcec.PublicKey

	// ScriptKey represents a tweaked Taproot output key encumbering the
	// different ways an asset can be spent.
	ScriptKey btcec.PublicKey

	// InternalKey is the BIP-340/341 public key of the receiver.
	InternalKey btcec.PublicKey

	// Amount is the number of asset units being requested by the receiver.
	Amount uint64

	// Type uniquely identifies the type of Taro asset.
	Type asset.Type
}

// PotentialSpend stores the information needed to check that an asset
// spend is possible, and prepare new asset leaves to be validated with the
// Taro VM.
type PotentialSpend struct {
	// InputAsset is the Asset being used by the sender.
	InputAsset *asset.Asset

	// NewAsset is the Asset that will be spent to the receiver. It may contain
	// a split commitment, and does not have a valid witness.
	NewAsset *asset.Asset

	// InputAssets maps asset PrevIDs to Assets being spent by the sender.
	InputAssets commitment.InputSet

	// SplitAssets maps split locators to split Assets, which is used by the
	// Taro VM when validating a spend with a split commitment.
	// NOTE: This is nil unless the InputAsset is being split.
	SplitAssets commitment.SplitSet

	// SplitCommitment contains all data needed to validate and commit to an
	// asset split.
	// NOTE: This is nil unless the InputAsset is being split.
	SplitCommitment *commitment.SplitCommitment

	// ChangeLocator identifies the asset split that is asset change, to be
	// spent back to the sender.
	// NOTE: This is nil unless the InputAsset is being split.
	ChangeLocator *commitment.SplitLocator

	// ReceiverLocator identifies the asset split that is to be
	// spent to the receiver.
	// NOTE: This is nil unless the InputAsset is being split.
	ReceiverLocator *commitment.SplitLocator
}

// A collection of structs created by validating a potential spend, that are
// used to commit to the spend in a Bitcoin transaction.
type ValidatedSpend struct {
	SenderCommitment   *commitment.TaroCommitment
	ReceiverCommitment *commitment.TaroCommitment
	SplitCommitment    *commitment.SplitCommitment
	ChangeLocator      *commitment.SplitLocator
	ReceiverLocator    *commitment.SplitLocator
}

// New creates an address for receiving a Taro asset.
func New(id asset.ID, familyKey *btcec.PublicKey, scriptKey btcec.PublicKey,
	internalKey btcec.PublicKey, amount uint64, assetType asset.Type, hrp string,
) *AddressTaro {

	payload := AddressTLV{
		Version:     asset.V0,
		ID:          id,
		FamilyKey:   familyKey,
		ScriptKey:   scriptKey,
		InternalKey: internalKey,
		Amount:      amount,
		Type:        assetType,
	}
	if IsBech32TaroPrefix(hrp + "1") {
		return &AddressTaro{
			hrp:     hrp,
			payload: payload,
		}
	}
	return nil
}

// TaroCommitmentKey is the key that maps to the root commitment for a specific
// asset or asset family within a TaroCommitment.
func (a AddressTLV) TaroCommitmentKey() [32]byte {
	return asset.TaroCommitmentKey(a.ID, a.FamilyKey)
}

// AssetCommitmentKey computes the key that maps to the location in the Taro
// asset tree where the sender creates a new asset leaf for the receiver.
func (a AddressTLV) AssetCommitmentKey() [32]byte {
	return asset.AssetCommitmentKey(a.ID, &a.ScriptKey, a.FamilyKey)
}

// PayToAddrScript constructs a P2TR script that embeds a Taro commitment
// by tweaking the receiver key by a Tapscript tree that contains the Taro
// commitment root. The Taro commitment must be reconstructed by the receiver,
// and they also need to Tapscript sibling hash used here if present.
func PayToAddrScript(internalKey *btcec.PublicKey, sibling *chainhash.Hash,
	commitment *commitment.TaroCommitment) ([]byte, error) {
	tapscriptRoot := commitment.TapscriptRoot(sibling)
	outputKey := txscript.ComputeTaprootOutputKey(internalKey,
		tapscriptRoot[:])
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(outputKey)).
		Script()
}

// prepareAssetSpend verifies that a TaroCommitment and previous input
// controlled by the sender can satisfy a Taro address, and if so computes
// the necessary new Asset or split commitment to complete the asset transfer.
// The new Asset leaf or split commitment need to be signed and validated
// before being spent.
func prepareAssetSpend(addr AddressTLV, prevInput asset.PrevID,
	prevTaroTree *commitment.TaroCommitment, changeIndex,
	receiverIndex uint32) (*PotentialSpend, error) {

	// Sanity check that our input could be used for this Taro address.
	// If so, extract the input Asset to use as a template for the new Asset
	// or input for a split commitment.
	prevAsset, err := isValidInput(prevTaroTree, prevInput.ScriptKey, addr)
	if err != nil {
		return nil, err
	}
	newSpend := PotentialSpend{InputAsset: prevAsset}

	// If our asset is a Collectible, or a Normal asset where the requested
	// amount exactly matches the input amount, we don't need a split.
	if addr.Type == asset.Collectible || addr.Amount == prevAsset.Amount {
		newSpend.NewAsset = prevAsset.Copy()
		newSpend.NewAsset.ScriptKey = addr.ScriptKey
		newSpend.NewAsset.PrevWitnesses = []asset.Witness{{
			PrevID:          &prevInput,
			TxWitness:       nil,
			SplitCommitment: nil,
		}}
		newSpend.InputAssets = commitment.InputSet{prevInput: prevAsset}
		return &newSpend, nil
	}

	// If the transfer requires an asset split, the details of each split asset
	// must be set before computing the SplitCommitment.
	changeLocator := commitment.SplitLocator{
		OutputIndex: changeIndex,
		AssetID:     addr.ID,
		ScriptKey:   prevInput.ScriptKey,
		Amount:      prevAsset.Amount - addr.Amount,
	}
	receiverLocator := commitment.SplitLocator{
		OutputIndex: receiverIndex,
		AssetID:     addr.ID,
		ScriptKey:   addr.ScriptKey,
		Amount:      addr.Amount,
	}
	splitCommitment, err := commitment.NewSplitCommitment(
		prevAsset, prevInput.OutPoint, &changeLocator, &receiverLocator,
	)
	if err != nil {
		return nil, err
	}

	// The split locators returned along with the SplitCommitment are needed
	// to place each split asset in the correct Bitcoin output.
	newSpend.NewAsset = splitCommitment.RootAsset
	newSpend.InputAssets = splitCommitment.PrevAssets
	newSpend.SplitAssets = splitCommitment.SplitAssets
	newSpend.SplitCommitment = splitCommitment
	newSpend.ChangeLocator = &changeLocator
	newSpend.ReceiverLocator = &receiverLocator
	return &newSpend, nil
}

func validateAssetSpend(privKey *btcec.PrivateKey,
	newSpend *PotentialSpend) (*asset.Asset, error) {

	// Sign a witness for the asset transfer, and create a new Asset
	// with the witness attached to use for validation.
	virtualTx, _, err := vm.VirtualTx(newSpend.NewAsset, newSpend.InputAssets)
	if err != nil {
		return nil, err
	}

	newWitness, err := signVirtualKeySpend(
		*privKey, virtualTx, newSpend.InputAsset, 0)
	if err != nil {
		return nil, err
	}

	validatedAsset := newSpend.NewAsset.Copy()
	validatedAsset.PrevWitnesses[0].TxWitness = *newWitness

	// If the transfer contains no asset splits, we only need to validate
	// the new asset with its witness attached.
	if newSpend.SplitCommitment == nil {
		vm, err := vm.New(validatedAsset, nil, newSpend.InputAssets)
		if err != nil {
			return nil, err
		}
		if vm.Execute() != nil {
			return nil, err
		}
		return validatedAsset, nil
	}

	// If the transfer includes an asset split, we have to validate each
	// split asset to ensure that our new Asset is committing to
	// a valid SplitCommitment.
	for _, splitAsset := range newSpend.SplitAssets {
		vm, err := vm.New(validatedAsset, splitAsset, newSpend.InputAssets)
		if err != nil {
			return nil, err
		}
		if vm.Execute() != nil {
			return nil, err
		}
	}
	return validatedAsset, nil
}

// CreateAssetSpend computes the asset leaf and split commitment needed to
// send assets to the receiver from the specified input. This is done by first
// validating that the input asset can satisfy the given Taro address. A split
// commitment is generated if needed, and the transfer is validated using the
// Taro VM. The returned asset leaves and split commitment should be used to
// construct new Taro commitments for both sender and receiver.
func CreateAssetSpend(privKey *btcec.PrivateKey, input asset.PrevID,
	inputCommitment *commitment.TaroCommitment, changeIdx, receiverIdx uint32,
	addr AddressTLV) (*ValidatedSpend, error) {

	// Check for validity of the input and compute the data needed to validate
	// the asset transfer.
	newSpend, err := prepareAssetSpend(
		addr, input, inputCommitment, changeIdx, receiverIdx,
	)
	if err != nil {
		return nil, err
	}

	// With the desired output assets and split commitment, sign a witness
	// for the transfer and validate with the Taro VM. If the transfer is
	// valid, the Asset is updated to contain the new witness.
	validatedAsset, err := validateAssetSpend(privKey, newSpend)
	if err != nil {
		return nil, err
	}

	// Remove the spent Asset from the AssetCommitment of the sender.
	senderCommitment, _ := inputCommitment.Asset(addr.TaroCommitmentKey())
	err = senderCommitment.Update(newSpend.InputAsset, true)
	if err != nil {
		return nil, err
	}

	// Add the change from the asset split to the AssetCommitment of the sender
	// if present.
	if newSpend.SplitCommitment != nil {
		changeAsset := newSpend.SplitAssets[*newSpend.ChangeLocator].Asset
		err = senderCommitment.Update(&changeAsset, false)
		if err != nil {
			return nil, err
		}
	}

	// Update the TaroCommitment of the sender.
	senderTaroCommitment := inputCommitment
	senderTaroCommitment.Update(senderCommitment, false)

	// Create a Taro tree for the receiver.
	validatedCommitment, err := commitment.NewAssetCommitment(validatedAsset)
	if err != nil {
		return nil, err
	}
	receiverTaroCommitment := commitment.NewTaroCommitment(validatedCommitment)

	// Provide the data needed to embed the asset spend in a Bitcoin
	// Bitcoin transaction and send necessary proofs to the receiver.
	validSpend := ValidatedSpend{senderTaroCommitment, receiverTaroCommitment,
		newSpend.SplitCommitment, newSpend.ChangeLocator,
		newSpend.ReceiverLocator}

	return &validSpend, nil
}

// isValidInput verifies that the Taro commitment of the input contains an
// asset that could be spent to the given Taro address.
func isValidInput(input *commitment.TaroCommitment,
	inputScriptKey btcec.PublicKey, address AddressTLV) (*asset.Asset, error) {
	// The top-level Taro tree must have a non-empty asset tree at the leaf
	// specified in the address.
	taroCommitmentKey := address.TaroCommitmentKey()
	assetCommitment, ok := input.Asset(taroCommitmentKey)
	if !ok {
		return nil, ErrMissingInputAsset
	}

	// The asset tree must have a non-empty Asset at the location
	// specified by the sender's script key.
	assetCommitmentKey := asset.AssetCommitmentKey(address.ID,
		&inputScriptKey, address.FamilyKey)
	inputAsset, _ := assetCommitment.AssetProof(assetCommitmentKey)
	if inputAsset == nil {
		return nil, ErrMissingInputAsset
	}

	// For Normal assets, we also check that the input asset amount is at least
	// as large as the amount specified in the address.
	if inputAsset.Type == asset.Normal && inputAsset.Amount < address.Amount {
		return nil, ErrInsufficientInputAsset
	}
	return inputAsset, nil
}

// signVirtualKeySpend generates a signature over a Taro virtual transaction,
// where the input asset was spendable via the key path. This signature is
// the witness for the output asset or split commitment.
func signVirtualKeySpend(privKey btcec.PrivateKey, virtualTx *wire.MsgTx,
	input *asset.Asset, idx uint32) (*wire.TxWitness, error) {
	sigHash, err := vm.InputKeySpendSigHash(virtualTx, input, idx)
	if err != nil {
		return nil, err
	}
	taprootPrivKey := txscript.TweakTaprootPrivKey(&privKey, nil)
	sig, err := schnorr.Sign(taprootPrivKey, sigHash)
	if err != nil {
		return nil, err
	}
	return &wire.TxWitness{sig.Serialize()}, nil
}

// EncodeRecords determines the non-nil records to include when encoding an
// address at runtime.
func (a AddressTLV) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 7)
	records = append(records, NewAddressVersionRecord(&a.Version))
	records = append(records, NewAddressIDRecord(&a.ID))
	if a.FamilyKey != nil {
		records = append(records, NewAddressFamilyKeyRecord(&a.FamilyKey))
	}
	records = append(records, NewAddressScriptKeyRecord(&a.ScriptKey))
	records = append(records, NewAddressInternalKeyRecord(&a.InternalKey))
	records = append(records, NewAddressAmountRecord(&a.Amount))
	if a.Type != asset.Normal {
		records = append(records, NewAddressTypeRecord(&a.Type))
	}
	return records
}

// DecodeRecords provides all records known for an address for proper
// decoding.
func (a *AddressTLV) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		NewAddressVersionRecord(&a.Version),
		NewAddressIDRecord(&a.ID),
		NewAddressFamilyKeyRecord(&a.FamilyKey),
		NewAddressScriptKeyRecord(&a.ScriptKey),
		NewAddressInternalKeyRecord(&a.InternalKey),
		NewAddressAmountRecord(&a.Amount),
		NewAddressTypeRecord(&a.Type),
	}
}

// Encode encodes an address into a TLV stream.
func (a AddressTLV) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes an address from a TLV stream.
func (a *AddressTLV) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(a.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// EncodeAddress returns a bech32m string encoding of a Taro address.
func (a AddressTaro) EncodeAddress() (string, error) {
	var buf bytes.Buffer
	if err := a.payload.Encode(&buf); err != nil {
		return "", err
	}
	// Group the address bytes into 5 bit groups, as this is what is used to
	// encode each character in the address string.
	converted, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", err
	}

	// Check that our address is targeting a supported network.
	if IsBech32TaroPrefix(a.hrp + "1") {
		bech, err := bech32.EncodeM(a.hrp, converted)
		if err != nil {
			return "", err
		}
		return bech, nil
	} else {
		return "", ErrUnsupportedHRP
	}
}

// DecodeAddress parses a bech32m encoded Taro address string and
// returns the HRP and address TLV.
func DecodeAddress(addr string) (*AddressTaro, error) {
	// Bech32m encoded Taro addresses start with a human-readable part
	// (hrp) followed by '1'. For Bitcoin mainnet the hrp is "taro", and for
	// testnet it is "tarot". If the address string has a prefix that matches
	// one of the prefixes for the known networks, we try to decode it as
	// a Taro address.
	oneIndex := strings.LastIndexByte(addr, '1')
	if oneIndex > 1 {
		prefix := addr[:oneIndex+1]
		if IsBech32TaroPrefix(prefix) {
			_, data, err := bech32.DecodeNoLimit(addr)
			if err != nil {
				return nil, err
			}

			// The remaining characters of the address returned are grouped into
			// words of 5 bits. In order to restore the original address TLV
			// bytes, we'll need to regroup into 8 bit words.
			converted, err := bech32.ConvertBits(data, 5, 8, false)
			if err != nil {
				return nil, err
			}

			// The HRP is everything before the found '1'.
			hrp := prefix[:len(prefix)-1]

			buf := bytes.NewBuffer(converted)
			var a AddressTaro
			if err := a.payload.Decode(buf); err != nil {
				return nil, err
			}
			a.hrp = hrp
			return &a, nil
		}
	}
	return nil, ErrInvalidBech32m
}
