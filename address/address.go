package address

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/tlv"
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
	if a.FamilyKey == nil {
		return a.ID
	}
	return sha256.Sum256(schnorr.SerializePubKey(a.FamilyKey))
}

// AssetCommitmentKey computes the key that maps to the location in the Taro
// asset tree where the sender creates a new asset leaf for the receiver.
func (a AddressTLV) AssetCommitmentKey() [32]byte {
	return AssetCommitmentKey(a.ID, a.ScriptKey, a.FamilyKey)
}

// TapLeaf constructs a 'TapLeaf' for this address, tagged with a Taro marker.
func (a *AddressTLV) TapLeaf() txscript.TapLeaf {
	var assetAmount [8]byte
	binary.BigEndian.PutUint64(assetAmount[:], a.Amount)
	// NOTE: What is meant by 'Taro leaf'? Just a script with a prefix of Taro marker
	// and Taro version byte? Similar to the root hash for an asset tree
	addressParts := [][]byte{
		commitment.TaroMarker[:], {byte(a.Version)}, a.ID[:],
		{byte(a.Type)}, assetAmount[:], {byte(TaroScriptVersion)},
		schnorr.SerializePubKey(&a.ScriptKey),
		schnorr.SerializePubKey(a.FamilyKey),
	}
	addressScript := bytes.Join(addressParts, nil)
	addressTapLeaf := txscript.NewBaseTapLeaf(addressScript)

	return addressTapLeaf
}

// TaprootScript construct a P2TR script for a Taro address. This script is
// spent to by the asset sender, and reconstructed by the receiver.
func (a *AddressTLV) TaprootScript() ([]byte, error) {
	addressTapLeaf := a.TapLeaf()
	addressTapRoot := txscript.AssembleTaprootScriptTree(addressTapLeaf).
		RootNode.TapHash()
	addressOutputKey := txscript.ComputeTaprootOutputKey(&a.InternalKey,
		addressTapRoot[:])
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(addressOutputKey)).
		Script()
}

// CreateAssetSpend computes the asset leaf and split commitment needed to
// send assets to the receiver from the specified input. This is done by first
// validating that the input asset can satisfy the given Taro address. A split
// commitment is generated if needed, and the transfer is validated using the
// Taro VM. The returned asset leaves and split commitment should be used to
// construct new Taro commitments for both sender and receiver.
func (a AddressTLV) CreateAssetSpend(privKey btcec.PrivateKey,
	input asset.PrevID, inputCommitment *commitment.TaroCommitment) (
	*asset.Asset, *asset.Asset, *commitment.SplitCommitment, error,
) {
	inputAsset := a.isValidInput(inputCommitment, input.ScriptKey)
	if inputAsset != nil {
		// To validate the transfer, we need the input and output assets, and
		// optionally a split commitment plus all created splits.
		var splitCommitment *commitment.SplitCommitment
		var newAsset *asset.Asset
		var inputAssets commitment.InputSet
		var splitAssets commitment.SplitSet
		// If our asset is a Collectible, or a Normal asset where the requested
		// amount exactly matches the input amount, we don't need a split.
		if a.Type == asset.Collectible || a.Amount == inputAsset.Amount {
			splitCommitment = nil
			splitAssets = nil
			newAsset = inputAsset.Copy()
			newAsset.ScriptKey = a.ScriptKey
			newAsset.PrevWitnesses = []asset.Witness{{
				PrevID:          &input,
				TxWitness:       nil,
				SplitCommitment: nil,
			}}
			inputAssets = commitment.InputSet{input: inputAsset}
		} else {
			// NOTE: Default to using the first output for asset change,
			// and the second output for the receiver.
			changeLocator := commitment.SplitLocator{
				OutputIndex: 0,
				AssetID:     a.ID,
				ScriptKey:   input.ScriptKey,
				Amount:      inputAsset.Amount - a.Amount,
			}
			receiverLocator := commitment.SplitLocator{
				OutputIndex: 1,
				AssetID:     a.ID,
				ScriptKey:   a.ScriptKey,
				Amount:      a.Amount,
			}
			var err error
			splitCommitment, err = commitment.NewSplitCommitment(
				inputAsset, input.OutPoint, &changeLocator, &receiverLocator,
			)
			if err != nil {
				return nil, nil, nil, err
			}
			newAsset = splitCommitment.RootAsset
			inputAssets = splitCommitment.PrevAssets
			splitAssets = splitCommitment.SplitAssets
		}
		// With the desired output assets and split commitment, sign a witness
		// for the transfer and validate with the Taro VM.
		virtualTx, _, err := vm.VirtualTx(newAsset, inputAssets)
		if err != nil {
			return nil, nil, nil, err
		}
		newWitness, err := signVirtualKeySpend(
			privKey, virtualTx, inputAsset, 0,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		newAsset.PrevWitnesses[0].TxWitness = *newWitness
		if len(splitAssets) == 0 {
			vm, err := vm.New(newAsset, nil, inputAssets)
			if err != nil {
				return nil, nil, nil, err
			}
			if vm.Execute() != nil {
				return nil, nil, nil, err
			}
		} else {
			for _, splitAsset := range splitAssets {
				vm, err := vm.New(newAsset, splitAsset, inputAssets)
				if err != nil {
					return nil, nil, nil, err
				}
				if vm.Execute() != nil {
					return nil, nil, nil, err
				}
			}
		}
		return inputAsset, newAsset, splitCommitment, nil

	}
	return nil, nil, nil, errors.New("address spend: input asset mismatch")
}

// isValidInput verifies that the Taro commitment of the input contains an
// asset that could be spent to the given Taro address. The input commitment
// should produce a proof of inclusion for the asset specified in the address,
// at a location controlled by the sender.
func (a AddressTLV) isValidInput(input *commitment.TaroCommitment,
	inputScriptKey btcec.PublicKey) *asset.Asset {
	taroCommitmentKey := a.TaroCommitmentKey()
	inputAssetCommitmentKey := AssetCommitmentKey(a.ID,
		inputScriptKey, a.FamilyKey)
	inputProof := input.Proof(taroCommitmentKey, inputAssetCommitmentKey)
	if inputProof.ProvesAssetInclusion() {
		// Check that the input asset amount is at least as large as the amount
		// specified in the address. This check does not apply to Collectibles.
		if inputProof.Asset.Type == asset.Normal &&
			inputProof.Asset.Amount < a.Amount {
			return nil
		}
		return inputProof.Asset
	}
	return nil
}

// AssetCommitmentKey is the key that maps to a specific owner of an asset
// within a Taro AssetCommitment.
func AssetCommitmentKey(assetID asset.ID, scriptKey btcec.PublicKey,
	familyKey *btcec.PublicKey) [32]byte {
	if familyKey == nil {
		return sha256.Sum256(schnorr.SerializePubKey(&scriptKey))
	}
	h := sha256.New()
	_, _ = h.Write(assetID[:])
	_, _ = h.Write(schnorr.SerializePubKey(&scriptKey))
	return *(*[32]byte)(h.Sum(nil))
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
		return "", fmt.Errorf("unsupported hrp value %s", a.hrp)
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
	return nil, fmt.Errorf("invalid bech32m string")
}
