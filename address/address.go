package address

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrUnsupportedHRP is an error returned when we attempt to encode a
	// Taro address with an HRP for a network without Taro support.
	ErrUnsupportedHRP = errors.New(
		"address: unsupported HRP value",
	)

	// ErrMismatchedHRP is an error returned when we attempt to decode a
	// Taro address with an HRP that does not match the expected network.
	ErrMismatchedHRP = errors.New(
		"address: network mismatch",
	)

	// ErrInvalidBech32m is an error returned when we attempt to decode a
	// Taro address from a string that is not a valid bech32m string.
	ErrInvalidBech32m = errors.New(
		"address: invalid bech32m string",
	)

	// ErrInvalidAmountCollectible is an error returned when we attempt to
	// create a Taro address for a Collectible asset with an amount not
	// equal to one.
	ErrInvalidAmountCollectible = errors.New(
		"address: collectible asset amount not one",
	)

	// ErrInvalidAmountNormal is an error returned when we attempt to
	// create a Taro address for a Normal asset with an amount of zero.
	ErrInvalidAmountNormal = errors.New(
		"address: normal asset amount of zero",
	)

	// ErrUnsupportedAssetType is an error returned when we attempt to
	// create a Taro address for a non-standard asset type.
	ErrUnsupportedAssetType = errors.New(
		"address: unsupported asset type",
	)
)

const (
	// TaroScriptVersion is the highest version of Taro script supported.
	TaroScriptVersion uint8 = 0
)

// Taro represents a Taro address. Taro addresses specify an asset, pubkey, and
// amount.
type Taro struct {
	// ChainParams is the reference to the chain parameters that were used
	// to encode the Taro addresses.
	ChainParams *ChainParams

	// Version is the Taro version of the asset.
	Version asset.Version

	// ID is the hash that uniquely identifies the asset requested by the
	// receiver.
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
	//
	// TODO(roasbeef): sort of redundant w/ the asset ID?
	Type asset.Type
}

// New creates an address for receiving a Taro asset.
func New(id asset.ID, familyKey *btcec.PublicKey, scriptKey btcec.PublicKey,
	internalKey btcec.PublicKey, amt uint64, assetType asset.Type,
	net *ChainParams) (*Taro, error) {

	// Check for invalid combinations of asset type and amount.
	// Collectible assets must have an amount of 1, and Normal assets must
	// have a non-zero amount. We also reject invalid asset types.
	switch assetType {
	case asset.Collectible:
		if amt != 1 {
			return nil, ErrInvalidAmountCollectible
		}

	case asset.Normal:
		if amt == 0 {
			return nil, ErrInvalidAmountNormal
		}

	default:
		return nil, ErrUnsupportedAssetType
	}

	if !IsBech32MTaroPrefix(net.TaroHRP + "1") {
		return nil, ErrUnsupportedHRP
	}

	payload := Taro{
		ChainParams: net,
		Version:     asset.V0,
		ID:          id,
		FamilyKey:   familyKey,
		ScriptKey:   scriptKey,
		InternalKey: internalKey,
		Amount:      amt,
		Type:        assetType,
	}
	return &payload, nil
}

// Copy returns a deep copy of an Address.
func (a *Taro) Copy() *Taro {
	addressCopy := *a

	if a.FamilyKey != nil {
		famKey := *a.FamilyKey
		addressCopy.FamilyKey = &famKey
	}

	return &addressCopy
}

// Net returns the ChainParams struct matching the Taro address network.
func (a *Taro) Net() (*ChainParams, error) {
	return Net(a.ChainParams.TaroHRP)
}

// TaroCommitmentKey is the key that maps to the root commitment for the asset
// family specified by a Taro address.
func (a *Taro) TaroCommitmentKey() [32]byte {
	return asset.TaroCommitmentKey(a.ID, a.FamilyKey)
}

// AssetCommitmentKey is the key that maps to the asset leaf for the asset
// specified by a Taro address.
func (a *Taro) AssetCommitmentKey() [32]byte {
	return asset.AssetCommitmentKey(a.ID, &a.ScriptKey, a.FamilyKey == nil)
}

// PayToAddrScript constructs a P2TR script that embeds a Taro commitment
// by tweaking the receiver key by a Tapscript tree that contains the Taro
// commitment root. The Taro commitment must be reconstructed by the receiver,
// and they also need to Tapscript sibling hash used here if present.
func PayToAddrScript(internalKey btcec.PublicKey, sibling *chainhash.Hash,
	commitment commitment.TaroCommitment) ([]byte, error) {

	tapscriptRoot := commitment.TapscriptRoot(sibling)
	outputKey := txscript.ComputeTaprootOutputKey(
		&internalKey, tapscriptRoot[:],
	)

	return vm.PayToTaprootScript(outputKey)
}

// EncodeRecords determines the non-nil records to include when encoding an
// address at runtime.
func (a *Taro) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 7)
	records = append(records, newAddressVersionRecord(&a.Version))
	records = append(records, newAddressIDRecord(&a.ID))

	if a.FamilyKey != nil {
		records = append(records, newAddressFamilyKeyRecord(&a.FamilyKey))
	}

	records = append(records, newAddressScriptKeyRecord(&a.ScriptKey))
	records = append(records, newAddressInternalKeyRecord(&a.InternalKey))
	records = append(records, newAddressAmountRecord(&a.Amount))

	if a.Type != asset.Normal {
		records = append(records, newAddressTypeRecord(&a.Type))
	}

	return records
}

// DecodeRecords provides all records known for an address for proper
// decoding.
func (a *Taro) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		newAddressVersionRecord(&a.Version),
		newAddressIDRecord(&a.ID),
		newAddressFamilyKeyRecord(&a.FamilyKey),
		newAddressScriptKeyRecord(&a.ScriptKey),
		newAddressInternalKeyRecord(&a.InternalKey),
		newAddressAmountRecord(&a.Amount),
		newAddressTypeRecord(&a.Type),
	}
}

// Encode encodes an address into a TLV stream.
func (a *Taro) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes an address from a TLV stream.
func (a *Taro) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(a.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// EncodeAddress returns a bech32m string encoding of a Taro address.
func (a *Taro) EncodeAddress() (string, error) {
	var buf bytes.Buffer
	if err := a.Encode(&buf); err != nil {
		return "", err
	}

	// Group the address bytes into 5 bit groups, as this is what is used
	// to encode each character in the address string.
	converted, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", err
	}

	// Check that our address is targeting a supported network.
	if IsBech32MTaroPrefix(a.ChainParams.TaroHRP + "1") {
		bech, err := bech32.EncodeM(a.ChainParams.TaroHRP, converted)
		if err != nil {
			return "", err
		}
		return bech, nil
	}

	return "", ErrUnsupportedHRP
}

// DecodeAddress parses a bech32m encoded Taro address string and
// returns the HRP and address TLV.
func DecodeAddress(addr string, net *ChainParams) (*Taro, error) {
	// Bech32m encoded Taro addresses start with a human-readable part
	// (hrp) followed by '1'. For Bitcoin mainnet the hrp is "taro", and
	// for testnet it is "tarot". If the address string has a prefix that
	// matches one of the prefixes for the known networks, we try to decode
	// it as a Taro address.
	oneIndex := strings.LastIndexByte(addr, '1')
	if oneIndex <= 0 {
		return nil, ErrInvalidBech32m
	}

	prefix := addr[:oneIndex+1]
	if !IsBech32MTaroPrefix(prefix) {
		return nil, ErrUnsupportedHRP
	}

	// The HRP is everything before the found '1'.
	hrp := prefix[:len(prefix)-1]

	// Ensure that the hrp we deocded matches the network we're trying to
	// use the address on.
	if !IsForNet(hrp, net) {
		return nil, ErrMismatchedHRP
	}

	// At this point, the HRP is valid/known, and for the target network,
	// so we can decode the TLV blob into an actual address struct.
	_, data, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return nil, err
	}

	// The remaining characters of the address returned are grouped into
	// words of 5 bits. In order to restore the original address TLV bytes,
	// we'll need to regroup into 8 bit words.
	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}

	var a Taro
	buf := bytes.NewBuffer(converted)
	if err := a.Decode(buf); err != nil {
		return nil, err
	}

	a.ChainParams = net

	return &a, nil
}
