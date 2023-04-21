package address

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
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

	// ErrNoAddr is returned if no address is found in the address store.
	ErrNoAddr = errors.New(
		"address: no address found",
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

	// AssetID is the asset ID of the asset.
	AssetID asset.ID

	// GroupKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	GroupKey *btcec.PublicKey

	// ScriptKey represents a tweaked Taproot output key encumbering the
	// different ways an asset can be spent.
	ScriptKey btcec.PublicKey

	// InternalKey is the BIP-340/341 public key of the receiver.
	InternalKey btcec.PublicKey

	// Amount is the number of asset units being requested by the receiver.
	Amount uint64

	// assetGen is the receiving asset's genesis metadata which directly
	// maps to its unique ID within the Taro protocol.
	assetGen asset.Genesis
}

// New creates an address for receiving a Taro asset.
func New(genesis asset.Genesis, groupKey *btcec.PublicKey,
	scriptKey btcec.PublicKey, internalKey btcec.PublicKey, amt uint64,
	net *ChainParams) (*Taro, error) {

	// Check for invalid combinations of asset type and amount.
	// Collectible assets must have an amount of 1, and Normal assets must
	// have a non-zero amount. We also reject invalid asset types.
	switch genesis.Type {
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
		AssetID:     genesis.ID(),
		GroupKey:    groupKey,
		ScriptKey:   scriptKey,
		InternalKey: internalKey,
		Amount:      amt,
		assetGen:    genesis,
	}
	return &payload, nil
}

// Copy returns a deep copy of an Address.
func (a *Taro) Copy() *Taro {
	addressCopy := *a

	if a.GroupKey != nil {
		groupPubKey := *a.GroupKey
		addressCopy.GroupKey = &groupPubKey
	}

	return &addressCopy
}

// Net returns the ChainParams struct matching the Taro address network.
func (a *Taro) Net() (*ChainParams, error) {
	return Net(a.ChainParams.TaroHRP)
}

// AssetType returns the type of asset that this address was generated for.
func (a *Taro) AssetType() asset.Type {
	return a.assetGen.Type
}

// AttachGenesis attaches the asset's genesis metadata to the address.
func (a *Taro) AttachGenesis(gen asset.Genesis) {
	a.assetGen = gen
}

// TaroCommitmentKey is the key that maps to the root commitment for the asset
// group specified by a Taro address.
func (a *Taro) TaroCommitmentKey() [32]byte {
	return asset.TaroCommitmentKey(a.AssetID, a.GroupKey)
}

// AssetCommitmentKey is the key that maps to the asset leaf for the asset
// specified by a Taro address.
func (a *Taro) AssetCommitmentKey() [32]byte {
	return asset.AssetCommitmentKey(
		a.AssetID, &a.ScriptKey, a.GroupKey == nil,
	)
}

// TaroCommitment constructs the Taro commitment that is expected to appear on
// chain when assets are being sent to this address.
func (a *Taro) TaroCommitment() (*commitment.TaroCommitment, error) {
	key := a.AssetCommitmentKey()
	tree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// If this genesis wasn't actually set, then we'll fail here as we need
	// it in order to make the asset template.
	var zeroOp wire.OutPoint
	if a.assetGen.FirstPrevOut == zeroOp {
		return nil, fmt.Errorf("unknown asset genesis")
	}

	// We first need to create an asset from the address in order to encode
	// it in the TLV leaf.
	var groupKey *asset.GroupKey
	if a.GroupKey != nil {
		groupKey = &asset.GroupKey{
			GroupPubKey: *a.GroupKey,
		}
	}
	newAsset, err := asset.New(
		a.assetGen, a.Amount, 0, 0, asset.NewScriptKey(&a.ScriptKey),
		groupKey,
	)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := newAsset.Encode(&buf); err != nil {
		return nil, err
	}

	leaf := mssmt.NewLeafNode(buf.Bytes(), a.Amount)

	// We use the default, in-memory store that doesn't actually use the
	// context.
	updatedTree, err := tree.Insert(context.Background(), key, leaf)
	if err != nil {
		return nil, err
	}

	updatedRoot, err := updatedTree.Root(context.Background())
	if err != nil {
		return nil, err
	}

	taroCommitment, err := commitment.NewTaroCommitment(
		&commitment.AssetCommitment{
			Version:  a.Version,
			AssetID:  a.AssetID,
			TreeRoot: updatedRoot,
		},
	)

	return taroCommitment, err
}

// TaprootOutputKey returns the on-chain Taproot output key.
func (a *Taro) TaprootOutputKey(sibling *chainhash.Hash) (*btcec.PublicKey,
	error) {

	c, err := a.TaroCommitment()
	if err != nil {
		return nil, fmt.Errorf("unable to derive taro commitment: %w",
			err)
	}
	tapscriptRoot := c.TapscriptRoot(sibling)
	taprootOutputKey := txscript.ComputeTaprootOutputKey(
		&a.InternalKey, tapscriptRoot[:],
	)

	return taprootOutputKey, nil
}

// EncodeRecords determines the non-nil records to include when encoding an
// address at runtime.
func (a *Taro) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 6)
	records = append(records, newAddressVersionRecord(&a.Version))
	records = append(records, newAddressAssetID(&a.AssetID))

	if a.GroupKey != nil {
		records = append(records, newAddressGroupKeyRecord(&a.GroupKey))
	}

	records = append(records, newAddressScriptKeyRecord(&a.ScriptKey))
	records = append(records, newAddressInternalKeyRecord(&a.InternalKey))
	records = append(records, newAddressAmountRecord(&a.Amount))

	return records
}

// DecodeRecords provides all records known for an address for proper
// decoding.
func (a *Taro) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		newAddressVersionRecord(&a.Version),
		newAddressAssetID(&a.AssetID),
		newAddressGroupKeyRecord(&a.GroupKey),
		newAddressScriptKeyRecord(&a.ScriptKey),
		newAddressInternalKeyRecord(&a.InternalKey),
		newAddressAmountRecord(&a.Amount),
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
