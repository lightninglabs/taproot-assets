package address

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrUnsupportedHRP is an error returned when we attempt to encode a
	// Taproot Asset address with an HRP for a network without Taproot Asset
	// support.
	ErrUnsupportedHRP = errors.New("address: unsupported HRP value")

	// ErrMismatchedHRP is an error returned when we attempt to decode a
	// Taproot Asset address with an HRP that does not match the expected
	// network.
	ErrMismatchedHRP = errors.New("address: network mismatch")

	// ErrInvalidBech32m is an error returned when we attempt to decode a
	// Taproot Asset address from a string that is not a valid bech32m
	// string.
	ErrInvalidBech32m = errors.New("address: invalid bech32m string")

	// ErrInvalidAmountCollectible is an error returned when we attempt to
	// create a Taproot Asset address for a Collectible asset with an amount
	// not equal to one.
	ErrInvalidAmountCollectible = errors.New(
		"address: collectible asset amount not one",
	)

	// ErrInvalidAmountNormal is an error returned when we attempt to
	// create a Taproot Asset address for a Normal asset with an amount of
	// zero.
	ErrInvalidAmountNormal = errors.New(
		"address: normal asset amount of zero",
	)

	// ErrUnsupportedAssetType is an error returned when we attempt to
	// create a Taproot Asset address for a non-standard asset type.
	ErrUnsupportedAssetType = errors.New("address: unsupported asset type")

	// ErrNoAddr is returned if no address is found in the address store.
	ErrNoAddr = errors.New("address: no address found")

	// ErrScriptKeyNotFound is returned when a script key is not found in
	// the local database.
	ErrScriptKeyNotFound = errors.New("script key not found")

	// ErrInternalKeyNotFound is returned when an internal key is not found
	// in the local database.
	ErrInternalKeyNotFound = errors.New("internal key not found")

	// ErrUnknownVersion is returned when encountering an address with an
	// unrecognised version number.
	ErrUnknownVersion = errors.New("address: unknown version number")
)

// Version denotes the version of a Taproot Asset address format.
type Version uint8

const (
	// V0 is the initial Taproot Asset address format version.
	V0 Version = 0

	// LatestVersion is the latest supported Taproot Asset address version.
	latestVersion = V0
)

// Tap represents a Taproot Asset address. Taproot Asset addresses specify an
// asset, pubkey, and amount.
type Tap struct {
	// Version is the version of the address.
	Version Version

	// ChainParams is the reference to the chain parameters that were used
	// to encode the Taproot Asset address.
	ChainParams *ChainParams

	// AssetVersion is the Taproot Asset version of the asset.
	AssetVersion asset.Version

	// AssetID is the asset ID of the asset.
	AssetID asset.ID

	// GroupKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	GroupKey *btcec.PublicKey

	// ScriptKey represents a tweaked Taproot output key encumbering the
	// different ways an asset can be spent.
	ScriptKey btcec.PublicKey

	// InternalKey is the BIP-0340/0341 public key of the receiver.
	InternalKey btcec.PublicKey

	// TapscriptSibling is the tapscript sibling preimage of the script that
	// will be committed to alongside the assets received through this
	// address. This will usually be empty.
	TapscriptSibling *commitment.TapscriptPreimage

	// Amount is the number of asset units being requested by the receiver.
	Amount uint64

	// assetGen is the receiving asset's genesis metadata which directly
	// maps to its unique ID within the Taproot Asset protocol.
	assetGen asset.Genesis

	// ProofCourierAddr is the address of the proof courier that will be
	// used to distribute related proofs for this address.
	ProofCourierAddr url.URL
}

// newAddrOptions are a set of options that can modified how a new address is
// created.
type newAddrOptions struct {
	assetVersion asset.Version
}

// defaultNewAddrOptions returns a newAddrOptions struct with default values.`
func defaultNewAddrOptions() *newAddrOptions {
	return &newAddrOptions{
		assetVersion: asset.V0,
	}
}

// NewAddrOpt is a functional option that allows callers to modify how a new
// address will be created.
type NewAddrOpt func(*newAddrOptions)

// WithAssetVersion is a new address option that allows callers to specify the
// version of the asset version in the address.
func WithAssetVersion(v asset.Version) NewAddrOpt {
	return func(o *newAddrOptions) {
		o.assetVersion = v
	}
}

// New creates an address for receiving a Taproot asset.
//
// TODO(ffranr): This function takes many arguments. Add a struct to better
// organise its arguments.
func New(version Version, genesis asset.Genesis, groupKey *btcec.PublicKey,
	groupWitness wire.TxWitness, scriptKey btcec.PublicKey,
	internalKey btcec.PublicKey, amt uint64,
	tapscriptSibling *commitment.TapscriptPreimage,
	net *ChainParams, proofCourierAddr url.URL,
	opts ...NewAddrOpt) (*Tap, error) {

	options := defaultNewAddrOptions()
	for _, opt := range opts {
		opt(options)
	}

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

	if !IsBech32MTapPrefix(net.TapHRP + "1") {
		return nil, ErrUnsupportedHRP
	}

	// Check the version of the address format.
	if IsUnknownVersion(version) {
		return nil, ErrUnknownVersion
	}

	// We can only use a tapscript sibling that is not a Taproot Asset
	// commitment.
	if tapscriptSibling != nil {
		if _, err := tapscriptSibling.TapHash(); err != nil {
			return nil, errors.New("address: tapscript sibling " +
				"is invalid")
		}
	}

	if groupKey != nil && len(groupWitness) == 0 {
		return nil, fmt.Errorf("address: missing group signature")
	}

	payload := Tap{
		Version:          version,
		ChainParams:      net,
		AssetVersion:     options.assetVersion,
		AssetID:          genesis.ID(),
		GroupKey:         groupKey,
		ScriptKey:        scriptKey,
		InternalKey:      internalKey,
		TapscriptSibling: tapscriptSibling,
		Amount:           amt,
		assetGen:         genesis,
		ProofCourierAddr: proofCourierAddr,
	}
	return &payload, nil
}

// Copy returns a deep copy of an Address.
func (a *Tap) Copy() *Tap {
	addressCopy := *a

	if a.GroupKey != nil {
		groupPubKey := *a.GroupKey
		addressCopy.GroupKey = &groupPubKey
	}

	return &addressCopy
}

// Net returns the ChainParams struct matching the Taproot Asset address
// network.
func (a *Tap) Net() (*ChainParams, error) {
	return Net(a.ChainParams.TapHRP)
}

// AssetType returns the type of asset that this address was generated for.
func (a *Tap) AssetType() asset.Type {
	return a.assetGen.Type
}

// AttachGenesis attaches the asset's genesis metadata to the address.
func (a *Tap) AttachGenesis(gen asset.Genesis) {
	a.assetGen = gen
}

// TapCommitmentKey is the key that maps to the root commitment for the asset
// group specified by a Taproot Asset address.
func (a *Tap) TapCommitmentKey() [32]byte {
	return asset.TapCommitmentKey(a.AssetID, a.GroupKey)
}

// AssetCommitmentKey is the key that maps to the asset leaf for the asset
// specified by a Taproot Asset address.
func (a *Tap) AssetCommitmentKey() [32]byte {
	return asset.AssetCommitmentKey(
		a.AssetID, &a.ScriptKey, a.GroupKey == nil,
	)
}

// TapCommitment constructs the Taproot Asset commitment that is expected to
// appear on chain when assets are being sent to this address.
func (a *Tap) TapCommitment() (*commitment.TapCommitment, error) {
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
		asset.WithAssetVersion(a.AssetVersion),
	)
	if err != nil {
		return nil, err
	}

	return commitment.FromAssets(newAsset)
}

// TaprootOutputKey returns the on-chain Taproot output key.
func (a *Tap) TaprootOutputKey() (*btcec.PublicKey, error) {
	c, err := a.TapCommitment()
	if err != nil {
		return nil, fmt.Errorf("unable to derive Taproot Asset "+
			"commitment: %w", err)
	}

	var siblingHash *chainhash.Hash
	if a.TapscriptSibling != nil {
		siblingHash, err = a.TapscriptSibling.TapHash()
		if err != nil {
			return nil, fmt.Errorf("unable to derive tapscript "+
				"sibling hash: %w", err)
		}
	}

	tapscriptRoot := c.TapscriptRoot(siblingHash)
	taprootOutputKey := txscript.ComputeTaprootOutputKey(
		&a.InternalKey, tapscriptRoot[:],
	)

	// Make sure we always return the parity stripped key.
	taprootOutputKey, _ = schnorr.ParsePubKey(schnorr.SerializePubKey(
		taprootOutputKey,
	))

	return taprootOutputKey, nil
}

// EncodeRecords determines the non-nil records to include when encoding an
// address at runtime.
func (a *Tap) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 9)
	records = append(records, newAddressVersionRecord(&a.Version))
	records = append(records, newAddressAssetVersionRecord(&a.AssetVersion))
	records = append(records, newAddressAssetID(&a.AssetID))

	if a.GroupKey != nil {
		records = append(records, newAddressGroupKeyRecord(&a.GroupKey))
	}

	records = append(records, newAddressScriptKeyRecord(&a.ScriptKey))
	records = append(records, newAddressInternalKeyRecord(&a.InternalKey))
	if a.TapscriptSibling != nil {
		records = append(records, newAddressTapscriptSiblingRecord(
			&a.TapscriptSibling,
		))
	}
	records = append(records, newAddressAmountRecord(&a.Amount))

	records = append(
		records, newProofCourierAddrRecord(&a.ProofCourierAddr),
	)

	return records
}

// DecodeRecords provides all records known for an address for proper
// decoding.
func (a *Tap) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		newAddressVersionRecord(&a.Version),
		newAddressAssetVersionRecord(&a.AssetVersion),
		newAddressAssetID(&a.AssetID),
		newAddressGroupKeyRecord(&a.GroupKey),
		newAddressScriptKeyRecord(&a.ScriptKey),
		newAddressInternalKeyRecord(&a.InternalKey),
		newAddressTapscriptSiblingRecord(&a.TapscriptSibling),
		newAddressAmountRecord(&a.Amount),
		newProofCourierAddrRecord(&a.ProofCourierAddr),
	}
}

// Encode encodes an address into a TLV stream.
func (a *Tap) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes an address from a TLV stream.
func (a *Tap) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(a.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// EncodeAddress returns a bech32m string encoding of a Taproot Asset address.
func (a *Tap) EncodeAddress() (string, error) {
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
	if IsBech32MTapPrefix(a.ChainParams.TapHRP + "1") {
		bech, err := bech32.EncodeM(a.ChainParams.TapHRP, converted)
		if err != nil {
			return "", err
		}
		return bech, nil
	}

	return "", ErrUnsupportedHRP
}

// String returns the string representation of a Taproot Asset address.
func (a *Tap) String() string {
	return fmt.Sprintf("TapAddr{id=%s, amount=%d, script_key=%x}",
		a.AssetID, a.Amount, a.ScriptKey.SerializeCompressed())
}

// IsUnknownVersion returns true if the address version is not recognized by
// this implementation of tap.
func IsUnknownVersion(v Version) bool {
	switch v {
	case V0:
		return false
	default:
		return true
	}
}

// DecodeAddress parses a bech32m encoded Taproot Asset address string and
// returns the HRP and address TLV.
func DecodeAddress(addr string, net *ChainParams) (*Tap, error) {
	// Bech32m encoded Taproot Asset addresses start with a human-readable
	// part (hrp) followed by '1'. For Bitcoin mainnet the hrp is "tap",
	// and for testnet it is "tapt". If the address string has a prefix
	// that matches one of the prefixes for the known networks, we try to
	// decode it as a Taproot Asset address.
	oneIndex := strings.LastIndexByte(addr, '1')
	if oneIndex <= 0 {
		return nil, ErrInvalidBech32m
	}

	prefix := addr[:oneIndex+1]
	if !IsBech32MTapPrefix(prefix) {
		return nil, ErrUnsupportedHRP
	}

	// The HRP is everything before the found '1'.
	hrp := prefix[:len(prefix)-1]

	// Ensure that the hrp we decoded matches the network we're trying to
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

	var a Tap
	buf := bytes.NewBuffer(converted)
	if err := a.Decode(buf); err != nil {
		return nil, err
	}

	a.ChainParams = net

	// Ensure that the address version is known.
	if a.Version > latestVersion {
		return nil, ErrUnknownVersion
	}

	return &a, nil
}
