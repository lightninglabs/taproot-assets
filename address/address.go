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
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
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
		"address: zero amount cannot be used for normal asset " +
			"addresses of V0 or V1",
	)

	// ErrUnsupportedAssetType is an error returned when we attempt to
	// create a Taproot Asset address for a non-standard asset type.
	ErrUnsupportedAssetType = errors.New("address: unsupported asset type")

	// ErrNoAddr is returned if no address is found in the address store.
	ErrNoAddr = errors.New("address: no address found")

	// ErrNoEvent is returned if no event is found in the event store.
	ErrNoEvent = errors.New("address: no event found")

	// ErrScriptKeyNotFound is returned when a script key is not found in
	// the local database.
	ErrScriptKeyNotFound = errors.New("script key not found")

	// ErrInternalKeyNotFound is returned when an internal key is not found
	// in the local database.
	ErrInternalKeyNotFound = errors.New("internal key not found")

	// ErrUnknownVersion is returned when encountering an address with an
	// unrecognised version number.
	ErrUnknownVersion = errors.New("address: unknown version number")

	// ErrInvalidProofCourierAddr is returned when we attempt to create a
	// Taproot Asset address with a proof courier address that is not valid.
	ErrInvalidProofCourierAddr = errors.New(
		"address: invalid proof courier address",
	)
)

// Version denotes the version of a Taproot Asset address format.
type Version uint8

const (
	// V0 is the initial Taproot Asset address format version.
	V0 Version = 0

	// V1 addresses use V2 Taproot Asset commitments.
	V1 Version = 1

	// V2 addresses support sending grouped assets and require the new
	// auth mailbox proof courier address format.
	V2 Version = 2

	// LatestVersion is the latest supported Taproot Asset address version.
	latestVersion = V2
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

	// AssetID is the asset ID of the asset. This will be all zeroes for
	// V2 addresses that have a group key set.
	AssetID asset.ID

	// GroupKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	GroupKey *btcec.PublicKey

	// ScriptKey represents the asset's Taproot output key encumbering the
	// different ways an asset can be spent. This is different for V2
	// addresses, where this key is not the Taproot output key but the
	// Taproot internal key (the bare/raw key) of the asset script key (not
	// to be confused with the InternalKey below, which is for the on-chain
	// part of the address). The sender will use this key to encrypt the
	// send fragment that they post to the proof courier's mailbox. The raw
	// script key will also be used by the sender to derive different
	// Taproot output script keys for each asset ID.
	ScriptKey btcec.PublicKey

	// InternalKey is the BIP-0340/0341 public key of the receiver.
	InternalKey btcec.PublicKey

	// TapscriptSibling is the tapscript sibling preimage of the script that
	// will be committed to alongside the assets received through this
	// address. This will usually be empty.
	TapscriptSibling *commitment.TapscriptPreimage

	// Amount is the number of asset units being requested by the receiver.
	// The amount is allowed to be zero for V2 addresses, where the sender
	// will post a fragment containing the asset IDs and amounts to the
	// proof courier's mailbox.
	Amount uint64

	// assetGen is the receiving asset's genesis metadata which directly
	// maps to its unique ID within the Taproot Asset protocol. For a
	// grouped address, this will be the genesis of the asset genesis that
	// started the group. This doesn't matter in the context of an address,
	// because currently the genesis is only used to find out the type of
	// asset (normal vs. collectible).
	// TODO(guggero): Remove this field and combine the asset ID and group
	// key into a single asset specifier.
	assetGen asset.Genesis

	// ProofCourierAddr is the address of the proof courier that will be
	// used to distribute related proofs for this address. For V2 addresses
	// the proof courier address is mandatory and must be a valid auth
	// mailbox address.
	ProofCourierAddr url.URL

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing.
	// This enables forward compatibility with future versions of the
	// protocol as it allows new odd (optional) types to be added without
	// breaking old clients that don't yet fully understand them.
	UnknownOddTypes tlv.TypeMap
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
	tapscriptSibling *commitment.TapscriptPreimage, net *ChainParams,
	proofCourierAddr url.URL, opts ...NewAddrOpt) (*Tap, error) {

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
		if amt == 0 && version != V2 {
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

	// Version 2 addresses behave slightly differently than V0 and V1
	// addresses.
	addressAssetID := genesis.ID()
	if version == V2 {
		// Addresses with version 2 or later must use the new
		// authmailbox proof courier type.
		if proofCourierAddr.Scheme !=
			proof.AuthMailboxUniRpcCourierType {

			return nil, fmt.Errorf("%w: address version %d must "+
				"use the '%s' proof courier type",
				ErrInvalidProofCourierAddr, version,
				proof.AuthMailboxUniRpcCourierType)
		}

		// If a group key is provided, then we zero out the asset ID in
		// the address, as it doesn't make sense (we'll ignore it anyway
		// when sending assets to this address).
		if groupKey != nil {
			addressAssetID = asset.ID{}
		}
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
		AssetID:          addressAssetID,
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

// CommitmentVersion returns the Taproot Asset commitment version that matches
// the address version.
func CommitmentVersion(vers Version) (*commitment.TapCommitmentVersion,
	error) {

	switch vers {
	// For V0, the correct commitment version could be V0 or V1; we
	// can't know without accessing all leaves of the commitment itself.
	case V0:
		return nil, nil
	case V1, V2:
		return fn.Ptr(commitment.TapCommitmentV2), nil
	default:
		return nil, ErrUnknownVersion
	}
}

// ScriptKeyForAssetID returns the script key for this address for the given
// asset ID. For V2 addresses, this will derive a unique script key for the
// asset ID using the internal script key and a Pedersen commitment. For
// addresses before V2, the script key is always the Taproot output key as
// specified in the address directly.
func (a *Tap) ScriptKeyForAssetID(assetID asset.ID) (*btcec.PublicKey, error) {
	// For addresses before V2, the script key is always the Taproot output
	// key as specified in the address directly.
	if a.Version != V2 {
		return &a.ScriptKey, nil
	}

	// For V2 addresses, the script key is the internal key, which is used
	// to derive the Taproot output key for each asset ID using a unique
	// Pedersen commitment.
	scriptKey, err := asset.DeriveUniqueScriptKey(
		a.ScriptKey, assetID, asset.ScriptKeyDerivationUniquePedersen,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to derive unique script key: %w",
			err)
	}

	return scriptKey.PubKey, nil
}

// UsesSendManifests returns true if the address requires the new authmailbox
// proof courier type to transport a send manifest from the sender to the
// receiver. If this is true, it means the address supports sending grouped
// assets and also requires unique script keys for each asset ID.
func (a *Tap) UsesSendManifests() bool {
	return a.Version == V2
}

// SupportsGroupedAssets returns true if the address supports grouped assets.
func (a *Tap) SupportsGroupedAssets() bool {
	// Only V2 addresses support grouped assets.
	return a.Version == V2
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
	assetSpecifier := asset.NewSpecifierOptionalGroupPubKey(
		a.AssetID, a.GroupKey,
	)

	return asset.TapCommitmentKey(assetSpecifier)
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
		groupKey, asset.WithAssetVersion(a.AssetVersion),
	)
	if err != nil {
		return nil, err
	}

	commitmentVersion, err := CommitmentVersion(a.Version)
	if err != nil {
		return nil, err
	}

	return commitment.FromAssets(commitmentVersion, newAsset)
}

// TaprootOutputKey returns the on-chain Taproot output key.
func (a *Tap) TaprootOutputKey() (*btcec.PublicKey, error) {
	// V2 addresses can't be predicted on-chain, so the Taproot output key
	// doesn't make any sense. But because this is the primary identifier
	// for an address in the database, we still need to use a unique key.
	// We've already ensured that the script key is unique for v2 addresses,
	// so we can use that instead.
	if a.Version == V2 {
		// Make sure we always return the parity stripped key.
		return schnorr.ParsePubKey(schnorr.SerializePubKey(
			&a.ScriptKey,
		))
	}

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

	// Add any unknown odd types that were encountered during decoding.
	return asset.CombineRecords(records, a.UnknownOddTypes)
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

	unknownOddTypes, err := asset.TlvStrictDecodeP2P(
		stream, r, KnownAddressTypes,
	)
	if err != nil {
		return err
	}

	a.UnknownOddTypes = unknownOddTypes

	return nil
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
	s := asset.NewSpecifierOptionalGroupPubKey(a.AssetID, a.GroupKey)
	return fmt.Sprintf("TapAddr{specifier=%s, amount=%d, script_key=%x}",
		&s, a.Amount, a.ScriptKey.SerializeCompressed())
}

// IsUnknownVersion returns true if the address version is not recognized by
// this implementation of tap.
func IsUnknownVersion(v Version) bool {
	switch v {
	case V0, V1, V2:
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

// UnmarshalVersion parses an address version from the RPC variant.
func UnmarshalVersion(version taprpc.AddrVersion) (Version, error) {
	// For now, we'll only support two address versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case taprpc.AddrVersion_ADDR_VERSION_UNSPECIFIED:
		return V1, nil

	case taprpc.AddrVersion_ADDR_VERSION_V0:
		return V0, nil

	case taprpc.AddrVersion_ADDR_VERSION_V1:
		return V1, nil

	case taprpc.AddrVersion_ADDR_VERSION_V2:
		return V2, nil

	default:
		return 0, fmt.Errorf("unknown address version: %v", version)
	}
}

// MarshalVersion marshals the native address version into the RPC variant.
func MarshalVersion(version Version) (taprpc.AddrVersion, error) {
	// For now, we'll only support two address versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case V0:
		return taprpc.AddrVersion_ADDR_VERSION_V0, nil

	case V1:
		return taprpc.AddrVersion_ADDR_VERSION_V1, nil

	case V2:
		return taprpc.AddrVersion_ADDR_VERSION_V2, nil

	default:
		return 0, fmt.Errorf("unknown address version: %v", version)
	}
}
