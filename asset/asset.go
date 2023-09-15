package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/slices"
)

// SerializedKey is a type for representing a public key, serialized in the
// compressed, 33-byte form.
type SerializedKey [33]byte

// ToPubKey returns the public key parsed from the serialized key.
func (s SerializedKey) ToPubKey() (*btcec.PublicKey, error) {
	return btcec.ParsePubKey(s[:])
}

// SchnorrSerialized returns the Schnorr serialized, x-only 32-byte
// representation of the serialized key.
func (s SerializedKey) SchnorrSerialized() []byte {
	return s[1:]
}

// CopyBytes returns a copy of the underlying array as a byte slice.
func (s SerializedKey) CopyBytes() []byte {
	c := make([]byte, 33)
	copy(c, s[:])

	return c
}

// ToSerialized serializes a public key in its 33-byte compressed form.
func ToSerialized(pubKey *btcec.PublicKey) SerializedKey {
	var serialized SerializedKey
	copy(serialized[:], pubKey.SerializeCompressed())

	return serialized
}

// Version denotes the version of the Taproot Asset protocol in effect for an
// asset.
type Version uint8

var (
	// ZeroPrevID is the blank prev ID used for genesis assets and also
	// asset split leaves.
	ZeroPrevID PrevID

	// NUMSBytes is the NUMs point we'll use for un-spendable script keys.
	// It was generated via a try-and-increment approach using the phrase
	// "taproot-assets" with SHA2-256. The code for the try-and-increment
	// approach can be seen here:
	// https://github.com/lightninglabs/lightning-node-connect/tree/master/mailbox/numsgen
	NUMSBytes, _ = hex.DecodeString(
		"027c79b9b26e463895eef5679d8558942c86c4ad2233adef01bc3e6d540b" +
			"3653fe",
	)
	NUMSPubKey, _     = btcec.ParsePubKey(NUMSBytes)
	NUMSCompressedKey = ToSerialized(NUMSPubKey)
	NUMSScriptKey     = ScriptKey{
		PubKey: NUMSPubKey,
	}

	// ErrUnknownVersion is returned when an asset with an unknown asset
	// version is being used.
	ErrUnknownVersion = errors.New("asset: unknown asset version")
)

const (
	// TaprootAssetsKeyFamily is the key family used to generate internal
	// keys that tapd will use creating internal taproot keys and also any
	// other keys used for asset script keys.
	// This was derived via: sum(map(lambda y: ord(y), 'tapd')).
	// In order words: take the word tapd and return the integer
	// representation of each character and sum those. We get 425, then
	// divide that by 2, to allow us to fit this into just a 2-byte integer
	// and to ensure compatibility with the remote signer.
	TaprootAssetsKeyFamily = 212

	// V0 is the initial Taproot Asset protocol version.
	V0 Version = 0
)

const (
	// MetaHashLen is the length of the metadata hash.
	MetaHashLen = 32
)

// Genesis encodes an asset's genesis metadata which directly maps to its unique
// ID within the Taproot Asset protocol.
type Genesis struct {
	// FirstPrevOut represents the outpoint of the transaction's first
	// input that resulted in the creation of the asset.
	//
	// NOTE: This is immutable for the lifetime of the asset.
	FirstPrevOut wire.OutPoint

	// Tag is a human-readable identifier for the asset. This does not need
	// to be unique, but asset issuers should attempt for it to be unique if
	// possible.
	//
	// NOTE: This is immutable for the lifetime of the asset.
	Tag string

	// MetaHash is the hash of the set of encoded meta data. This value is
	// carried along for all assets transferred in the "light cone" of the
	// genesis asset. The preimage for this field may optionally be
	// revealed within the genesis asset proof for this asset.
	//
	// NOTE: This is immutable for the lifetime of the asset.
	MetaHash [MetaHashLen]byte

	// OutputIndex is the index of the output that carries the unique
	// Taproot Asset commitment in the genesis transaction.
	OutputIndex uint32

	// Type uniquely identifies the type of Taproot asset.
	Type Type
}

// TagHash computes the SHA-256 hash of the asset's tag.
func (g Genesis) TagHash() [sha256.Size]byte {
	// TODO(roasbeef): make the tag similar to the meta data here?
	//  * would then mean the Genesis struct is also constant sized
	return sha256.Sum256([]byte(g.Tag))
}

// ID serves as a unique identifier of an asset, resulting from:
//
//	sha256(genesisOutPoint || sha256(tag) || sha256(metadata) ||
//	  outputIndex || assetType)
type ID [sha256.Size]byte

// String returns the hex-encoded string representation of the ID.
func (i ID) String() string {
	return hex.EncodeToString(i[:])
}

// ID computes an asset's unique identifier from its metadata.
func (g Genesis) ID() ID {
	tagHash := g.TagHash()

	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &g.FirstPrevOut)
	_, _ = h.Write(tagHash[:])
	_, _ = h.Write(g.MetaHash[:])
	_ = binary.Write(h, binary.BigEndian, g.OutputIndex)
	_ = binary.Write(h, binary.BigEndian, g.Type)
	return *(*ID)(h.Sum(nil))
}

// GroupKeyTweak returns the tweak bytes that commit to the previous outpoint,
// output index and type of the genesis.
func (g Genesis) GroupKeyTweak() []byte {
	var keyGroupBytes bytes.Buffer
	_ = wire.WriteOutPoint(&keyGroupBytes, 0, 0, &g.FirstPrevOut)
	_ = binary.Write(&keyGroupBytes, binary.BigEndian, g.OutputIndex)
	_ = binary.Write(&keyGroupBytes, binary.BigEndian, g.Type)
	return keyGroupBytes.Bytes()
}

// Encode encodes an asset genesis.
func (g Genesis) Encode(w io.Writer) error {
	var buf [8]byte
	return GenesisEncoder(w, &g, &buf)
}

// DecodeGenesis decodes an asset genesis.
func DecodeGenesis(r io.Reader) (Genesis, error) {
	var (
		buf [8]byte
		gen Genesis
	)
	err := GenesisDecoder(r, &gen, &buf, 0)
	return gen, err
}

// Type denotes the asset types supported by the Taproot Asset protocol.
type Type uint8

const (
	// Normal is an asset that can be represented in multiple units,
	// resembling a divisible asset.
	Normal Type = 0

	// Collectible is a unique asset, one that cannot be represented in
	// multiple units.
	Collectible Type = 1
)

// String returns a human-readable description of the type.
func (t Type) String() string {
	switch t {
	case Normal:
		return "Normal"
	case Collectible:
		return "Collectible"
	default:
		return "<Unknown>"
	}
}

// PrevID serves as a reference to an asset's previous input.
type PrevID struct {
	// OutPoint refers to the asset's previous output position within a
	// transaction.
	OutPoint wire.OutPoint

	// ID is the asset ID of the previous asset tree.
	ID ID

	// TODO(roasbeef): need another ref type for assets w/ a key group?

	// ScriptKey is the previously tweaked Taproot output key committing to
	// the possible spending conditions of the asset. PrevID is being used
	// as map keys, so we want to only use data types with fixed and
	// comparable content, which a btcec.PublicKey might not be.
	ScriptKey SerializedKey
}

// Hash returns the SHA-256 hash of all items encapsulated by PrevID.
func (id PrevID) Hash() [sha256.Size]byte {
	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &id.OutPoint)
	_, _ = h.Write(id.ID[:])
	_, _ = h.Write(id.ScriptKey.SchnorrSerialized())
	return *(*[sha256.Size]byte)(h.Sum(nil))
}

// SplitCommitment represents the asset witness for an asset split.
type SplitCommitment struct {
	// Proof is the proof for a particular asset split resulting from a
	// split commitment.
	Proof mssmt.Proof

	// RootAsset is the asset containing the root of the split commitment
	// tree from which the `Proof` above was computed from.
	RootAsset Asset
}

// DeepEqual returns true if this split commitment is equal with the given split
// commitment.
func (s *SplitCommitment) DeepEqual(o *SplitCommitment) bool {
	if s == nil || o == nil {
		return s == o
	}

	if len(s.Proof.Nodes) != len(o.Proof.Nodes) {
		return false
	}

	for i := range s.Proof.Nodes {
		nodeA := s.Proof.Nodes[i]
		nodeB := o.Proof.Nodes[i]
		if !mssmt.IsEqualNode(nodeA, nodeB) {
			return false
		}
	}

	// We can't directly compare the root assets, as some non-TLV fields
	// might be different in unit tests. To avoid introducing flakes, we
	// only compare the encoded TLV data.
	var bufA, bufB bytes.Buffer

	// We ignore errors here, these possible errors (incorrect TLV stream
	// being created) are covered in unit tests.
	_ = s.RootAsset.Encode(&bufA)
	_ = o.RootAsset.Encode(&bufB)

	return bytes.Equal(bufA.Bytes(), bufB.Bytes())
}

// Witness is a nested TLV stream within the main Asset TLV stream that contains
// the necessary data to verify the movement of an asset. All fields should be
// nil to represent the creation of an asset, `TxWitness` and
// `SplitCommitmentProof` are mutually exclusive otherwise.
type Witness struct {
	// PrevID is a reference to an asset's previous input.
	//
	// NOTE: This should only be nil upon the creation of an asset.
	PrevID *PrevID

	// TxWitness is a witness that satisfies the asset's previous ScriptKey.
	//
	// NOTE: This field and `SplitCommitmentProof` are mutually exclusive,
	// except upon the creation of an asset, where both should be nil.
	TxWitness wire.TxWitness

	// SplitCommitmentProof is used to permit the spending of an asset UTXO
	// created as a result of an asset split. When an asset is split, the
	// non-change UTXO commits to the location of all other splits within an
	// MS-SMT tree. When spending a change UTXO resulting from a
	// `SplitCommitment`, a normal `Witness` isn't required, instead the
	// owner of the change asset UTXO must prove that it holds a valid split
	// which was authorized by the main transfer transaction.
	//
	// Outputs with the same `SplitCommitment` are said to share a single
	// `Witness` as such outputs are the result of a new asset split.
	// Therefore, we only need a single witness and the resulting merkle-sum
	// asset tree to verify a transfer.
	//
	// NOTE: This field and `TxWitness` are mutually exclusive,
	// except upon the creation of an asset, where both should be nil.
	//
	// TODO: This still needs to be specified further in the BIPs, see
	// https://github.com/lightninglabs/taproot-assets/issues/3.
	SplitCommitment *SplitCommitment
}

// EncodeRecords determines the non-nil records to include when encoding an
// asset witness at runtime.
func (w *Witness) EncodeRecords() []tlv.Record {
	var records []tlv.Record
	if w.PrevID != nil {
		records = append(records, NewWitnessPrevIDRecord(&w.PrevID))
	}
	if len(w.TxWitness) > 0 {
		records = append(records, NewWitnessTxWitnessRecord(
			&w.TxWitness,
		))
	}
	if w.SplitCommitment != nil {
		records = append(records, NewWitnessSplitCommitmentRecord(
			&w.SplitCommitment,
		))
	}
	return records
}

// DecodeRecords provides all records known for an asset witness for proper
// decoding.
func (w *Witness) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		NewWitnessPrevIDRecord(&w.PrevID),
		NewWitnessTxWitnessRecord(&w.TxWitness),
		NewWitnessSplitCommitmentRecord(&w.SplitCommitment),
	}
}

// Encode encodes an asset witness into a TLV stream.
func (w *Witness) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(w.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Decode decodes an asset witness from a TLV stream.
func (w *Witness) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(w.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// DeepEqual returns true if this witness is equal with the given witness.
func (w *Witness) DeepEqual(o *Witness) bool {
	if w == nil || o == nil {
		return w == o
	}

	if !reflect.DeepEqual(w.PrevID, o.PrevID) {
		return false
	}

	if !reflect.DeepEqual(w.TxWitness, o.TxWitness) {
		return false
	}

	return w.SplitCommitment.DeepEqual(o.SplitCommitment)
}

// ScriptVersion denotes the asset script versioning scheme.
type ScriptVersion uint16

const (
	// ScriptV0 represents the initial asset script version of the Taproot
	// Asset protocol. In this version, assets commit to a tweaked Taproot
	// output key, allowing the ability for an asset to indirectly commit to
	// multiple spending conditions.
	ScriptV0 ScriptVersion = 0
)

// AssetGroup holds information about an asset group, including the genesis
// information needed re-tweak the raw key.
type AssetGroup struct {
	*Genesis

	*GroupKey
}

// GroupKey is the tweaked public key that is used to associate assets together
// across distinct asset IDs, allowing further issuance of the asset to be made
// possible.
type GroupKey struct {
	// RawKey is the raw group key before the tweak with the genesis point
	// has been applied.
	RawKey keychain.KeyDescriptor

	// GroupPubKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible. The tweaked public key is the result of:
	//   groupInternalKey + sha256(groupInternalKey || genesisOutPoint) * G
	GroupPubKey btcec.PublicKey

	// TapscriptRoot is the root of the Tapscript tree that commits to all
	// script spend conditions for the group key. Instead of spending an
	// asset, these scripts are used to define witnesses more complex than
	// a Schnorr signature for reissuing assets.
	TapscriptRoot [sha256.Size]byte

	// Witness is a stack of witness elements that authorizes the membership
	// of an asset in a particular asset group. The witness can be a single
	// signature or a script from the tapscript tree committed to with the
	// TapscriptRoot, and follows the witness rules in BIP-341.
	Witness wire.TxWitness
}

// GroupKeyReveal is a type for representing the data used to derive the tweaked
// key used to identify an asset group. The final tweaked key is the result of:
// TapTweak(groupInternalKey, tapscriptRoot)
type GroupKeyReveal struct {
	// RawKey is the public key that is tweaked twice to derive the final
	// tweaked group key. The final tweaked key is the result of:
	// 	groupInternalKey =  RawKey * sha256(assetID || RawKey) * G.
	// 	GroupPubKey = TapTweak(groupInternalKey, TapscriptRoot)
	RawKey SerializedKey

	// TapscriptRoot is the root of the Tapscript tree that commits to all
	// script spend conditions for the group key. Instead of spending an
	// asset, these scripts are used to define witnesses more complex than
	// a Schnorr signature for reissuing assets. This is either empty/nil or
	// a 32-byte hash.
	TapscriptRoot []byte
}

// GroupPubKey returns the group public key derived from the group key reveal.
func (g *GroupKeyReveal) GroupPubKey(assetID ID) (*btcec.PublicKey, error) {
	rawKey, err := g.RawKey.ToPubKey()
	if err != nil {
		return nil, err
	}

	return GroupPubKey(rawKey, assetID[:], g.TapscriptRoot)
}

func GroupPubKey(rawKey *btcec.PublicKey, singleTweak, tapTweak []byte) (
	*btcec.PublicKey, error) {

	if len(singleTweak) != sha256.Size {
		return nil, fmt.Errorf("genesis tweak must be %d bytes",
			sha256.Size)
	}

	// A nil Tapscript root will be represented as an empty byte slice after
	// encoding and decoding, so we need to check for both forms.
	internalKey := input.TweakPubKeyWithTweak(rawKey, singleTweak)
	if tapTweak == nil || bytes.Equal(tapTweak, []byte{}) {
		return txscript.ComputeTaprootKeyNoScript(internalKey), nil
	}

	if len(tapTweak) != sha256.Size {
		return nil, fmt.Errorf("tapscript tweaks must be %d bytes",
			sha256.Size)
	}

	return txscript.ComputeTaprootOutputKey(internalKey, tapTweak), nil
}

// IsEqual returns true if this group key and signature are exactly equivalent
// to the passed other group key.
func (g *GroupKey) IsEqual(otherGroupKey *GroupKey) bool {
	if g == nil {
		return otherGroupKey == nil
	}

	if otherGroupKey == nil {
		return false
	}

	equalGroup := g.IsEqualGroup(otherGroupKey)
	if !equalGroup {
		return false
	}

	if g.TapscriptRoot != otherGroupKey.TapscriptRoot {
		return false
	}

	if len(g.Witness) != len(otherGroupKey.Witness) {
		return false
	}

	return slices.EqualFunc(
		g.Witness, otherGroupKey.Witness, func(a, b []byte) bool {
			return bytes.Equal(a, b)
		},
	)
}

// IsEqualGroup returns true if this group key describes the same asset group
// as the passed other group key.
func (g *GroupKey) IsEqualGroup(otherGroupKey *GroupKey) bool {
	// If this key is nil, the other must be nil too.
	if g == nil {
		return otherGroupKey == nil
	}

	// This key is non nil, other must be non nil too.
	if otherGroupKey == nil {
		return false
	}

	// Make sure the RawKey are equivalent.
	if !EqualKeyDescriptors(g.RawKey, otherGroupKey.RawKey) {
		return false
	}

	return g.GroupPubKey.IsEqual(&otherGroupKey.GroupPubKey)
}

// hasAnnex returns true if the provided witness includes an annex element,
// otherwise returns false.
func hasAnnex(witness wire.TxWitness) bool {
	// By definition, the annex element can not be the sole element in the
	// witness stack.
	if len(witness) < 2 {
		return false
	}

	// If an annex element is included in the witness stack, by definition,
	// it will be the last element and will be prefixed by a Taproot annex
	// tag.
	lastElement := witness[len(witness)-1]
	if len(lastElement) == 0 {
		return false
	}

	return lastElement[0] == txscript.TaprootAnnexTag
}

// IsGroupSig checks if the given witness represents a key path spend of the
// tweaked group key. Such a witness must include one Schnorr signature, and
// can include an optional annex (matching the rules specified in BIP-341).
// If the signature is valid, IsGroupSig returns true and the parsed signature.
func IsGroupSig(witness wire.TxWitness) (*schnorr.Signature, bool) {
	if len(witness) == 0 || len(witness) > 2 {
		return nil, false
	}

	if len(witness[0]) != schnorr.SignatureSize {
		return nil, false
	}

	// If we have two witness elements and the first is a signature, the
	// second must be a valid annex.
	if len(witness) == 2 && !hasAnnex(witness) {
		return nil, false
	}

	groupSig, err := schnorr.ParseSignature(witness[0])
	if err != nil {
		return nil, false
	}

	return groupSig, true
}

// ParseGroupWitness parses a group witness that was stored as a TLV stream
// in the DB.
func ParseGroupWitness(witness []byte) (wire.TxWitness, error) {
	var (
		buf          [8]byte
		b            = bytes.NewReader(witness)
		witnessStack wire.TxWitness
	)

	err := TxWitnessDecoder(b, &witnessStack, &buf, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to parse group witness: %w", err)
	}

	return witnessStack, nil
}

// SerializeGroupWitness serializes a group witness into a TLV stream suitable
// for storing in the DB.
func SerializeGroupWitness(witness wire.TxWitness) ([]byte, error) {
	if len(witness) == 0 {
		return nil, fmt.Errorf("group witness cannot be empty")
	}

	var (
		buf [8]byte
		b   bytes.Buffer
	)

	err := TxWitnessEncoder(&b, &witness, &buf)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize group witness: %w",
			err)
	}

	return b.Bytes(), nil
}

// ParseGroupSig parses a group signature that was stored as a group witness in
// the DB. It returns an error if the witness is not a single Schnorr signature.
func ParseGroupSig(witness []byte) (*schnorr.Signature, error) {
	groupWitness, err := ParseGroupWitness(witness)
	if err != nil {
		return nil, err
	}

	groupSig, isSig := IsGroupSig(groupWitness)
	if !isSig {
		return nil, fmt.Errorf("group witness must be a single " +
			"Schnorr signature")
	}

	return groupSig, nil
}

// IsLocal returns true if the private key that corresponds to this group key
// is held by this daemon. A non-local group key is stored with the internal key
// family and index set to their default values, 0.
func (g *GroupKey) IsLocal() bool {
	return g.RawKey.Family == TaprootAssetsKeyFamily
}

// EqualKeyDescriptors returns true if the two key descriptors are equal.
func EqualKeyDescriptors(a, o keychain.KeyDescriptor) bool {
	if a.KeyLocator != o.KeyLocator {
		return false
	}

	if a.PubKey == nil || o.PubKey == nil {
		return a.PubKey == o.PubKey
	}

	return a.PubKey.IsEqual(o.PubKey)
}

// TweakedScriptKey is an embedded struct which is primarily used by wallets to
// be able to keep track of the tweak of a script key along side the raw key
// derivation information.
type TweakedScriptKey struct {
	// RawKey is the raw script key before the script key tweak is applied.
	// We store a full key descriptor here for wallet purposes, but will
	// only encode the pubkey above for the normal script leaf TLV
	// encoding.
	RawKey keychain.KeyDescriptor

	// Tweak is the tweak that is applied on the raw script key to get the
	// public key. If this is nil, then a BIP-0086 tweak is assumed.
	Tweak []byte
}

// ScriptKey represents a tweaked Taproot output key encumbering the different
// ways an asset can be spent.
type ScriptKey struct {
	// PubKey is the script key that'll be encoded in the final TLV format.
	// All signatures are checked against this script key.
	PubKey *btcec.PublicKey

	*TweakedScriptKey
}

// IsUnSpendable returns true if this script key is equal to the un-spendable
// NUMS point.
func (s ScriptKey) IsUnSpendable() (bool, error) {
	if s.PubKey == nil {
		return false, fmt.Errorf("script key has nil public key")
	}

	return NUMSPubKey.IsEqual(s.PubKey), nil
}

// NewScriptKey constructs a ScriptKey with only the publicly available
// information. This resulting key may or may not have a tweak applied to it.
func NewScriptKey(key *btcec.PublicKey) ScriptKey {
	// Since we'll never query lnd for a tweaked key, it doesn't matter if
	// we lose the parity information here. And this will only ever be
	// serialized on chain in a 32-bit representation as well.
	key, _ = schnorr.ParsePubKey(
		schnorr.SerializePubKey(key),
	)
	return ScriptKey{
		PubKey: key,
	}
}

// NewScriptKeyBip86 constructs a ScriptKey tweaked BIP-0086 style. The
// resulting script key will include the specified BIP-0086 tweak (no real
// tweak), and also apply that to the final external PubKey.
func NewScriptKeyBip86(rawKey keychain.KeyDescriptor) ScriptKey {
	// Tweak the script key BIP-0086 style (such that we only commit to the
	// internal key when signing).
	tweakedPubKey := txscript.ComputeTaprootKeyNoScript(
		rawKey.PubKey,
	)

	// Since we'll never query lnd for a tweaked key, it doesn't matter if
	// we lose the parity information here. And this will only ever be
	// serialized on chain in a 32-bit representation as well.
	tweakedPubKey, _ = schnorr.ParsePubKey(
		schnorr.SerializePubKey(tweakedPubKey),
	)

	return ScriptKey{
		PubKey: tweakedPubKey,
		TweakedScriptKey: &TweakedScriptKey{
			RawKey: rawKey,
		},
	}
}

// DeriveGroupKey derives an asset's group key based on an internal public
// key descriptor, the original group asset genesis, and the asset's genesis.
func DeriveGroupKey(genSigner GenesisSigner, genBuilder GenesisTxBuilder,
	rawKey keychain.KeyDescriptor, initialGen Genesis,
	newAsset *Asset) (*GroupKey, error) {

	// First, perform the final checks on the asset being authorized for
	// group membership.
	if newAsset == nil {
		return nil, fmt.Errorf("grouped asset cannot be nil")
	}

	if !newAsset.HasGenesisWitness() {
		return nil, fmt.Errorf("asset is not a genesis asset")
	}

	if initialGen.Type != newAsset.Type {
		return nil, fmt.Errorf("asset group type mismatch")
	}

	// Compute the tweaked group key and set it in the asset before
	// creating the virtual minting transaction.
	genesisTweak := initialGen.ID()
	tweakedGroupKey, err := GroupPubKey(rawKey.PubKey, genesisTweak[:], nil)
	if err != nil {
		return nil, fmt.Errorf("cannot tweak group key: %w", err)
	}

	assetWithGroup := newAsset.Copy()
	assetWithGroup.GroupKey = &GroupKey{
		GroupPubKey: *tweakedGroupKey,
	}

	// Build the virtual transaction that represents the minting of the new
	// asset, which will be signed to generate the group witness.
	genesisTx, prevOut, err := genBuilder.BuildGenesisTx(assetWithGroup)
	if err != nil {
		return nil, fmt.Errorf("cannot build virtual tx: %w", err)
	}

	// Build the static signing descriptor needed to sign the virtual
	// minting transaction. This is restricted to group keys with an empty
	// tapscript root and key path spends.
	signDesc := &lndclient.SignDescriptor{
		KeyDesc:     rawKey,
		SingleTweak: genesisTweak[:],
		SignMethod:  input.TaprootKeySpendBIP0086SignMethod,
		Output:      prevOut,
		HashType:    txscript.SigHashDefault,
		InputIndex:  0,
	}
	sig, err := genSigner.SignVirtualTx(signDesc, genesisTx, prevOut)
	if err != nil {
		return nil, err
	}

	return &GroupKey{
		RawKey:      rawKey,
		GroupPubKey: *tweakedGroupKey,
		Witness:     wire.TxWitness{sig.Serialize()},
	}, nil
}

// Asset represents a Taproot asset.
type Asset struct {
	// Version is the Taproot Asset version of the asset.
	Version Version

	// Genesis encodes an asset's genesis metadata which directly maps to
	// its unique ID within the Taproot Asset protocol.
	Genesis

	// Amount is the number of units represented by the asset.
	Amount uint64

	// LockTime, if non-zero, restricts an asset from being moved prior to
	// the represented block height in the chain.
	LockTime uint64

	// RelativeLockTime, if non-zero, restricts an asset from being moved
	// until a number of blocks after the confirmation height of the latest
	// transaction for the asset is reached.
	RelativeLockTime uint64

	// PrevWitnesses contains the witness(es) of an asset's previous
	// transfer.
	PrevWitnesses []Witness

	// SplitCommitmentRoot is the root node of the MS-SMT storing split
	// commitments.
	//
	// NOTE: This should only be set when the previous transfer of an asset
	// resulted in a value split.
	SplitCommitmentRoot mssmt.Node

	// ScriptVersion denotes how an asset's ScriptKey should be validated.
	ScriptVersion ScriptVersion

	// ScriptKey represents a tweaked Taproot output key encumbering the
	// different ways an asset can be spent.
	ScriptKey ScriptKey

	// GroupKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	GroupKey *GroupKey
}

// IsUnknownVersion returns true if an asset has a version that is not
// recognized by this implementation of tap.
func (a *Asset) IsUnknownVersion() bool {
	switch a.Version {
	case V0:
		return false
	default:
		return true
	}
}

// New instantiates a new asset with a genesis asset witness.
func New(genesis Genesis, amount, locktime, relativeLocktime uint64,
	scriptKey ScriptKey, groupKey *GroupKey) (*Asset, error) {

	// Collectible assets can only ever be issued once.
	if genesis.Type != Normal && amount != 1 {
		return nil, fmt.Errorf("amount must be 1 for asset of type %v",
			genesis.Type)
	}

	// Valid genesis asset witness.
	genesisWitness := Witness{
		PrevID:          &PrevID{},
		TxWitness:       nil,
		SplitCommitment: nil,
	}

	// Genesis assets with an asset group must have the group witness stored
	// in the genesis asset witness, if present.
	if groupKey != nil && groupKey.Witness != nil {
		genesisWitness.TxWitness = groupKey.Witness
	}

	return &Asset{
		Version:             V0,
		Genesis:             genesis,
		Amount:              amount,
		LockTime:            locktime,
		RelativeLockTime:    relativeLocktime,
		PrevWitnesses:       []Witness{genesisWitness},
		SplitCommitmentRoot: nil,
		ScriptVersion:       ScriptV0,
		ScriptKey:           scriptKey,
		GroupKey:            groupKey,
	}, nil
}

// TapCommitmentKey is the key that maps to the root commitment for a specific
// asset group within a TapCommitment.
//
// NOTE: This function is also used outside the asset package.
func TapCommitmentKey(assetID ID, groupKey *btcec.PublicKey) [32]byte {
	if groupKey == nil {
		return assetID
	}
	return sha256.Sum256(schnorr.SerializePubKey(groupKey))
}

// TapCommitmentKey is the key that maps to the root commitment for a specific
// asset group within a TapCommitment.
func (a *Asset) TapCommitmentKey() [32]byte {
	if a.GroupKey == nil {
		return TapCommitmentKey(a.Genesis.ID(), nil)
	}
	return TapCommitmentKey(a.Genesis.ID(), &a.GroupKey.GroupPubKey)
}

// AssetCommitmentKey returns a key which can be used to locate an
// asset within an AssetCommitment that is specific to a particular owner
// (script key).
//
// NOTE: This function is also used outside the asset package.
func AssetCommitmentKey(assetID ID, scriptKey *btcec.PublicKey,
	issuanceDisabled bool) [32]byte {

	if issuanceDisabled {
		return sha256.Sum256(schnorr.SerializePubKey(scriptKey))
	}

	h := sha256.New()
	_, _ = h.Write(assetID[:])
	_, _ = h.Write(schnorr.SerializePubKey(scriptKey))
	return *(*[32]byte)(h.Sum(nil))
}

// AssetCommitmentKey is the key that maps to a specific owner of an asset
// within a Taproot AssetCommitment.
func (a *Asset) AssetCommitmentKey() [32]byte {
	issuanceDisabled := a.GroupKey == nil
	return AssetCommitmentKey(
		a.Genesis.ID(), a.ScriptKey.PubKey, issuanceDisabled,
	)
}

// HasGenesisWitness determines whether an asset has a valid genesis witness,
// which should only have one input with a zero PrevID and empty witness and
// split commitment proof.
func (a *Asset) HasGenesisWitness() bool {
	if len(a.PrevWitnesses) != 1 {
		return false
	}

	witness := a.PrevWitnesses[0]
	if witness.PrevID == nil || len(witness.TxWitness) > 0 ||
		witness.SplitCommitment != nil {

		return false
	}

	return *witness.PrevID == ZeroPrevID
}

// NeedsGenesisWitnessForGroup determines whether an asset is a genesis grouped
// asset, which does not yet have a group witness.
func (a *Asset) NeedsGenesisWitnessForGroup() bool {
	return a.HasGenesisWitness() && a.GroupKey != nil
}

// HasGenesisWitnessForGroup determines whether an asset has a witness for a
// genesis asset in an asset group. This asset must have a non-empty group key
// and a single prevWitness with a zero PrevID, empty split commitment proof,
// and non-empty witness.
func (a *Asset) HasGenesisWitnessForGroup() bool {
	if a.GroupKey == nil || len(a.PrevWitnesses) != 1 {
		return false
	}

	// The single PrevWitness must have a ZeroPrevID, non-empty witness, and
	// nil split commitment.
	witness := a.PrevWitnesses[0]
	if witness.PrevID == nil || len(witness.TxWitness) == 0 ||
		witness.SplitCommitment != nil {

		return false
	}

	return *witness.PrevID == ZeroPrevID
}

// HasSplitCommitmentWitness returns true if an asset has a split commitment
// witness.
func (a *Asset) HasSplitCommitmentWitness() bool {
	if len(a.PrevWitnesses) != 1 {
		return false
	}

	witness := a.PrevWitnesses[0]

	return witness.PrevID != nil && len(witness.TxWitness) == 0 &&
		witness.SplitCommitment != nil
}

// IsUnSpendable returns true if an asset uses the un-spendable script key and
// has zero value.
func (a *Asset) IsUnSpendable() bool {
	return ToSerialized(a.ScriptKey.PubKey) == NUMSCompressedKey &&
		a.Amount == 0
}

// Copy returns a deep copy of an Asset.
func (a *Asset) Copy() *Asset {
	assetCopy := *a

	assetCopy.PrevWitnesses = make([]Witness, len(a.PrevWitnesses))
	for idx := range a.PrevWitnesses {
		witness := a.PrevWitnesses[idx]

		var witnessCopy Witness
		if witness.PrevID != nil {
			witnessCopy.PrevID = &PrevID{
				OutPoint:  witness.PrevID.OutPoint,
				ID:        witness.PrevID.ID,
				ScriptKey: witness.PrevID.ScriptKey,
			}
		}
		if len(witness.TxWitness) > 0 {
			witnessCopy.TxWitness = make(
				wire.TxWitness, len(witness.TxWitness),
			)
			for i, witnessItem := range witness.TxWitness {
				witnessCopy.TxWitness[i] = make(
					[]byte, len(witnessItem),
				)
				copy(witnessCopy.TxWitness[i], witnessItem)
			}
		}
		if witness.SplitCommitment != nil {
			witnessCopy.SplitCommitment = &SplitCommitment{
				Proof:     *witness.SplitCommitment.Proof.Copy(),
				RootAsset: *witness.SplitCommitment.RootAsset.Copy(),
			}
		}
		assetCopy.PrevWitnesses[idx] = witnessCopy
	}

	if a.SplitCommitmentRoot != nil {
		assetCopy.SplitCommitmentRoot = mssmt.NewComputedNode(
			a.SplitCommitmentRoot.NodeHash(),
			a.SplitCommitmentRoot.NodeSum(),
		)
	}

	assetCopy.ScriptKey = ScriptKey{
		PubKey: a.ScriptKey.PubKey,
	}

	if a.ScriptKey.TweakedScriptKey != nil {
		assetCopy.ScriptKey.TweakedScriptKey = &TweakedScriptKey{}
		assetCopy.ScriptKey.RawKey = a.ScriptKey.RawKey
		assetCopy.ScriptKey.Tweak = make([]byte, len(a.ScriptKey.Tweak))
		copy(assetCopy.ScriptKey.Tweak, a.ScriptKey.Tweak)
	}

	if a.GroupKey != nil {
		assetCopy.GroupKey = &GroupKey{
			RawKey:      a.GroupKey.RawKey,
			GroupPubKey: a.GroupKey.GroupPubKey,
			Witness:     a.GroupKey.Witness,
		}
	}

	return &assetCopy
}

// DeepEqual returns true if this asset is equal with the given asset.
func (a *Asset) DeepEqual(o *Asset) bool {
	if a.Version != o.Version {
		return false
	}

	// The ID commits to everything in the Genesis, including the type.
	if a.ID() != o.ID() {
		return false
	}

	if a.Amount != o.Amount {
		return false
	}
	if a.LockTime != o.LockTime {
		return false
	}
	if a.RelativeLockTime != o.RelativeLockTime {
		return false
	}
	if a.ScriptVersion != o.ScriptVersion {
		return false
	}

	if !mssmt.IsEqualNode(a.SplitCommitmentRoot, o.SplitCommitmentRoot) {
		return false
	}

	if !reflect.DeepEqual(a.ScriptKey, o.ScriptKey) {
		return false
	}

	if !a.GroupKey.IsEqual(o.GroupKey) {
		return false
	}

	if len(a.PrevWitnesses) != len(o.PrevWitnesses) {
		return false
	}

	for i := range a.PrevWitnesses {
		if !a.PrevWitnesses[i].DeepEqual(&o.PrevWitnesses[i]) {
			return false
		}
	}

	return true
}

// EncodeRecords determines the non-nil records to include when encoding an
// asset at runtime.
func (a *Asset) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 11)
	records = append(records, NewLeafVersionRecord(&a.Version))
	records = append(records, NewLeafGenesisRecord(&a.Genesis))
	records = append(records, NewLeafTypeRecord(&a.Type))
	records = append(records, NewLeafAmountRecord(&a.Amount))
	if a.LockTime > 0 {
		records = append(records, NewLeafLockTimeRecord(&a.LockTime))
	}
	if a.RelativeLockTime > 0 {
		records = append(records, NewLeafRelativeLockTimeRecord(
			&a.RelativeLockTime,
		))
	}
	if len(a.PrevWitnesses) > 0 {
		records = append(records, NewLeafPrevWitnessRecord(
			&a.PrevWitnesses,
		))
	}
	if a.SplitCommitmentRoot != nil {
		records = append(records, NewLeafSplitCommitmentRootRecord(
			&a.SplitCommitmentRoot,
		))
	}
	records = append(records, NewLeafScriptVersionRecord(&a.ScriptVersion))
	records = append(records, NewLeafScriptKeyRecord(&a.ScriptKey.PubKey))
	if a.GroupKey != nil {
		records = append(records, NewLeafGroupKeyRecord(&a.GroupKey))
	}
	return records
}

// DecodeRecords provides all records known for an asset witness for proper
// decoding.
func (a *Asset) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		NewLeafVersionRecord(&a.Version),
		NewLeafGenesisRecord(&a.Genesis),
		NewLeafTypeRecord(&a.Type),
		NewLeafAmountRecord(&a.Amount),
		NewLeafLockTimeRecord(&a.LockTime),
		NewLeafRelativeLockTimeRecord(&a.RelativeLockTime),
		NewLeafPrevWitnessRecord(&a.PrevWitnesses),
		NewLeafSplitCommitmentRootRecord(&a.SplitCommitmentRoot),
		NewLeafScriptVersionRecord(&a.ScriptVersion),
		NewLeafScriptKeyRecord(&a.ScriptKey.PubKey),
		NewLeafGroupKeyRecord(&a.GroupKey),
	}
}

// Encode encodes an asset into a TLV stream.
func (a *Asset) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes an asset from a TLV stream.
func (a *Asset) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(a.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// Leaf returns the asset encoded as a MS-SMT leaf node.
func (a *Asset) Leaf() (*mssmt.LeafNode, error) {
	if a.IsUnknownVersion() {
		return nil, ErrUnknownVersion
	}
	var buf bytes.Buffer
	if err := a.Encode(&buf); err != nil {
		return nil, err
	}
	return mssmt.NewLeafNode(buf.Bytes(), a.Amount), nil
}
