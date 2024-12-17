package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/slices"
)

const (
	// MaxAssetNameLength is the maximum byte length of an asset's name.
	// This byte length is equivalent to character count for single-byte
	// UTF-8 characters.
	MaxAssetNameLength = 64

	// MaxAssetEncodeSizeBytes is the size we expect an asset to not exceed
	// in its encoded form. This is used to prevent OOMs when decoding
	// assets. The main contributing factor to this size are the previous
	// witnesses which we currently allow to number up to 65k witnesses.
	MaxAssetEncodeSizeBytes = blockchain.MaxBlockWeight
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

const (
	// V0 is the initial Taproot Asset protocol version.
	V0 Version = 0

	// V1 is the version of asset serialization that doesn't include the
	// witness field when creating a TAP commitment. This is similar to
	// segwit as found in Bitcoin land.
	V1 Version = 1
)

// EncodeType is used to denote the type of encoding used for an asset.
type EncodeType uint8

const (
	// EncodeNormal normal is the normal encoding type for an asset.
	EncodeNormal EncodeType = iota

	// EncodeSegwit denotes that the witness vector field is not to be
	// encoded.
	EncodeSegwit
)

var (
	// ZeroPrevID is the blank prev ID used for genesis assets and also
	// asset split leaves.
	ZeroPrevID PrevID

	// EmptyGenesis is the empty Genesis struct used for alt leaves.
	EmptyGenesis Genesis

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
	// possible. Users usually recognise this field as the asset's name.
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

// Record returns a TLV record that can be used to encode/decode an ID to/from a
// TLV stream.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (i *ID) Record() tlv.Record {
	const recordSize = sha256.Size

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeStaticRecord(0, i, recordSize, IDEncoder, IDDecoder)
}

// Ensure ID implements the tlv.RecordProducer interface.
var _ tlv.RecordProducer = (*ID)(nil)

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

var (
	// ErrUnwrapAssetID is an error type which is returned when an asset ID
	// cannot be unwrapped from a specifier.
	ErrUnwrapAssetID = errors.New("unable to unwrap asset ID")
)

// Specifier is a type that can be used to specify an asset by its ID, its asset
// group public key, or both.
type Specifier struct {
	// id is the asset ID.
	id fn.Option[ID]

	// groupKey is the asset group public key.
	groupKey fn.Option[btcec.PublicKey]
}

// NewSpecifier creates a new Specifier instance based on the provided
// parameters.
//
// The Specifier identifies an asset using either an asset ID, a group public
// key, or a group key. At least one of these must be specified if the
// `mustBeSpecified` parameter is set to true.
func NewSpecifier(id *ID, groupPubKey *btcec.PublicKey, groupKey *GroupKey,
	mustBeSpecified bool) (Specifier, error) {

	// Return an error if the asset ID, group public key, and group key are
	// all nil and at least one of them must be specified.
	isAnySpecified := id != nil || groupPubKey != nil || groupKey != nil
	if !isAnySpecified && mustBeSpecified {
		return Specifier{}, fmt.Errorf("at least one of the asset ID "+
			"or asset group key fields must be specified "+
			"(id=%v, groupPubKey=%v, groupKey=%v)",
			id, groupPubKey, groupKey)
	}

	// Create an option for the asset ID.
	optId := fn.MaybeSome(id)

	// Create an option for the group public key.
	optGroupPubKey := fn.MaybeSome(groupPubKey)

	if groupKey != nil {
		optGroupPubKey = fn.Some(groupKey.GroupPubKey)
	}

	return Specifier{
		id:       optId,
		groupKey: optGroupPubKey,
	}, nil
}

// NewSpecifierOptionalGroupPubKey creates a new specifier that specifies an
// asset by its ID and an optional group public key.
func NewSpecifierOptionalGroupPubKey(id ID,
	groupPubKey *btcec.PublicKey) Specifier {

	s := Specifier{
		id: fn.Some(id),
	}

	if groupPubKey != nil {
		s.groupKey = fn.Some(*groupPubKey)
	}

	return s
}

// NewSpecifierOptionalGroupKey creates a new specifier that specifies an
// asset by its ID and an optional group key.
func NewSpecifierOptionalGroupKey(id ID, groupKey *GroupKey) Specifier {
	s := Specifier{
		id: fn.Some(id),
	}

	if groupKey != nil {
		s.groupKey = fn.Some(groupKey.GroupPubKey)
	}

	return s
}

// NewSpecifierFromId creates a new specifier that specifies an asset by its ID.
func NewSpecifierFromId(id ID) Specifier {
	return Specifier{
		id: fn.Some(id),
	}
}

// NewSpecifierFromGroupKey creates a new specifier that specifies an asset by
// its group public key.
func NewSpecifierFromGroupKey(groupPubKey btcec.PublicKey) Specifier {
	return Specifier{
		groupKey: fn.Some(groupPubKey),
	}
}

// String returns a human-readable description of the specifier.
func (s *Specifier) String() string {
	// An unset asset ID is represented as an empty string.
	var assetIdStr string
	s.WhenId(func(id ID) {
		assetIdStr = id.String()
	})

	var groupKeyBytes []byte
	s.WhenGroupPubKey(func(key btcec.PublicKey) {
		groupKeyBytes = key.SerializeCompressed()
	})

	return fmt.Sprintf("AssetSpecifier(id=%s, group_pub_key=%x)",
		assetIdStr, groupKeyBytes)
}

// AsBytes returns the asset ID and group public key as byte slices.
func (s *Specifier) AsBytes() ([]byte, []byte) {
	var assetIDBytes, groupKeyBytes []byte

	s.WhenGroupPubKey(func(groupKey btcec.PublicKey) {
		groupKeyBytes = groupKey.SerializeCompressed()
	})

	s.WhenId(func(id ID) {
		assetIDBytes = id[:]
	})

	return assetIDBytes, groupKeyBytes
}

// HasId returns true if the asset ID field is specified.
func (s *Specifier) HasId() bool {
	return s.id.IsSome()
}

// HasGroupPubKey returns true if the asset group public key field is specified.
func (s *Specifier) HasGroupPubKey() bool {
	return s.groupKey.IsSome()
}

// IsSome returns true if the specifier is set.
func (s *Specifier) IsSome() bool {
	return s.HasId() || s.HasGroupPubKey()
}

// WhenId executes the given function if the ID field is specified.
func (s *Specifier) WhenId(f func(ID)) {
	s.id.WhenSome(f)
}

// WhenGroupPubKey executes the given function if asset group public key field
// is specified.
func (s *Specifier) WhenGroupPubKey(f func(btcec.PublicKey)) {
	s.groupKey.WhenSome(f)
}

// UnwrapIdOrErr unwraps the ID field or returns an error if it is not
// specified.
func (s *Specifier) UnwrapIdOrErr() (ID, error) {
	id := s.id.UnwrapToPtr()
	if id == nil {
		return ID{}, ErrUnwrapAssetID
	}

	return *id, nil
}

// UnwrapIdToPtr unwraps the ID field to a pointer.
func (s *Specifier) UnwrapIdToPtr() *ID {
	return s.id.UnwrapToPtr()
}

// UnwrapGroupKeyToPtr unwraps the asset group public key field to a pointer.
func (s *Specifier) UnwrapGroupKeyToPtr() *btcec.PublicKey {
	return s.groupKey.UnwrapToPtr()
}

// UnwrapToPtr unwraps the asset ID and asset group public key fields,
// returning them as pointers.
func (s *Specifier) UnwrapToPtr() (*ID, *btcec.PublicKey) {
	return s.UnwrapIdToPtr(), s.UnwrapGroupKeyToPtr()
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

// encodeRecords determines the non-nil records to include when encoding an
// asset witness at runtime. This version takes an extra param to determine if
// the witness should be encoded or not.
func (w *Witness) encodeRecords(encodeType EncodeType) []tlv.Record {
	var records []tlv.Record
	if w.PrevID != nil {
		records = append(records, NewWitnessPrevIDRecord(&w.PrevID))
	}
	if len(w.TxWitness) > 0 && encodeType == EncodeNormal {
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

// EncodeRecords determines the non-nil records to include when encoding an
// asset witness at runtime.
func (w *Witness) EncodeRecords() []tlv.Record {
	return w.encodeRecords(EncodeNormal)
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

// EncodeNoWitness encodes an asset witness into a TLV stream, but does not
// include the raw witness field. The prevID and the split commitment are still
// included.
func (w *Witness) EncodeNoWitness(writer io.Writer) error {
	stream, err := tlv.NewStream(w.encodeRecords(EncodeSegwit)...)
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

// DeepEqual returns true if this witness is equal with the given witness. If
// the skipTxWitness boolean is set, the TxWitness field of the Witness is not
// compared.
func (w *Witness) DeepEqual(skipTxWitness bool, o *Witness) bool {
	if w == nil || o == nil {
		return w == o
	}

	if !reflect.DeepEqual(w.PrevID, o.PrevID) {
		return false
	}

	if !w.SplitCommitment.DeepEqual(o.SplitCommitment) {
		return false
	}

	// If we're not comparing the TxWitness, we're done. This might be
	// useful when comparing witnesses of segregated witness version assets.
	if skipTxWitness {
		return true
	}

	return reflect.DeepEqual(w.TxWitness, o.TxWitness)
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

// TapscriptTreeNodes represents the two supported ways to define a tapscript
// tree to be used as a sibling for a Taproot Asset commitment, an asset group
// key, or an asset script key. This type is used for interfacing with the DB,
// not for supplying in a proof or key derivation. The inner fields are mutually
// exclusive.
type TapscriptTreeNodes struct {
	// leaves is created from an ordered list of TapLeaf objects and
	// represents a Tapscript tree.
	leaves *TapLeafNodes

	// branch is created from a TapBranch and represents the tapHashes of
	// the child nodes of a TapBranch.
	branch *TapBranchNodes
}

// GetLeaves returns an Option containing a copy of the internal TapLeafNodes,
// if it exists.
func GetLeaves(ttn TapscriptTreeNodes) fn.Option[TapLeafNodes] {
	return fn.MaybeSome(ttn.leaves)
}

// GetBranch returns an Option containing a copy of the internal TapBranchNodes,
// if it exists.
func GetBranch(ttn TapscriptTreeNodes) fn.Option[TapBranchNodes] {
	return fn.MaybeSome(ttn.branch)
}

// FromBranch creates a TapscriptTreeNodes object from a TapBranchNodes object.
func FromBranch(tbn TapBranchNodes) TapscriptTreeNodes {
	return TapscriptTreeNodes{
		branch: &tbn,
	}
}

// FromLeaves creates a TapscriptTreeNodes object from a TapLeafNodes object.
func FromLeaves(tln TapLeafNodes) TapscriptTreeNodes {
	return TapscriptTreeNodes{
		leaves: &tln,
	}
}

// CheckTapLeafSanity asserts that a TapLeaf script is smaller than the maximum
// witness size, and that the TapLeaf version is Tapscript v0.
func CheckTapLeafSanity(leaf *txscript.TapLeaf) error {
	if leaf == nil {
		return fmt.Errorf("leaf cannot be nil")
	}

	if leaf.LeafVersion != txscript.BaseLeafVersion {
		return fmt.Errorf("tapleaf version %d not supported",
			leaf.LeafVersion)
	}

	if len(leaf.Script) == 0 {
		return fmt.Errorf("tapleaf script is empty")
	}

	if len(leaf.Script) >= blockchain.MaxBlockWeight {
		return fmt.Errorf("tapleaf script too large")
	}

	return nil
}

// TapLeafNodes represents an ordered list of TapLeaf objects, that have been
// checked for their script version and size. These leaves can be stored to and
// loaded from the DB.
type TapLeafNodes struct {
	v []txscript.TapLeaf
}

// TapTreeNodesFromLeaves sanity checks an ordered list of TapLeaf objects and
// constructs a TapscriptTreeNodes object if all leaves are valid.
func TapTreeNodesFromLeaves(leaves []txscript.TapLeaf) (*TapscriptTreeNodes,
	error) {

	err := CheckTapLeavesSanity(leaves)
	if err != nil {
		return nil, err
	}

	nodes := TapscriptTreeNodes{
		leaves: &TapLeafNodes{
			v: leaves,
		},
	}

	return &nodes, nil
}

// CheckTapLeavesSanity asserts that a slice of TapLeafs is below the maximum
// size, and that each leaf passes a sanity check for script version and size.
func CheckTapLeavesSanity(leaves []txscript.TapLeaf) error {
	if len(leaves) == 0 {
		return fmt.Errorf("no leaves given")
	}

	// The maximum number of leaves we will allow for a Tapscript tree we
	// store is 2^15 - 1. To use a larger tree, create a TapscriptTreeNodes
	// object from a TapBranch instead.
	if len(leaves) > math.MaxInt16 {
		return fmt.Errorf("tapleaf count larger than %d",
			math.MaxInt16)
	}

	// Reject any leaf not using the initial Tapscript version, or with a
	// script size above the maximum blocksize.
	for i := range leaves {
		err := CheckTapLeafSanity(&leaves[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// ToLeaves returns the TapLeaf slice inside a TapLeafNodes object.
func ToLeaves(l TapLeafNodes) []txscript.TapLeaf {
	return append([]txscript.TapLeaf{}, l.v...)
}

// LeafNodesRootHash returns the root hash of a Tapscript tree built from the
// TapLeaf nodes in a TapLeafNodes object.
func LeafNodesRootHash(l TapLeafNodes) chainhash.Hash {
	return txscript.AssembleTaprootScriptTree(l.v...).RootNode.TapHash()
}

// TapBranchNodesLen is the length of a TapBranch represented as a byte arrray.
const TapBranchNodesLen = 64

// TapBranchNodes represents the tapHashes of the child nodes of a TapBranch.
// These tapHashes can be stored to and loaded from the DB.
type TapBranchNodes struct {
	left  [chainhash.HashSize]byte
	right [chainhash.HashSize]byte
}

// TapTreeNodesFromBranch creates a TapscriptTreeNodes object from a TapBranch.
func TapTreeNodesFromBranch(branch txscript.TapBranch) TapscriptTreeNodes {
	return TapscriptTreeNodes{
		branch: &TapBranchNodes{
			left:  branch.Left().TapHash(),
			right: branch.Right().TapHash(),
		},
	}
}

// ToBranch returns an encoded TapBranchNodes object.
func ToBranch(b TapBranchNodes) [][]byte {
	return EncodeTapBranchNodes(b)
}

// BranchNodesRootHash returns the root hash of a Tapscript tree built from the
// tapHashes stored in a TapBranchNodes object.
func BranchNodesRootHash(b TapBranchNodes) chainhash.Hash {
	return NewTapBranchHash(b.left, b.right)
}

// NewTapBranchHash takes the raw tap hashes of the left and right nodes and
// hashes them into a branch.
func NewTapBranchHash(l, r chainhash.Hash) chainhash.Hash {
	if bytes.Compare(l[:], r[:]) > 0 {
		l, r = r, l
	}

	return *chainhash.TaggedHash(chainhash.TagTapBranch, l[:], r[:])
}

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
	//
	// 	internalKey = rawKey + singleTweak * G
	// 	tweakedGroupKey = TapTweak(internalKey, tapTweak)
	GroupPubKey btcec.PublicKey

	// TapscriptRoot is the root of the Tapscript tree that commits to all
	// script spend conditions for the group key. Instead of spending an
	// asset, these scripts are used to define witnesses more complex than
	// a Schnorr signature for reissuing assets. A group key with an empty
	// Tapscript root can only authorize reissuance with a signature.
	TapscriptRoot []byte

	// Witness is a stack of witness elements that authorizes the membership
	// of an asset in a particular asset group. The witness can be a single
	// signature or a script from the tapscript tree committed to with the
	// TapscriptRoot, and follows the witness rules in BIP-341.
	Witness wire.TxWitness
}

// GroupKeyRequest contains the essential fields used to derive a group key.
type GroupKeyRequest struct {
	// RawKey is the raw group key before the tweak with the genesis point
	// has been applied.
	RawKey keychain.KeyDescriptor

	// AnchorGen is the genesis of the group anchor, which is the asset used
	// to derive the single tweak for the group key. For a new group key,
	// this will be the genesis of the new asset.
	AnchorGen Genesis

	// TapscriptRoot is the root of a Tapscript tree that includes script
	// spend conditions for the group key. A group key with an empty
	// Tapscript root can only authorize reissuance with a signature.
	TapscriptRoot []byte

	// NewAsset is the asset which we are requesting group membership for.
	// A successful request will produce a witness that authorizes this
	// asset to be a member of this asset group.
	NewAsset *Asset
}

// GroupVirtualTx contains all the information needed to produce an asset group
// witness, except for the group internal key descriptor (or private key). A
// GroupVirtualTx is constructed from a GroupKeyRequest.
type GroupVirtualTx struct {
	// Tx is a virtual transaction that represents the genesis state
	// transition of a grouped asset.
	Tx wire.MsgTx

	// PrevOut is a transaction output that represents a grouped asset.
	// PrevOut uses the tweaked group key as its PkScript. This is used in
	// combination with GroupVirtualTx.Tx as input for a GenesisSigner.
	PrevOut wire.TxOut

	// GenID is the asset ID of the grouped asset in a GroupKeyRequest. This
	// ID is needed to construct a sign descriptor for a GenesisSigner, as
	// it is the single tweak for the group internal key.
	GenID ID

	// TweakedKey is the tweaked group key for the given GroupKeyRequest.
	// This is later used to construct a complete GroupKey, after a
	// GenesisSigner has produced an asset group witness.
	TweakedKey btcec.PublicKey
}

// GroupKeyReveal represents the data used to derive the adjusted key that
// uniquely identifies an asset group.
type GroupKeyReveal interface {
	// RawKey returns the raw key of the group key reveal.
	RawKey() SerializedKey

	// SetRawKey sets the raw key of the group key reveal.
	SetRawKey(SerializedKey)

	// TapscriptRoot returns the tapscript root of the group key reveal.
	TapscriptRoot() []byte

	// SetTapscriptRoot sets the tapscript root of the group key reveal.
	SetTapscriptRoot([]byte)

	// GroupPubKey returns the group public key derived from the group key
	// reveal.
	GroupPubKey(assetID ID) (*btcec.PublicKey, error)
}

// GroupKeyRevealV0 is a version 0 group key reveal type for representing the
// data used to derive the tweaked key used to identify an asset group. The
// final tweaked key is the result of: TapTweak(groupInternalKey, tapscriptRoot)
type GroupKeyRevealV0 struct {
	// RawKey is the public key that is tweaked twice to derive the final
	// tweaked group key. The final tweaked key is the result of:
	// internalKey = rawKey + singleTweak * G
	// tweakedGroupKey = TapTweak(internalKey, tapTweak)
	rawKey SerializedKey

	// TapscriptRoot is the root of the Tapscript tree that commits to all
	// script spend conditions for the group key. Instead of spending an
	// asset, these scripts are used to define witnesses more complex than
	// a Schnorr signature for reissuing assets. This is either empty/nil or
	// a 32-byte hash.
	tapscriptRoot []byte
}

// Ensure that GroupKeyRevealV0 implements the GroupKeyReveal interface.
var _ GroupKeyReveal = (*GroupKeyRevealV0)(nil)

// NewGroupKeyRevealV0 creates a new version 0 group key reveal instance.
func NewGroupKeyRevealV0(rawKey SerializedKey,
	tapscriptRoot []byte) GroupKeyReveal {

	return &GroupKeyRevealV0{
		rawKey:        rawKey,
		tapscriptRoot: tapscriptRoot,
	}
}

// RawKey returns the raw key of the group key reveal.
func (g *GroupKeyRevealV0) RawKey() SerializedKey {
	return g.rawKey
}

// SetRawKey sets the raw key of the group key reveal.
func (g *GroupKeyRevealV0) SetRawKey(rawKey SerializedKey) {
	g.rawKey = rawKey
}

// TapscriptRoot returns the tapscript root of the group key reveal.
func (g *GroupKeyRevealV0) TapscriptRoot() []byte {
	return g.tapscriptRoot
}

// SetTapscriptRoot sets the tapscript root of the group key reveal.
func (g *GroupKeyRevealV0) SetTapscriptRoot(tapscriptRoot []byte) {
	g.tapscriptRoot = tapscriptRoot
}

// GroupPubKey returns the group public key derived from the group key reveal.
func (g *GroupKeyRevealV0) GroupPubKey(assetID ID) (*btcec.PublicKey, error) {
	rawKey, err := g.RawKey().ToPubKey()
	if err != nil {
		return nil, fmt.Errorf("group reveal raw key invalid: %w", err)
	}

	return GroupPubKeyV0(rawKey, assetID[:], g.TapscriptRoot())
}

// GroupPubKeyV0 derives a version 0 tweaked group key from a public key and two
// tweaks; the single tweak is the asset ID of the group anchor asset, and the
// tapTweak is the root of a tapscript tree that commits to script-based
// conditions for reissuing assets as part of this asset group. The tweaked key
// is defined by:
//
//	internalKey = rawKey + singleTweak * G
//	tweakedGroupKey = TapTweak(internalKey, tapTweak)
func GroupPubKeyV0(rawKey *btcec.PublicKey, singleTweak, tapTweak []byte) (
	*btcec.PublicKey, error) {

	if len(singleTweak) != sha256.Size {
		return nil, fmt.Errorf("genesis tweak must be %d bytes",
			sha256.Size)
	}

	internalKey := input.TweakPubKeyWithTweak(rawKey, singleTweak)

	switch len(tapTweak) {
	case 0:
		return txscript.ComputeTaprootKeyNoScript(internalKey), nil

	case sha256.Size:
		return txscript.ComputeTaprootOutputKey(internalKey, tapTweak),
			nil

	default:
		return nil, fmt.Errorf("tapscript tweaks must be %d bytes",
			sha256.Size)
	}
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

	if !bytes.Equal(g.TapscriptRoot, otherGroupKey.TapscriptRoot) {
		return false
	}

	if len(g.Witness) != len(otherGroupKey.Witness) {
		return false
	}

	return slices.EqualFunc(g.Witness, otherGroupKey.Witness, bytes.Equal)
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
// be able to keep track of the tweak of a script key alongside the raw key
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

	// DeclaredKnown indicates that this script key has been explicitly
	// declared as being important to the local wallet, even if it might not
	// be fully known to the local wallet. This could perhaps also be named
	// "imported", though that might imply that the corresponding private
	// key was also somehow imported and available. The only relevance this
	// flag has is that assets with a declared key are shown in the asset
	// list/balance.
	DeclaredKnown bool
}

// IsEqual returns true is this tweaked script key is exactly equivalent to the
// passed other tweaked script key.
func (ts *TweakedScriptKey) IsEqual(other *TweakedScriptKey) bool {
	if ts == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	if !bytes.Equal(ts.Tweak, other.Tweak) {
		return false
	}

	return EqualKeyDescriptors(ts.RawKey, other.RawKey)
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
func (s *ScriptKey) IsUnSpendable() (bool, error) {
	if s.PubKey == nil {
		return false, fmt.Errorf("script key has nil public key")
	}

	return NUMSPubKey.IsEqual(s.PubKey), nil
}

// IsEqual returns true is this script key is exactly equivalent to the passed
// other script key.
func (s *ScriptKey) IsEqual(otherScriptKey *ScriptKey) bool {
	if s == nil {
		return otherScriptKey == nil
	}

	if otherScriptKey == nil {
		return false
	}

	if s.PubKey == nil {
		return otherScriptKey.PubKey == nil
	}

	if otherScriptKey.PubKey == nil {
		return false
	}

	if !s.TweakedScriptKey.IsEqual(otherScriptKey.TweakedScriptKey) {
		return false
	}

	return s.PubKey.IsEqual(otherScriptKey.PubKey)
}

// DeclaredAsKnown returns true if this script key has either been derived by
// the local wallet or was explicitly declared to be known by using the
// DeclareScriptKey RPC. Knowing the key conceptually means the key belongs to
// the local wallet or is at least known by a software that operates on the
// local wallet. The DeclaredAsKnown flag is never serialized in proofs, so this
// is never explicitly set for keys foreign to the local wallet. Therefore, if
// this method returns true for a script key, it means the asset with the script
// key will be shown in the wallet balance.
func (s *ScriptKey) DeclaredAsKnown() bool {
	return s.TweakedScriptKey != nil && s.TweakedScriptKey.DeclaredKnown
}

// HasScriptPath returns true if we know the internals of the script key and
// there is a tweak applied to it. This means that the script key is not a
// BIP-0086 key.
func (s *ScriptKey) HasScriptPath() bool {
	return s.TweakedScriptKey != nil && len(s.TweakedScriptKey.Tweak) > 0
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

// NewGroupKeyRequest constructs and validates a group key request.
func NewGroupKeyRequest(internalKey keychain.KeyDescriptor, anchorGen Genesis,
	newAsset *Asset, scriptRoot []byte) (*GroupKeyRequest, error) {

	req := &GroupKeyRequest{
		RawKey:        internalKey,
		AnchorGen:     anchorGen,
		NewAsset:      newAsset,
		TapscriptRoot: scriptRoot,
	}

	err := req.Validate()
	if err != nil {
		return nil, err
	}

	return req, nil
}

// Validate ensures that the asset intended to be a member of an asset group is
// well-formed.
func (req *GroupKeyRequest) Validate() error {
	// Perform the final checks on the asset being authorized for group
	// membership.
	if req.NewAsset == nil {
		return fmt.Errorf("grouped asset cannot be nil")
	}

	// The asset in the request must have the default genesis asset witness,
	// and no group key. Those fields can only be populated after group
	// witness creation.
	if !req.NewAsset.HasGenesisWitness() {
		return fmt.Errorf("asset is not a genesis asset")
	}

	if req.NewAsset.GroupKey != nil {
		return fmt.Errorf("asset already has group key")
	}

	if req.AnchorGen.Type != req.NewAsset.Type {
		return fmt.Errorf("asset group type mismatch")
	}

	if req.RawKey.PubKey == nil {
		return fmt.Errorf("missing group internal key")
	}

	tapscriptRootSize := len(req.TapscriptRoot)
	if tapscriptRootSize != 0 && tapscriptRootSize != sha256.Size {
		return fmt.Errorf("tapscript root must be %d bytes",
			sha256.Size)
	}

	return nil
}

// BuildGroupVirtualTx derives the tweaked group key for group key request,
// and constructs the group virtual TX needed to construct a sign descriptor and
// produce an asset group witness.
func (req *GroupKeyRequest) BuildGroupVirtualTx(genBuilder GenesisTxBuilder) (
	*GroupVirtualTx, error) {
	// First, perform the final checks on the asset being authorized for
	// group membership.
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	// Compute the tweaked group key and set it in the asset before
	// creating the virtual minting transaction.
	genesisTweak := req.AnchorGen.ID()
	tweakedGroupKey, err := GroupPubKeyV0(
		req.RawKey.PubKey, genesisTweak[:], req.TapscriptRoot,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot tweak group key: %w", err)
	}

	assetWithGroup := req.NewAsset.Copy()
	assetWithGroup.GroupKey = &GroupKey{
		GroupPubKey: *tweakedGroupKey,
	}

	// Build the virtual transaction that represents the minting of the new
	// asset, which will be signed to generate the group witness.
	genesisTx, prevOut, err := genBuilder.BuildGenesisTx(assetWithGroup)
	if err != nil {
		return nil, fmt.Errorf("cannot build virtual tx: %w", err)
	}

	return &GroupVirtualTx{
		Tx:         *genesisTx,
		PrevOut:    *prevOut,
		GenID:      genesisTweak,
		TweakedKey: *tweakedGroupKey,
	}, nil
}

// AssembleGroupKeyFromWitness constructs a group key given a group witness
// generated externally.
func AssembleGroupKeyFromWitness(genTx GroupVirtualTx, req GroupKeyRequest,
	tapLeaf *psbt.TaprootTapLeafScript, scriptWitness []byte) (*GroupKey,
	error) {

	if scriptWitness == nil {
		return nil, fmt.Errorf("script witness cannot be nil")
	}

	groupKey := &GroupKey{
		RawKey:        req.RawKey,
		GroupPubKey:   genTx.TweakedKey,
		TapscriptRoot: req.TapscriptRoot,
		Witness:       wire.TxWitness{scriptWitness},
	}

	if tapLeaf != nil {
		if tapLeaf.LeafVersion != txscript.BaseLeafVersion {
			return nil, fmt.Errorf("unsupported script version")
		}

		groupKey.Witness = append(
			groupKey.Witness, tapLeaf.Script, tapLeaf.ControlBlock,
		)
	}

	return groupKey, nil
}

// DeriveGroupKey derives an asset's group key based on an internal public key
// descriptor, the original group asset genesis, and the asset's genesis.
func DeriveGroupKey(genSigner GenesisSigner, genTx GroupVirtualTx,
	req GroupKeyRequest, tapLeaf *psbt.TaprootTapLeafScript) (*GroupKey,
	error) {

	// Populate the signing descriptor needed to sign the virtual minting
	// transaction.
	signDesc := &lndclient.SignDescriptor{
		KeyDesc:     req.RawKey,
		SingleTweak: genTx.GenID[:],
		TapTweak:    req.TapscriptRoot,
		Output:      &genTx.PrevOut,
		HashType:    txscript.SigHashDefault,
		InputIndex:  0,
	}

	// There are three possible signing cases: BIP-0086 key spend path, key
	// spend path with a script root, and script spend path.
	switch {
	// If there is no tapscript root, we're doing a BIP-0086 key spend.
	case len(signDesc.TapTweak) == 0:
		signDesc.SignMethod = input.TaprootKeySpendBIP0086SignMethod

	// No leaf means we're not signing a specific script, so this is the key
	// spend path with a tapscript root.
	case len(signDesc.TapTweak) != 0 && tapLeaf == nil:
		signDesc.SignMethod = input.TaprootKeySpendSignMethod

	// One leaf hash and a merkle root means we're signing a specific
	// script.
	case len(signDesc.TapTweak) != 0 && tapLeaf != nil:
		signDesc.SignMethod = input.TaprootScriptSpendSignMethod
		signDesc.WitnessScript = tapLeaf.Script

	default:
		return nil, fmt.Errorf("bad sign descriptor for group key")
	}

	sig, err := genSigner.SignVirtualTx(signDesc, &genTx.Tx, &genTx.PrevOut)
	if err != nil {
		return nil, err
	}

	witness := wire.TxWitness{sig.Serialize()}

	// If this was a script spend, we also have to add the script itself and
	// the control block to the witness, otherwise the verifier will reject
	// the generated witness.
	if signDesc.SignMethod == input.TaprootScriptSpendSignMethod {
		witness = append(
			witness, signDesc.WitnessScript, tapLeaf.ControlBlock,
		)
	}

	return &GroupKey{
		RawKey:        signDesc.KeyDesc,
		GroupPubKey:   genTx.TweakedKey,
		TapscriptRoot: signDesc.TapTweak,
		Witness:       witness,
	}, nil
}

// PendingGroupWitness specifies the asset group witness for an asset seedling
// in an unsealed minting batch.
type PendingGroupWitness struct {
	GenID   ID
	Witness wire.TxWitness
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
	// the represented block height in the chain. This value needs to be set
	// on the asset that is spending from a script key with a CLTV script.
	LockTime uint64

	// RelativeLockTime, if non-zero, restricts an asset from being moved
	// until a number of blocks after the confirmation height of the latest
	// transaction for the asset is reached. This value needs to be set
	// on the asset that is spending from a script key with a CSV script.
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

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing
	// as a leaf to arrive at the same byte representation and with that
	// same commitment root hash. This enables forward compatibility with
	// future versions of the protocol as it allows new odd (optional) types
	// to be added without breaking old clients that don't yet fully
	// understand them.
	UnknownOddTypes tlv.TypeMap
}

// IsUnknownVersion returns true if an asset has a version that is not
// recognized by this implementation of tap.
func (a *Asset) IsUnknownVersion() bool {
	switch a.Version {
	case V0, V1:
		return false
	default:
		return true
	}
}

// newAssetOptions is a struct that is used to customize how a new asset is to
// be created.
type newAssetOptions struct {
	assetVersion Version
}

// defaultNewAssetOptions returns the default set of asset versions.
func defaultNewAssetOptions() *newAssetOptions {
	return &newAssetOptions{
		assetVersion: V0,
	}
}

// NewAssetOpt is used to modify how a new asset is to be created.
type NewAssetOpt func(*newAssetOptions)

// WithAssetVersion can be used to create an asset with a custom version.
func WithAssetVersion(v Version) NewAssetOpt {
	return func(o *newAssetOptions) {
		o.assetVersion = v
	}
}

// New instantiates a new asset with a genesis asset witness.
func New(genesis Genesis, amount, locktime, relativeLocktime uint64,
	scriptKey ScriptKey, groupKey *GroupKey,
	opts ...NewAssetOpt) (*Asset, error) {

	options := defaultNewAssetOptions()
	for _, opt := range opts {
		opt(options)
	}

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
	if groupKey != nil && groupKey.Witness != nil &&
		len(groupKey.Witness) != 0 {

		genesisWitness.TxWitness = groupKey.Witness
	}

	return &Asset{
		Version:             options.assetVersion,
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
// asset within a TapCommitment.
//
// NOTE: This function is also used outside the asset package.
func TapCommitmentKey(assetSpecifier Specifier) [32]byte {
	var commitmentKey [32]byte

	switch {
	case assetSpecifier.HasGroupPubKey():
		assetSpecifier.WhenGroupPubKey(func(pubKey btcec.PublicKey) {
			serializedPubKey := schnorr.SerializePubKey(&pubKey)
			commitmentKey = sha256.Sum256(serializedPubKey)
		})

	case assetSpecifier.HasId():
		assetSpecifier.WhenId(func(id ID) {
			commitmentKey = id
		})

	default:
		// We should never reach this point as the asset specifier
		// should always have either a group public key, an asset ID, or
		// both.
		panic("invalid asset specifier")
	}

	return commitmentKey
}

// TapCommitmentKey is the key that maps to the root commitment for a specific
// asset group within a TapCommitment.
func (a *Asset) TapCommitmentKey() [32]byte {
	return TapCommitmentKey(a.Specifier())
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

// IsGenesisAsset returns true if an asset is a genesis asset.
func (a *Asset) IsGenesisAsset() bool {
	return a.HasGenesisWitness() || a.HasGenesisWitnessForGroup()
}

// HasSplitCommitmentWitness returns true if an asset has a split commitment
// witness.
func (a *Asset) HasSplitCommitmentWitness() bool {
	if len(a.PrevWitnesses) != 1 {
		return false
	}

	return IsSplitCommitWitness(a.PrevWitnesses[0])
}

// IsUnSpendable returns true if an asset uses the un-spendable script key and
// has zero value.
func (a *Asset) IsUnSpendable() bool {
	return ToSerialized(a.ScriptKey.PubKey) == NUMSCompressedKey &&
		a.Amount == 0
}

// IsBurn returns true if an asset uses an un-spendable script key that was
// constructed using the proof-of-burn scheme.
func (a *Asset) IsBurn() bool {
	// If the script key is nil, then we can't say if this is a burn or not.
	if a.ScriptKey.PubKey == nil {
		return false
	}

	// The same goes for the witness, if there is none (yet?), then we can't
	// tell if this is a burn or not.
	if len(a.PrevWitnesses) == 0 {
		return false
	}

	return IsBurnKey(a.ScriptKey.PubKey, a.PrevWitnesses[0])
}

// PrimaryPrevID returns the primary prev ID of an asset. This is the prev ID of
// the first witness, unless the first witness is a split-commitment witness,
// in which case it is the prev ID of the first witness of the root asset.
// The first witness effectively corresponds to the asset's direct lineage.
func (a *Asset) PrimaryPrevID() (*PrevID, error) {
	prevWitnesses := a.Witnesses()
	if len(prevWitnesses) == 0 {
		return nil, fmt.Errorf("asset missing previous witnesses")
	}

	// The primary prev ID is the first witness's prev ID.
	primaryWitness := prevWitnesses[0]
	return primaryWitness.PrevID, nil
}

// Witnesses returns the witnesses of an asset. If the asset has a split
// commitment witness, the witnesses of the root asset are returned.
func (a *Asset) Witnesses() []Witness {
	if a.HasSplitCommitmentWitness() {
		rootAsset := a.PrevWitnesses[0].SplitCommitment.RootAsset
		return rootAsset.PrevWitnesses
	}

	return a.PrevWitnesses
}

// UpdateTxWitness updates the transaction witness at the given index with the
// provided witness stack. The previous witness index references the input that
// is spent.
func (a *Asset) UpdateTxWitness(prevWitnessIndex int,
	witness wire.TxWitness) error {

	if len(a.PrevWitnesses) == 0 {
		return fmt.Errorf("missing previous witnesses")
	}

	if prevWitnessIndex >= len(a.PrevWitnesses) {
		return fmt.Errorf("invalid previous witness index")
	}

	targetPrevWitness := &a.PrevWitnesses[prevWitnessIndex]
	if a.HasSplitCommitmentWitness() {
		rootAsset := targetPrevWitness.SplitCommitment.RootAsset
		targetPrevWitness = &rootAsset.PrevWitnesses[prevWitnessIndex]
	}

	targetPrevWitness.TxWitness = witness

	return nil
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
		assetCopy.ScriptKey.TweakedScriptKey = &TweakedScriptKey{
			DeclaredKnown: a.ScriptKey.DeclaredKnown,
		}
		assetCopy.ScriptKey.RawKey = a.ScriptKey.RawKey

		if len(a.ScriptKey.Tweak) > 0 {
			assetCopy.ScriptKey.Tweak = make(
				[]byte, len(a.ScriptKey.Tweak),
			)
			copy(assetCopy.ScriptKey.Tweak, a.ScriptKey.Tweak)
		}
	}

	if a.GroupKey != nil {
		assetCopy.GroupKey = &GroupKey{
			RawKey:        a.GroupKey.RawKey,
			GroupPubKey:   a.GroupKey.GroupPubKey,
			TapscriptRoot: a.GroupKey.TapscriptRoot,
			Witness:       a.GroupKey.Witness,
		}
	}

	return &assetCopy
}

// CopySpendTemplate is similar to Copy, but should be used when wanting to
// spend an input asset in a new transaction. Compared to Copy, this method
// also blanks out some other fields that shouldn't always be carried along for
// a dependent spend.
func (a *Asset) CopySpendTemplate() *Asset {
	assetCopy := a.Copy()

	// We nil out the split commitment root, as we don't need to carry that
	// into the next spend.
	assetCopy.SplitCommitmentRoot = nil

	// We'll also make sure to clear out the lock time and relative lock
	// time from the input. The input at this point is already valid, so we
	// don't need to inherit the time lock encumbrance.
	assetCopy.RelativeLockTime = 0
	assetCopy.LockTime = 0

	return assetCopy
}

// DeepEqual returns true if this asset is equal with the given asset.
func (a *Asset) DeepEqual(o *Asset) bool {
	return a.deepEqual(false, o)
}

// DeepEqualAllowSegWitIgnoreTxWitness returns true if this asset is equal with
// the given asset, ignoring the TxWitness field of the Witness if the asset
// version is v1.
func (a *Asset) DeepEqualAllowSegWitIgnoreTxWitness(o *Asset) bool {
	return a.deepEqual(true, o)
}

// deepEqual returns true if this asset is equal with the given asset. The
// allowSegWitIgnoreTxWitness flag is used to determine whether the TxWitness
// field of the Witness should be ignored if the asset version is v1.
func (a *Asset) deepEqual(allowSegWitIgnoreTxWitness bool, o *Asset) bool {
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

	// If both assets have a script public key, comparing that is enough.
	// We just want to know that we have the same key, not that the internal
	// representation (e.g. the TweakedKey sub struct being set) is the same
	// as well.
	switch {
	// If only one of the keys is nil, they are not equal.
	case (a.ScriptKey.PubKey == nil && o.ScriptKey.PubKey != nil) ||
		(a.ScriptKey.PubKey != nil && o.ScriptKey.PubKey == nil):

		return false

	// If both are non-nil, we compare the public keys.
	case a.ScriptKey.PubKey != nil && o.ScriptKey.PubKey != nil &&
		!a.ScriptKey.PubKey.IsEqual(o.ScriptKey.PubKey):

		return false

	// If both are nil or both are non-nil and equal, we continue below.
	default:
		// Continue below
	}

	if !a.GroupKey.IsEqual(o.GroupKey) {
		return false
	}

	if len(a.PrevWitnesses) != len(o.PrevWitnesses) {
		return false
	}

	for i := range a.PrevWitnesses {
		oPrevWitness := &o.PrevWitnesses[i]
		skipTxWitness := a.Version == V1 && allowSegWitIgnoreTxWitness
		if !a.PrevWitnesses[i].DeepEqual(skipTxWitness, oPrevWitness) {
			return false
		}
	}

	return true
}

// encodeRecords determines the non-nil records to include when encoding an
// asset at runtime.
func (a *Asset) encodeRecords(encodeType EncodeType) []tlv.Record {
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
			&a.PrevWitnesses, encodeType,
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

	// Add any unknown odd types that were encountered during decoding.
	return CombineRecords(records, a.UnknownOddTypes)
}

// EncodeRecords determines the non-nil records to include when encoding an
// asset at runtime.
func (a *Asset) EncodeRecords() []tlv.Record {
	return a.encodeRecords(EncodeNormal)
}

// Record returns a TLV record that can be used to encode/decode an Asset
// to/from a TLV stream.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (a *Asset) Record() tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		if err := a.Encode(&buf); err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}

	// We pass 0 here as the type will be overridden when used along with
	// the tlv.RecordT type.
	return tlv.MakeDynamicRecord(
		0, a, sizeFunc, LeafEncoder, LeafDecoder,
	)
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
		// We don't need to worry about encoding the witness or not
		// when we decode, so we just use EncodeNormal here.
		NewLeafPrevWitnessRecord(&a.PrevWitnesses, EncodeNormal),
		NewLeafSplitCommitmentRootRecord(&a.SplitCommitmentRoot),
		NewLeafScriptVersionRecord(&a.ScriptVersion),
		NewLeafScriptKeyRecord(&a.ScriptKey.PubKey),
		NewLeafGroupKeyRecord(&a.GroupKey),
	}
}

// Encode encodes an asset into a TLV stream. This is used for encoding proof
// files and state transitions.
func (a *Asset) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// EncodeNoWitness encodes the asset without the witness into a TLV stream.
// This is used for serializing on an asset as a leaf within a TAP MS-SMT tree.
// This only applies when the asset version is v1.
func (a *Asset) EncodeNoWitness(w io.Writer) error {
	stream, err := tlv.NewStream(a.encodeRecords(EncodeSegwit)...)
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

	unknownOddTypes, err := TlvStrictDecode(stream, r, KnownAssetLeafTypes)
	if err != nil {
		return err
	}

	a.UnknownOddTypes = unknownOddTypes

	return nil
}

// Leaf returns the asset encoded as a MS-SMT leaf node.
func (a *Asset) Leaf() (*mssmt.LeafNode, error) {
	if a.IsUnknownVersion() {
		return nil, ErrUnknownVersion
	}
	var buf bytes.Buffer

	switch a.Version {
	case V0:
		if err := a.Encode(&buf); err != nil {
			return nil, err
		}
	case V1:
		if err := a.EncodeNoWitness(&buf); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown asset version: %v", a.Version)
	}

	return mssmt.NewLeafNode(buf.Bytes(), a.Amount), nil
}

// Specifier returns the asset's specifier.
func (a *Asset) Specifier() Specifier {
	id := a.Genesis.ID()
	return NewSpecifierOptionalGroupKey(id, a.GroupKey)
}

// Validate ensures that an asset is valid.
func (a *Asset) Validate() error {
	// TODO(ffranr): Add validation check for remaining fields.
	return ValidateAssetName(a.Genesis.Tag)
}

// Ensure Asset implements the tlv.RecordProducer interface.
var _ tlv.RecordProducer = (*Asset)(nil)

// ValidateAssetName validates an asset name (the asset's genesis tag).
func ValidateAssetName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("asset name cannot be empty")
	}

	// Ensure the asset name is not too long.
	if len(name) > MaxAssetNameLength {
		return fmt.Errorf("asset name cannot exceed %d bytes",
			MaxAssetNameLength)
	}

	// Ensure the asset name is a valid UTF-8 string.
	if !utf8.ValidString(name) {
		return fmt.Errorf("asset name is not a valid UTF-8 string")
	}

	// Ensure each character is printable.
	for _, char := range name {
		if !unicode.IsPrint(char) {
			hexValue := fmt.Sprintf("\\x%X", char)
			return fmt.Errorf("asset name cannot contain "+
				"unprintable character: %s", hexValue)
		}
	}

	// Ensure the asset name does not contain only spaces.
	if len(strings.TrimSpace(name)) == 0 {
		return fmt.Errorf("asset name cannot contain only spaces")
	}

	return nil
}

// ChainAsset is a wrapper around the base asset struct that includes
// information detailing where in the chain the asset is currently anchored.
type ChainAsset struct {
	*Asset

	// IsSpent indicates whether the above asset was previously spent.
	IsSpent bool

	// AnchorTx is the transaction that anchors this chain asset.
	AnchorTx *wire.MsgTx

	// AnchorBlockHash is the blockhash that mined the anchor tx.
	AnchorBlockHash chainhash.Hash

	// AnchorBlockHeight is the height of the block that mined the anchor
	// tx.
	AnchorBlockHeight uint32

	// AnchorOutpoint is the outpoint that commits to the asset.
	AnchorOutpoint wire.OutPoint

	// AnchorInternalKey is the raw internal key that was used to create the
	// anchor Taproot output key.
	AnchorInternalKey *btcec.PublicKey

	// AnchorMerkleRoot is the Taproot merkle root hash of the anchor output
	// the asset was committed to. If there is no Tapscript sibling, this is
	// equal to the Taproot Asset root commitment hash.
	AnchorMerkleRoot []byte

	// AnchorTapscriptSibling is the serialized preimage of a Tapscript
	// sibling, if there was one. If this is empty, then the
	// AnchorTapscriptSibling hash is equal to the Taproot root hash of the
	// anchor output.
	AnchorTapscriptSibling []byte

	// AnchorLeaseOwner is the identity of the application that currently
	// has a lease on this UTXO. If empty/nil, then the UTXO is not
	// currently leased. A lease means that the UTXO is being
	// reserved/locked to be spent in an upcoming transaction and that it
	// should not be available for coin selection through any of the wallet
	// RPCs.
	AnchorLeaseOwner [32]byte

	// AnchorLeaseExpiry is the expiry of the lease. If the expiry is nil or
	// the time is in the past, then the lease is not valid and the UTXO is
	// available for coin selection.
	AnchorLeaseExpiry *time.Time
}

// An AltLeaf is a type that is used to carry arbitrary data, and does not
// represent a Taproot asset. An AltLeaf can be used to anchor other protocols
// alongside Taproot Asset transactions.
type AltLeaf[T any] interface {
	// Copyable asserts that the target type of this interface satisfies
	// the Copyable interface.
	fn.Copyable[*T]

	// ValidateAltLeaf ensures that an AltLeaf is valid.
	ValidateAltLeaf() error

	// EncodeAltLeaf encodes an AltLeaf into a TLV stream.
	EncodeAltLeaf(w io.Writer) error

	// DecodeAltLeaf decodes an AltLeaf from a TLV stream.
	DecodeAltLeaf(r io.Reader) error
}

// NewAltLeaf instantiates a new valid AltLeaf.
func NewAltLeaf(key ScriptKey, keyVersion ScriptVersion,
	prevWitness []Witness) (*Asset, error) {

	if key.PubKey == nil {
		return nil, fmt.Errorf("script key must be non-nil")
	}

	return &Asset{
		Version:             V0,
		Genesis:             EmptyGenesis,
		Amount:              0,
		LockTime:            0,
		RelativeLockTime:    0,
		PrevWitnesses:       prevWitness,
		SplitCommitmentRoot: nil,
		GroupKey:            nil,
		ScriptKey:           key,
		ScriptVersion:       keyVersion,
	}, nil
}

// CopyAltLeaves performs a deep copy of an AltLeaf slice.
func CopyAltLeaves(a []AltLeaf[Asset]) []AltLeaf[Asset] {
	if len(a) == 0 {
		return nil
	}

	return ToAltLeaves(fn.CopyAll(FromAltLeaves(a)))
}

// ValidateAltLeaf checks that an Asset is a valid AltLeaf. An Asset used as an
// AltLeaf must meet these constraints:
// - Version must be V0.
// - Genesis must be the empty Genesis.
// - Amount, LockTime, and RelativeLockTime must be 0.
// - SplitCommitmentRoot and GroupKey must be nil.
// - ScriptKey must be non-nil.
func (a *Asset) ValidateAltLeaf() error {
	if a.Version != V0 {
		return fmt.Errorf("alt leaf version must be 0")
	}

	if a.Genesis != EmptyGenesis {
		return fmt.Errorf("alt leaf genesis must be the empty genesis")
	}

	if a.Amount != 0 {
		return fmt.Errorf("alt leaf amount must be 0")
	}

	if a.LockTime != 0 {
		return fmt.Errorf("alt leaf lock time must be 0")
	}

	if a.RelativeLockTime != 0 {
		return fmt.Errorf("alt leaf relative lock time must be 0")
	}

	if a.SplitCommitmentRoot != nil {
		return fmt.Errorf("alt leaf split commitment root must be " +
			"empty")
	}

	if a.GroupKey != nil {
		return fmt.Errorf("alt leaf group key must be empty")
	}

	if a.ScriptKey.PubKey == nil {
		return fmt.Errorf("alt leaf script key must be non-nil")
	}

	return nil
}

// encodeAltLeafRecords determines the set of non-nil records to include when
// encoding an AltLeaf. Since the Genesis, Group Key, Amount, and Version fields
// are static, we can omit those fields.
func (a *Asset) encodeAltLeafRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 3)

	// Always use the normal witness encoding, since the asset version is
	// always V0.
	if len(a.PrevWitnesses) > 0 {
		records = append(records, NewLeafPrevWitnessRecord(
			&a.PrevWitnesses, EncodeNormal,
		))
	}
	records = append(records, NewLeafScriptVersionRecord(&a.ScriptVersion))
	records = append(records, NewLeafScriptKeyRecord(&a.ScriptKey.PubKey))

	// Add any unknown odd types that were encountered during decoding.
	return CombineRecords(records, a.UnknownOddTypes)
}

// EncodeAltLeaf encodes an AltLeaf into a TLV stream.
func (a *Asset) EncodeAltLeaf(w io.Writer) error {
	stream, err := tlv.NewStream(a.encodeAltLeafRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// DecodeAltLeaf decodes an AltLeaf from a TLV stream. The normal Asset decoder
// can be reused here, since any Asset field not encoded in the AltLeaf will
// be set to its default value, which matches the AltLeaf validity constraints.
func (a *Asset) DecodeAltLeaf(r io.Reader) error {
	return a.Decode(r)
}

// Ensure Asset implements the AltLeaf interface.
var _ AltLeaf[Asset] = (*Asset)(nil)

// ToAltLeaves casts []Asset to []AltLeafAsset, without checking that the assets
// are valid AltLeaves.
func ToAltLeaves(leaves []*Asset) []AltLeaf[Asset] {
	return fn.Map(leaves, func(l *Asset) AltLeaf[Asset] {
		return l
	})
}

// FromAltLeaves casts []AltLeafAsset to []Asset, which is always safe.
func FromAltLeaves(leaves []AltLeaf[Asset]) []*Asset {
	return fn.Map(leaves, func(l AltLeaf[Asset]) *Asset {
		return l.(*Asset)
	})
}
