package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

// Version denotes the version of the Taro protocol in effect for an asset.
type Version uint8

const (
	// V0 is the initial Taro protocol version.
	V0 Version = 0
)

// Genesis encodes an asset's genesis metadata which directly maps to its unique
// ID within the Taro protocol.
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

	// Metadata encodes metadata related to the asset.
	//
	// NOTE: This is immutable for the lifetime of the asset.
	//
	// TODO: Would this usually be a JSON blob? It may be worth
	// standardizing a schema subset for interoperability across wallets
	// when displaying this metadata.
	Metadata []byte

	// OutputIndex is the index of the output that carries the unique Taro
	// commitment in the genesis transaction.
	OutputIndex uint32
}

// TagHash computes the SHA-256 hash of the asset's tag.
func (g Genesis) TagHash() [sha256.Size]byte {
	return sha256.Sum256([]byte(g.Tag))
}

// MetadataHash computes the SHA-256 hash of the asset's metadata.
func (g Genesis) MetadataHash() [sha256.Size]byte {
	return sha256.Sum256(g.Metadata)
}

// ID serves as a unique identifier of an asset, resulting from:
//   sha256(genesisOutPoint || sha256(tag) || sha256(metadata) || outputIndex)
type ID [sha256.Size]byte

// ID computes an asset's unique identifier from its metadata.
func (g Genesis) ID() ID {
	tagHash := g.TagHash()
	metadataHash := g.MetadataHash()

	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &g.FirstPrevOut)
	_, _ = h.Write(tagHash[:])
	_, _ = h.Write(metadataHash[:])
	_ = binary.Write(h, binary.BigEndian, g.OutputIndex)
	return *(*ID)(h.Sum(nil))
}

// Type denotes the asset types supported by the Taro protocol.
type Type uint8

const (
	// Normal is an asset that can be represented in multiple units,
	// resembling a divisible asset.
	Normal Type = 0

	// Collectible is a unique asset, one that cannot be represented in
	// multiple units.
	Collectible Type = 1
)

// PrevID serves as a reference to an asset's previous input.
type PrevID struct {
	// OutPoint refers to the asset's previous output position within a
	// transaction.
	OutPoint wire.OutPoint

	// ID is the asset ID of the previous asset tree.
	ID ID

	// TODO(roasbeef): need another ref type for assets w/ a key family?

	// ScriptKey is the previous tweaked Taproot output key committing to
	// the possible spending conditions of the asset.
	ScriptKey btcec.PublicKey
}

// Hash returns the SHA-256 hash of all items encapsulated by PrevID.
func (id PrevID) Hash() [sha256.Size]byte {
	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &id.OutPoint)
	_, _ = h.Write(id.ID[:])
	_, _ = h.Write(schnorr.SerializePubKey(&id.ScriptKey))
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
	// https://github.com/lightninglabs/taro/issues/3.
	SplitCommitment *SplitCommitment
}

// EncodeRecords determines the non-nil records to include when encoding an
// asset witness at runtime.
func (w Witness) EncodeRecords() []tlv.Record {
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
func (w Witness) Encode(writer io.Writer) error {
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

// ScriptVersion denotes the asset script versioning scheme.
type ScriptVersion uint16

const (
	// ScriptV0 represents the initial asset script version of the Taro
	// protocol. In this version, assets commit to a tweaked Taproot output
	// key, allowing the ability for an asset to indirectly commit to
	// multiple spending conditions.
	ScriptV0 ScriptVersion = 0
)

// FamilyKey is the tweaked public key that is used to associate assets together
// across distinct asset IDs, allowing further issuance of the asset to be made
// possible.
type FamilyKey struct {
	// Key is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible. The tweaked public key is the result of:
	//   familyInternalKey + sha256(familyInternalKey || genesisOutPoint) * G
	Key btcec.PublicKey

	// Sig is a signature over an asset's ID by `Key`.
	Sig schnorr.Signature
}

// DeriveFamilyKey derives an asset's family key based on some internal private
// key and an asset genesis.
func DeriveFamilyKey(internalPrivKey *btcec.PrivateKey,
	genesis *Genesis) (*FamilyKey, error) {

	var genesisPrevOut bytes.Buffer
	err := wire.WriteOutPoint(&genesisPrevOut, 0, 0, &genesis.FirstPrevOut)
	if err != nil {
		return nil, err
	}
	tweakedPrivKey := txscript.TweakTaprootPrivKey(
		internalPrivKey, genesisPrevOut.Bytes(),
	)

	id := genesis.ID()
	sig, err := schnorr.Sign(tweakedPrivKey, id[:])
	if err != nil {
		return nil, err
	}

	return &FamilyKey{
		Key: *tweakedPrivKey.PubKey(),
		Sig: *sig,
	}, nil
}

// Asset represents a Taro asset.
type Asset struct {
	// Version is the Taro version of the asset.
	Version Version

	// Genesis encodes an asset's genesis metadata which directly maps to
	// its unique ID within the Taro protocol.
	Genesis Genesis

	// Type uniquely identifies the type of Taro asset.
	Type Type

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
	ScriptKey btcec.PublicKey

	// FamilyKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs, allowing further issuance of the
	// asset to be made possible.
	FamilyKey *FamilyKey
}

// New instantiates a new fungible asset of type `Normal` with a genesis asset
// witness.
func New(genesis *Genesis, amount, locktime, relativeLocktime uint64,
	scriptKey btcec.PublicKey, familyKey *FamilyKey) *Asset {

	return &Asset{
		Version:          V0,
		Genesis:          *genesis,
		Type:             Normal,
		Amount:           amount,
		LockTime:         locktime,
		RelativeLockTime: relativeLocktime,
		PrevWitnesses: []Witness{{
			// Valid genesis asset witness.
			PrevID:          &PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: nil,
		ScriptVersion:       ScriptV0,
		ScriptKey:           scriptKey,
		FamilyKey:           familyKey,
	}
}

// NewCollectible instantiates a new `Collectible` asset.
func NewCollectible(genesis *Genesis, locktime, relativeLocktime uint64,
	scriptKey btcec.PublicKey, familyKey *FamilyKey) *Asset {

	return &Asset{
		Version:          V0,
		Genesis:          *genesis,
		Type:             Collectible,
		Amount:           1,
		LockTime:         locktime,
		RelativeLockTime: relativeLocktime,
		PrevWitnesses: []Witness{{
			// Valid genesis asset witness.
			PrevID:          &PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: nil,
		ScriptVersion:       ScriptV0,
		ScriptKey:           scriptKey,
		FamilyKey:           familyKey,
	}
}

// TaroCommitmentKey is the key that maps to the root commitment for a specific
// asset family within a TaroCommitment.
func (a Asset) TaroCommitmentKey() [32]byte {
	if a.FamilyKey == nil {
		return [32]byte(a.Genesis.ID())
	}
	return sha256.Sum256(schnorr.SerializePubKey(&a.FamilyKey.Key))
}

// AssetCommitmentKey is the key that maps to a specific owner of an asset
// within a Taro AssetCommitment.
func (a Asset) AssetCommitmentKey() [32]byte {
	if a.FamilyKey == nil {
		return sha256.Sum256(schnorr.SerializePubKey(&a.ScriptKey))
	}
	assetID := a.Genesis.ID()
	h := sha256.New()
	_, _ = h.Write(assetID[:])
	_, _ = h.Write(schnorr.SerializePubKey(&a.ScriptKey))
	return *(*[32]byte)(h.Sum(nil))
}

// Copy returns a deep copy of an Asset.
func (a Asset) Copy() *Asset {
	assetCopy := a

	// Perform a deep copy of all pointer data types.
	assetCopy.Genesis.Metadata = make([]byte, len(a.Genesis.Metadata))
	copy(assetCopy.Genesis.Metadata, a.Genesis.Metadata)

	assetCopy.PrevWitnesses = make([]Witness, 0, len(a.PrevWitnesses))
	for _, witness := range a.PrevWitnesses {
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
		assetCopy.PrevWitnesses = append(
			assetCopy.PrevWitnesses, witnessCopy,
		)
	}

	if a.SplitCommitmentRoot != nil {
		assetCopy.SplitCommitmentRoot = mssmt.NewComputedNode(
			a.SplitCommitmentRoot.NodeKey(),
			a.SplitCommitmentRoot.NodeSum(),
		)
	}

	if a.FamilyKey != nil {
		assetCopy.FamilyKey = &FamilyKey{
			Key: a.FamilyKey.Key,
			Sig: a.FamilyKey.Sig,
		}
	}

	return &assetCopy
}

// EncodeRecords determines the non-nil records to include when encoding an
// asset at runtime.
func (a Asset) EncodeRecords() []tlv.Record {
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
	records = append(records, NewLeafScriptKeyRecord(&a.ScriptKey))
	if a.FamilyKey != nil {
		records = append(records, NewLeafFamilyKeyRecord(&a.FamilyKey))
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
		NewLeafScriptKeyRecord(&a.ScriptKey),
		NewLeafFamilyKeyRecord(&a.FamilyKey),
	}
}

// Encode encodes an asset into a TLV stream.
func (a Asset) Encode(w io.Writer) error {
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
	var buf bytes.Buffer
	if err := a.Encode(&buf); err != nil {
		return nil, err
	}
	return mssmt.NewLeafNode(buf.Bytes(), a.Amount), nil
}
