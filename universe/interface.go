package universe

import (
	"context"
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
)

// Identifier...
type Identifier struct {
	AssetID asset.ID

	GroupKey *btcec.PublicKey
}

// MintingLeaf...
//
// TODO(roasbeef): just can use the same encode/decode then?
type MintingLeaf struct {
	GenesisWithGroup

	GenesisProof *proof.Proof

	// Amt...
	Amt int64
}

// LeafNode...
func (m *MintingLeaf) LeafNode() *mssmt.LeafNode {
	return nil
}

// BaseKey...
//
// TODO(roasbeef): abstract over this?
//   - interface, then can re-use TreeStorage for more stuff
//
// TODO(roasbeef): final key structure:
//
//	assetID (base root) -> hash(mintingPoint || scriptKey)
//	 * able to fetch all script keys for a given output
type BaseKey struct {
	// MintingOutpoint...
	MintingOutpoint wire.OutPoint

	// ScriptKey...
	ScriptKey *asset.ScriptKey

	// TODO(roasbeef): add asset type too?
}

// UniverseKey...
func (b *BaseKey) UniverseKey() [32]byte {
	// key = sha256(mintingOutpoint || scriptKey)
	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &b.MintingOutpoint)
	h.Write(schnorr.SerializePubKey(b.ScriptKey.PubKey))

	var k [32]byte
	copy(k[:], h.Sum(nil))

	return k
}

// IssuanceProof...
type IssuanceProof struct {
	// MintingKey...
	MintingKey BaseKey

	// UniverseRoot
	UniverseRoot mssmt.Node

	// InclusionProof...
	InclusionProof *mssmt.Proof

	// Leaf...
	Leaf *MintingLeaf
}

// Descriptor....
//
// TODO(roasbeef): rename to Background?
type Descriptor interface {
	// Init...
	Init(familyKey *btcec.PublicKey, assetID *asset.ID) error

	// FamilyKey...
	FamilyKey(context.Context) (*btcec.PublicKey, error)

	// AssetID...
	AssetID(context.Context) (*asset.ID, error)

	// GenesisPoints...
	//
	// TODO(roasbeef): also return assetIDs as well? so then just the base
	// keys?
	GenesisPoints(ctx context.Context) ([]wire.OutPoint, error)

	// AddGenesis...
	AddGenesis(context.Context, wire.OutPoint) error
}

// BaseBackend...
//
// TODO(roasbeef): gRPC service to match this, think about the REST mapping
type BaseBackend interface {
	// RootNode...
	//  * namespace is groupKey/assetID?
	RootNode(context.Context) (mssmt.Node, error)

	// TODO(roasbeef): iterate over all keys, etc, etc.

	// RegisterIssuance...
	//
	// TODO(roasbeef): move to below?
	RegisterIssuance(ctx context.Context,
		key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error)

	// FetchIssuanceProof...
	//  * if script key not set, then fetch all
	FetchIssuanceProof(ctx context.Context,
		key BaseKey) ([]*IssuanceProof, error)

	// MintingKeys...
	MintingKeys(ctx context.Context) ([]BaseKey, error)

	// MintingLeaves...
	MintingLeaves(ctx context.Context) ([]MintingLeaf, error)
}

// Commitment...
type Commitment struct {
	// BlockHeader...
	BlockHeight uint32

	// BlockHeader...
	BlockHeader wire.BlockHeader

	// MerkleProof...
	MerkleProof *proof.TxMerkleProof

	// UniverseRoot...
	UniverseRoot mssmt.Node
}

// CommittedIssuance..
type CommittedIssuanceProof struct {
	// ChainProof...
	ChainProof *Commitment

	// TaroProof...
	TaroProof *IssuanceProof
}

// ChainCommiter...
type ChainCommiter interface {
	// CommitUniverse...
	CommitUniverse(universe BaseBackend) (*Commitment, error)
}

// Cannonical...
//
// TODO(roasbeef): sync methods too, divide into read/write?
type Cannonical interface {
	BaseBackend

	// Query...
	Query(context.Context, BaseKey) (*CommittedIssuanceProof, error)

	// LatestCommitment...
	LatestCommitment() (*Commitment, error)

	// UpdateChainCommitment...
	UpdateChainCommitment(chainCommits ...ChainCommiter) (*Commitment, error)
}
