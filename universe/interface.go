package universe

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
)

// MintingLeaf...
//
// TODO(roasbeef): just can use the same encode/decode then?
type MintingLeaf struct {
	*proof.Proof
}

// IssuanceProof...
type IssuanceProof struct {
	// UniverseRoot
	UniverseRoot mssmt.Node

	// MintingKey...
	MintingKey BaseKey

	// InclusionProof...
	InclusionProof *mssmt.Proof

	// Leaf...
	Leaf *MintingLeaf
}

// BaseKey...
//
// TODO(roasbeef): abstract over this?
//   - interface, then can re-use TreeStorage for more stuff
type BaseKey struct {
	// GenesisPoint...
	GenesisPoint wire.OutPoint

	// AssetID...
	//
	// TODO(roasbeef): mandatory if key family?
	AssetID *asset.ID
}

// Identifier...
type Identifier struct {
	// TODO(roasbeef): then use this in place? Either[famKey, assetID]
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

// Base...
//
// TODO(roasbeef): gRPC service to match this, think about the REST mapping
type Base interface {
	// RootNode...
	RootNode(context.Context) (mssmt.Node, error)

	// RegisterIssuance...
	//
	// TODO(roasbeef): move to below?
	RegisterIssuance(key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error)

	// FetchIssuanceProof...
	FetchIssuanceProof(key BaseKey) (*IssuanceProof, error)
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
	CommitUniverse(universe Base) (*Commitment, error)
}

// Cannonical...
//
// TODO(roasbeef): sync methods too, divide into read/write?
type Cannonical interface {
	Base

	// Query...
	Query(context.Context, BaseKey) (*CommittedIssuanceProof, error)

	// LatestCommitment...
	LatestCommitment() (*Commitment, error)

	// UpdateChainCommitment...
	UpdateChainCommitment(chainCommits ...ChainCommiter) (*Commitment, error)
}
