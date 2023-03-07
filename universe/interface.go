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

// Identifier is the identifier for a root/base universe.
type Identifier struct {
	// AssetID is the aseet ID for the universe.
	//
	// TODO(roasbeef): make both pointers?
	AssetID asset.ID

	// GroupKey is the group key for the universe.
	GroupKey *btcec.PublicKey
}

// GenesisWithGroup is a two tuple that groups the genesis of an asset with the
// group key it's assocaited with (if that exists).
type GenesisWithGroup struct {
	asset.Genesis

	*asset.GroupKey
}

// MintingLeaf is a leaf node in the SMT that represents a minting output. For
// each new asset created for a given asset/universe, a new minting leaf is
// created.
type MintingLeaf struct {
	GenesisWithGroup

	// GenesisProof is the proof of the newly created asset.
	//
	// TODO(roasbeef): have instead be a reader? easier to mmap in the
	// future
	GenesisProof proof.Blob

	// Amt is the amount of units created.
	Amt uint64
}

// SmtLeafNode returns the SMT leaf node for the given minting leaf.
func (m *MintingLeaf) SmtLeafNode() *mssmt.LeafNode {
	return mssmt.NewLeafNode(m.GenesisProof[:], uint64(m.Amt))
}

// BaseKey is the top level key for a Base/Root universe. This will be used to
// key into the MS-SMT. The final key is: sha256(mintingOutpoint || scriptKey).
// This ensures that all leaves for a given asset will be uniquely keyed in the
// universe tree.
type BaseKey struct {
	// MintingOutpoint is the minting outpoint, or the outpoint where the
	// nelwy created assets reside within.
	MintingOutpoint wire.OutPoint

	// ScriptKey is the script key of the base asset. If this isn't
	// specified, then the caller is attempting to query for all the script
	// keys at that minting outpoint.
	ScriptKey *asset.ScriptKey

	// TODO(roasbeef): add asset type too?
}

// UniverseKey is the key for a universe.
func (b BaseKey) UniverseKey() [32]byte {
	// key = sha256(mintingOutpoint || scriptKey)
	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &b.MintingOutpoint)
	h.Write(schnorr.SerializePubKey(b.ScriptKey.PubKey))

	var k [32]byte
	copy(k[:], h.Sum(nil))

	return k
}

// IssuanceProof is a complete issuance proof for a given asset specified by
// the minintng key. This proof can be used to verify that a valid asset exists
// (based on the proof in the leaf), and that the asset is commited to within
// the universe root.
type IssuanceProof struct {
	// MintingKey is the minting key for the asset.
	MintingKey BaseKey

	// UniverseRoot is the root of the universe that the asset is located
	// within.
	UniverseRoot mssmt.Node

	// InclusionProof is the inclusion proof for the asset within the
	// universe tree.
	InclusionProof *mssmt.Proof

	// Leaf is the leaf node for the asset within the universe tree.
	Leaf *MintingLeaf
}

// BaseBackend is the backend storage interface for a base universe. The
// backend can be used to store issuance profs, retrieve them, and also fetch
// the set of keys and leaves stored within the universe.
//
// TODO(roasbeef): gRPC service to match this, think about the REST mapping
type BaseBackend interface {
	// RootNode returns the root node for a given base universe.
	RootNode(context.Context) (mssmt.Node, error)

	// RegisterIssuance inserts a new minting leaf within the universe
	// tree, stored at the base key.
	RegisterIssuance(ctx context.Context,
		key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error)

	// FetchIssuanceProof returns an issuance proof for the target key. If
	// the key doesn't have a script key specified, then all the proofs for
	// the minting outpoint will be returned. If neither are specified,
	// then proofs for all the inserted leaves will be returned.
	//
	// TODO(roasbeef): can eventually do multi-proofs for the SMT
	FetchIssuanceProof(ctx context.Context,
		key BaseKey) ([]*IssuanceProof, error)

	// MintingKeys returns all the keys inserted in the universe.
	MintingKeys(ctx context.Context) ([]BaseKey, error)

	// MintingLeaves returns all the minting leaves inserted into the
	// universe.
	MintingLeaves(ctx context.Context) ([]MintingLeaf, error)
}

// BaseRoot is the ms-smt root for a base universe. This root can be used to
// compare against other trackers of a base universe to find discrepancies
// (unknown issuance events, etc).
type BaseRoot struct {
	ID Identifier

	mssmt.Node
}

// BaseForest is an interface used to keep track of the set of base universe
// roots that we know of. The BaseBackend interface is used to interact with a
// particular base universe, while this is used to obtain aggregate information
// about the universes.
type BaseForest interface {
	// RootNodes returns the complete set of known root nodes for the set
	// of assets tracked in the base Universe.
	RootNodes(ctx context.Context) ([]BaseRoot, error)

	// TODO(roasbeef): other stats stuff here, like total number of assets, etc
	//  * also eventually want pull/fetch stats, can be pulled out into another instance
}

// Registrar is an interface that allows a caller to register issuance of a new
// asset in a local/remote base universe instance.
type Registrar interface {
	// RegisterIssuance inserts a new minting leaf within the target
	// universe tree (based on the ID), stored at the base key.
	RegisterIssuance(ctx context.Context, id Identifier, key BaseKey,
		leaf *MintingLeaf) (*IssuanceProof, error)
}

// Commitment is an on chain universe commitment. This includes the merkle
// proof for a transaction which anchors the target universe root.
type Commitment struct {
	// BlockHeight is the height of the block that the commitment is
	// contained within.
	BlockHeight uint32

	// BlockHeader is the block header that commits to the transaction.
	BlockHeader wire.BlockHeader

	// MerkleProof is a merkle proof for the above transaction that the
	// anchor output was included.
	MerkleProof *proof.TxMerkleProof

	// UniverseRoot is the full Universe root for this commitment.
	UniverseRoot mssmt.Node
}

// CommittedIssuanceProof couples together a Bitcoin level merkle proof
// commitment with an issuance proof. This allows remote callers to verify that
// their responses re actually committed to within the chain.
type CommittedIssuanceProof struct {
	// ChainProof is the on chain proof that shows the Universe root has
	// been stamped in the chain.
	ChainProof *Commitment

	// TaroProof is a proof of new asset issuance.
	TaroProof *IssuanceProof
}

// ChainCommiter is used to commit a Universe backend in the chain.
type ChainCommiter interface {
	// CommitUniverse takes a Universe and returns a new commitment to that
	// Universe in the main chain.
	CommitUniverse(universe BaseBackend) (*Commitment, error)
}

// canonical is an interface that allows a caller to query for the latest
// canonical Universe information related to an asset.
//
// TODO(roasbeef): sync methods too, divide into read/write?
type Cannonical interface {
	BaseBackend

	// Query returns a fully proved response for the target base key.
	Query(context.Context, BaseKey) (*CommittedIssuanceProof, error)

	// LatestCommitment returns the latest chain commitment.
	LatestCommitment() (*Commitment, error)

	// UpdateChainCommitment takes in a series of chain commitments and
	// updates the commitment on chain.
	UpdateChainCommitment(chainCommits ...ChainCommiter) (*Commitment, error)
}
