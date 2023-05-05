package universe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
)

var (
	// ErrNoUniverseRoot is returned when no universe root is found.
	ErrNoUniverseRoot = fmt.Errorf("no universe root found")

	// ErrNoUniverseServers is returned when no active Universe servers are
	// found in the DB.
	ErrNoUniverseServers = fmt.Errorf("no active federation servers")
)

// Identifier is the identifier for a root/base universe.
type Identifier struct {
	// AssetID is the asset ID for the universe.
	//
	// TODO(roasbeef): make both pointers?
	AssetID asset.ID

	// GroupKey is the group key for the universe.
	GroupKey *btcec.PublicKey
}

// String returns a string representation of the ID.
func (i *Identifier) String() string {
	if i.GroupKey != nil {
		h := sha256.Sum256(schnorr.SerializePubKey(i.GroupKey))
		return hex.EncodeToString(h[:])
	}

	return hex.EncodeToString(i.AssetID[:])
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
// the minting key. This proof can be used to verify that a valid asset exists
// (based on the proof in the leaf), and that the asset is committed to within
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

// VerifyRoot verifies that the inclusion proof for the root node matches the
// specified root. This is useful for sanity checking an issuance proof against
// the purported root, and the included leaf.
func (i *IssuanceProof) VerifyRoot(expectedRoot mssmt.Node) bool {
	reconstructedRoot := i.InclusionProof.Root(
		i.MintingKey.UniverseKey(),
		i.Leaf.SmtLeafNode(),
	)

	return mssmt.IsEqualNode(i.UniverseRoot, expectedRoot) &&
		mssmt.IsEqualNode(reconstructedRoot, expectedRoot)
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
	// tree, stored at the base key. The metaReveal type is purely
	// optional, and should be specified if the genesis proof committed to
	// a non-zero meta hash.
	RegisterIssuance(ctx context.Context,
		key BaseKey, leaf *MintingLeaf,
		metaReveal *proof.MetaReveal) (*IssuanceProof, error)

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

const (
	// DefaultUniverseRPCPort is the default port that the universe RPC is
	// hosted on.
	DefaultUniverseRPCPort = 10029
)

// resolveUniverseAddr maps an RPC universe host (of the form 'host' or
// 'host:port') into a net.Addr.
func resolverUniverseAddr(uniAddr string) (net.Addr, error) {

	var (
		host string
		port int
	)

	if len(uniAddr) == 0 {
		return nil, fmt.Errorf("universe host cannot be empty")
	}

	// Split the address into its host and port components.
	h, p, err := net.SplitHostPort(uniAddr)
	if err != nil {
		// If a port wasn't specified, we'll assume the address only
		// contains the host so we'll use the default port.
		host = uniAddr
		port = DefaultUniverseRPCPort
	} else {
		// Otherwise, we'll note both the host and ports.
		host = h
		portNum, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		port = portNum
	}

	// TODO(roasbeef): add tor support

	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	return net.ResolveTCPAddr("tcp", hostPort)
}

// ServerAddr wraps the reachable network address of a remote universe
// server.
type ServerAddr struct {
	// ID is the unique identifier of the remote universe.
	//
	// TODO(roasbeef): break out into generic ID wrapper struct?
	ID uint32

	// addrStr is the pure string version of the address before any name
	// resolution has taken place.
	addrStr string

	// addr is the resolved network address of the remote universe. This is
	// cached the first time so resolution doesn't need to be hit
	// repeatedly.
	addr net.Addr
}

// NewServerAddrFromStr creates a new server address from a string that is the
// host name of the remote universe server.
func NewServerAddrFromStr(s string) ServerAddr {
	return ServerAddr{
		addrStr: s,
	}
}

// NewServerAddr creates a new server address from both the universe addr ID
// and the host name string.
func NewServerAddr(i uint32, s string) ServerAddr {
	return ServerAddr{
		ID:      i,
		addrStr: s,
	}
}

// Addr returns the net.addr the universe is hosted at.
func (s *ServerAddr) Addr() (net.Addr, error) {
	if s.addr != nil {
		return s.addr, nil
	}

	addr, err := resolverUniverseAddr(s.addrStr)
	if err != nil {
		return nil, err
	}

	s.addr = addr
	return addr, err
}

// HostStr returns the host string of the remote universe server.
func (s *ServerAddr) HostStr() string {
	return s.addrStr
}

// SyncType is an enum that describes the type of sync that should be performed
// between a local and remote universe.
type SyncType uint8

const (
	// SyncIssuance is a sync that will only sync new asset issuance events.
	SyncIssuance SyncType = iota

	// SyncFull is a sync that will sync all the assets in the universe.
	SyncFull
)

// String returns a human readable string representation of the sync type.
func (s SyncType) String() string {
	switch s {
	case SyncIssuance:
		return "issuance"
	case SyncFull:
		return "full"
	default:
		return fmt.Sprintf("unknown(%v)", int(s))
	}
}

// AssetSyncDiff is the result of a success Universe sync. The diff contains the
// Universe root, and the set of assets that were added to the Universe.
type AssetSyncDiff struct {
	// OldUniverseRoot is the root of the universe before the sync.
	OldUniverseRoot BaseRoot

	// NewUniverseRoot is the new root of the Universe after the sync.
	NewUniverseRoot BaseRoot

	// NewAssetLeaves is the set of new leaf proofs that were added to the
	// Universe.
	NewLeafProofs []*MintingLeaf

	// TODO(roasbeef): ability to return if things failed?
	//  * can used a sealed interface to return the error
}

// Syncer is used to synchronize the state of two Universe instances: a local
// instance and a remote instance. As a Universe is a tree based structure,
// tree based bisection can be used to find the point of divergence with
// syncing happening once that's found.
type Syncer interface {
	// SyncUniverse attempts to synchronize the local universe with the
	// remote universe, governed by the sync type and the set of universe
	// IDs to sync.
	SyncUniverse(ctx context.Context, host ServerAddr,
		syncType SyncType,
		idsToSync ...Identifier) ([]AssetSyncDiff, error)
}

// DiffEngine is a Universe diff engine that can be used to compare the state
// of two universes and find the set of assets that are different between them.
type DiffEngine interface {
	BaseForest

	// RootNode returns the root node for a given base universe.
	RootNode(ctx context.Context, id Identifier) (BaseRoot, error)

	// MintingKeys returns all the keys inserted in the universe.
	MintingKeys(ctx context.Context, id Identifier) ([]BaseKey, error)

	// FethcIssuanceProof attempts to fetch an issuance proof for the
	// target base leaf based on the universe identifier
	// (assetID/groupKey).
	//
	// TODO(roasbeef): actually add this somewhere else?  * rn kinda
	// asymmetric, as just need this to complete final portion
	// of diff
	FetchIssuanceProof(ctx context.Context, id Identifier,
		key BaseKey) ([]*IssuanceProof, error)
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

// FederationLog is used to keep track of the set Universe servers that
// comprise our current federation. This'll be used by the AutoSyncer to
// periodically push and sync new proof events against the federation.
type FederationLog interface {
	// UniverseServers returns the set of servers in the federation.
	UniverseServers(ctx context.Context) ([]ServerAddr, error)

	// AddServers adds a slice of servers to the federation.
	AddServers(ctx context.Context, addrs ...ServerAddr) error

	// RemoveServers removes a set of servers from the federation.
	RemoveServers(ctx context.Context, addrs ...ServerAddr) error

	// LogNewSyncs logs a new sync event for each server. This can be used
	// to keep track of the last time we synced with a remote server.
	LogNewSyncs(ctx context.Context, addrs ...ServerAddr) error
}
