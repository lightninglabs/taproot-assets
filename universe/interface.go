package universe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
)

var (
	// ErrNoUniverseRoot is returned when no universe root is found.
	ErrNoUniverseRoot = fmt.Errorf("no universe root found")

	// ErrNoUniverseServers is returned when no active Universe servers are
	// found in the DB.
	ErrNoUniverseServers = fmt.Errorf("no active federation servers")

	// ErrDuplicateUniverse is returned when the Universe server being added
	// to the DB already exists.
	ErrDuplicateUniverse = fmt.Errorf("universe server already added")

	// ErrNoUniverseProofFound is returned when a user attempts to look up
	// a key in the universe that actually points to the empty leaf.
	ErrNoUniverseProofFound = fmt.Errorf("no universe proof found")
)

const (
	// MaxPageSize is the maximum page size that can be used when querying
	// for asset roots and leaves.
	MaxPageSize = 512
)

// Identifier is the identifier for a universe.
type Identifier struct {
	// AssetID is the asset ID for the universe.
	//
	// TODO(roasbeef): make both pointers?
	AssetID asset.ID

	// GroupKey is the group key for the universe.
	GroupKey *btcec.PublicKey

	// ProofType is the type of proof that should be stored in the universe.
	ProofType ProofType
}

// Bytes returns a bytes representation of the ID.
func (i *Identifier) Bytes() [32]byte {
	if i.GroupKey != nil {
		return sha256.Sum256(schnorr.SerializePubKey(i.GroupKey))
	}

	return i.AssetID
}

// String returns a string representation of the ID.
func (i *Identifier) String() string {
	// The namespace is prefixed by the proof type. This is done to make it
	// easier to identify the proof type when looking at a list of
	// namespaces (say, in a DB explorer).
	return fmt.Sprintf("%s-%x", i.ProofType, i.Bytes())
}

// StringForLog returns a string representation of the ID for logging.
func (i *Identifier) StringForLog() string {
	groupKey := "<nil>"
	if i.GroupKey != nil {
		groupKey = hex.EncodeToString(
			schnorr.SerializePubKey(i.GroupKey),
		)
	}

	return fmt.Sprintf("%v (asset_id=%x, group_key=%v, proof_type=%v)",
		i.String(), i.AssetID[:], groupKey, i.ProofType)
}

// IsEqual returns true if the two identifiers are equal.
func (i *Identifier) IsEqual(other Identifier) bool {
	if i == nil {
		return false
	}

	groupKeysEqual := false
	if i.GroupKey == nil || other.GroupKey == nil {
		groupKeysEqual = i.GroupKey == other.GroupKey
	} else {
		groupKeysEqual = i.GroupKey.IsEqual(other.GroupKey)
	}

	return i.AssetID == other.AssetID &&
		groupKeysEqual &&
		i.ProofType == other.ProofType
}

// NewUniIDFromAsset creates a new universe ID from an asset.
func NewUniIDFromAsset(a asset.Asset) Identifier {
	proofType := ProofTypeTransfer
	if a.IsGenesisAsset() {
		proofType = ProofTypeIssuance
	}

	if a.GroupKey != nil {
		return Identifier{
			GroupKey:  &a.GroupKey.GroupPubKey,
			ProofType: proofType,
		}
	}

	return Identifier{
		AssetID:   a.ID(),
		ProofType: proofType,
	}
}

// NewUniIDFromRawArgs creates a new universe ID from the raw arguments. The
// asset ID bytes and group key bytes are mutually exclusive. If the group key
// bytes are set, then the asset ID bytes will be ignored.
// This function is useful in deriving a universe ID from the data stored in the
// database.
func NewUniIDFromRawArgs(assetIDBytes []byte, groupKeyBytes []byte,
	proofTypeStr string) (Identifier, error) {

	proofType, err := ParseStrProofType(proofTypeStr)
	if err != nil {
		return Identifier{}, err
	}

	// If the group key bytes are set, then we'll preferentially populate
	// the universe ID with that and not the asset ID.
	if len(groupKeyBytes) != 0 {
		groupKey, err := parseGroupKey(groupKeyBytes)
		if err != nil {
			return Identifier{}, fmt.Errorf("unable to parse "+
				"group key: %w", err)
		}
		return Identifier{
			GroupKey:  groupKey,
			ProofType: proofType,
		}, nil
	}

	// At this point we know that the group key bytes are nil, so we'll
	// attempt to parse the asset ID bytes.
	if len(assetIDBytes) == 0 {
		return Identifier{}, fmt.Errorf("asset ID bytes and group " +
			"key bytes are both nil")
	}

	var assetID asset.ID
	copy(assetID[:], assetIDBytes)

	return Identifier{
		AssetID:   assetID,
		ProofType: proofType,
	}, nil
}

// parseGroupKey parses a group key from bytes, which can be in either the
// Schnorr or Compressed format.
func parseGroupKey(scriptKey []byte) (*btcec.PublicKey, error) {
	switch len(scriptKey) {
	case schnorr.PubKeyBytesLen:
		return schnorr.ParsePubKey(scriptKey)

	// Truncate the key and then parse as a Schnorr key.
	case btcec.PubKeyBytesLenCompressed:
		return schnorr.ParsePubKey(scriptKey[1:])

	default:
		return nil, fmt.Errorf("unknown script key length: %v",
			len(scriptKey))
	}
}

// ValidateProofUniverseType validates that the proof type matches the universe
// identifier proof type.
func ValidateProofUniverseType(a *asset.Asset, uniID Identifier) error {
	expectedProofType, err := NewProofTypeFromAsset(a)
	if err != nil {
		return err
	}

	if expectedProofType != uniID.ProofType {
		return fmt.Errorf("proof type mismatch: expected %s, got %s",
			expectedProofType, uniID.ProofType)
	}

	return nil
}

// GenesisWithGroup is a two tuple that groups the genesis of an asset with the
// group key it's associated with (if that exists).
type GenesisWithGroup struct {
	asset.Genesis

	*asset.GroupKey
}

// Leaf is a leaf node in the SMT that represents an asset issuance or transfer.
// For each asset issued or transferred for a given universe, a new leaf is
// created.
type Leaf struct {
	GenesisWithGroup

	// RawProof is either an issuance proof or a transfer proof associated
	// with/ the issuance or spend event which this leaf represents.
	RawProof proof.Blob

	// Asset is the asset that the leaf is associated with.
	Asset *asset.Asset

	// Amt is the amount of units associated with the coin.
	Amt uint64
}

// SmtLeafNode returns the SMT leaf node for the given leaf.
func (m *Leaf) SmtLeafNode() *mssmt.LeafNode {
	amount := m.Amt
	if !m.Asset.IsGenesisAsset() {
		// We set transfer proof amounts to 1 as the transfer universe
		// tracks the total number of transfers.
		amount = 1
	}

	return mssmt.NewLeafNode(m.RawProof, amount)
}

// LeafKey is the top level leaf key for a universe. This will be used to key
// into a universe's MS-SMT data structure. The final serialized key is:
// sha256(mintingOutpoint || scriptKey). This ensures that all
// leaves for a given asset will be uniquely keyed in the universe tree.
type LeafKey struct {
	// OutPoint is the outpoint at which the asset referenced by this key
	// resides.
	OutPoint wire.OutPoint

	// ScriptKey is the script key of the base asset. If this isn't
	// specified, then the caller is attempting to query for all the script
	// keys at that minting outpoint.
	ScriptKey *asset.ScriptKey

	// TODO(roasbeef): add asset type too?
}

// UniverseKey is the key for a universe.
func (b LeafKey) UniverseKey() [32]byte {
	// key = sha256(mintingOutpoint || scriptKey)
	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &b.OutPoint)
	h.Write(schnorr.SerializePubKey(b.ScriptKey.PubKey))

	var k [32]byte
	copy(k[:], h.Sum(nil))

	return k
}

// Proof associates a universe leaf (and key) with its corresponding multiverse
// and universe inclusion proofs.
//
// These inclusion proofs can be used to verify that a valid asset exists
// (based on the proof in the leaf), and that the asset is committed to within
// the universe root and multiverse root.
type Proof struct {
	// Leaf is the leaf node for the asset within the universe tree.
	Leaf *Leaf

	// LeafKey is the universe leaf key for the asset issuance or spend.
	LeafKey LeafKey

	// UniverseRoot is the root of the universe that the asset is located
	// within.
	UniverseRoot mssmt.Node

	// UniverseInclusionProof is the universe inclusion proof for the asset
	// within the universe tree.
	UniverseInclusionProof *mssmt.Proof

	// MultiverseRoot is the root of the multiverse tree that the asset is
	// located within.
	MultiverseRoot mssmt.Node

	// MultiverseInclusionProof is the inclusion proof for the asset within
	// the multiverse tree.
	MultiverseInclusionProof *mssmt.Proof
}

// VerifyRoot verifies that the inclusion proof for the root node matches the
// specified root. This is useful for sanity checking an issuance proof against
// the purported root, and the included leaf.
func (i *Proof) VerifyRoot(expectedRoot mssmt.Node) bool {
	leafNode := i.Leaf.SmtLeafNode()

	reconstructedRoot := i.UniverseInclusionProof.Root(
		i.LeafKey.UniverseKey(), leafNode,
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
	RootNode(context.Context) (mssmt.Node, string, error)

	// RegisterIssuance inserts a new minting leaf within the universe
	// tree, stored at the base key. The metaReveal type is purely
	// optional, and should be specified if the genesis proof committed to
	// a non-zero meta hash.
	RegisterIssuance(ctx context.Context, key LeafKey, leaf *Leaf,
		metaReveal *proof.MetaReveal) (*Proof, error)

	// FetchIssuanceProof returns an issuance proof for the target key. If
	// the key doesn't have a script key specified, then all the proofs for
	// the minting outpoint will be returned. If neither are specified,
	// then proofs for all the inserted leaves will be returned.
	//
	// TODO(roasbeef): can eventually do multi-proofs for the SMT
	FetchIssuanceProof(ctx context.Context,
		key LeafKey) ([]*Proof, error)

	// MintingKeys returns all the keys inserted in the universe.
	MintingKeys(ctx context.Context,
		q UniverseLeafKeysQuery) ([]LeafKey, error)

	// MintingLeaves returns all the minting leaves inserted into the
	// universe.
	MintingLeaves(ctx context.Context) ([]Leaf, error)

	// DeleteUniverse deletes all leaves, and the root, for a given base
	// universe.
	DeleteUniverse(ctx context.Context) (string, error)
}

// Root is the ms-smt root for a universe. This root can be used to compare
// against other trackers of a universe to find discrepancies (unknown issuance
// events, etc).
type Root struct {
	ID Identifier

	mssmt.Node

	// AssetName is the name of the asset. This might not always be set for
	// performance reasons.
	AssetName string

	// GroupedAssets is an optional map of asset IDs to the minted amount.
	// This is only set for grouped assets.
	GroupedAssets map[asset.ID]uint64
}

// MultiverseLeafDesc can be used to uniquely identify a Multiverse leave
// (which is a Universe root).  A leaf for a given Universe tree (proof type
// assumed) can be identified by either the asset ID or the target group key.
type MultiverseLeafDesc = fn.Either[asset.ID, btcec.PublicKey]

// MultiverseRoot is the ms-smt root for a multiverse. This root can be used to
// authenticate any leaf proofs.
type MultiverseRoot struct {
	// ProofType is the types of proofs that've been stored in the
	// multiverse.
	ProofType ProofType

	mssmt.Node
}

// MultiverseLeaf is the leaf within a Multiverse, this stores a value which is
// derived from the root of a normal Universe tree.
type MultiverseLeaf struct {
	// ID contains the information to uniquely identify the multiverse
	// root: assetID/groupKey and the proof type.
	ID Identifier

	*mssmt.LeafNode
}

// MultiverseArchive is an interface used to keep track of the set of universe
// roots that we know of. The BaseBackend interface is used to interact with a
// particular base universe, while this is used to obtain aggregate information
// about the universes.
type MultiverseArchive interface {
	// RootNodes returns the complete set of known root nodes for the set
	// of assets tracked in the base Universe.
	RootNodes(ctx context.Context, q RootNodesQuery) ([]Root, error)

	// UpsertProofLeaf upserts a proof leaf within the multiverse tree and
	// the universe tree that corresponds to the given key.
	UpsertProofLeaf(ctx context.Context, id Identifier, key LeafKey,
		leaf *Leaf,
		metaReveal *proof.MetaReveal) (*Proof, error)

	// UpsertProofLeafBatch upserts a proof leaf batch within the multiverse
	// tree and the universe tree that corresponds to the given key(s).
	UpsertProofLeafBatch(ctx context.Context, items []*Item) error

	// FetchProofLeaf returns a proof leaf for the target key. If the key
	// doesn't have a script key specified, then all the proof leafs for the
	// minting outpoint will be returned. If neither are specified, then all
	// inserted proof leafs will be returned.
	FetchProofLeaf(ctx context.Context, id Identifier,
		key LeafKey) ([]*Proof, error)

	// DeleteUniverse deletes all leaves, and the root, for given universe.
	DeleteUniverse(ctx context.Context, id Identifier) (string, error)

	// UniverseRootNode returns the Universe root node for the given asset
	// ID.
	UniverseRootNode(ctx context.Context, id Identifier) (Root, error)

	// UniverseLeafKeys returns the set of leaf keys for the given
	// universe.
	UniverseLeafKeys(ctx context.Context,
		q UniverseLeafKeysQuery) ([]LeafKey, error)

	// FetchLeaves returns the set of multiverse leaves that satisfy the set
	// of universe targets. If the set of targets is empty, all leaves for
	// the given proof type will be returned.
	FetchLeaves(ctx context.Context, universeTargets []MultiverseLeafDesc,
		proofType ProofType) ([]MultiverseLeaf, error)

	// MultiverseRootNode returns the Multiverse root node for the given
	// proof type.
	MultiverseRootNode(ctx context.Context,
		proofType ProofType) (fn.Option[MultiverseRoot], error)
}

// Registrar is an interface that allows a caller to upsert a proof leaf in a
// local/remote universe instance.
type Registrar interface {
	// UpsertProofLeaf upserts a proof leaf within the target universe tree.
	UpsertProofLeaf(ctx context.Context, id Identifier, key LeafKey,
		leaf *Leaf) (*Proof, error)

	// Close is used to shutdown the active registrar instance.
	Close() error
}

// Item contains the data fields necessary to insert/update a proof leaf
// within a multiverse and the related asset (group) specific universe.
type Item struct {
	// ID is the identifier of the asset (group) specific universe.
	ID Identifier

	// Key is the key that the leaf is or will be stored at.
	Key LeafKey

	// Leaf is the proof leaf which will be stored at the key.
	Leaf *Leaf

	// MetaReveal is the meta reveal associated with the given proof leaf.
	MetaReveal *proof.MetaReveal

	// LogProofSync is a boolean that indicates, if true, that the proof
	// leaf sync attempt should be logged and actively managed to ensure
	// that the federation push procedure is repeated in the event of a
	// failure.
	LogProofSync bool
}

// BatchRegistrar is an interface that allows a caller to register a batch of
// proof items within a universe.
type BatchRegistrar interface {
	Registrar

	// UpsertProofLeafBatch inserts a batch of proof leaves within the
	// target universe tree. We assume the proofs within the batch have
	// already been checked that they don't yet exist in the local database.
	UpsertProofLeafBatch(ctx context.Context, items []*Item) error
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
	ID int64

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
func NewServerAddr(i int64, s string) ServerAddr {
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

// String returns a human-readable string representation of the sync type.
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
	OldUniverseRoot Root

	// NewUniverseRoot is the new root of the Universe after the sync.
	NewUniverseRoot Root

	// NewAssetLeaves is the set of new leaf proofs that were added to the
	// Universe.
	NewLeafProofs []*Leaf

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
		syncType SyncType, syncConfigs SyncConfigs,
		idsToSync ...Identifier) ([]AssetSyncDiff, error)
}

// DiffEngine is a Universe diff engine that can be used to compare the state
// of two universes and find the set of assets that are different between them.
type DiffEngine interface {
	// RootNode returns the root node for a given base universe.
	RootNode(ctx context.Context, id Identifier) (Root, error)

	// RootNodes returns the set of root nodes for all known universes.
	RootNodes(ctx context.Context, q RootNodesQuery) ([]Root, error)

	// UniverseLeafKeys returns all the keys inserted in the universe.
	UniverseLeafKeys(ctx context.Context,
		q UniverseLeafKeysQuery) ([]LeafKey, error)

	// FetchProofLeaf attempts to fetch a proof leaf for the target leaf key
	// and given a universe identifier (assetID/groupKey).
	//
	// TODO(roasbeef): actually add this somewhere else?  * rn kinda
	// asymmetric, as just need this to complete final portion
	// of diff
	FetchProofLeaf(ctx context.Context, id Identifier,
		key LeafKey) ([]*Proof, error)

	// Close is used to shutdown the active diff engine instance.
	Close() error
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

	// TaprootAssetProof is a proof of new asset issuance.
	TaprootAssetProof *Proof
}

// ChainCommitter is used to commit a Universe backend in the chain.
type ChainCommitter interface {
	// CommitUniverse takes a Universe and returns a new commitment to that
	// Universe in the main chain.
	CommitUniverse(universe BaseBackend) (*Commitment, error)
}

// Canonical is an interface that allows a caller to query for the latest
// canonical Universe information related to an asset.
//
// TODO(roasbeef): sync methods too, divide into read/write?
type Canonical interface {
	BaseBackend

	// Query returns a fully proved response for the target base key.
	Query(context.Context, LeafKey) (*CommittedIssuanceProof, error)

	// LatestCommitment returns the latest chain commitment.
	LatestCommitment() (*Commitment, error)

	// UpdateChainCommitment takes in a series of chain commitments and
	// updates the commitment on chain.
	UpdateChainCommitment(chainCommits ...ChainCommitter) (*Commitment, error)
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

// ProofType is an enum that describes the type of proof which can be stored in
// a given universe.
type ProofType uint8

const (
	// ProofTypeUnspecified signifies an unspecified proof type.
	ProofTypeUnspecified ProofType = iota

	// ProofTypeIssuance corresponds to the issuance proof type.
	ProofTypeIssuance

	// ProofTypeTransfer corresponds to the transfer proof type.
	ProofTypeTransfer
)

// NewProofTypeFromAsset returns the proof type for the given asset proof.
func NewProofTypeFromAsset(a *asset.Asset) (ProofType, error) {
	if a == nil {
		return 0, fmt.Errorf("asset is nil")
	}

	if a.IsGenesisAsset() {
		return ProofTypeIssuance, nil
	}

	return ProofTypeTransfer, nil
}

// String returns a human-readable string representation of the proof type.
func (t ProofType) String() string {
	switch t {
	case ProofTypeUnspecified:
		return "unspecified"
	case ProofTypeIssuance:
		return "issuance"
	case ProofTypeTransfer:
		return "transfer"
	}

	return fmt.Sprintf("unknown(%v)", int(t))
}

// ParseStrProofType returns the proof type corresponding to the given string.
func ParseStrProofType(typeStr string) (ProofType, error) {
	switch typeStr {
	case "unspecified":
		return ProofTypeUnspecified, nil
	case "issuance":
		return ProofTypeIssuance, nil
	case "transfer":
		return ProofTypeTransfer, nil
	default:
		return 0, fmt.Errorf("unknown proof type: %v", typeStr)
	}
}

// FedGlobalSyncConfig is a config that can be used to specify the global
// (default) federation sync behavior.
type FedGlobalSyncConfig struct {
	// ProofTypes represents the configuration target universe proof type.
	ProofType ProofType

	// AllowSyncExport is a boolean that indicates whether leaves from
	// universes of the given proof type have may be inserted via federation
	// sync.
	AllowSyncInsert bool

	// AllowSyncExport is a boolean that indicates whether leaves from
	// universes of the given proof type have may be exported via federation
	// sync.
	AllowSyncExport bool
}

// FedUniSyncConfig is a config that can be used to specify the federation sync
// behavior for a given Universe.
type FedUniSyncConfig struct {
	// UniverseID is the ID of the Universe that the config applies to.
	UniverseID Identifier

	// AllowSyncInsert is a boolean that indicates whether leaves from the
	// target universe may be inserted via federation sync.
	AllowSyncInsert bool

	// AllowSyncExport is a boolean that indicates whether leaves from the
	// target universe may be exported via federation sync.
	AllowSyncExport bool
}

// FederationSyncConfigDB is used to manage the set of Universe servers as part
// of a federation.
type FederationSyncConfigDB interface {
	// QueryFederationSyncConfigs returns the global and universe specific
	// federation sync configs.
	QueryFederationSyncConfigs(ctx context.Context) ([]*FedGlobalSyncConfig,
		[]*FedUniSyncConfig, error)

	// UpsertFederationSyncConfig upserts both global and universe specific
	// federation sync configs.
	UpsertFederationSyncConfig(
		ctx context.Context, globalSyncConfigs []*FedGlobalSyncConfig,
		uniSyncConfigs []*FedUniSyncConfig) error
}

// SyncDirection is the direction of a proof sync.
type SyncDirection string

const (
	// SyncDirectionPush indicates that the sync is a push sync (from the local
	// server to the remote server).
	SyncDirectionPush SyncDirection = "push"

	// SyncDirectionPull indicates that the sync is a pull sync (from the remote
	// server to the local server).
	SyncDirectionPull SyncDirection = "pull"
)

// ParseStrSyncDirection parses a string into a SyncDirection.
func ParseStrSyncDirection(s string) (SyncDirection, error) {
	switch s {
	case string(SyncDirectionPush):
		return SyncDirectionPush, nil
	case string(SyncDirectionPull):
		return SyncDirectionPull, nil
	default:
		return "", fmt.Errorf("unknown sync direction: %v", s)
	}
}

// ProofSyncStatus is the status of a proof sync.
type ProofSyncStatus string

const (
	// ProofSyncStatusPending indicates that the sync is pending.
	ProofSyncStatusPending ProofSyncStatus = "pending"

	// ProofSyncStatusComplete indicates that the sync is complete.
	ProofSyncStatusComplete ProofSyncStatus = "complete"
)

// ParseStrProofSyncStatus parses a string into a ProofSyncStatus.
func ParseStrProofSyncStatus(s string) (ProofSyncStatus, error) {
	switch s {
	case string(ProofSyncStatusPending):
		return ProofSyncStatusPending, nil
	case string(ProofSyncStatusComplete):
		return ProofSyncStatusComplete, nil
	default:
		return "", fmt.Errorf("unknown proof sync status: %v", s)
	}
}

// ProofSyncLogEntry is a log entry for a proof sync.
type ProofSyncLogEntry struct {
	// Timestamp is the timestamp of the log entry.
	Timestamp time.Time

	// SyncStatus is the status of the sync.
	SyncStatus ProofSyncStatus

	// SyncDirection is the direction of the sync.
	SyncDirection SyncDirection

	// AttemptCounter is the number of times the sync has been attempted.
	AttemptCounter int64

	// ServerAddr is the address of the sync counterparty server.
	ServerAddr ServerAddr

	// UniID is the identifier of the universe associated with the sync event.
	UniID Identifier

	// LeafKey is the leaf key associated with the sync event.
	LeafKey LeafKey

	// Leaf is the leaf associated with the sync event.
	Leaf Leaf
}

// FederationProofSyncLog is used for CRUD operations relating to the federation
// proof sync log.
type FederationProofSyncLog interface {
	// UpsertFederationProofSyncLog upserts a federation proof sync log
	// entry for a given universe server and proof.
	UpsertFederationProofSyncLog(ctx context.Context, uniID Identifier,
		leafKey LeafKey, addr ServerAddr, syncDirection SyncDirection,
		syncStatus ProofSyncStatus,
		bumpSyncAttemptCounter bool) (int64, error)

	// QueryFederationProofSyncLog queries the federation proof sync log and
	// returns the log entries which correspond to the given universe proof
	// leaf.
	QueryFederationProofSyncLog(ctx context.Context, uniID Identifier,
		leafKey LeafKey, syncDirection SyncDirection,
		syncStatus ProofSyncStatus) ([]*ProofSyncLogEntry, error)

	// FetchPendingProofsSyncLog queries the federation proof sync log and
	// returns all log entries with sync status pending.
	FetchPendingProofsSyncLog(ctx context.Context,
		syncDirection *SyncDirection) ([]*ProofSyncLogEntry, error)

	// DeleteProofsSyncLogEntries deletes proof sync log entries.
	DeleteProofsSyncLogEntries(ctx context.Context,
		servers ...ServerAddr) error
}

// FederationDB is used for CRUD operations related to federation logs and
// configuration.
type FederationDB interface {
	FederationLog
	FederationProofSyncLog
	FederationSyncConfigDB
}

// SyncStatsSort is an enum used to specify the sort order of the returned sync
// stats.
type SyncStatsSort uint8

const (
	// SortByNone is a sentinel value that indicates that no sorting should
	// be done.
	SortByNone SyncStatsSort = iota

	// SortByAssetName sorts the returned stats by the asset name.
	SortByAssetName

	// SortByAssetType sorts the returned stats by the asset type.
	SortByAssetType

	// SortByAssetID sorts the returned stats by the asset ID.
	SortByAssetID

	// SortByTotalSyncs sorts the returned stats by the total number of
	// syncs.
	SortByTotalSyncs

	// SortByTotalProofs sorts the returned stats by the total number of
	// proofs.
	SortByTotalProofs

	// SortByGenesisHeight sorts the returned stats by the genesis height.
	SortByGenesisHeight

	// SortByTotalSupply sorts the returned stats by the total supply.
	SortByTotalSupply
)

// SortDirection is an enum used to specify the sort direction of the returned.
type SortDirection uint8

const (
	// SortAscending is a sentinel value that indicates that the sort
	// should be in ascending order.
	SortAscending SortDirection = iota

	// SortDescending is a sentinel value that indicates that the sort
	// should be in descending order.
	SortDescending
)

// SyncStatsQuery packages a set of query parameters to retrieve stats related
// to the sync activity of a given Universe. Any of the filters can be
// specified, however only a single sort by value should be specified. The
// offset and limit fields can be used to implement pagination.
type SyncStatsQuery struct {
	// AssetNameFilter can be used to filter for stats for a given asset name.
	AssetNameFilter string

	// AssetIDFilter can be used to filter for stats for a given asset ID.
	AssetIDFilter asset.ID

	// AssetTypeFilter can be used to filter for stats for a given asset
	// type.
	AssetTypeFilter *asset.Type

	// SortBy is the sort order to use when returning the stats.
	SortBy SyncStatsSort

	// SortDirection is the sort direction to use when returning the stats.
	SortDirection SortDirection

	// Offset is the offset to use when returning the stats. This can be
	// used to paginate the response.
	Offset int

	// Limit is the maximum number of stats to return. This can be used to
	// paginate the response.
	Limit int
}

// AssetSyncSnapshot is a snapshot of the sync activity for a given asset.
type AssetSyncSnapshot struct {
	// AssetID is the ID of the asset.
	AssetID asset.ID

	// GroupKey is the optional group key of the asset.
	GroupKey *btcec.PublicKey

	// GroupSupply is the total supply of the whole asset group. This is
	// only set for grouped assets.
	GroupSupply uint64

	// GenesisPoint is the first previous output that created the asset.
	GenesisPoint wire.OutPoint

	// AssetName is the name of the asset.
	AssetName string

	// AssetType is the type of the asset.
	AssetType asset.Type

	// TotalSupply is the total supply of the asset.
	TotalSupply uint64

	// GenesisHeight is the height of the block that the asset was created
	// in.
	GenesisHeight uint32

	// TotalSyncs is the total number of syncs that have been performed for
	// the target asset.
	TotalSyncs uint64

	// TotalProofs is the total number of proofs that have been inserted
	// for the asset.
	TotalProofs uint64

	// AnchorPoint is the outpoint of the transaction that created the
	// asset.
	AnchorPoint wire.OutPoint

	// TODO(roasbeef): add last sync?
}

// AssetSyncStats is the response to a SyncStatsQuery request. It contains the
// original query, and the set of sync stats generated by the query.
type AssetSyncStats struct {
	// Query is the original query that was used to generate the stats.
	Query SyncStatsQuery

	// SyncStats is the set of sync stats generated by the query.
	SyncStats []AssetSyncSnapshot
}

// AggregateStats is a set of aggregate stats for a given Universe.
type AggregateStats struct {
	// NumTotalAssets is the total number of assets in the Universe.
	NumTotalAssets uint64

	// NumTotalGroups is the total number of groups in the Universe.
	NumTotalGroups uint64

	// NumTotalSyncs is the total number of syncs that have been performed
	// in the Universe.
	NumTotalSyncs uint64

	// NumTotalProofs is the total number of proofs that have been inserted
	// into the Universe.
	NumTotalProofs uint64
}

// GroupedStatsQuery packages a set of query parameters to retrieve event based
// stats.
type GroupedStatsQuery struct {
	// StartTime is the start time to use when querying for stats.
	StartTime time.Time

	// EndTime is the end time to use when querying for stats.
	EndTime time.Time
}

// GroupedStats is a type for aggregated stats grouped by day.
type GroupedStats struct {
	AggregateStats

	// Date is the string formatted date (YYYY-MM-DD) that the stats are
	// for.
	Date string
}

// Telemetry it a type used by the Universe syncer and base universe to export
// telemetry information about the sync process. This logs events of new
// proofs, and also sync events for entire asset trees.
//
// TODO(roasbeef): prob want to add a wrapper around multiple instances, eg: to
// the main db and also prometheus or w/e
type Telemetry interface {
	// AggregateSyncStats returns stats aggregated over all assets within
	// the Universe.
	AggregateSyncStats(ctx context.Context) (AggregateStats, error)

	// LogSyncEvent logs a sync event for the target universe.
	//
	// TODO(roasbeef): log based on a given leaf, or entire tree?
	//  * rn main entrypoint is in RPC server, which is leaf based
	//  * alternatively, can log when a set of leaves are queried, as
	//    that's still a sync event, but can be a noop
	LogSyncEvent(ctx context.Context, uniID Identifier,
		key LeafKey) error

	// LogSyncEvents logs sync events for the target universe.
	LogSyncEvents(ctx context.Context, uniIDs ...Identifier) error

	// LogNewProofEvent logs a new proof insertion event for the target
	// universe.
	LogNewProofEvent(ctx context.Context, uniID Identifier,
		key LeafKey) error

	// LogNewProofEvents logs new proof insertion events for the target
	// universe.
	LogNewProofEvents(ctx context.Context, uniIDs ...Identifier) error

	// QuerySyncStats attempts to query the stats for the target universe.
	// For a given asset ID, tag, or type, the set of universe stats is
	// returned which lists information such as the total number of syncs
	// and known proofs for a given Universe server instance.
	QuerySyncStats(ctx context.Context,
		q SyncStatsQuery) (*AssetSyncStats, error)

	// QueryAssetStatsPerDay returns the stats for all assets grouped by
	// day.
	QueryAssetStatsPerDay(ctx context.Context,
		q GroupedStatsQuery) ([]*GroupedStats, error)
}
