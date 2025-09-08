package supplycommit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	// ErrNoBlockInfo is returned when a root commitment is expected to have
	// block information, but it is missing.
	ErrNoBlockInfo = fmt.Errorf("no block info available")
)

const (
	// DefaultCommitConfTarget is the default confirmation target used when
	// crafting the commitment transaction. This is used in fee estimation.
	DefaultCommitConfTarget = 6
)

// SupplySubTree is an enum that represents the different types of supply sub
// trees within the main supply tree. The sub trees are used to track how the
// supply shifts in response to: mints, burns, and ignores.
type SupplySubTree uint8

const (

	// MintTreeType is the sub tree that tracks mints.
	MintTreeType SupplySubTree = iota

	// BurnTreeType is the sub tree that tracks burns.
	BurnTreeType

	// IgnoreTreeType is the sub tree that tracks ignores.
	IgnoreTreeType
)

// String returns the string representation of the supply sub tree.
func (s SupplySubTree) String() string {
	switch s {
	case MintTreeType:
		return "mint_supply"
	case BurnTreeType:
		return "burn"
	case IgnoreTreeType:
		return "ignore"
	default:
		return "unknown"
	}
}

// AllSupplySubTrees contains all possible valid SupplySubTree values.
var AllSupplySubTrees = []SupplySubTree{
	MintTreeType,
	BurnTreeType,
	IgnoreTreeType,
}

// UniverseKey is the key used to identify the universe in the supply tree. This
// is scoped to a root supply tree for a given asset specifier.
func (s SupplySubTree) UniverseKey() [32]byte {
	treeName := s.String()
	treeKey := sha256.Sum256([]byte(treeName))

	return treeKey
}

// SupplyTrees is a map of the different supply sub trees. The keys are the sub
// trees, and the values are the actual trees.
type SupplyTrees map[SupplySubTree]mssmt.Tree

// FetchOrCreate fetches the sub tree for the given asset spec. If the sub tree
// doesn't exist, it will be created and returned.
func (s SupplyTrees) FetchOrCreate(treeType SupplySubTree) mssmt.Tree {
	tree, ok := s[treeType]
	if ok {
		return tree
	}

	// If the tree doesn't exist, we'll create it.
	tree = mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	s[treeType] = tree

	return tree
}

// SupplyLeaves is the response type for fetching the supply leaves for a given
// asset specifier.
type SupplyLeaves struct {
	// IssuanceLeafEntries is a slice of issuance leaves.
	IssuanceLeafEntries []NewMintEvent

	// BurnLeafEntries is a slice of burn leaves.
	BurnLeafEntries []NewBurnEvent

	// IgnoreLeafEntries is a slice of ignore leaves.
	IgnoreLeafEntries []NewIgnoreEvent
}

// AllUpdates returns a slice of all supply update events contained within
// the SupplyLeaves instance. This includes mints, burns, and ignores.
func (s SupplyLeaves) AllUpdates() []SupplyUpdateEvent {
	mint := func(e NewMintEvent) SupplyUpdateEvent {
		return &e
	}
	burn := func(e NewBurnEvent) SupplyUpdateEvent {
		return &e
	}
	ignore := func(e NewIgnoreEvent) SupplyUpdateEvent {
		return &e
	}
	allUpdates := make(
		[]SupplyUpdateEvent, 0, len(s.IssuanceLeafEntries)+
			len(s.BurnLeafEntries)+len(s.IgnoreLeafEntries),
	)
	allUpdates = append(allUpdates, fn.Map(s.IssuanceLeafEntries, mint)...)
	allUpdates = append(allUpdates, fn.Map(s.BurnLeafEntries, burn)...)
	allUpdates = append(allUpdates, fn.Map(s.IgnoreLeafEntries, ignore)...)

	return allUpdates
}

// ValidateBlockHeights ensures that all supply leaves have a non-zero block
// height.
func (s SupplyLeaves) ValidateBlockHeights() error {
	// Block height must be non-zero for all leaves.
	for _, leaf := range s.IssuanceLeafEntries {
		if leaf.BlockHeight() == 0 {
			return fmt.Errorf("mint leaf has zero block height")
		}
	}

	for _, leaf := range s.BurnLeafEntries {
		if leaf.BlockHeight() == 0 {
			return fmt.Errorf("burn leaf has zero block height")
		}
	}

	for _, leaf := range s.IgnoreLeafEntries {
		if leaf.BlockHeight() == 0 {
			return fmt.Errorf("ignore leaf has zero block height")
		}
	}

	return nil
}

// NewSupplyLeavesFromEvents creates a SupplyLeaves instance from a slice of
// SupplyUpdateEvent instances.
func NewSupplyLeavesFromEvents(events []SupplyUpdateEvent) (SupplyLeaves,
	error) {

	var leaves SupplyLeaves
	for idx := range events {
		event := events[idx]

		switch e := event.(type) {
		case *NewMintEvent:
			leaves.IssuanceLeafEntries = append(
				leaves.IssuanceLeafEntries, *e,
			)

		case *NewBurnEvent:
			leaves.BurnLeafEntries = append(
				leaves.BurnLeafEntries, *e,
			)

		case *NewIgnoreEvent:
			leaves.IgnoreLeafEntries = append(
				leaves.IgnoreLeafEntries, *e,
			)

		default:
			return leaves, fmt.Errorf("unknown event type: %T", e)
		}
	}

	return leaves, nil
}

// AssetLookup is an interface that allows us to query for asset
// information, such as asset groups and asset metadata.
type AssetLookup interface {
	// QueryAssetGroupByID attempts to fetch an asset group by its asset ID.
	// If the asset group cannot be found, then ErrAssetGroupUnknown is
	// returned.
	QueryAssetGroupByID(ctx context.Context,
		assetID asset.ID) (*asset.AssetGroup, error)

	// QueryAssetGroupByGroupKey fetches the asset group with a matching
	// tweaked key, including the genesis information used to create the
	// group.
	QueryAssetGroupByGroupKey(ctx context.Context,
		groupKey *btcec.PublicKey) (*asset.AssetGroup, error)

	// FetchAssetMetaForAsset attempts to fetch an asset meta based on an
	// asset ID.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID asset.ID) (*proof.MetaReveal, error)

	// FetchInternalKeyLocator attempts to fetch the key locator information
	// for the given raw internal key. If the key cannot be found, then
	// ErrInternalKeyNotFound is returned.
	FetchInternalKeyLocator(ctx context.Context,
		rawKey *btcec.PublicKey) (keychain.KeyLocator, error)
}

// FetchLatestAssetMetadata returns the latest asset metadata for the
// given asset specifier.
func FetchLatestAssetMetadata(ctx context.Context, lookup AssetLookup,
	assetSpec asset.Specifier) (proof.MetaReveal, error) {

	var zero proof.MetaReveal

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return zero, err
	}

	// TODO(ffranr): This currently retrieves asset metadata using the
	//  genesis ID. Update it to retrieve by the latest asset ID instead,
	//  which will provide access to the most up-to-date canonical universe
	//  list.
	assetGroup, err := lookup.QueryAssetGroupByGroupKey(ctx, groupKey)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch asset group "+
			"by group key: %w", err)
	}

	// Retrieve the asset metadata for the asset group. This will
	// include the delegation key and universe commitment flag.
	metaReveal, err := lookup.FetchAssetMetaForAsset(
		ctx, assetGroup.Genesis.ID(),
	)
	if err != nil {
		return zero, fmt.Errorf("faild to fetch asset meta: %w", err)
	}

	return *metaReveal, nil
}

// SupplyTreeView is an interface that allows the state machine to obtain an up
// to date snapshot of the root supply tree, as the sub trees (ignore, burn,
// mint) committed in the main supply tree.
type SupplyTreeView interface {
	// FetchSubTree returns the sub tree for the given asset spec. This
	// instance returned should be a copy, as mutations make take place in
	// the tree.
	FetchSubTree(ctx context.Context, assetSpec asset.Specifier,
		treeType SupplySubTree) lfn.Result[mssmt.Tree]

	// FetchSubTrees returns all the sub trees for the given asset spec.
	FetchSubTrees(ctx context.Context,
		assetSpec asset.Specifier) lfn.Result[SupplyTrees]

	// FetchRootSupplyTree returns the root supply tree which contains a
	// commitment to each of the sub trees.
	FetchRootSupplyTree(ctx context.Context,
		assetSpec asset.Specifier) lfn.Result[mssmt.Tree]

	// FetchSupplyLeavesByHeight returns the set of supply leaves for the
	// given asset specifier within the specified height range.
	FetchSupplyLeavesByHeight(ctx context.Context,
		assetSpec asset.Specifier, startHeight,
		endHeight uint32) lfn.Result[SupplyLeaves]
}

// PreCommitment is a struct that represents a pre-commitment to an asset
// commitment. A pre-commitment is an extra transaction that exists in the same
// on-chain transaction as a new issuance event.
type PreCommitment struct {
	// BlockHeight is the block height of the transaction that contains the
	// pre-commitment.
	BlockHeight uint32

	// MintingTxn is the minting transaction itself that created the pre
	// commitment.
	MintingTxn *wire.MsgTx

	// OutIdx specifies the index of the pre-commitment output within the
	// batch mint anchor transaction.
	OutIdx uint32

	// InternalKey is the Taproot internal public key associated with the
	// pre-commitment output.
	InternalKey keychain.KeyDescriptor

	// GroupPubKey is the asset group public key associated with this
	// pre-commitment output.
	GroupPubKey btcec.PublicKey
}

// TxIn returns the transaction input that corresponds to the pre-commitment.
func (p *PreCommitment) TxIn() *wire.TxIn {
	return &wire.TxIn{
		PreviousOutPoint: p.OutPoint(),
	}
}

// OutPoint returns the outpoint that corresponds to the pre-commitment output.
// This is the output that is spent by the supply commitment anchoring
// transaction.
func (p *PreCommitment) OutPoint() wire.OutPoint {
	return wire.OutPoint{
		Hash:  p.MintingTxn.TxHash(),
		Index: p.OutIdx,
	}
}

// PreCommits is a slice of pre-commitments.
type PreCommits = []PreCommitment

// CommitmentBlock captures the finalized on-chain state of a supply commitment
// transaction after it has been mined. It records block-level metadata and the
// actual fee paid to anchor the commitment.
type CommitmentBlock struct {
	// Height is the block height of the block that contains the
	// commitment.
	Height uint32

	// Hash is the hash of the block that contains the commitment.
	Hash chainhash.Hash

	// TxIndex is the index of the supply commitment transaction within
	// the block.
	TxIndex uint32

	// BlockHeader is the block header of the block that contains the
	// commitment.
	BlockHeader *wire.BlockHeader

	// MerkleProof is the merkle proof that proves that the supply
	// commitment transaction is included in the block.
	MerkleProof *proof.TxMerkleProof

	// ChainFees is the amount in sats paid in on-chain fees for the
	// supply commitment transaction.
	ChainFees int64
}

// RootCommitment is the root commitment that contains the commitment to the the
// sub-supply trees for a given asset.
type RootCommitment struct {
	// Txn is the transaction that created the root commitment.
	Txn *wire.MsgTx

	// TxOutIdx is the index of the output in the transaction where the
	// commitment resides.
	TxOutIdx uint32

	// InternalKey is the internal key used to create the commitment output.
	InternalKey keychain.KeyDescriptor

	// Output key is the taproot output key used to create the commitment
	// output.
	OutputKey *btcec.PublicKey

	// SupplyRoot is the root of the supply tree that contains the set of
	// sub-commitments. The sum value of this tree is the outstanding supply
	// value.
	SupplyRoot *mssmt.BranchNode

	// CommitmentBlock is the block that contains the commitment to the
	// asset supply. This may be None if the commitment has not yet
	// been mined.
	CommitmentBlock fn.Option[CommitmentBlock]

	// SpentCommitment is the outpoint of the previous root commitment that
	// this root commitment is spending. This will be None if this is the
	// first root commitment for the asset.
	SpentCommitment fn.Option[wire.OutPoint]
}

// TxIn returns the transaction input that corresponds to the root commitment.
// This is used to spend the old commitment output, and create a new one.
func (r *RootCommitment) TxIn() *wire.TxIn {
	return &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  r.Txn.TxHash(),
			Index: r.TxOutIdx,
		},
	}
}

// TxOut returns the transaction output that corresponds to the root commitment.
// This is used to create a new commitment output.
//
// TODO(roasbeef): expand, add support for tapscript as well
func (r *RootCommitment) TxOut() (*wire.TxOut, error) {
	txOut, _, err := RootCommitTxOut(
		r.InternalKey.PubKey, r.OutputKey, r.SupplyRoot.NodeHash(),
	)

	return txOut, err
}

// CommitPoint returns the outpoint that corresponds to the root commitment.
func (r *RootCommitment) CommitPoint() wire.OutPoint {
	return wire.OutPoint{
		Hash:  r.Txn.TxHash(),
		Index: r.TxOutIdx,
	}
}

// computeSupplyCommitTapscriptRoot creates the tapscript root hash for a supply
// commitment with the given supply root hash.
func computeSupplyCommitTapscriptRoot(supplyRootHash mssmt.NodeHash,
) ([]byte, error) {

	// Create a non-spendable script leaf that commits to the supply root.
	tapLeaf, err := asset.NewNonSpendableScriptLeaf(
		asset.PedersenVersion, supplyRootHash[:],
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create leaf: %w", err)
	}

	tapscriptTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	rootHash := tapscriptTree.RootNode.TapHash()
	return rootHash[:], nil
}

// TapscriptRoot returns the tapscript root hash that commits to the supply
// root. This is tweaked with the internal key to derive the output key.
func (r *RootCommitment) TapscriptRoot() ([]byte, error) {
	supplyRootHash := r.SupplyRoot.NodeHash()
	return computeSupplyCommitTapscriptRoot(supplyRootHash)
}

// VerifyChainAnchor checks that the on-chain information is correct.
func (r *RootCommitment) VerifyChainAnchor(merkleVerifier proof.MerkleVerifier,
	headerVerifier proof.HeaderVerifier) error {

	block, err := r.CommitmentBlock.UnwrapOrErr(ErrNoBlockInfo)
	if err != nil {
		return fmt.Errorf("unable to verify root commitment: %w", err)
	}

	if block.MerkleProof == nil {
		return fmt.Errorf("merkle proof is missing")
	}

	if block.BlockHeader == nil {
		return fmt.Errorf("block header is missing")
	}

	if block.Hash != block.BlockHeader.BlockHash() {
		return fmt.Errorf("block hash %v does not match block header "+
			"hash %v", block.Hash, block.BlockHeader.BlockHash())
	}

	if r.Txn == nil {
		return fmt.Errorf("root commitment transaction is missing")
	}

	if r.SupplyRoot == nil {
		return fmt.Errorf("supply root is missing")
	}

	err = fn.MapOptionZ(
		r.SpentCommitment, func(prevOut wire.OutPoint) error {
			if !proof.TxSpendsPrevOut(r.Txn, &prevOut) {
				return fmt.Errorf("commitment TX doesn't " +
					"spend previous commitment outpoint")
			}

			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("unable to verify spent commitment: %w", err)
	}

	err = merkleVerifier(
		r.Txn, block.MerkleProof, block.BlockHeader.MerkleRoot,
	)
	if err != nil {
		return fmt.Errorf("unable to verify merkle proof: %w", err)
	}

	err = headerVerifier(*block.BlockHeader, block.Height)
	if err != nil {
		return fmt.Errorf("unable to verify block header: %w", err)
	}

	if r.TxOutIdx >= uint32(len(r.Txn.TxOut)) {
		return fmt.Errorf("tx out index %d is out of bounds for "+
			"transaction with %d outputs", r.TxOutIdx,
			len(r.Txn.TxOut))
	}

	txOut := r.Txn.TxOut[r.TxOutIdx]
	expectedOut, _, err := RootCommitTxOut(
		r.InternalKey.PubKey, nil, r.SupplyRoot.NodeHash(),
	)
	if err != nil {
		return fmt.Errorf("unable to create expected output: %w", err)
	}

	if txOut.Value != expectedOut.Value {
		return fmt.Errorf("tx out value %d does not match expected "+
			"value %d", txOut.Value, expectedOut.Value)
	}

	if !bytes.Equal(txOut.PkScript, expectedOut.PkScript) {
		return fmt.Errorf("tx out pk script %x does not match "+
			"expected pk script %x", txOut.PkScript,
			expectedOut.PkScript)
	}

	// Everything that we can check just from the static information
	// provided checks out.
	return nil
}

// RootCommitTxOut returns the transaction output that corresponds to the root
// commitment. This is used to create a new commitment output.
func RootCommitTxOut(internalKey *btcec.PublicKey,
	tapOutKey *btcec.PublicKey, supplyRootHash mssmt.NodeHash) (*wire.TxOut,
	*btcec.PublicKey, error) {

	var taprootOutputKey *btcec.PublicKey
	if tapOutKey == nil {
		// We'll create a new unspendable output that contains a
		// commitment to the root.
		rootHash, err := computeSupplyCommitTapscriptRoot(
			supplyRootHash,
		)
		if err != nil {
			return nil, nil, err
		}

		taprootOutputKey = txscript.ComputeTaprootOutputKey(
			internalKey, rootHash,
		)
	} else {
		taprootOutputKey = tapOutKey
	}

	pkScript, err := txscript.PayToTaprootScript(taprootOutputKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create pk script: %w",
			err)
	}

	txOut := wire.TxOut{
		Value:    int64(tapsend.DummyAmtSats),
		PkScript: pkScript,
	}

	return &txOut, taprootOutputKey, nil
}

// ChainProof stores the information needed to prove that a given supply commit
// tx has properly been mined in the Bitcoin blockchain.
type ChainProof struct {
	// Header is the block header of the block that contains the supply
	// commitment transaction.
	Header wire.BlockHeader

	// BlockHeight is the block height of the block that contains the supply
	// commitment transaction.
	BlockHeight uint32

	// MerkleProof is the merkle proof that proves that the supply
	// commitment transaction is included in the block.
	MerkleProof proof.TxMerkleProof

	// TxIndex is the index of the supply commitment transaction in the
	// block.
	TxIndex uint32
}

// SupplyStateTransition represents a new pending supply commitment.
type SupplyStateTransition struct {
	// OldCommitment is the old commitment that is being spent. This is used
	// to create the new commitment output (by spending this input).
	OldCommitment lfn.Option[RootCommitment]

	// UnspentPreCommits is the set of unspent pre-commitments that are
	// unspent. These will also be used as input into the new commit txn.
	UnspentPreCommits []PreCommitment

	// PendingUpdates is the set of new updates that are being added to the
	// commitment. These are the new mints, burns, or ignores.
	PendingUpdates []SupplyUpdateEvent

	// NewCommitment is the new commitment that is being created.
	//
	// TODO(roasbeef): opt? may not exist before pending updates added
	NewCommitment RootCommitment

	// ChainProof is the chain proof that proves that the new commitment has
	// been mined in the Bitcoin blockchain. If None, then the commitment
	// has not yet been mined.
	ChainProof lfn.Option[ChainProof]
}

// RootCommitResp is the response type for the root commitment. It captures the
// fact that there may not be a root commitment yet for a given asset.
type RootCommitResp = lfn.Result[lfn.Option[RootCommitment]]

// CommitmentTracker is used to track the state of the pre-commitment and
// commitment outputs that are currently confirmed on-chain for a given asset
// specifier.
type CommitmentTracker interface {
	// UnspentPrecommits returns the set of unspent pre-commitments for a
	// given asset spec. The asset spec will only specify a group key, and
	// not also an asset ID.
	UnspentPrecommits(ctx context.Context,
		assetSpec asset.Specifier) lfn.Result[PreCommits]

	// SupplyCommit returns the root commitment for a given asset spec. From
	// the PoV of the chain, this is a singleton instance.
	SupplyCommit(ctx context.Context,
		assetSpec asset.Specifier) RootCommitResp
}

// Wallet the main wallet interface used to managed PSBT packets, and
// import taproot output keys into the wallet.
type Wallet interface {
	// FundPsbt attaches enough inputs to the target PSBT packet for it to
	// be valid.
	FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs uint32,
		feeRate chainfee.SatPerKWeight,
		changeIdx int32) (*tapsend.FundedPsbt, error)

	// SignPsbt fully signs the target PSBT packet.
	SignPsbt(context.Context, *psbt.Packet) (*psbt.Packet, error)

	// ImportTaprootOutput imports a new taproot output key into the wallet.
	ImportTaprootOutput(context.Context, *btcec.PublicKey) (btcutil.Address,
		error)

	// UnlockInput unlocks the set of target inputs after a batch or send
	// transaction is abandoned.
	UnlockInput(context.Context, wire.OutPoint) error
}

// KeyRing is an interface that allows the state machine to derive new keys
// within the keychain.
type KeyRing interface {
	// DeriveNextTaprootAssetKey attempts to derive the *next* key within
	// the Taproot Asset key family.
	DeriveNextTaprootAssetKey(ctx context.Context) (keychain.KeyDescriptor,
		error)
}

// IgnoreCheckerCache is an interface that allows the state machine to
// invalidate the ignore checker cache when a new supply commitment is created.
type IgnoreCheckerCache interface {
	// InvalidateCache is used to invalidate the ignore checker cache when
	// a new supply commitment is created.
	InvalidateCache(btcec.PublicKey)
}

// StateMachineStore is an interface that allows the state machine to persist
// its state across restarts. This is used to track the state of the state
// machine, and the set of pending updates that are being applied to the
// commitment.
type StateMachineStore interface {
	// InsertPendingUpdate attempts to insert a new pending update into the
	// update log of the target supply commit state machine. If the state
	// machine doesn't yet exist, then it will be created at the
	// UpdatesPendingState. If the state machine exists, but is in a
	// different state then UpdatesPendingState, then an error will be
	// returned.
	//
	// This method will also create a new pending SupplyStateTransition.
	InsertPendingUpdate(context.Context, asset.Specifier,
		SupplyUpdateEvent) error

	// InsertSignedCommitTx will associated a new signed commitment
	// anchor transaction with the current active supply commitment state
	// transition. This'll update the existing funded txn with a signed
	// copy. Finally the state of the  supply commit state transition will
	// transition to CommitBroadcastState.
	InsertSignedCommitTx(context.Context, asset.Specifier,
		SupplyCommitTxn) error

	// CommitState is used to commit the state of the state machine to then
	// disk.
	CommitState(context.Context, asset.Specifier, State) error

	// FetchState attempts to fetch the state of the state machine for the
	// target asset specifier. If the state machine doesn't exist, then an
	// error will be returned.
	//
	// TODO(roasbeef): also have it return the next event if exists?
	FetchState(context.Context, asset.Specifier) (State,
		lfn.Option[SupplyStateTransition], error)

	// ApplyStateTransition is used to apply a new state transition to the
	// target state machine. Once the transition has been applied, the state
	// machine will transition back to the default state.
	//
	// To apply a state transition, the following operations must be carried
	// out:
	//   * Insert the set of PendingUpdates into their respective sub supply
	//   trees.
	//   * Insert the new supply try leaves into the universe supply root.
	//   * Update the current supply commitment with the target chain
	//     transaction (output index, etc).
	//   * Update the block height and merkle proof information.
	//   * Update the internal key and output key of the commitment
	//     transaction.
	//   * Update the target state machine to the Default state.
	//   * Mark the target state transition as finalized.
	ApplyStateTransition(context.Context, asset.Specifier,
		SupplyStateTransition) error

	// FreezePendingTransition marks the current pending transition for a
	// group key as frozen.
	FreezePendingTransition(context.Context, asset.Specifier) error

	// BindDanglingUpdatesToTransition finds any supply update events for
	// the given asset specifier that are not yet associated with a
	// transition, creates a new transition for them, and links them. It
	// returns the list of events that were bound. If no dangling events are
	// found, it returns an empty slice and no error.
	BindDanglingUpdatesToTransition(context.Context,
		asset.Specifier) ([]SupplyUpdateEvent, error)
}

// SupplySyncer is an interface that allows the state machine to insert
// supply commitments into the remote universe server.
type SupplySyncer interface {
	// PushSupplyCommitment pushes a supply commitment to the remote
	// universe server. This function should block until the sync insertion
	// is complete.
	//
	// Returns a map of per-server errors keyed by server host string and
	// an internal error. If all pushes succeed, both return values are nil.
	// If some pushes fail, the map contains only the failed servers and
	// their corresponding errors. If there's an internal/system error that
	// prevents the operation from proceeding, it's returned as the second
	// value.
	PushSupplyCommitment(ctx context.Context, assetSpec asset.Specifier,
		commitment RootCommitment, updateLeaves SupplyLeaves,
		chainProof ChainProof,
		canonicalUniverses []url.URL) (map[string]error, error)
}

// Environment is a set of dependencies that a state machine may need to carry
// out the logic for a given state transition. All fields are to be considered
// immutable, and will be fixed for the lifetime of the state machine.
type Environment struct {
	// AssetSpec is the asset specifier that is used to identify the asset
	// that we're maintaining a supply commit for.
	AssetSpec asset.Specifier

	// TreeView is the interface that allows the state machine to obtain an
	// up to date snapshot of the root supply tree, and the relevant set of
	// subtrees.
	TreeView SupplyTreeView

	// Commitments is used to track the state of the pre-commitment and
	// commitment outputs that are currently confirmed on-chain.
	Commitments CommitmentTracker

	// Wallet is the main wallet interface used to managed PSBT packets.
	Wallet Wallet

	// AssetLookup is used to look up asset information such as asset groups
	// and asset metadata.
	AssetLookup AssetLookup

	// KeyRing is the main key ring interface used to manage keys.
	KeyRing KeyRing

	// Chain is our access to the current main chain.
	//
	// TODO(roasbeef): can make a slimmer version of
	Chain tapgarden.ChainBridge

	// SupplySyncer is used to insert supply commitments into the remote
	// universe server.
	SupplySyncer SupplySyncer

	// StateLog is the main state log that is used to track the state of the
	// state machine. This is used to persist the state of the state machine
	// across restarts.
	StateLog StateMachineStore

	// CommitConfTarget is the confirmation target used when crafting the
	// commitment transaction.
	CommitConfTarget uint32

	// ChainParams is the chain parameters for the chain that we're
	// operating on.
	ChainParams chaincfg.Params

	// IgnoreCheckerCache is used to invalidate the ignore cache when a new
	// supply commitment is created.
	IgnoreCheckerCache IgnoreCheckerCache

	// Log is the prefixed logger for this supply commitment state machine.
	Log btclog.Logger
}

// SupplyCommitTxn encapsulates the details of the transaction that creates a
// new supply commitment on chain.
type SupplyCommitTxn struct {
	// Txn is the transaction that creates the supply commitment.
	Txn *wire.MsgTx

	// InternalKey is the internal key descriptor used for the commitment
	// output. This preserves the full key derivation information.
	InternalKey keychain.KeyDescriptor

	// OutputKey is the taproot output key used for the commitment output.
	OutputKey *btcec.PublicKey

	// OutputIndex is the index of the commitment output within the Txn.
	OutputIndex uint32
}

// Name returns the name of the environment. This is used to uniquely identify
// the environment of related state machines. For this state machine, the name
// is based on the channel ID.
func (e *Environment) Name() string {
	return fmt.Sprintf("universe_supply_commit(%v)", e.AssetSpec)
}

// Logger returns the logger for this environment. If a logger was provided in
// the environment configuration, it returns that logger. Otherwise, it returns
// the package-level logger with an asset-specific prefix.
func (e *Environment) Logger() btclog.Logger {
	if e.Log != nil {
		return e.Log
	}

	return NewAssetLogger(e.AssetSpec.String())
}
