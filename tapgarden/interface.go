package tapgarden

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
)

const (
	// IssuanceTxLabel defines the label assigned to an on-chain transaction
	// that represents a tapd asset issuance.
	IssuanceTxLabel = "tapd-asset-issuance"
)

// FundBatchResp is the response returned from the FundBatch method.
type FundBatchResp struct {
	// Batch is the batch that was funded.
	Batch *VerboseBatch
}

// Planter is responsible for batching a set of seedlings into a minting batch
// that will eventually be confirmed on chain.
type Planter interface {
	// QueueNewSeedling attempts to queue a new seedling request (the
	// intent for New asset creation or ongoing issuance) to the Planter.
	// A channel is returned where future updates will be sent over. If an
	// error is returned no issuance operation was possible.
	QueueNewSeedling(req *Seedling) (SeedlingUpdates, error)

	// ListBatches lists the set of batches submitted for minting, or the
	// details of a specific batch.
	ListBatches(params ListBatchesParams) ([]*VerboseBatch, error)

	// CancelSeedling attempts to cancel the creation of a new asset
	// identified by its name. If the seedling has already progressed to a
	// point where the genesis PSBT has been broadcasted, an error is
	// returned.
	CancelSeedling() error

	// FundBatch attempts to provide a genesis point for the current batch,
	// or create a new funded batch.
	FundBatch(params FundParams) (*FundBatchResp, error)

	// SealBatch attempts to seal the current batch, by providing or
	// deriving all witnesses necessary to create the final genesis TX.
	SealBatch(params SealParams) (*MintingBatch, error)

	// FinalizeBatch signals that the asset minter should finalize
	// the current batch, if one exists.
	FinalizeBatch(params FinalizeParams) (*MintingBatch, error)

	// CancelBatch signals that the asset minter should cancel the
	// current batch, if one exists.
	CancelBatch() (*btcec.PublicKey, error)

	// Start signals that the asset minter should being operations.
	Start() error

	// Stop signals that the asset minter should attempt a graceful
	// shutdown.
	Stop() error

	// EventPublisher is a subscription interface that allows callers to
	// subscribe to events that are relevant to the Planter.
	fn.EventPublisher[fn.Event, bool]
}

// BatchState an enum that represents the various stages of a minting batch.
type BatchState uint8

const (
	// BatchStatePending denotes that the batch is pending and may have
	// some assets allocated to it.
	BatchStatePending BatchState = 0

	// BatchStateFrozen denotes that a batch is frozen, and no new
	// seedlings can be added to it.
	BatchStateFrozen BatchState = 1

	// BatchStateCommitted denotes that a batch now has an unsigned genesis
	// PSBT packet and the set of seedlings have been made into sprouts
	// with all relevant fields populated.
	BatchStateCommitted BatchState = 2

	// BatchStateBroadcast denotes a batch now has a fully signed genesis
	// transaction and can be broadcast to the network.
	BatchStateBroadcast BatchState = 3

	// BatchStateConfirmed denotes that a batch has confirmed on chain, and
	// only needs a sufficient amount of confirmations before it can be
	// finalized.
	BatchStateConfirmed BatchState = 4

	// BatchStateFinalized is the final state for a batch. In this terminal
	// state the batch has been confirmed on chain, with all assets
	// created.
	BatchStateFinalized BatchState = 5

	// BatchStateSeedlingCancelled denotes that a batch has been cancelled,
	// and will not be passed to a caretaker.
	BatchStateSeedlingCancelled BatchState = 6

	// BatchStateSproutCancelled denotes that a batch has been cancelled
	// after being passed to a caretaker and sprouting.
	BatchStateSproutCancelled BatchState = 7
)

// String returns a human-readable string for the target batch state.
func (b BatchState) String() string {
	switch b {
	case BatchStatePending:
		return "BatchStatePending"

	case BatchStateFrozen:
		return "BatchStateFrozen"

	case BatchStateCommitted:
		return "BatchStateCommitted"

	case BatchStateBroadcast:
		return "BatchStateBroadcast"

	case BatchStateConfirmed:
		return "BatchStateConfirmed"

	case BatchStateFinalized:
		return "BatchStateFinalized"

	case BatchStateSeedlingCancelled:
		return "BatchStateSeedlingCancelled"

	case BatchStateSproutCancelled:
		return "BatchStateSproutCancelled"

	default:
		return fmt.Sprintf("UnknownState(%d)", b)
	}
}

// NewBatchState creates a BatchState from a uint8, returning an error if the
// input value does not map to a valid BatchState.
func NewBatchState(state uint8) (BatchState, error) {
	switch BatchState(state) {
	case BatchStatePending:
		return BatchStatePending, nil

	case BatchStateFrozen:
		return BatchStateFrozen, nil

	case BatchStateCommitted:
		return BatchStateCommitted, nil

	case BatchStateBroadcast:
		return BatchStateBroadcast, nil

	case BatchStateConfirmed:
		return BatchStateConfirmed, nil

	case BatchStateFinalized:
		return BatchStateFinalized, nil

	case BatchStateSeedlingCancelled:
		return BatchStateSeedlingCancelled, nil

	case BatchStateSproutCancelled:
		return BatchStateSproutCancelled, nil

	default:
		return BatchStateSproutCancelled,
			fmt.Errorf("unknown batch state: %v", state)
	}
}

// MintingStore is a log that stores information related to the set of pending
// minting batches. The ChainPlanter and ChainCaretaker use this log to record
// the process of seeding, planting, and finally maturing taproot assets that are
// a part of the batch.
type MintingStore interface {
	asset.TapscriptTreeManager

	// CommitMintingBatch commits a new minting batch to disk, identified
	// by its batch key.
	CommitMintingBatch(ctx context.Context, newBatch *MintingBatch) error

	// UpdateBatchState writes the new batch state to disk and, on
	// success, mirrors it into the in-memory batch. Either both writes
	// succeed and the in-memory state advances, or both stay at the
	// prior value. Callers must never mutate batch state by any other
	// route.
	UpdateBatchState(ctx context.Context, batch *MintingBatch,
		newState BatchState) error

	// AddSeedlingsToBatch adds a new seedling to an existing batch. Once
	// added this batch should remain in the BatchStatePending state.
	//
	// TODO(roasbeef): assumption that only one pending batch at a time?
	AddSeedlingsToBatch(ctx context.Context, batchKey *btcec.PublicKey,
		seedlings ...*Seedling) error

	// FetchAllBatches fetches all the batches on disk.
	FetchAllBatches(ctx context.Context) ([]*MintingBatch, error)

	// FetchNonFinalBatches fetches all non-finalized batches, meaning
	// batches that haven't yet fully confirmed on chain.
	FetchNonFinalBatches(ctx context.Context) ([]*MintingBatch, error)

	// FetchMintingBatch is used to fetch a single minting batch specified
	// by the batch key.
	FetchMintingBatch(ctx context.Context,
		batchKey *btcec.PublicKey) (*MintingBatch, error)

	// SealBatch seals a batch by assigning and persisting asset groups for
	// the seedlings it contains.
	SealBatch(ctx context.Context, batch *MintingBatch,
		newAssetGroups []*asset.AssetGroup) error

	// FetchSeedlingGroups is used to fetch the asset groups for seedlings
	// associated with a funded batch.
	FetchSeedlingGroups(ctx context.Context, genesisOutpoint wire.OutPoint,
		anchorOutputIndex uint32,
		seedlings []*Seedling) ([]*asset.AssetGroup, error)

	// AddSproutsToBatch adds a new set of sprouts to the batch, along with
	// a GenesisPacket, that once signed and broadcast with create the
	// set of assets on chain.
	//
	// NOTE: On success the batch transitions to BatchStateCommitted on
	// disk and the in-memory state of the supplied batch is advanced to
	// match. On failure neither moves.
	AddSproutsToBatch(ctx context.Context, batch *MintingBatch,
		genesisPacket *FundedMintAnchorPsbt,
		assets *commitment.TapCommitment) error

	// CommitSignedGenesisTx adds a fully signed genesis transaction to the
	// batch, along with the Taproot Asset script root, which is the
	// left/right sibling for the Taproot Asset tapscript commitment in the
	// transaction.
	//
	// NOTE: On success the batch transitions to BatchStateBroadcast on
	// disk and the in-memory state of the supplied batch is advanced to
	// match. On failure neither moves.
	CommitSignedGenesisTx(ctx context.Context, batch *MintingBatch,
		genesisTx *tapsend.FundedPsbt, anchorOutputIndex uint32,
		merkleRoot, tapTreeRoot, tapSibling []byte) error

	// MarkBatchConfirmed marks the batch as confirmed on chain. The passed
	// block location information determines where exactly in the chain the
	// batch was confirmed.
	//
	// NOTE: On success the batch transitions to BatchStateConfirmed on
	// disk and the in-memory state of the supplied batch is advanced to
	// match. On failure neither moves.
	MarkBatchConfirmed(ctx context.Context, batch *MintingBatch,
		blockHash *chainhash.Hash, blockHeight uint32,
		txIndex uint32, mintingProofs proof.AssetBlobs) error

	// FetchGroupByGenesis fetches the asset group created by the genesis
	// referenced by the given ID.
	FetchGroupByGenesis(ctx context.Context,
		genesisID int64) (*asset.AssetGroup, error)

	// FetchGroupByGroupKey fetches the asset group with a matching tweaked
	// key, including the genesis information used to create the group.
	FetchGroupByGroupKey(ctx context.Context,
		groupKey *btcec.PublicKey) (*asset.AssetGroup, error)

	// FetchScriptKeyByTweakedKey fetches the populated script key given the
	// tweaked script key.
	FetchScriptKeyByTweakedKey(ctx context.Context,
		tweakedKey *btcec.PublicKey) (*asset.TweakedScriptKey, error)

	// FetchAssetMeta fetches the meta reveal for an asset genesis.
	FetchAssetMeta(ctx context.Context, ID asset.ID) (*proof.MetaReveal,
		error)

	// CommitBatchFunding atomically persists the funded genesis
	// transaction and the optional tapscript sibling root hash for a
	// batch in a single transaction. Either both writes succeed or
	// neither persists, so a partial-failure cannot leave the batch
	// in an inconsistent on-disk state.
	//
	// NOTE: The tapscript tree referenced by rootHash (if non-nil)
	// must already be committed to disk.
	CommitBatchFunding(ctx context.Context, batchKey *btcec.PublicKey,
		rootHash *chainhash.Hash,
		genesisTx FundedMintAnchorPsbt) error

	// FetchDelegationKey fetches the delegation key for the given asset
	// group public key.
	FetchDelegationKey(ctx context.Context,
		groupKey btcec.PublicKey) (fn.Option[DelegationKey], error)
}

var (
	// ErrNoGenesis is returned when fetching an asset genesis fails.
	ErrNoGenesis = errors.New("unable to fetch genesis asset")

	// ErrBatchAlreadySealed is returned when a minting batch is already
	// sealed.
	ErrBatchAlreadySealed = errors.New("batch is already sealed")
)
