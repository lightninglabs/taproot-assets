package tapgarden

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// Planter is responsible for batching a set of seedlings into a minting batch
// that will eventually be confirmed on chain.
type Planter interface {
	// QueueNewSeedling attempts to queue a new seedling request (the
	// intent for New asset creation or ongoing issuance) to the Planter.
	// A channel is returned where future updates will be sent over. If an
	// error is returned no issuance operation was possible.
	QueueNewSeedling(req *Seedling) (SeedlingUpdates, error)

	// TODO(roasbeef): list seeds, their pending state, etc, etc

	// TODO(roasbeef): notification methods also?

	// ListBatches lists the set of batches submitted for minting, or the
	// details of a specific batch.
	ListBatches(batchKey *btcec.PublicKey) ([]*MintingBatch, error)

	// CancelSeedling attempts to cancel the creation of a new asset
	// identified by its name. If the seedling has already progressed to a
	// point where the genesis PSBT has been broadcasted, an error is
	// returned.
	CancelSeedling() error

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

	// UpdateBatchState updates the batch state on disk identified by the
	// batch key.
	UpdateBatchState(ctx context.Context, batchKey *btcec.PublicKey,
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

	// AddSproutsToBatch adds a new set of sprouts to the batch, along with
	// a GenesisPacket, that once signed and broadcast with create the
	// set of assets on chain.
	//
	// NOTE: The BatchState should transition to BatchStateCommitted upon a
	// successful call.
	AddSproutsToBatch(ctx context.Context, batchKey *btcec.PublicKey,
		genesisPacket *tapsend.FundedPsbt,
		assets *commitment.TapCommitment) error

	// CommitSignedGenesisTx adds a fully signed genesis transaction to the
	// batch, along with the Taproot Asset script root, which is the
	// left/right sibling for the Taproot Asset tapscript commitment in the
	// transaction.
	//
	// NOTE: The BatchState should transition to the BatchStateBroadcast
	// state upon a successful call.
	CommitSignedGenesisTx(ctx context.Context, batchKey *btcec.PublicKey,
		genesisTx *tapsend.FundedPsbt, anchorOutputIndex uint32,
		merkleRoot, tapTreeRoot, tapSibling []byte) error

	// MarkBatchConfirmed marks the batch as confirmed on chain. The passed
	// block location information determines where exactly in the chain the
	// batch was confirmed.
	//
	// NOTE: The BatchState should transition to the BatchStateConfirmed
	// state upon a successful call.
	MarkBatchConfirmed(ctx context.Context, batchKey *btcec.PublicKey,
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

	// CommitBatchTapSibling adds a tapscript sibling to the batch,
	// specified by the sibling root hash.
	//
	// NOTE: The tapscript tree that defines the batch sibling must already
	// be committed to disk.
	CommitBatchTapSibling(ctx context.Context, batchKey *btcec.PublicKey,
		rootHash *chainhash.Hash) error
}

// ChainBridge is our bridge to the target chain. It's used to get confirmation
// notifications, the current height, publish transactions, and also estimate
// fees.
type ChainBridge interface {
	// RegisterConfirmationsNtfn registers an intent to be notified once
	// txid reaches numConfs confirmations.
	RegisterConfirmationsNtfn(ctx context.Context, txid *chainhash.Hash,
		pkScript []byte, numConfs, heightHint uint32,
		includeBlock bool,
		reOrgChan chan struct{}) (*chainntnfs.ConfirmationEvent,
		chan error, error)

	// RegisterBlockEpochNtfn registers an intent to be notified of each
	// new block connected to the main chain.
	RegisterBlockEpochNtfn(ctx context.Context) (chan int32, chan error,
		error)

	// GetBlock returns a chain block given its hash.
	GetBlock(context.Context, chainhash.Hash) (*wire.MsgBlock, error)

	// GetBlockHash returns the hash of the block in the best blockchain at
	// the given height.
	GetBlockHash(context.Context, int64) (chainhash.Hash, error)

	// VerifyBlock returns an error if a block (with given header and
	// height) is not present on-chain. It also checks to ensure that block
	// height corresponds to the given block header.
	VerifyBlock(ctx context.Context, header wire.BlockHeader,
		height uint32) error

	// CurrentHeight return the current height of the main chain.
	CurrentHeight(context.Context) (uint32, error)

	// PublishTransaction attempts to publish a new transaction to the
	// network.
	PublishTransaction(context.Context, *wire.MsgTx) error

	// EstimateFee returns a fee estimate for the confirmation target.
	EstimateFee(ctx context.Context,
		confTarget uint32) (chainfee.SatPerKWeight, error)
}

// WalletAnchor is the main wallet interface used to managed PSBT packets, and
// import public keys into the wallet.
type WalletAnchor interface {
	// FundPsbt attaches enough inputs to the target PSBT packet for it to
	// be valid.
	FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs uint32,
		feeRate chainfee.SatPerKWeight) (*tapsend.FundedPsbt, error)

	// SignAndFinalizePsbt fully signs and finalizes the target PSBT
	// packet.
	SignAndFinalizePsbt(context.Context, *psbt.Packet) (*psbt.Packet, error)

	// ImportTaprootOutput imports a new public key into the wallet, as a
	// P2TR output.
	ImportTaprootOutput(context.Context, *btcec.PublicKey) (btcutil.Address, error)

	// UnlockInput unlocks the set of target inputs after a batch is
	// abandoned.
	UnlockInput(context.Context) error

	// ListUnspentImportScripts lists all UTXOs of the imported Taproot
	// scripts.
	ListUnspentImportScripts(ctx context.Context) ([]*lnwallet.Utxo, error)

	// ListTransactions returns all known transactions of the backing lnd
	// node. It takes a start and end block height which can be used to
	// limit the block range that we query over. These values can be left
	// as zero to include all blocks. To include unconfirmed transactions
	// in the query, endHeight must be set to -1.
	ListTransactions(ctx context.Context, startHeight, endHeight int32,
		account string) ([]lndclient.Transaction, error)

	// SubscribeTransactions creates a uni-directional stream from the
	// server to the client in which any newly discovered transactions
	// relevant to the wallet are sent over.
	SubscribeTransactions(context.Context) (<-chan lndclient.Transaction,
		<-chan error, error)
}

// KeyRing is a mirror of the keychain.KeyRing interface, with the addition of
// a passed context which allows for cancellation of requests.
type KeyRing interface {
	// DeriveNextKey attempts to derive the *next* key within the key
	// family (account in BIP-0043) specified. This method should return the
	// next external child within this branch.
	DeriveNextKey(context.Context,
		keychain.KeyFamily) (keychain.KeyDescriptor, error)

	// DeriveKey attempts to derive an arbitrary key specified by the
	// passed KeyLocator. This may be used in several recovery scenarios,
	// or when manually rotating something like our current default node
	// key.
	DeriveKey(context.Context,
		keychain.KeyLocator) (keychain.KeyDescriptor, error)

	// IsLocalKey returns true if the key is under the control of the wallet
	// and can be derived by it.
	IsLocalKey(context.Context, keychain.KeyDescriptor) bool
}
