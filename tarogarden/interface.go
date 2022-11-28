package tarogarden

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// ErrDuplicateSeedlingName is an error type for use with asset seedling name
// unique constraint violations.
var ErrDuplicateSeedlingName = errors.New(
	"new asset seedling shares the same name as an existing asset",
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

	// CancelSeedling attempts to cancel the creation of a new asset
	// identified by its name. If the seedling has already progressed to a
	// point where the genesis PSBT has been broadcasted, an error is
	// returned.
	CancelSeedling() error

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

	default:
		return fmt.Sprintf("UnknownState(%v)", int(b))
	}
}

// MintingStore is a log that stores information related to the set of pending
// minting batches. The ChainPlanter and ChainCaretaker use this log to record
// the process of seeding, planting, and finally maturing taro assets that are
// a part of the batch.
type MintingStore interface {
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

	// FetchNonFinalBatches fetches all non-finalized batches, meaning
	// batches that haven't yet fully confirmed on chain.
	FetchNonFinalBatches(ctx context.Context) ([]*MintingBatch, error)

	// AddSproutsToBatch adds a new set of sprouts to the batch, along with
	// a GenesisPacket, that once signed and broadcast with create the
	// set of assets on chain.
	//
	// NOTE: The BatchState should transition to BatchStateCommitted upon a
	// successful call.
	AddSproutsToBatch(ctx context.Context, batchKey *btcec.PublicKey,
		genesisPacket *FundedPsbt, assets *commitment.TaroCommitment) error

	// CommitSignedGenesisTx adds a fully signed genesis transaction to the
	// batch, along with the taro script root, which is the left/right
	// sibling for the Taro tapscript commitment in the transaction.
	//
	// NOTE: The BatchState should transition to the BatchStateBroadcast
	// state upon a successful call.
	CommitSignedGenesisTx(ctx context.Context, batchKey *btcec.PublicKey,
		genesisTx *FundedPsbt, anchorOutputIndex uint32,
		taroScriptRoot []byte) error

	// MarkBatchConfirmed marks the batch as confirmed on chain. The passed
	// block location information determines where exactly in the chain the
	// batch was confirmed.
	//
	// NOTE: The BatchState should transition to the BatchStateConfirmed
	// state upon a successful call.
	MarkBatchConfirmed(ctx context.Context, batchKey *btcec.PublicKey,
		blockHash *chainhash.Hash, blockHeight uint32,
		txIndex uint32, mintingProofs proof.AssetBlobs) error
}

// ChainBridge is our bridge to the target chain. It's used to get confirmation
// notifications, the current height, publish transactions, and also estimate
// fees.
type ChainBridge interface {
	// RegisterConfirmationsNtfn registers an intent to be notified once
	// txid reaches numConfs confirmations.
	RegisterConfirmationsNtfn(ctx context.Context, txid *chainhash.Hash,
		pkScript []byte, numConfs, heightHint uint32,
		includeBlock bool) (*chainntnfs.ConfirmationEvent, chan error,
		error)

	// CurrentHeight return the current height of the main chain.
	CurrentHeight(context.Context) (uint32, error)

	// PublishTransaction attempts to publish a new transaction to the
	// network.
	PublishTransaction(context.Context, *wire.MsgTx) error

	// EstimateFee returns a fee estimate for the confirmation target.
	EstimateFee(ctx context.Context,
		confTarget uint32) (chainfee.SatPerKWeight, error)
}

// FundedPsbt represents a fully funded PSBT transaction.
type FundedPsbt struct {
	// Pkt is the PSBT packet itself.
	Pkt *psbt.Packet

	// ChangeOutputIndex denotes which output in the PSBT packet is the
	// change output. We use this to figure out which output will store our
	// Taro commitment (the non-change output).
	ChangeOutputIndex int32

	// ChainFees is the amount in sats paid in on-chain fees for this
	// transaction.
	ChainFees int64

	// LockedUTXOs is the set of UTXOs that were locked to create the PSBT
	// packet.
	LockedUTXOs []wire.OutPoint
}

// WalletAnchor is the main wallet interface used to managed PSBT packets, and
// import public keys into the wallet.
type WalletAnchor interface {
	// FundPsbt attaches enough inputs to the target PSBT packet for it to
	// be valid.
	FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs uint32,
		feeRate chainfee.SatPerKWeight) (FundedPsbt, error)

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
	// family (account in BIP43) specified. This method should return the
	// next external child within this branch.
	DeriveNextKey(context.Context,
		keychain.KeyFamily) (keychain.KeyDescriptor, error)

	// DeriveKey attempts to derive an arbitrary key specified by the
	// passed KeyLocator. This may be used in several recovery scenarios,
	// or when manually rotating something like our current default node
	// key.
	DeriveKey(context.Context,
		keychain.KeyLocator) (keychain.KeyDescriptor, error)
}
