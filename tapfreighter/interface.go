package tapfreighter

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/keychain"
)

// CommitmentConstraints conveys the constraints on the type of Taproot asset
// commitments needed to satisfy a send request. Typically, for Bitcoin we just
// care about the amount. In the case of Taproot Asset, we also need to worry
// about the asset ID, and also the type of asset we need.
//
// NOTE: Only the GroupKey or the AssetID should be set.
type CommitmentConstraints struct {
	// GroupKey is the required group key. This is an optional field, if
	// set then the asset returned may have a distinct asset ID to the one
	// specified below.
	GroupKey *btcec.PublicKey

	// AssetID is the asset ID that needs to be satisfied.
	AssetID *asset.ID

	// MinAmt is the minimum amount that an asset commitment needs to hold
	// to satisfy the constraints.
	MinAmt uint64
}

// String returns the string representation of the commitment constraints.
func (c *CommitmentConstraints) String() string {
	var groupKeyBytes, assetIDBytes []byte
	if c.GroupKey != nil {
		groupKeyBytes = c.GroupKey.SerializeCompressed()
	}
	if c.AssetID != nil {
		assetIDBytes = c.AssetID[:]
	}
	return fmt.Sprintf("group_key=%x, asset_id=%x, min_amt=%d",
		groupKeyBytes, assetIDBytes, c.MinAmt)
}

// AnchoredCommitment is the response to satisfying the set of
// CommitmentConstraints. This includes the asset itself, and also information
// needed to locate the asset on-chain and also prove its existence.
type AnchoredCommitment struct {
	// AnchorPoint is the outpoint that the Commitment below is anchored on
	// in the main chain.
	AnchorPoint wire.OutPoint

	// AnchorOutputValue is output value of the anchor output.
	AnchorOutputValue btcutil.Amount

	// InternalKey is the internal key that's used to anchor the commitment
	// in the above out point.
	InternalKey keychain.KeyDescriptor

	// TapscriptSibling is the tapscript sibling preimage of this asset.
	// This will usually be nil.
	TapscriptSibling *commitment.TapscriptPreimage

	// Commitment is the full Taproot Asset commitment anchored at the above
	// outpoint. This includes both the asset to be used as an input, along
	// with any other assets that might be collocated in this commitment.
	Commitment *commitment.TapCommitment

	// Asset is the asset that ratifies the above constraints, and should
	// be used as an input to a transaction.
	Asset *asset.Asset
}

var (
	// ErrMatchingAssetsNotFound is returned when an instance of
	// AssetStoreListCoins cannot satisfy the given asset identification
	// constraints.
	ErrMatchingAssetsNotFound = fmt.Errorf("failed to find coin(s) that " +
		"satisfy given constraints; if previous transfers are un-" +
		"confirmed, wait for them to confirm before trying again")
)

// CoinLister attracts over the coin selection process needed to be
// able to execute moving taproot assets on chain.
type CoinLister interface {
	// ListEligibleCoins takes the set of commitment constraints and returns
	// an AnchoredCommitment that returns all the information needed to use
	// the commitment as an input to an on chain Taproot Asset transaction.
	//
	// If coin selection cannot be completed, then ErrMatchingAssetsNotFound
	// should be returned.
	ListEligibleCoins(context.Context,
		CommitmentConstraints) ([]*AnchoredCommitment, error)

	// LeaseCoins leases/locks/reserves coins for the given lease owner
	// until the given expiry. This is used to prevent multiple concurrent
	// coin selection attempts from selecting the same coin(s).
	LeaseCoins(ctx context.Context, leaseOwner [32]byte, expiry time.Time,
		utxoOutpoints ...wire.OutPoint) error

	// ReleaseCoins releases/unlocks coins that were previously leased and
	// makes them available for coin selection again.
	ReleaseCoins(ctx context.Context, utxoOutpoints ...wire.OutPoint) error

	// DeleteExpiredLeases deletes all expired leases from the database.
	DeleteExpiredLeases(ctx context.Context) error
}

// MultiCommitmentSelectStrategy is an enum that describes the strategy that
// should be used when preferentially selecting multiple commitments.
type MultiCommitmentSelectStrategy uint8

const (
	// PreferMaxAmount is a strategy which considers commitments in order of
	// descending amounts and selects the first subset which cumulatively
	// sums to at least the minimum target amount.
	PreferMaxAmount MultiCommitmentSelectStrategy = iota
)

// CoinSelector is an interface that describes the functionality used in
// selecting coins during the asset send process.
type CoinSelector interface {
	// SelectCoins returns a set of not yet leased coins that satisfy the
	// given constraints and strategy. The coins returned are leased for the
	// default lease duration.
	SelectCoins(ctx context.Context, constraints CommitmentConstraints,
		strategy MultiCommitmentSelectStrategy) ([]*AnchoredCommitment,
		error)

	// ReleaseCoins releases/unlocks coins that were previously leased and
	// makes them available for coin selection again.
	ReleaseCoins(ctx context.Context, utxoOutpoints ...wire.OutPoint) error
}

// TransferInput represents the database level input to an asset transfer.
type TransferInput struct {
	// PrevID contains the anchor point, ID and script key of the asset that
	// is being spent.
	asset.PrevID

	// Amount is the input amount that was spent.
	Amount uint64
}

// Anchor represents the database level representation of an anchor output.
type Anchor struct {
	// OutPoint is the chain location of the anchor output.
	OutPoint wire.OutPoint

	// Value is output value of the anchor output.
	Value btcutil.Amount

	// InternalKey is the new internal key that commits to the set of assets
	// anchored at the new outpoint.
	InternalKey keychain.KeyDescriptor

	// TaprootAssetRoot is the Taproot Asset commitment root hash of the
	// anchor output.
	TaprootAssetRoot []byte

	// MerkleRoot is the root of the tap script merkle tree that also
	// contains the Taproot Asset commitment of the anchor output. If there
	// is no tapscript sibling, then this is equal to the TaprootAssetRoot.
	MerkleRoot []byte

	// TapscriptSibling is the serialized preimage of the tapscript sibling
	// of the Taproot Asset commitment.
	TapscriptSibling []byte

	// NumPassiveAssets is the number of passive assets in the commitment
	// for this anchor output.
	NumPassiveAssets uint32
}

// TransferOutput represents the database level output to an asset transfer.
type TransferOutput struct {
	// Anchor is the new location of the Taproot Asset commitment referenced
	// by this transfer output.
	Anchor Anchor

	// Type indicates what type of output this is, which has an influence on
	// whether the asset is set or what witness type is expected to be
	// generated for the asset.
	Type tappsbt.VOutputType

	// ScriptKey is the new script key.
	ScriptKey asset.ScriptKey

	// ScriptKeyLocal indicates whether the script key is known to the lnd
	// node connected to this daemon. If this is false, then we won't create
	// a new asset entry in our database as we consider this to be an
	// outbound transfer.
	ScriptKeyLocal bool

	// Amount is the new amount for the asset.
	Amount uint64

	// AssetVersion is the new asset version for this output.
	AssetVersion asset.Version

	// WitnessData is the new witness data for this asset.
	WitnessData []asset.Witness

	// SplitCommitmentRoot is the root split commitment for this asset.
	// This will only be set if a split was required to complete the send.
	SplitCommitmentRoot mssmt.Node

	// ProofSuffix is the fully serialized proof suffix of the output which
	// includes all the proof information other than the final chain
	// information.
	ProofSuffix []byte

	// ProofCourierAddr is the bytes encoded proof courier service address
	// associated with this output.
	ProofCourierAddr []byte
}

// OutboundParcel represents the database level delta of an outbound Taproot
// Asset parcel (outbound spend). A spend will destroy a series of assets listed
// as inputs, and re-create them as new outputs. Along the way some assets may
// have been split or sent to others. This is reflected in the set of
// TransferOutputs.
type OutboundParcel struct {
	// AnchorTx is the new transaction that commits to the set of Taproot
	// Assets found at the above NewAnchorPoint.
	AnchorTx *wire.MsgTx

	// AnchorTxHeightHint is a block height recorded before the anchor tx is
	// broadcast, used as a starting block height when registering for
	// confirmations.
	AnchorTxHeightHint uint32

	// TransferTime holds the timestamp of the outbound spend.
	TransferTime time.Time

	// ChainFees is the amount in sats paid in on-chain fees for the
	// anchor transaction.
	ChainFees int64

	// PassiveAssets is the set of passive assets that are re-anchored
	// during the parcel confirmation process.
	PassiveAssets []*tappsbt.VPacket

	// PassiveAssetsAnchor is the anchor point for the passive assets. This
	// might be a distinct anchor from any active transfer in case the
	// active transfers don't create any change going back to us.
	PassiveAssetsAnchor *Anchor

	// Inputs represents the list of previous assets that were spent with
	// this transfer.
	Inputs []TransferInput

	// Outputs represents the list of new assets that were created with this
	// transfer.
	Outputs []TransferOutput
}

// AssetConfirmEvent is used to mark a batched spend as confirmed on disk.
type AssetConfirmEvent struct {
	// AnchorTXID is the anchor transaction's hash that was previously
	// unconfirmed.
	AnchorTXID chainhash.Hash

	// BlockHash is the block hash that confirmed the above anchor point.
	BlockHash chainhash.Hash

	// BlockHeight is the height of the block hash above.
	BlockHeight int32

	// TxIndex is the location within the block that confirmed the anchor
	// point.
	TxIndex int32

	// FinalProofs is the set of final full proof chain files that are going
	// to be stored on disk, one for each output in the outbound parcel.
	FinalProofs map[asset.SerializedKey]*proof.AnnotatedProof

	// PassiveAssetProofFiles is the set of passive asset proof files that
	// are re-anchored during the parcel confirmation process.
	PassiveAssetProofFiles map[asset.ID][]*proof.AnnotatedProof
}

// ExportLog is used to track the state of outbound Taproot Asset parcels
// (batched spends). This log is used by the ChainPorter to mark pending
// outbound deliveries, and finally confirm the deliveries once they've been
// committed to the main chain.
type ExportLog interface {
	// LogPendingParcel marks an outbound parcel as pending on disk. This
	// commits the set of changes to disk (the asset deltas) but doesn't
	// mark the batched spend as being finalized.
	LogPendingParcel(context.Context, *OutboundParcel, [32]byte,
		time.Time) error

	// PendingParcels returns the set of parcels that haven't yet been
	// finalized. This can be used to query the set of unconfirmed
	// transactions for re-broadcast.
	PendingParcels(context.Context) ([]*OutboundParcel, error)

	// ConfirmParcelDelivery marks a spend event on disk as confirmed. This
	// updates the on-chain reference information on disk to point to this
	// new spend.
	ConfirmParcelDelivery(context.Context, *AssetConfirmEvent) error
}

// ChainBridge aliases into the ChainBridge of the tapgarden package.
type ChainBridge = tapgarden.ChainBridge

// WalletAnchor aliases into the WalletAnchor of the taparden package.
type WalletAnchor interface {
	tapgarden.WalletAnchor

	// SignPsbt signs all the inputs it can in the passed-in PSBT packet,
	// returning a new one with updated signature/witness data.
	SignPsbt(ctx context.Context, packet *psbt.Packet) (*psbt.Packet, error)
}

// KeyRing aliases into the KeyRing of the tapgarden package.
type KeyRing = tapgarden.KeyRing

// Signer aliases into the Signer interface of the tapscript package.
type Signer = tapscript.Signer

// Porter is a high level interface that wraps the main caller execution point
// to the ChainPorter.
type Porter interface {
	// RequestShipment attempts to request that a new send be funneled
	// through the chain porter. If successful, an initial response will be
	// returned with the pending transfer information.
	RequestShipment(req Parcel) (*OutboundParcel, error)

	// Start signals that the asset minter should being operations.
	Start() error

	// Stop signals that the asset minter should attempt a graceful
	// shutdown.
	Stop() error

	// EventPublisher is a subscription interface that allows callers to
	// subscribe to events that are relevant to the Porter.
	fn.EventPublisher[fn.Event, bool]
}
