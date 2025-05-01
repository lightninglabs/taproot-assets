package tapfreighter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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

const (
	// TransferTxLabel defines the label assigned to an on-chain transaction
	// that represents a tapd asset transfer.
	TransferTxLabel = "tapd-asset-transfer"
)

// CommitmentConstraints conveys the constraints on the type of Taproot asset
// commitments needed to satisfy a send request. Typically, for Bitcoin we just
// care about the amount. In the case of Taproot Asset, we also need to worry
// about the asset ID, and also the type of asset we need.
//
// NOTE: Only the GroupKey or the AssetID should be set.
type CommitmentConstraints struct {
	// AssetSpecifier specifies the asset.
	AssetSpecifier asset.Specifier

	// MinAmt is the minimum amount that an asset commitment needs to hold
	// to satisfy the constraints.
	MinAmt uint64

	// MaxAmt specifies the maximum amount that an asset commitment needs to
	// hold to satisfy the constraints.
	MaxAmt uint64

	// PrevIDs are the set of inputs allowed to be used.
	PrevIDs []asset.PrevID

	// DistinctSpecifier indicates whether we _only_ look at either the
	// group key _or_ the asset ID but not both. That means, if the group
	// key is set, we ignore the asset ID and allow multiple inputs of the
	// same group to be selected.
	DistinctSpecifier bool

	// ScriptKeyType is the type of script key the assets are expected to
	// have. If this is fn.None, then any script key type is allowed.
	ScriptKeyType fn.Option[asset.ScriptKeyType]
}

// AssetBurn holds data related to a burn of an asset.
type AssetBurn struct {
	// Note is a user provided description for the transfer.
	Note string

	// AssetID is the ID of the burnt asset.
	AssetID []byte

	// GroupKey is the group key of the group the burnt asset belongs to.
	GroupKey []byte

	// Amount is the amount of the asset that got burnt.
	Amount uint64

	// AnchorTxid is the txid of the transaction this burn is anchored to.
	AnchorTxid chainhash.Hash
}

// String returns the string representation of the commitment constraints.
func (c *CommitmentConstraints) String() string {
	assetIDBytes, groupKeyBytes := c.AssetSpecifier.AsBytes()

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

// PrevID returns the previous ID of the asset commitment.
func (c *AnchoredCommitment) PrevID() asset.PrevID {
	return asset.PrevID{
		OutPoint:  c.AnchorPoint,
		ID:        c.Asset.ID(),
		ScriptKey: asset.ToSerialized(c.Asset.ScriptKey.PubKey),
	}
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
		strategy MultiCommitmentSelectStrategy,
		maxVersion commitment.TapCommitmentVersion,
	) ([]*AnchoredCommitment, error)

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

	// CommitmentVersion is the version of the Taproot Asset commitment
	// anchored in this output.
	CommitmentVersion *uint8

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

	// PkScript is the pkScript of the anchor output.
	PkScript []byte
}

// OutputIdentifier is a key that can be used to uniquely identify a transfer
// output.
type OutputIdentifier [32]byte

// NewOutputIdentifier creates a new output identifier for the given asset ID,
// output index and script key. This is used to uniquely identify the output
// from the transfer entries in the database.
func NewOutputIdentifier(id asset.ID, outputIndex uint32,
	scriptKey btcec.PublicKey) OutputIdentifier {

	keyData := make([]byte, 32+4+len(scriptKey.SerializeCompressed()))
	copy(keyData[0:32], id[:])
	binary.BigEndian.PutUint32(keyData[32:36], outputIndex)
	copy(keyData[36:], scriptKey.SerializeCompressed())
	return sha256.Sum256(keyData)
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

	// LockTime, if non-zero, restricts an asset from being moved prior to
	// the represented block height in the chain. This value needs to be set
	// on the asset that is spending from a script key with a CLTV script.
	LockTime uint64

	// RelativeLockTime, if non-zero, restricts an asset from being moved
	// until a number of blocks after the confirmation height of the latest
	// transaction for the asset is reached. This value needs to be set
	// on the asset that is spending from a script key with a CSV script.
	RelativeLockTime uint64

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

	// ProofDeliveryComplete is a flag that indicates whether the proof
	// delivery for this output is complete.
	//
	// This field can take one of the following values:
	// - None: A proof will not be delivered to a counterparty.
	// - False: The proof has not yet been delivered successfully.
	// - True: The proof has been delivered to the recipient.
	ProofDeliveryComplete fn.Option[bool]

	// Position is the position of the output in the transfer output list.
	Position uint64
}

// ShouldDeliverProof returns true if a proof corresponding to the subject
// transfer output should be delivered to a peer.
func (out *TransferOutput) ShouldDeliverProof() (bool, error) {
	// If any proof delivery is already complete (some true), no further
	// delivery is needed. However, if the proof delivery status is
	// unset (none), we won't use that status in determining whether proof
	// delivery is necessary. The field may not be set yet.
	if out.ProofDeliveryComplete.UnwrapOr(false) {
		return false, nil
	}

	// If the proof courier address is unspecified, we don't need to deliver
	// a proof.
	if len(out.ProofCourierAddr) == 0 {
		return false, nil
	}

	// The proof courier address may have been specified in error, in which
	// case we will conduct further checks to determine if a proof should be
	// delivered.
	//
	// If the script key is un-spendable, we don't need to deliver a proof.
	unSpendable, err := out.ScriptKey.IsUnSpendable()
	if err != nil {
		return false, fmt.Errorf("error checking if script key is "+
			"unspendable: %w", err)
	}

	if unSpendable {
		return false, nil
	}

	// If this is an output that is going to our own node/wallet, we don't
	// need to deliver a proof.
	if out.ScriptKey.TweakedScriptKey != nil && out.ScriptKeyLocal {
		return false, nil
	}

	// If the script key is a burn key, we don't need to deliver a proof.
	if len(out.WitnessData) > 0 && asset.IsBurnKey(
		out.ScriptKey.PubKey, out.WitnessData[0],
	) {

		return false, nil
	}

	// At this point, we should deliver a proof.
	return true, nil
}

// UniqueKey returns a unique key that can be used to identify the output.
// Because this requires the output proof to be set to extract the asset ID, an
// error is returned if it is not.
func (out *TransferOutput) UniqueKey() (OutputIdentifier, error) {
	var zero [32]byte
	if len(out.ProofSuffix) == 0 {
		return zero, fmt.Errorf("proof suffix not set")
	}

	var (
		outProofAsset  asset.Asset
		inclusionProof proof.TaprootProof
	)
	err := proof.SparseDecode(
		bytes.NewReader(out.ProofSuffix),
		proof.AssetLeafRecord(&outProofAsset),
		proof.InclusionProofRecord(&inclusionProof),
	)
	if err != nil {
		return zero, fmt.Errorf("unable to sparse decode proof: %w",
			err)
	}

	return NewOutputIdentifier(
		outProofAsset.ID(), inclusionProof.OutputIndex,
		*out.ScriptKey.PubKey,
	), nil
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

	// AnchorTxBlockHash is the block hash of the block that contains the
	// anchor transaction. This is set once the anchor transaction is
	// confirmed.
	AnchorTxBlockHash fn.Option[chainhash.Hash]

	// AnchorTxBlockHeight is the block height of the block that contains
	// the anchor transaction. This is set once the anchor transaction is
	// confirmed.
	AnchorTxBlockHeight uint32

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

	// Label is a user provided label for the transfer.
	Label string
}

// Copy creates a deep copy of the OutboundParcel.
func (o *OutboundParcel) Copy() *OutboundParcel {
	newParcel := &OutboundParcel{
		AnchorTxHeightHint: o.AnchorTxHeightHint,
		TransferTime:       o.TransferTime,
		ChainFees:          o.ChainFees,
		PassiveAssets:      fn.CopyAll(o.PassiveAssets),
		Inputs:             fn.CopySlice(o.Inputs),
		Outputs:            fn.CopySlice(o.Outputs),
	}

	if o.AnchorTx != nil {
		newParcel.AnchorTx = o.AnchorTx.Copy()
	}

	if o.PassiveAssetsAnchor != nil {
		oldAnchor := o.PassiveAssetsAnchor
		newParcel.PassiveAssetsAnchor = &Anchor{
			OutPoint:          oldAnchor.OutPoint,
			Value:             oldAnchor.Value,
			InternalKey:       oldAnchor.InternalKey,
			TaprootAssetRoot:  oldAnchor.TaprootAssetRoot,
			CommitmentVersion: oldAnchor.CommitmentVersion,
			MerkleRoot:        oldAnchor.MerkleRoot,
			TapscriptSibling:  oldAnchor.TapscriptSibling,
			NumPassiveAssets:  oldAnchor.NumPassiveAssets,
		}
	}

	return newParcel
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
	FinalProofs map[OutputIdentifier]*proof.AnnotatedProof

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

	// ConfirmProofDelivery marks a transfer output proof as successfully
	// transferred.
	ConfirmProofDelivery(context.Context, wire.OutPoint, uint64) error

	// LogAnchorTxConfirm updates the send package state on disk to reflect
	// the confirmation of the anchor transaction, ensuring the on-chain
	// reference information is up to date.
	LogAnchorTxConfirm(context.Context, *AssetConfirmEvent,
		[]*AssetBurn) error

	// QueryParcels returns the set of confirmed or unconfirmed parcels.
	QueryParcels(ctx context.Context, anchorTxHash *chainhash.Hash,
		pending bool) ([]*OutboundParcel, error)
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

	// QueryParcels returns the set of confirmed or unconfirmed parcels. If
	// the anchor tx hash is Some, then a query for an parcel with the
	// matching anchor hash will be made.
	QueryParcels(ctx context.Context,
		anchorTxHash fn.Option[chainhash.Hash], pending bool,
	) ([]*OutboundParcel, error)

	// Start signals that the asset minter should being operations.
	Start() error

	// Stop signals that the asset minter should attempt a graceful
	// shutdown.
	Stop() error

	// EventPublisher is a subscription interface that allows callers to
	// subscribe to events that are relevant to the Porter.
	fn.EventPublisher[fn.Event, bool]
}
