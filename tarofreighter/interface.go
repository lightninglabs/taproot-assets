package tarofreighter

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/keychain"
)

// CommitmentConstraints conveys the constraints on the type of Taro asset
// commitments needed to satisfy a send request. Typically for Bitcoin we just
// care about the amount. In the case of Taro, we also need to worry about the
// asset ID, and also the type of asset we need.
//
// NOTE: Only the FamilyKey or the AssetID should be set.
type CommitmentConstraints struct {
	// FamilyKey is the required family key. This is an optional field, if
	// set then the asset returned may have a distinct asset ID to the one
	// specified below.
	FamilyKey *btcec.PublicKey

	// AssetID is the asset ID that needs to be satisfied.
	AssetID *asset.ID

	// MinAmt is the minimum amount that an asset commitment needs to hold
	// to satisfy the constraints.
	MinAmt uint64
}

// AnchoredCommitment is the response to satisfying the set of
// CommitmentConstraints. This includes the asset itself, and also information
// needed to locate the asset on-chain and also prove its existence.
type AnchoredCommitment struct {
	// AnchorPoint is the outpoint that the Commitment below is anchored on
	// in the main chain.
	AnchorPoint wire.OutPoint

	// AnchorOutputValue is outout value of the anchor output.
	AnchorOutputValue btcutil.Amount

	// InternalKey is the internal key that's used to anchor the commitment
	// in the above out point.
	InternalKey btcec.PublicKey

	// TapscriptSibling is the tapscript sibling of this asset. This will
	// usually be blank.
	TapscriptSibling []byte

	// Commitment is the full Taro commitment anchored at the above
	// outpoint. This includes both the asset to be used as an input, along
	// with any other assets that might be collocated in this commitment.
	Commitment *commitment.TaroCommitment

	// Asset is the asset that ratifies the above constraints, and should
	// be used as an input to a transaction.
	Asset *asset.Asset
}

// CommitmentSelector attracts over the coin selection process needed to be
// able to execute moving taro assets on chain.
type CommitmentSelector interface {
	// SelectCommitment takes the set of commitment constraints and returns
	// an AnchoredCommitment that returns all the information needed to use
	// the commitment as an input to an on chain taro transaction.
	SelectCommitment(context.Context,
		CommitmentConstraints) ([]*AnchoredCommitment, error)
}

// AssetSpendDelta describes the mutation of an asset as part of an outbound
// parcel (batched send). As we always require script keys to be unique, we
// simply need to know the old script key, and the new amount.
type AssetSpendDelta struct {
	// OldScriptKey is the old script key that uniquely identified the
	// spent asset on disk.
	OldScriptKey btcec.PublicKey

	// NewAmt is the new amount for the asset.
	NewAmt uint64

	// NewScriptKey is the new script key. We assume BIP 86 usage when
	// updating the script keys on disk.
	NewScriptKey asset.ScriptKey

	// WitnessData is the new witness data for this asset.
	WitnessData []asset.Witness
}

// OutboundParcelDelta represents the database level delta of an outbound taro
// parcel (outbound spend). A spend will destroy a series of assets at the old
// anchor point, and re-create them at the new anchor point. Along the way some
// assets may have been split or sent to others. This is reflected in the set
// of AssetSpendDeltas.
type OutboundParcelDelta struct {
	// OldAnchorPoint is the old/current location of the Taro commitment
	// that was spent as an input.
	OldAnchorPoint wire.OutPoint

	// NewAnchorPoint is the new location of the Taro commitment referenced
	// by the OldAnchorPoint.
	NewAnchorPoint wire.OutPoint

	// NewInternalKey is the new internal key that commits to the set of
	// assets anchored at the new outpoint.
	//
	// TODO(roasbeef): move below fields into new struct?
	NewInternalKey keychain.KeyDescriptor

	// TaroRoot is the new Taro root that commits to the set of modified
	// and unmodified assets.
	TaroRoot []byte

	// TapscriptSibling is the tapscript sibling for the asset commitment
	// above.
	TapscriptSibling []byte

	// AnchorTx is the new transaction that commits to the set of Taro
	// assets found at the above NewAnchorPoint.
	AnchorTx *wire.MsgTx

	// AssetSpendDeltas describes the set of mutated assets that now live
	// at the new anchor tx point.
	AssetSpendDeltas []AssetSpendDelta

	// TODO(roasbeef): also include pre-populated state transition blobs to
	// append/extend for entire set of assets?
	//  * if want to append in db, need incremental hash for proof file
	//  digest
}

// AssetConfirmEvent is used to mark a batched spend as confirmed on disk.
type AssetConfirmEvent struct {
	// AnchorPoint is the anchor point that was previously unconfirmed.
	AnchorPoint wire.OutPoint

	// BlockHash is the block hash that confirmed the above anchor point.
	BlockHash chainhash.Hash

	// BlockHeight is the height of the block hash above.
	BlockHeight int32

	// TxIndex is the location within the block that confirmed the anchor
	// point.
	TxIndex int32
}

// ExportLog is used to track the state of outbound taro parcels (batched
// spends). This log is used by the ChainPorter to mark pending outbound
// deliveries, and finally confirm the deliveries once they've been committed
// to the main chain.
//
// TODO(roasbeef): also want to be able to roll back? rbf, double spends, etc,
// etc.
type ExportLog interface {
	// LogPendingParcel marks an outbound parcel as pending on disk. This
	// commits the set of changes to disk (the asset deltas) but doesn't
	// mark the batched spend as being finalized.
	LogPendingParcel(context.Context, *OutboundParcelDelta) error

	// PendingParcels returns the set of parcels that haven't yet been
	// finalized. This can be used to query the set of unconfirmed
	// transactions for re-broadcast.
	PendingParcels(context.Context) ([]*OutboundParcelDelta, error)

	// ConfirmParcelDelivery marks a spend event on disk as confirmed. This
	// updates the on-chain reference information on disk to point to this
	// new spend.
	ConfirmParcelDelivery(context.Context, *AssetConfirmEvent) error
}

// ChainBridge aliases into the ChainBridge of the tarogarden package.
type ChainBridge = tarogarden.ChainBridge

// WalletAnchor aliases into the WalletAnchor of the tarogarden package.
type WalletAnchor = tarogarden.WalletAnchor

// KeyRing aliases into the KeyRing of the tarogarden package.
type KeyRing = tarogarden.KeyRing

// Signer aliases into the Signer interface of the taroscript package.
type Signer = taroscript.Signer
