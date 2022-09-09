package tarofreighter

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
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

	// Amt is the minimum amount that an asset commitment needs to hold to
	// satisfy the constraints.
	Amt uint64
}

// AnchoredCommitment is the response to satisfying the set of
// CommitmentConstraints. This includes the asset itself, and also information
// needed to locate the asset on-chain and also prove its existence.
type AnchoredCommitment struct {
	// AnchorPoint is the outpoint that the Commitment below is anchored on
	// in the main chain.
	AnchorPoint wire.OutPoint

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
