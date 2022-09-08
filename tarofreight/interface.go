package tarofreight

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/tarogarden"
)

// TODO(roasbeef):
//  * disk state update
//  * signing

// CommitmentConstraints...
type CommitmentConstraints struct {
	// FamilyKey...
	FamilyKey *btcec.PublicKey

	// ID...
	ID asset.ID

	// Amt...
	Amt uint64

	// AssetType...
	AssetType asset.Type
}

// AnchoredCommitment...
type AnchoredCommitment struct {
	// AnchorPoint...
	AnchorPoint wire.OutPoint

	// InternalKey...
	InternalKey *btcec.PublicKey

	// TapscriptSibling...
	TapscriptSibling []byte

	// Commitment...
	Commitment commitment.TaroCommitment

	// Asset...
	Asset asset.Asset
}

// CommitmentSelector....
type CommitmentSelector interface {
	// SelectCommitment...
	SelectCommitment(c *CommitmentConstraints) (*AnchoredCommitment, error)
}

// KeyRing...
type KeyRing = tarogarden.KeyRing

// WalletAnchor...
type WalletAnchor = tarogarden.WalletAnchor

// ChainBridge...
type ChainBridge = tarogarden.ChainBridge
