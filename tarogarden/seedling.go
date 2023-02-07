package tarogarden

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/asset"
)

var (
	// ErrInvalidAssetType is returned if an invalid asset type is passed
	// in.
	//
	// TODO(roasbeef): make proper error type struct?
	ErrInvalidAssetType = fmt.Errorf("invalid asset type")

	// ErrNoAssetName is returned if an asset request doesn't have a valid
	// name.
	ErrNoAssetName = fmt.Errorf("asset name cannot be blank")

	// ErrInvalidAssetAmt is returned in an asset request has an invalid
	// amount.
	ErrInvalidAssetAmt = fmt.Errorf("asset amt cannot be zero")
)

// MintingState is an enum that tracks an asset through the various minting
// stages.
type MintingState uint8

const (
	// MintingStateNone is the default state, no actions have been taken.
	MintingStateNone MintingState = iota

	// MintingStateSeed denotes the seedling as been added to a batch.
	MintingStateSeed

	// MintingStateSeedling denotes that a seedling has been finalized in a
	// batch and now has a corresponding asset associated with it.
	MintingStateSeedling

	// MintingStateSeedling denotes that a seedling has been paired with a
	// genesis transaction and broadcast for confirmation.
	MintingStateSprout

	// MintingStateAdult denotes that a seedling has been confirmed on
	// chain and reached full adult hood.
	MintingStateAdult
)

// SeedlingUpdate is a struct used to send notifications w.r.t the state of a
// seedling back to the caller.
type SeedlingUpdate struct {
	// NewState is the new state a seedling has transitioned to.
	NewState MintingState

	// BatchKey is the key for the batch that the seedling is a part of.
	// This is only populated once the seedling has reached the
	// MintingStateSeed state.
	BatchKey *btcec.PublicKey

	// Error if non-nil, denotes that an terminal error state has been
	// reached.
	Error error
}

// SeedlingUpdates is a channel that will be used to send updates for each
// seedling back to the caller.
type SeedlingUpdates chan SeedlingUpdate

// Seedling is an adolescent Taro asset that will one day bloom into a fully
// grown plant.
type Seedling struct {
	// AssetType is the type of the asset.
	AssetType asset.Type

	// AssetName is the name of the asset.
	AssetName string

	// Metadata is the set of metadata associated with the asset.
	//
	// TODO(roasbeef): redundant w/ the above?
	Metadata []byte

	// Amount is the total amount of the asset.
	Amount uint64

	// GroupInfo contains the information needed to link this asset to an
	// exiting group.
	GroupInfo *asset.AssetGroup

	// EnableEmission if true, then an asset group key will be specified
	// for this asset meaning future assets linked to it can be created.
	EnableEmission bool

	// NoBatch if true, then this asset will be bundled immediately in a
	// batch without waiting for the normal ticker.
	NoBatch bool

	// update is used to send updates w.r.t the state of the batch.
	updates SeedlingUpdates
}

// validateFields attempts to validate the set of input fields for the passed
// seedling, an error is returned if any of the fields are out of spec.
//
// TODO(roasbeef): have this series of check be a DB level constraint?
func (c Seedling) validateFields() error {
	switch {
	// Only normal and collectible asset types are supported.
	//
	// TODO(roasbeef): lift into new constant?
	case c.AssetType != asset.Normal && c.AssetType != asset.Collectible:
		return fmt.Errorf("%v: %v", int(c.AssetType),
			ErrInvalidAssetType)

	// The asset name can't be blank as that's needed to generate the asset
	// ID.
	//
	// TODO(roasbeef): also bubble up to the spec?
	case c.AssetName == "":
		return ErrNoAssetName

	// Creating an asset with zero available supply is not allowed.
	case c.Amount == 0:
		return ErrInvalidAssetAmt
	}

	return nil
}

// validateGroupKey attempts to validate that the non-zero group key provided
// with a seedling is owned by the daemon and can be used with this seedling.
func (c Seedling) validateGroupKey(group asset.AssetGroup) error {
	// We must be able to sign with the group key.
	if !group.GroupKey.IsLocal() {
		groupKeyBytes := c.GroupInfo.GroupPubKey.SerializeCompressed()
		return fmt.Errorf("can't sign with group key %x", groupKeyBytes)
	}

	// The seedling asset type must match the group asset type.
	if c.AssetType != group.Genesis.Type {
		return fmt.Errorf("seedling type does not match "+
			"group asset type %v", group.Genesis.Type)
	}

	return nil
}

// HasGroupKey checks if a seedling specifies a particular group key.
func (c Seedling) HasGroupKey() bool {
	// We have to nest these checks to avoid dereferencing a nil pointer and
	// panicking. If the GroupKey is set, the tweaked public key has already
	// been parsed.
	if c.GroupInfo != nil {
		if c.GroupInfo.GroupKey != nil {
			return true
		}
	}

	return false
}

// String returns a human readable representation for the AssetSeedling.
func (c Seedling) String() string {
	return fmt.Sprintf("AssetSeedling(name=%v, type=%v, amt=%v) received",
		c.AssetName, c.AssetType, c.Amount)
}
