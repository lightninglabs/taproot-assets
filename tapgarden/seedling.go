package tapgarden

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// ErrInvalidAssetType is returned if an invalid asset type is passed
	// in.
	//
	// TODO(roasbeef): make proper error type struct?
	ErrInvalidAssetType = fmt.Errorf("invalid asset type")

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

	// MintingStateSprout denotes that a seedling has been paired with a
	// genesis transaction and broadcast for confirmation.
	MintingStateSprout

	// MintingStateAdult denotes that a seedling has been confirmed on
	// chain and reached full adulthood.
	MintingStateAdult
)

// SeedlingUpdate is a struct used to send notifications w.r.t the state of a
// seedling back to the caller.
type SeedlingUpdate struct {
	// NewState is the new state a seedling has transitioned to.
	NewState MintingState

	// PendingBatch is the current pending batch that the seedling has been
	// added to.
	PendingBatch *MintingBatch

	// Error if non-nil, denotes that an terminal error state has been
	// reached.
	Error error
}

// SeedlingUpdates is a channel that will be used to send updates for each
// seedling back to the caller.
type SeedlingUpdates chan SeedlingUpdate

// Seedling is an adolescent Taproot asset that will one day bloom into a fully
// grown plant.
type Seedling struct {
	// AssetVersion is the version of the asset to be created.
	AssetVersion asset.Version

	// AssetType is the type of the asset.
	AssetType asset.Type

	// AssetName is the name of the asset.
	AssetName string

	// Meta is the set of metadata associated with the asset.
	Meta *proof.MetaReveal

	// Amount is the total amount of the asset.
	Amount uint64

	// GroupInfo contains the information needed to link this asset to an
	// exiting group.
	GroupInfo *asset.AssetGroup

	// EnableEmission if true, then an asset group key will be specified
	// for this asset meaning future assets linked to it can be created.
	EnableEmission bool

	// UniverseCommitments indicates whether the minting event which
	// will be associated with the seedling supports universe commitments.
	// If set to true, the seedling can only be included in a minting batch
	// where all assets share the same asset group key, which must be
	// specified.
	//
	// Universe commitments are minter-controlled, on-chain anchored
	// attestations regarding the state of the universe.
	UniverseCommitments bool

	// DelegationKey is the public key that is used to verify universe
	// commitment related on-chain outputs and proofs.
	DelegationKey fn.Option[keychain.KeyDescriptor]

	// GroupAnchor is the name of another seedling in the pending batch that
	// will anchor an asset group. This seedling will be minted with the
	// same group key as the anchor asset.
	GroupAnchor *string

	// update is used to send updates w.r.t the state of the batch.
	updates SeedlingUpdates

	// ScriptKey is the tweaked Taproot key that will be used to spend the
	// asset after minting. By default, this key is constructed with a
	// BIP-0086 style tweak.
	ScriptKey asset.ScriptKey

	// GroupInternalKey is the raw group key before the tweak with the
	// genesis point or tapscript root has been applied.
	GroupInternalKey *keychain.KeyDescriptor

	// GroupTapscriptRoot is the root of the Tapscript tree that commits to
	// all script spend conditions for the group key. Instead of spending an
	// asset, these scripts are used to define witnesses more complex than
	// a Schnorr signature for reissuing assets. A group key with an empty
	// Tapscript root can only authorize re-issuance with a signature.
	GroupTapscriptRoot []byte

	// ExternalKey is an optional field that allows specifying an external
	// signing key for the group virtual transaction during minting. This
	// key enables signing operations to be performed externally, outside
	// the daemon.
	ExternalKey fn.Option[asset.ExternalKey]
}

// validateFields attempts to validate the set of input fields for the passed
// seedling, an error is returned if any of the fields are out of spec.
//
// NOTE: This function does not check the group key. That check is performed in
// the validateGroupKey method.
func (c Seedling) validateFields() error {
	// Validate the asset name.
	err := asset.ValidateAssetName(c.AssetName)
	if err != nil {
		return err
	}

	switch {
	// Only normal and collectible asset types are supported.
	//
	// TODO(roasbeef): lift into new constant?
	case c.AssetType != asset.Normal && c.AssetType != asset.Collectible:
		return fmt.Errorf("%v: %w", int(c.AssetType),
			ErrInvalidAssetType)

	// Creating an asset with zero available supply is not allowed.
	case c.Amount == 0:
		return ErrInvalidAssetAmt
	}

	// Validate the asset metadata.
	err = c.Meta.Validate()
	if err != nil {
		return err
	}

	// The group tapscript root must be 32 bytes.
	tapscriptRootSize := len(c.GroupTapscriptRoot)
	if tapscriptRootSize != 0 && tapscriptRootSize != sha256.Size {
		return fmt.Errorf("tapscript root must be %d bytes",
			sha256.Size)
	}

	return nil
}

// validateGroupKey attempts to validate that the non-zero group key provided
// with a seedling is owned by the daemon and can be used with this seedling.
func (c Seedling) validateGroupKey(group asset.AssetGroup,
	anchorMeta *proof.MetaReveal) error {

	// If an external key isn't specified but the actual group key used
	// isn't local to this daemon, we won't be able to sign with it.
	if c.ExternalKey.IsNone() && !group.GroupKey.IsLocal() {
		groupKeyBytes := c.GroupInfo.GroupPubKey.SerializeCompressed()
		return fmt.Errorf("can't sign with group key %x", groupKeyBytes)
	}

	// If there is an external key defined, we need to check that it matches
	// the group key.
	err := fn.MapOptionZ(
		c.ExternalKey, func(extKey asset.ExternalKey) error {
			if group.GroupKey == nil {
				return fmt.Errorf("group key is nil")
			}

			if group.GroupKey.RawKey.PubKey == nil {
				return fmt.Errorf("group raw key is nil")
			}

			pk, err := extKey.PubKey()
			if err != nil {
				return fmt.Errorf("error getting external "+
					"key: %w", err)
			}

			if !pk.IsEqual(group.RawKey.PubKey) {
				return fmt.Errorf("external key does not " +
					"match group key")
			}

			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("error validating external key: %w", err)
	}

	// The seedling asset type must match the group asset type.
	if c.AssetType != group.Genesis.Type {
		return fmt.Errorf("seedling type does not match "+
			"group asset type %v", group.Genesis.Type)
	}

	return validateAnchorMeta(c.Meta, anchorMeta)
}

// validateAnchorMeta checks that the metadata of the seedling matches that of
// the group anchor, if there is a group anchor.
func validateAnchorMeta(seedlingMeta *proof.MetaReveal,
	anchorMeta *proof.MetaReveal) error {

	// The decimal display of the seedling must match that of the group
	// anchor. We already validated the seedling metadata, so we don't care
	// if the value is explicit or if the metadata is JSON, but we must
	// compute the same value for both assets.
	var (
		seedlingDecDisplay uint32
		anchorDecDisplay   uint32
	)
	if seedlingMeta != nil {
		_, seedlingDecDisplay, _ = seedlingMeta.GetDecDisplay()
	}
	if anchorMeta != nil {
		_, anchorDecDisplay, _ = anchorMeta.GetDecDisplay()
	}

	if seedlingDecDisplay != anchorDecDisplay {
		return fmt.Errorf("seedling decimal display does not match "+
			"group anchor: %d, %d", seedlingDecDisplay,
			anchorDecDisplay)
	}

	// If the anchor asset had universe commitments turned on, then the
	// seedling must also have them.
	var (
		seedlingUniverseCommitments bool
		anchorUniverseCommitments   bool
	)
	if seedlingMeta != nil && seedlingMeta.UniverseCommitments {
		seedlingUniverseCommitments = true
	}
	if anchorMeta != nil && anchorMeta.UniverseCommitments {
		anchorUniverseCommitments = true
	}

	// If the anchor asset has universe commitment feature turned on, then
	// the same must be true for the seedling.
	if anchorUniverseCommitments && !seedlingUniverseCommitments {
		return fmt.Errorf("seedling universe commitments flag is " +
			"false but must be true since the group anchor's " +
			"flag is true")
	}

	// For now, we simply require a delegation key to be set when universe
	// commitments are turned on.
	if seedlingUniverseCommitments && seedlingMeta.DelegationKey.IsNone() {
		return fmt.Errorf("delegation key must be set for universe " +
			"commitments flag")
	}

	return nil
}

// Genesis reconstructs the asset genesis for a seedling.
func (c Seedling) Genesis(genOutpoint wire.OutPoint,
	genIndex uint32) asset.Genesis {

	gen := asset.Genesis{
		FirstPrevOut: genOutpoint,
		Tag:          c.AssetName,
		OutputIndex:  genIndex,
		Type:         c.AssetType,
	}

	if c.Meta != nil {
		gen.MetaHash = c.Meta.MetaHash()
	}

	return gen
}

// HasGroupKey checks if a seedling specifies a particular group key.
func (c Seedling) HasGroupKey() bool {
	return c.GroupInfo != nil && c.GroupInfo.GroupKey != nil
}

// String returns a human-readable representation for the AssetSeedling.
func (c Seedling) String() string {
	return fmt.Sprintf("AssetSeedling(name=%v, type=%v, amt=%v, "+
		"version=%v) received",
		c.AssetName, c.AssetType, c.Amount, c.AssetVersion)
}
