package commitment

import (
	"errors"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// AssetDetails contains all of the configurable parameters of an Asset to
// specify upon mint.
type AssetDetails struct {
	// Version is the type of the asset to mint.
	Version asset.Version

	// Type is the type of asset to mint.
	Type asset.Type

	// ScriptKey is the Taproot key with ownership of the asset.
	ScriptKey keychain.KeyDescriptor

	// Amount is the amount of assets that should be minted for `ScriptKey`.
	// NOTE: This should be nil when minting `Collectible` assets.
	Amount *uint64

	// LockTime is the earliest height in the blockchain at which the
	// asset(s) to mint can be spent from `ScriptKey`.
	LockTime uint64

	// RelativeLockTime is the number of blocks after the on-chain
	// confirmation height in the blockchain at which the asset(s) to mint
	// can be spent from `ScriptKey`.
	RelativeLockTime uint64
}

// mintAssets mints a series of assets based on the same asset ID and group key.
func mintAssets(genesis asset.Genesis, groupKey *asset.GroupKey,
	mintDetails ...*AssetDetails) ([]*asset.Asset, error) {

	assets := make([]*asset.Asset, 0, len(mintDetails))
	for _, mint := range mintDetails {
		mint := mint

		if mint.Type != genesis.Type {
			return nil, fmt.Errorf("mint asset type mismatch, "+
				"got %v while genesis committed to %v",
				mint.Type, genesis.Type)
		}

		var amount uint64
		switch mint.Type {
		case asset.Normal:
			if mint.Amount == nil || *mint.Amount < 1 {
				return nil, errors.New("zero mint amount for " +
					"normal asset")
			}
			amount = *mint.Amount

		case asset.Collectible:
			if mint.Amount != nil && *mint.Amount != 1 {
				return nil, fmt.Errorf("invalid mint amount "+
					"%v for collectible asset",
					*mint.Amount)
			}
			amount = 1

		default:
			return nil, fmt.Errorf("unhandled asset type %v",
				mint.Type)
		}

		a, err := asset.New(
			genesis, amount, mint.LockTime, mint.RelativeLockTime,
			asset.NewScriptKeyBip86(mint.ScriptKey), groupKey,
			asset.WithAssetVersion(mint.Version),
		)
		if err != nil {
			return nil, err
		}

		assets = append(assets, a)
	}

	return assets, nil
}

// Mint mints a series of assets within a new Taproot Asset commitment. The
// distribution and other parameters of these assets can be specified through
// `AssetDetails`.
func Mint(genesis asset.Genesis, groupKey *asset.GroupKey,
	details ...*AssetDetails) (*TapCommitment, []*asset.Asset, error) {

	assets, err := mintAssets(genesis, groupKey, details...)
	if err != nil {
		return nil, nil, err
	}
	assetCommitment, err := NewAssetCommitment(assets...)
	if err != nil {
		return nil, nil, err
	}
	tapCommitment, err := NewTapCommitment(assetCommitment)
	if err != nil {
		return nil, nil, err
	}

	return tapCommitment, assets, nil
}
