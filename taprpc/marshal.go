package taprpc

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// KeyLookup is used to determine whether a key is under the control of the
// local wallet.
type KeyLookup interface {
	// IsLocalKey returns true if the key is under the control of the
	// wallet and can be derived by it.
	IsLocalKey(ctx context.Context, desc keychain.KeyDescriptor) bool
}

// UnmarshalAssetVersion parses an asset version from the RPC variant.
func UnmarshalAssetVersion(version AssetVersion) (asset.Version, error) {
	// For now we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case AssetVersion_ASSET_VERSION_V0:
		return asset.V0, nil

	case AssetVersion_ASSET_VERSION_V1:
		return asset.V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalAssetVersion parses an asset version from the RPC variant.
func MarshalAssetVersion(version asset.Version) (AssetVersion, error) {
	// For now we'll only support two asset versions. The ones in the
	// future should be reserved for future use, so we disallow unknown
	// versions.
	switch version {
	case asset.V0:
		return AssetVersion_ASSET_VERSION_V0, nil

	case asset.V1:
		return AssetVersion_ASSET_VERSION_V1, nil

	default:
		return 0, fmt.Errorf("unknown asset version: %v", version)
	}
}

// MarshalAsset converts an asset to its rpc representation.
func MarshalAsset(ctx context.Context, a *asset.Asset,
	isSpent, withWitness bool,
	keyRing KeyLookup) (*Asset, error) {

	assetID := a.Genesis.ID()
	scriptKeyIsLocal := false
	if a.ScriptKey.TweakedScriptKey != nil && keyRing != nil {
		scriptKeyIsLocal = keyRing.IsLocalKey(
			ctx, a.ScriptKey.RawKey,
		)
	}

	assetVersion, err := MarshalAssetVersion(a.Version)
	if err != nil {
		return nil, err
	}

	rpcAsset := &Asset{
		Version: assetVersion,
		AssetGenesis: &GenesisInfo{
			GenesisPoint: a.Genesis.FirstPrevOut.String(),
			AssetType:    AssetType(a.Type),
			Name:         a.Genesis.Tag,
			MetaHash:     a.Genesis.MetaHash[:],
			AssetId:      assetID[:],
			OutputIndex:  a.Genesis.OutputIndex,
			Version:      int32(assetVersion),
		},
		Amount:           a.Amount,
		LockTime:         int32(a.LockTime),
		RelativeLockTime: int32(a.RelativeLockTime),
		ScriptVersion:    int32(a.ScriptVersion),
		ScriptKey:        a.ScriptKey.PubKey.SerializeCompressed(),
		ScriptKeyIsLocal: scriptKeyIsLocal,
		IsSpent:          isSpent,
		IsBurn:           a.IsBurn(),
	}

	if a.GroupKey != nil {
		var (
			rawKey       []byte
			groupWitness []byte
			err          error
		)

		if a.GroupKey.RawKey.PubKey != nil {
			rawKey = a.GroupKey.RawKey.PubKey.SerializeCompressed()
		}
		if len(a.GroupKey.Witness) != 0 {
			groupWitness, err = asset.SerializeGroupWitness(
				a.GroupKey.Witness,
			)
			if err != nil {
				return nil, err
			}
		}
		rpcAsset.AssetGroup = &AssetGroup{
			RawGroupKey:     rawKey,
			TweakedGroupKey: a.GroupKey.GroupPubKey.SerializeCompressed(),
			AssetWitness:    groupWitness,
		}
	}

	if withWitness {
		for idx := range a.PrevWitnesses {
			witness := a.PrevWitnesses[idx]

			prevID := witness.PrevID
			rpcPrevID := &PrevInputAsset{
				AnchorPoint: prevID.OutPoint.String(),
				AssetId:     prevID.ID[:],
				ScriptKey:   prevID.ScriptKey[:],
			}

			var rpcSplitCommitment *SplitCommitment
			if witness.SplitCommitment != nil {
				rootAsset, err := MarshalAsset(
					ctx, &witness.SplitCommitment.RootAsset,
					false, true, nil,
				)
				if err != nil {
					return nil, err
				}

				rpcSplitCommitment = &SplitCommitment{
					RootAsset: rootAsset,
				}
			}

			rpcAsset.PrevWitnesses = append(
				rpcAsset.PrevWitnesses, &PrevWitness{
					PrevId:          rpcPrevID,
					TxWitness:       witness.TxWitness,
					SplitCommitment: rpcSplitCommitment,
				},
			)
		}
	}

	return rpcAsset, nil
}
