package tarodb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/tarodb/sqlite"
)

// UpsertAssetStore is a sub-set of the main sqlite.Querier interface that
// contains methods related to inserting/updating assets.
type UpsertAssetStore interface {
	// UpsertGenesisPoint inserts a new or updates an existing genesis point
	// on disk, and returns the primary key.
	UpsertGenesisPoint(ctx context.Context, prevOut []byte) (int32, error)

	// UpsertGenesisAsset inserts a new or updates an existing genesis asset
	// (the base asset info) in the DB, and returns the primary key.
	//
	// TODO(roasbeef): hybrid version of the main tx interface that an
	// accept two diff storage interfaces?
	//
	//  * or use a sort of mix-in type?
	UpsertGenesisAsset(ctx context.Context, arg GenesisAsset) (int32, error)

	// UpsertInternalKey inserts a new or updates an existing internal key
	// into the database.
	UpsertInternalKey(ctx context.Context, arg InternalKey) (int32, error)

	// UpsertScriptKey inserts a new script key on disk into the DB.
	UpsertScriptKey(context.Context, NewScriptKey) (int32, error)

	// InsertAssetFamilySig inserts a new asset family sig into the DB.
	InsertAssetFamilySig(ctx context.Context, arg AssetFamSig) (int32, error)

	// UpsertAssetFamilyKey inserts a new or updates an existing family key
	// on disk, and returns the primary key.
	UpsertAssetFamilyKey(ctx context.Context, arg AssetFamilyKey) (int32,
		error)

	// InsertNewAsset inserts a new asset on disk.
	InsertNewAsset(ctx context.Context,
		arg sqlite.InsertNewAssetParams) (int32, error)
}

// upsertAssetsWithGenesis imports new assets and their genesis information into
// the database.
func upsertAssetsWithGenesis(ctx context.Context, q UpsertAssetStore,
	genesisOutpoint wire.OutPoint, assets []*asset.Asset,
	anchorUtxoIDs []sql.NullInt32) (int32, []int32, error) {

	genesisPoint, err := encodeOutpoint(genesisOutpoint)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to encode genesis point: %w",
			err)
	}

	// First, we'll insert the component that ties together all the assets
	// in this batch: the genesis point.
	genesisPointID, err := q.UpsertGenesisPoint(ctx, genesisPoint)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to insert genesis point: %w",
			err)
	}

	// With the genesis point inserted, we'll now insert each asset into the
	// database. Some assets have a key family, so we'll need to insert them
	// before we can insert the asset itself.
	assetIDs := make([]int32, len(assets))
	for idx, a := range assets {
		// First, we'll insert the genesis_assets row which
		// tracks all the information that uniquely derives a
		// given asset ID.
		assetID := a.Genesis.ID()
		genAssetID, err := q.UpsertGenesisAsset(ctx, GenesisAsset{
			AssetID:        assetID[:],
			AssetTag:       a.Genesis.Tag,
			MetaData:       a.Genesis.Metadata,
			OutputIndex:    int32(a.Genesis.OutputIndex),
			AssetType:      int16(a.Type),
			GenesisPointID: genesisPointID,
		})
		if err != nil {
			return 0, nil, fmt.Errorf("unable to insert genesis "+
				"asset: %w", err)
		}

		// This asset has as key family, so we'll insert it into the
		// database. If it doesn't exist, the UPSERT query will still
		// return the family_id we'll need.
		familySigID, err := upsertFamilyKey(
			ctx, a.FamilyKey, q, genesisPointID, genAssetID,
		)
		if err != nil {
			return 0, nil, fmt.Errorf("unable to upsert family "+
				"key: %w", err)
		}

		scriptKeyID, err := upsertScriptKey(ctx, a.ScriptKey, q)
		if err != nil {
			return 0, nil, fmt.Errorf("unable to upsert script "+
				"key: %w", err)
		}

		// Is the asset anchored already?
		var anchorUtxoID sql.NullInt32
		if len(anchorUtxoIDs) > 0 {
			anchorUtxoID = anchorUtxoIDs[idx]
		}

		// With all the dependent data inserted, we can now insert the
		// base asset information itself.
		assetIDs[idx], err = q.InsertNewAsset(
			ctx, sqlite.InsertNewAssetParams{
				AssetID:          genAssetID,
				Version:          int32(a.Version),
				ScriptKeyID:      scriptKeyID,
				AssetFamilySigID: familySigID,
				ScriptVersion:    int32(a.ScriptVersion),
				Amount:           int64(a.Amount),
				LockTime:         sqlInt32(a.LockTime),
				RelativeLockTime: sqlInt32(a.RelativeLockTime),
				AnchorUtxoID:     anchorUtxoID,
			},
		)
		if err != nil {
			return 0, nil, fmt.Errorf("unable to insert asset: %w",
				err)
		}
	}

	return genesisPointID, assetIDs, nil
}

// upsertFamilyKey inserts or updates a family key and its associated internal
// key.
func upsertFamilyKey(ctx context.Context, familyKey *asset.FamilyKey,
	q UpsertAssetStore, genesisPointID, genAssetID int32) (sql.NullInt32,
	error) {

	// No family key, this asset is not re-issuable.
	var nullID sql.NullInt32
	if familyKey == nil {
		return nullID, nil
	}

	// Before we can insert a new asset key family, we'll also need to
	// insert an internal key which will be referenced by the key family.
	// When we insert a proof, we don't know the raw key. So we just insert
	// the tweaked key as the internal key.
	//
	// TODO(roasbeef):
	//   * don't have the key desc information here necessarily
	//   * inserting the fam key rn, which is ok as its external w/ no key
	//     desc info
	tweakedKeyBytes := familyKey.FamKey.SerializeCompressed()
	rawKeyBytes := familyKey.FamKey.SerializeCompressed()
	if familyKey.RawKey.PubKey != nil {
		rawKeyBytes = familyKey.RawKey.PubKey.SerializeCompressed()
	}

	keyID, err := q.UpsertInternalKey(ctx, InternalKey{
		RawKey:    rawKeyBytes,
		KeyFamily: int32(familyKey.RawKey.Family),
		KeyIndex:  int32(familyKey.RawKey.Index),
	})
	if err != nil {
		return nullID, fmt.Errorf("unable to insert internal key: %w",
			err)
	}
	famID, err := q.UpsertAssetFamilyKey(ctx, AssetFamilyKey{
		TweakedFamKey:  tweakedKeyBytes,
		InternalKeyID:  keyID,
		GenesisPointID: genesisPointID,
	})
	if err != nil {
		return nullID, fmt.Errorf("unable to insert family key: %w",
			err)
	}

	// With the statement above complete, we'll now insert the
	// asset_family_sig entry for this, which has a one-to-many relationship
	// with family keys (there can be many sigs for a family key which link
	// together otherwise disparate asset IDs).
	//
	// TODO(roasbeef): sig here doesn't actually matter?
	famSigID, err := q.InsertAssetFamilySig(ctx, AssetFamSig{
		GenesisSig: familyKey.Sig.Serialize(),
		GenAssetID: genAssetID,
		KeyFamID:   famID,
	})
	if err != nil {
		return nullID, fmt.Errorf("unable to insert fam sig: %w", err)
	}

	return sqlInt32(famSigID), nil
}

// upsertScriptKey inserts or updates a script key and its associated internal
// key.
func upsertScriptKey(ctx context.Context, scriptKey asset.ScriptKey,
	q UpsertAssetStore) (int32, error) {

	if scriptKey.TweakedScriptKey != nil {
		rawScriptKeyID, err := q.UpsertInternalKey(ctx, InternalKey{
			RawKey:    scriptKey.RawKey.PubKey.SerializeCompressed(),
			KeyFamily: int32(scriptKey.RawKey.Family),
			KeyIndex:  int32(scriptKey.RawKey.Index),
		})
		if err != nil {
			return 0, fmt.Errorf("unable to insert internal key: "+
				"%w", err)
		}
		scriptKeyID, err := q.UpsertScriptKey(ctx, NewScriptKey{
			InternalKeyID:    rawScriptKeyID,
			TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
			Tweak:            scriptKey.Tweak,
		})
		if err != nil {
			return 0, fmt.Errorf("unable to insert script key: "+
				"%w", err)
		}

		return scriptKeyID, nil
	}

	// At this point, we only have the actual asset as read from a TLV, so
	// we don't actually have the raw script key here. Instead, we'll use
	// an UPSERT to trigger a conflict on the tweaked script key so we can
	// obtain the script key ID we need here. This is for the proof
	// import based on an addr send.
	//
	// TODO(roasbeef): or just fetch the one we need?
	scriptKeyID, err := q.UpsertScriptKey(ctx, NewScriptKey{
		TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
	})
	if err != nil {
		// If this fails, then we're just importing the proof to mirror
		// the state of another node. In this case, we'll just import
		// the key in the asset (a tweaked key) as an internal key. We
		// can't actually use this asset, but the import will complete.
		//
		// TODO(roasbeef): remove after itest work
		rawScriptKeyID, err := q.UpsertInternalKey(ctx, InternalKey{
			RawKey: scriptKey.PubKey.SerializeCompressed(),
		})
		if err != nil {
			return 0, fmt.Errorf("unable to insert internal key: "+
				"%w", err)
		}
		scriptKeyID, err = q.UpsertScriptKey(ctx, NewScriptKey{
			InternalKeyID:    rawScriptKeyID,
			TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
		})
		if err != nil {
			return 0, fmt.Errorf("unable to insert script key: "+
				"%w", err)
		}
	}

	return scriptKeyID, nil
}
