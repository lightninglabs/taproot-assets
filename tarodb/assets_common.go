package tarodb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/tarodb/sqlc"
)

// UpsertAssetStore is a sub-set of the main sqlc.Querier interface that
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

	// UpsertAssetFamilySig inserts a new asset family sig into the DB.
	UpsertAssetFamilySig(ctx context.Context, arg AssetFamSig) (int32, error)

	// UpsertAssetFamilyKey inserts a new or updates an existing family key
	// on disk, and returns the primary key.
	UpsertAssetFamilyKey(ctx context.Context, arg AssetFamilyKey) (int32,
		error)

	// InsertNewAsset inserts a new asset on disk.
	InsertNewAsset(ctx context.Context,
		arg sqlc.InsertNewAssetParams) (int32, error)
}

// upsertGenesis imports a new genesis point into the database or returns the
// existing ID if that point already exists.
func upsertGenesisPoint(ctx context.Context, q UpsertAssetStore,
	genesisOutpoint wire.OutPoint) (int32, error) {

	genesisPoint, err := encodeOutpoint(genesisOutpoint)
	if err != nil {
		return 0, fmt.Errorf("unable to encode genesis point: %w", err)
	}

	// First, we'll insert the component that ties together all the assets
	// in a batch: the genesis point.
	genesisPointID, err := q.UpsertGenesisPoint(ctx, genesisPoint)
	if err != nil {
		return 0, fmt.Errorf("unable to insert genesis point: %w", err)
	}

	return genesisPointID, nil
}

// upsertGenesis imports a new genesis record into the database or returns the
// existing ID of the genesis if it already exists.
func upsertGenesis(ctx context.Context, q UpsertAssetStore,
	genesisPointID int32, genesis asset.Genesis) (int32, error) {

	// Then we'll insert the genesis_assets row which tracks all the
	// information that uniquely derives a given asset ID.
	assetID := genesis.ID()
	genAssetID, err := q.UpsertGenesisAsset(ctx, GenesisAsset{
		AssetID:        assetID[:],
		AssetTag:       genesis.Tag,
		MetaData:       genesis.Metadata,
		OutputIndex:    int32(genesis.OutputIndex),
		AssetType:      int16(genesis.Type),
		GenesisPointID: genesisPointID,
	})
	if err != nil {
		return 0, fmt.Errorf("unable to insert genesis asset: %w", err)
	}

	return genAssetID, nil
}

// upsertAssetsWithGenesis imports new assets and their genesis information into
// the database.
func upsertAssetsWithGenesis(ctx context.Context, q UpsertAssetStore,
	genesisOutpoint wire.OutPoint, assets []*asset.Asset,
	anchorUtxoIDs []sql.NullInt32) (int32, []int32, error) {

	// First, we'll insert the component that ties together all the assets
	// in a batch: the genesis point.
	genesisPointID, err := upsertGenesisPoint(ctx, q, genesisOutpoint)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to upsert genesis point: %w",
			err)
	}

	// We'll now insert each asset into the database. Some assets have a key
	// family, so we'll need to insert them before we can insert the asset
	// itself.
	assetIDs := make([]int32, len(assets))
	for idx, a := range assets {
		// First, we make sure the genesis asset information exists in
		// the database.
		genAssetID, err := upsertGenesis(
			ctx, q, genesisPointID, a.Genesis,
		)
		if err != nil {
			return 0, nil, fmt.Errorf("unable to upsert genesis: "+
				"%w", err)
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
			ctx, sqlc.InsertNewAssetParams{
				GenesisID:        genAssetID,
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
	famSigID, err := q.UpsertAssetFamilySig(ctx, AssetFamSig{
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

// FetchGenesisStore houses the methods related to fetching genesis assets.
type FetchGenesisStore interface {
	// FetchGenesisByID returns a single genesis asset by its primary key
	// ID.
	FetchGenesisByID(ctx context.Context, assetID int32) (Genesis, error)
}

// fetchGenesis returns a fully populated genesis record from the database,
// identified by its primary key ID.
func fetchGenesis(ctx context.Context, q FetchGenesisStore,
	assetID int32) (asset.Genesis, error) {

	// Now we fetch the genesis information that so far we
	// only have the ID for in the address record.
	gen, err := q.FetchGenesisByID(ctx, assetID)
	if err != nil {
		return asset.Genesis{}, fmt.Errorf("unable to fetch genesis: "+
			"%w", err)
	}

	// Next, we'll populate the asset genesis information which
	// includes the genesis prev out, and the other information
	// needed to derive an asset ID.
	var genesisPrevOut wire.OutPoint
	err = readOutPoint(bytes.NewReader(gen.PrevOut), 0, 0, &genesisPrevOut)
	if err != nil {
		return asset.Genesis{}, fmt.Errorf("unable to read outpoint: "+
			"%w", err)
	}

	return asset.Genesis{
		FirstPrevOut: genesisPrevOut,
		Tag:          gen.AssetTag,
		Metadata:     gen.MetaData,
		OutputIndex:  uint32(gen.OutputIndex),
		Type:         asset.Type(gen.AssetType),
	}, nil
}
