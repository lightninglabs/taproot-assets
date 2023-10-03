package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/keychain"
)

// UpsertAssetStore is a sub-set of the main sqlc.Querier interface that
// contains methods related to inserting/updating assets.
type UpsertAssetStore interface {
	// UpsertGenesisPoint inserts a new or updates an existing genesis point
	// on disk, and returns the primary key.
	UpsertGenesisPoint(ctx context.Context, prevOut []byte) (int32, error)

	// AnchorGenesisPoint associates a genesis point with the transaction
	// that mints the associated assets on disk.
	AnchorGenesisPoint(ctx context.Context, arg GenesisPointAnchor) error

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTxParams) (int32, error)

	// UpsertGenesisAsset inserts a new or updates an existing genesis asset
	// (the base asset info) in the DB, and returns the primary key.
	//
	// TODO(roasbeef): hybrid version of the main tx interface that an
	// accept two diff storage interfaces?
	//
	//  * or use a sort of mix-in type?
	UpsertGenesisAsset(ctx context.Context, arg GenesisAsset) (int32, error)

	// FetchGenesisID is used to fetch the database ID of asset genesis
	// information already in the DB.
	FetchGenesisID(ctx context.Context,
		arg sqlc.FetchGenesisIDParams) (int32, error)

	// FetchScriptKeyIDByTweakedKey determines the database ID of a script
	// key by querying it by the tweaked key.
	FetchScriptKeyIDByTweakedKey(ctx context.Context,
		tweakedScriptKey []byte) (int32, error)

	// UpsertInternalKey inserts a new or updates an existing internal key
	// into the database.
	UpsertInternalKey(ctx context.Context, arg InternalKey) (int32, error)

	// UpsertScriptKey inserts a new script key on disk into the DB.
	UpsertScriptKey(context.Context, NewScriptKey) (int32, error)

	// UpsertAssetGroupWitness inserts a new asset group witness into the DB.
	UpsertAssetGroupWitness(ctx context.Context,
		arg AssetGroupWitness) (int32, error)

	// UpsertAssetGroupKey inserts a new or updates an existing group key
	// on disk, and returns the primary key.
	UpsertAssetGroupKey(ctx context.Context, arg AssetGroupKey) (int32,
		error)

	// InsertNewAsset inserts a new asset on disk.
	InsertNewAsset(ctx context.Context,
		arg sqlc.InsertNewAssetParams) (int32, error)

	// UpsertAssetMeta inserts a new asset meta into the DB.
	UpsertAssetMeta(ctx context.Context, arg NewAssetMeta) (int32, error)

	// SetAssetSpent marks an asset as being spent in the database. The
	// updated asset's database ID is returned.
	SetAssetSpent(ctx context.Context, arg SetAssetSpentParams) (int32,
		error)
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
		MetaDataHash:   genesis.MetaHash[:],
		OutputIndex:    int32(genesis.OutputIndex),
		AssetType:      int16(genesis.Type),
		GenesisPointID: genesisPointID,
	})
	if err != nil {
		return 0, fmt.Errorf("unable to insert genesis asset: %w", err)
	}

	return genAssetID, nil
}

// fetchGenesisID fetches the primary key ID for a genesis record already
// in the database.
func fetchGenesisID(ctx context.Context, q UpsertAssetStore,
	genesis asset.Genesis) (int32, error) {

	genPoint, err := encodeOutpoint(genesis.FirstPrevOut)
	if err != nil {
		return 0, fmt.Errorf("unable to encode genesis point: %w", err)
	}

	assetID := genesis.ID()
	genAssetID, err := q.FetchGenesisID(ctx, sqlc.FetchGenesisIDParams{
		AssetID:     assetID[:],
		AssetTag:    genesis.Tag,
		MetaHash:    genesis.MetaHash[:],
		OutputIndex: int32(genesis.OutputIndex),
		AssetType:   int16(genesis.Type),
		PrevOut:     genPoint,
	})
	if err != nil {
		return 0, fmt.Errorf("unable to fetch genesis asset: %w", err)
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
	// group, so we'll need to insert them before we can insert the asset
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

		// This asset has as key group, so we'll insert it into the
		// database. If it doesn't exist, the UPSERT query will still
		// return the group_id we'll need.
		groupWitnessID, err := upsertGroupKey(
			ctx, a.GroupKey, q, genesisPointID, genAssetID,
		)
		if err != nil {
			return 0, nil, fmt.Errorf("unable to upsert group "+
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
				GenesisID:           genAssetID,
				Version:             int32(a.Version),
				ScriptKeyID:         scriptKeyID,
				AssetGroupWitnessID: groupWitnessID,
				ScriptVersion:       int32(a.ScriptVersion),
				Amount:              int64(a.Amount),
				LockTime:            sqlInt32(a.LockTime),
				RelativeLockTime:    sqlInt32(a.RelativeLockTime),
				AnchorUtxoID:        anchorUtxoID,
			},
		)
		if err != nil {
			return 0, nil, fmt.Errorf("unable to insert asset: %w",
				err)
		}
	}

	return genesisPointID, assetIDs, nil
}

// upsertGroupKey inserts or updates a group key and its associated internal
// key.
func upsertGroupKey(ctx context.Context, groupKey *asset.GroupKey,
	q UpsertAssetStore, genesisPointID, genAssetID int32) (sql.NullInt32,
	error) {

	// No group key, this asset is not re-issuable.
	var nullID sql.NullInt32
	if groupKey == nil {
		return nullID, nil
	}

	// Before we can insert a new asset key group, we'll also need to
	// insert an internal key which will be referenced by the key group.
	// When we insert a proof, we don't know the raw key. So we just insert
	// the tweaked key as the internal key.
	//
	// TODO(roasbeef):
	//   * don't have the key desc information here necessarily
	//   * inserting the group key rn, which is ok as its external w/ no key
	//     desc info
	tweakedKeyBytes := groupKey.GroupPubKey.SerializeCompressed()
	rawKeyBytes := groupKey.GroupPubKey.SerializeCompressed()
	if groupKey.RawKey.PubKey != nil {
		rawKeyBytes = groupKey.RawKey.PubKey.SerializeCompressed()
	}

	keyID, err := q.UpsertInternalKey(ctx, InternalKey{
		RawKey:    rawKeyBytes,
		KeyFamily: int32(groupKey.RawKey.Family),
		KeyIndex:  int32(groupKey.RawKey.Index),
	})
	if err != nil {
		return nullID, fmt.Errorf("unable to insert internal key: %w",
			err)
	}

	// The only valid size for a non-empty Tapscript root is 32 bytes.
	if len(groupKey.TapscriptRoot) != 0 &&
		len(groupKey.TapscriptRoot) != sha256.Size {

		return nullID, fmt.Errorf("tapscript root invalid: wrong size")
	}

	groupID, err := q.UpsertAssetGroupKey(ctx, AssetGroupKey{
		TweakedGroupKey: tweakedKeyBytes,
		TapscriptRoot:   groupKey.TapscriptRoot,
		InternalKeyID:   keyID,
		GenesisPointID:  genesisPointID,
	})
	if err != nil {
		return nullID, fmt.Errorf("unable to insert group key: %w",
			err)
	}

	// With the statement above complete, we'll now insert the
	// asset_group_sig entry for this, which has a one-to-many relationship
	// with group keys (there can be many sigs for a group key which link
	// together otherwise disparate asset IDs). But the witness is optional,
	// so in case we don't have one, we can just return a nil ID.
	if len(groupKey.Witness) == 0 {
		return nullID, nil
	}

	witnessBytes, err := asset.SerializeGroupWitness(groupKey.Witness)
	if err != nil {
		return nullID, err
	}

	groupWitnessID, err := q.UpsertAssetGroupWitness(ctx, AssetGroupWitness{
		WitnessStack: witnessBytes,
		GenAssetID:   genAssetID,
		GroupKeyID:   groupID,
	})
	if err != nil {
		return nullID, fmt.Errorf("unable to insert group sig: %w", err)
	}

	return sqlInt32(groupWitnessID), nil
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
	// we don't actually have the raw script key here. Let's check if we
	// have the script key already.
	scriptKeyID, err := q.FetchScriptKeyIDByTweakedKey(
		ctx, scriptKey.PubKey.SerializeCompressed(),
	)
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

	// Now we fetch the genesis information that so far we only have the ID
	// for in the address record.
	gen, err := q.FetchGenesisByID(ctx, assetID)
	if err != nil {
		return asset.Genesis{}, fmt.Errorf("unable to fetch genesis: "+
			"%w", err)
	}

	// Next, we'll populate the asset genesis information which includes
	// the genesis prev out, and the other information needed to derive an
	// asset ID.
	var genesisPrevOut wire.OutPoint
	err = readOutPoint(bytes.NewReader(gen.PrevOut), 0, 0, &genesisPrevOut)
	if err != nil {
		return asset.Genesis{}, fmt.Errorf("unable to read outpoint: "+
			"%w", err)
	}

	var metaHash [32]byte
	copy(metaHash[:], gen.MetaDataHash)

	return asset.Genesis{
		FirstPrevOut: genesisPrevOut,
		Tag:          gen.AssetTag,
		MetaHash:     metaHash,
		OutputIndex:  uint32(gen.OutputIndex),
		Type:         asset.Type(gen.AssetType),
	}, nil
}

// GroupStore houses the methods related to fetching specific asset groups.
type GroupStore interface {
	FetchGenesisStore

	// FetchGroupByGenesis fetches information on the asset group created
	// with the asset genesis referenced by a specific genesis ID.
	FetchGroupByGenesis(ctx context.Context,
		genesisID int32) (sqlc.FetchGroupByGenesisRow, error)

	// FetchGroupByGroupKey fetches information on the asset group with
	// a matching group key.
	FetchGroupByGroupKey(ctx context.Context,
		groupKey []byte) (sqlc.FetchGroupByGroupKeyRow, error)
}

// fetchGroupByGenesis fetches the asset group created by the genesis referenced
// by the given ID.
func fetchGroupByGenesis(ctx context.Context, q GroupStore,
	genID int32) (*asset.AssetGroup, error) {

	groupInfo, err := q.FetchGroupByGenesis(ctx, genID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("no matching asset group: %w", err)
	case err != nil:
		return nil, err
	}

	groupGenesis, err := fetchGenesis(ctx, q, genID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch group genesis info: "+
			"%w", err)
	}

	groupKey, err := parseGroupKeyInfo(
		groupInfo.TweakedGroupKey, groupInfo.RawKey,
		groupInfo.WitnessStack, groupInfo.TapscriptRoot,
		groupInfo.KeyFamily, groupInfo.KeyIndex,
	)
	if err != nil {
		return nil, err
	}

	return &asset.AssetGroup{
		Genesis:  &groupGenesis,
		GroupKey: groupKey,
	}, nil
}

// fetchGroupByGroupKey fetches the asset group with a matching tweaked key,
// including the genesis information used to create the group.
func fetchGroupByGroupKey(ctx context.Context, q GroupStore,
	tweakedKey *btcec.PublicKey) (*asset.AssetGroup, error) {

	groupKeyQuery := tweakedKey.SerializeCompressed()
	groupInfo, err := q.FetchGroupByGroupKey(ctx, groupKeyQuery[:])
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("no matching asset group: %w", err)
	case err != nil:
		return nil, err
	}

	groupGenesis, err := fetchGenesis(ctx, q, groupInfo.GenAssetID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch group genesis info: "+
			"%w", err)
	}

	groupKey, err := parseGroupKeyInfo(
		groupKeyQuery, groupInfo.RawKey, groupInfo.WitnessStack,
		groupInfo.TapscriptRoot, groupInfo.KeyFamily, groupInfo.KeyIndex,
	)
	if err != nil {
		return nil, err
	}

	return &asset.AssetGroup{
		Genesis:  &groupGenesis,
		GroupKey: groupKey,
	}, nil
}

// parseGroupKeyInfo maps information on a group key into a GroupKey.
func parseGroupKeyInfo(tweakedKey, rawKey, witness, tapscriptRoot []byte,
	keyFamily, keyIndex int32) (*asset.GroupKey, error) {

	tweakedGroupKey, err := btcec.ParsePubKey(tweakedKey)
	if err != nil {
		return nil, err
	}

	untweakedKey, err := btcec.ParsePubKey(rawKey)
	if err != nil {
		return nil, err
	}

	groupRawKey := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(keyFamily),
			Index:  uint32(keyIndex),
		},
		PubKey: untweakedKey,
	}

	var groupWitness wire.TxWitness
	if len(witness) != 0 {
		groupWitness, err = asset.ParseGroupWitness(witness)
		if err != nil {
			return nil, err
		}
	}

	return &asset.GroupKey{
		RawKey:        groupRawKey,
		GroupPubKey:   *tweakedGroupKey,
		TapscriptRoot: tapscriptRoot,
		Witness:       groupWitness,
	}, nil
}

// maybeUpsertAssetMeta inserts a meta on disk and returns the primary key of
// that meta if metaReveal is non nil.
func maybeUpsertAssetMeta(ctx context.Context, db UpsertAssetStore,
	assetGen *asset.Genesis, metaReveal *proof.MetaReveal) (int32, error) {

	var (
		metaHash [32]byte
		metaBlob []byte
		metaType sql.NullInt16

		err error
	)

	switch {
	// If there's a meta reveal with this asset genesis, then we'll also be
	// inserting a blob and meta type.
	case metaReveal != nil:
		metaHash = metaReveal.MetaHash()
		metaBlob = metaReveal.Data
		metaType = sql.NullInt16{
			Int16: int16(metaReveal.Type),
			Valid: true,
		}

	// Otherwise, we'll just be inserting only the meta hash. At a later
	// time, the reveal/blob can also be inserted.
	case assetGen != nil:
		metaHash = assetGen.MetaHash

	// In the default case, there's no actual meta reveal, so we'll just
	// use the meta hash of all zeroes.
	default:
	}

	assetMetaID, err := db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash: metaHash[:],
		MetaDataBlob: metaBlob,
		MetaDataType: metaType,
	})
	if err != nil {
		return assetMetaID, err
	}

	return assetMetaID, nil
}
