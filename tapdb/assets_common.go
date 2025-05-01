package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
)

// UpsertAssetStore is a sub-set of the main sqlc.Querier interface that
// contains methods related to inserting/updating assets.
type UpsertAssetStore interface {
	// UpsertGenesisPoint inserts a new or updates an existing genesis point
	// on disk, and returns the primary key.
	UpsertGenesisPoint(ctx context.Context, prevOut []byte) (int64, error)

	// AnchorGenesisPoint associates a genesis point with the transaction
	// that mints the associated assets on disk.
	AnchorGenesisPoint(ctx context.Context, arg GenesisPointAnchor) error

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTxParams) (int64, error)

	// UpsertGenesisAsset inserts a new or updates an existing genesis asset
	// (the base asset info) in the DB, and returns the primary key.
	//
	// TODO(roasbeef): hybrid version of the main tx interface that an
	// accept two diff storage interfaces?
	//
	//  * or use a sort of mix-in type?
	UpsertGenesisAsset(ctx context.Context, arg GenesisAsset) (int64, error)

	// FetchGenesisID is used to fetch the database ID of asset genesis
	// information already in the DB.
	FetchGenesisID(ctx context.Context,
		arg sqlc.FetchGenesisIDParams) (int64, error)

	// FetchGenesisIDByAssetID fetches the database ID of an asset genesis
	// by its asset ID.
	FetchGenesisIDByAssetID(ctx context.Context,
		assetID []byte) (int64, error)

	// FetchScriptKeyIDByTweakedKey determines the database ID of a script
	// key by querying it by the tweaked key.
	FetchScriptKeyIDByTweakedKey(ctx context.Context,
		tweakedScriptKey []byte) (int64, error)

	// UpsertInternalKey inserts a new or updates an existing internal key
	// into the database.
	UpsertInternalKey(ctx context.Context, arg InternalKey) (int64, error)

	// UpsertScriptKey inserts a new script key on disk into the DB.
	UpsertScriptKey(context.Context, NewScriptKey) (int64, error)

	// UpsertAssetGroupWitness inserts a new asset group witness into the DB.
	UpsertAssetGroupWitness(ctx context.Context,
		arg AssetGroupWitness) (int64, error)

	// UpsertAssetGroupKey inserts a new or updates an existing group key
	// on disk, and returns the primary key.
	UpsertAssetGroupKey(ctx context.Context, arg AssetGroupKey) (int64,
		error)

	// QueryAssets fetches a filtered set of fully confirmed assets.
	QueryAssets(context.Context, QueryAssetFilters) ([]ConfirmedAsset,
		error)

	// UpsertAsset inserts a new asset on disk, or returns the ID of the
	// existing asset if it already exists.
	UpsertAsset(ctx context.Context,
		arg sqlc.UpsertAssetParams) (int64, error)

	// UpsertAssetMeta inserts a new asset meta into the DB.
	UpsertAssetMeta(ctx context.Context, arg NewAssetMeta) (int64, error)

	// SetAssetSpent marks an asset as being spent in the database. The
	// updated asset's database ID is returned.
	SetAssetSpent(ctx context.Context, arg SetAssetSpentParams) (int64,
		error)

	// UpsertTapscriptTreeRootHash inserts a new tapscript tree root hash.
	UpsertTapscriptTreeRootHash(ctx context.Context,
		arg TapscriptTreeRootHash) (int64, error)
}

var (
	// ErrEncodeGenesisPoint is returned when encoding a genesis point
	// before upserting it fails.
	ErrEncodeGenesisPoint = errors.New("unable to encode genesis point")

	// ErrReadOutpoint is returned when decoding an outpoint fails.
	ErrReadOutpoint = errors.New("unable to read outpoint")

	// ErrUpsertGenesisPoint is returned when upserting a genesis point
	// fails.
	ErrUpsertGenesisPoint = errors.New("unable to upsert genesis point")

	// ErrUpsertGroupKey is returned when upserting a group key fails.
	ErrUpsertGroupKey = errors.New("unable to upsert group key")

	// ErrUpsertInternalKey is returned when upserting an internal key
	// fails.
	ErrUpsertInternalKey = errors.New("unable to upsert internal key")

	// ErrUpsertScriptKey is returned when upserting a script key fails.
	ErrUpsertScriptKey = errors.New("unable to upsert script key")

	// ErrNoAssetGroup is returned when no matching asset group is found.
	ErrNoAssetGroup = errors.New("no matching asset group")

	// ErrNoAssetMeta is returned when no matching asset meta is found.
	ErrNoAssetMeta = errors.New("no matching asset meta")

	// ErrGroupGenesisInfo is returned when fetching genesis info for an
	// asset group fails.
	ErrGroupGenesisInfo = errors.New("unable to fetch group genesis info")

	// ErrTapscriptRootSize is returned when the given tapscript root is not
	// exactly 32 bytes.
	ErrTapscriptRootSize = errors.New("tapscript root invalid: wrong size")

	// ErrFetchGenesisID is returned when fetching the database ID for an
	// asset genesis fails.
	ErrFetchGenesisID = errors.New("unable to fetch genesis asset")
)

// upsertGenesis imports a new genesis point into the database or returns the
// existing ID if that point already exists.
func upsertGenesisPoint(ctx context.Context, q UpsertAssetStore,
	genesisOutpoint wire.OutPoint) (int64, error) {

	genesisPoint, err := encodeOutpoint(genesisOutpoint)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrEncodeGenesisPoint, err)
	}

	// First, we'll insert the component that ties together all the assets
	// in a batch: the genesis point.
	genesisPointID, err := q.UpsertGenesisPoint(ctx, genesisPoint)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUpsertGenesisPoint, err)
	}

	return genesisPointID, nil
}

// upsertGenesis imports a new genesis record into the database or returns the
// existing ID of the genesis if it already exists.
func upsertGenesis(ctx context.Context, q UpsertAssetStore,
	genesisPointID int64, genesis asset.Genesis) (int64, error) {

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
	genesis asset.Genesis) (int64, error) {

	genPoint, err := encodeOutpoint(genesis.FirstPrevOut)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrEncodeGenesisPoint, err)
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
		return 0, fmt.Errorf("%w: %w", ErrFetchGenesisID, err)
	}

	return genAssetID, nil
}

// upsertAssetsWithGenesis imports new assets and their genesis information into
// the database.
func upsertAssetsWithGenesis(ctx context.Context, q UpsertAssetStore,
	genesisOutpoint wire.OutPoint, assets []*asset.Asset,
	anchorUtxoIDs []sql.NullInt64) (int64, []int64, error) {

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
	assetIDs := make([]int64, len(assets))
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
			return 0, nil, fmt.Errorf("%w: %w", ErrUpsertGroupKey,
				err)
		}

		scriptKeyID, err := upsertScriptKey(ctx, a.ScriptKey, q)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %w", ErrUpsertScriptKey,
				err)
		}

		// Is the asset anchored already?
		var anchorUtxoID sql.NullInt64
		if len(anchorUtxoIDs) > 0 {
			anchorUtxoID = anchorUtxoIDs[idx]
		}

		// Check for matching assets in the database. If we find one,
		// we'll just use its primary key ID, and we won't attempt to
		// insert the asset again.
		existingAssets, err := q.QueryAssets(ctx, QueryAssetFilters{
			AnchorUtxoID: anchorUtxoID,
			GenesisID:    sqlInt64(genAssetID),
			ScriptKeyID:  sqlInt64(scriptKeyID),
		})
		if err != nil {
			return 0, nil, fmt.Errorf("unable to query assets: %w",
				err)
		}

		if len(existingAssets) > 0 {
			assetIDs[idx] = existingAssets[0].AssetPrimaryKey
			continue
		}

		// With all the dependent data inserted, we can now insert the
		// base asset information itself.
		assetIDs[idx], err = q.UpsertAsset(ctx, sqlc.UpsertAssetParams{
			GenesisID:           genAssetID,
			Version:             int32(a.Version),
			ScriptKeyID:         scriptKeyID,
			AssetGroupWitnessID: groupWitnessID,
			ScriptVersion:       int32(a.ScriptVersion),
			Amount:              int64(a.Amount),
			LockTime:            sqlInt32(a.LockTime),
			RelativeLockTime:    sqlInt32(a.RelativeLockTime),
			AnchorUtxoID:        anchorUtxoID,
		})
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
	q UpsertAssetStore, genesisPointID, genAssetID int64) (sql.NullInt64,
	error) {

	// No group key, this asset is not re-issuable.
	var nullID sql.NullInt64
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
		return nullID, fmt.Errorf("%w: %w", ErrUpsertInternalKey, err)
	}

	// The only valid size for a non-empty Tapscript root is 32 bytes.
	if len(groupKey.TapscriptRoot) != 0 &&
		len(groupKey.TapscriptRoot) != sha256.Size {

		return nullID, ErrTapscriptRootSize
	}

	// Upsert the custom tapscript root if set. We will pass the returned ID
	// to the group key upsert.
	rootID, err := fn.MapOptionZ(
		groupKey.CustomTapscriptRoot,
		func(root chainhash.Hash) lfn.Result[sql.NullInt32] {
			id, err := q.UpsertTapscriptTreeRootHash(
				ctx, TapscriptTreeRootHash{
					RootHash:   root[:],
					BranchOnly: false,
				},
			)
			if err != nil {
				return lfn.Err[sql.NullInt32](err)
			}

			return lfn.Ok(sqlInt32(id))
		},
	).Unpack()
	if err != nil {
		return nullID, fmt.Errorf("failed to upsert custom tapscript "+
			"root: %w", err)
	}

	// Upsert the group key itself.
	groupID, err := q.UpsertAssetGroupKey(ctx, AssetGroupKey{
		Version:             int32(groupKey.Version),
		TweakedGroupKey:     tweakedKeyBytes,
		TapscriptRoot:       groupKey.TapscriptRoot,
		InternalKeyID:       keyID,
		GenesisPointID:      genesisPointID,
		CustomSubtreeRootID: rootID,
	})
	if err != nil {
		return nullID, fmt.Errorf("%w: %w", ErrUpsertGroupKey, err)
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

	return sqlInt64(groupWitnessID), nil
}

// upsertScriptKey inserts or updates a script key and its associated internal
// key.
func upsertScriptKey(ctx context.Context, scriptKey asset.ScriptKey,
	q UpsertAssetStore) (int64, error) {

	if scriptKey.TweakedScriptKey != nil {
		rawScriptKeyID, err := q.UpsertInternalKey(ctx, InternalKey{
			RawKey:    scriptKey.RawKey.PubKey.SerializeCompressed(),
			KeyFamily: int32(scriptKey.RawKey.Family),
			KeyIndex:  int32(scriptKey.RawKey.Index),
		})
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrUpsertInternalKey,
				err)
		}
		scriptKeyID, err := q.UpsertScriptKey(ctx, NewScriptKey{
			InternalKeyID:    rawScriptKeyID,
			TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
			Tweak:            scriptKey.Tweak,
			KeyType:          sqlInt16(scriptKey.Type),
		})
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrUpsertScriptKey, err)
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
			return 0, fmt.Errorf("%w: %w", ErrUpsertInternalKey,
				err)
		}
		scriptKeyID, err = q.UpsertScriptKey(ctx, NewScriptKey{
			InternalKeyID:    rawScriptKeyID,
			TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
			KeyType:          sqlInt16(asset.ScriptKeyUnknown),
		})
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrUpsertScriptKey, err)
		}
	}

	return scriptKeyID, nil
}

// FetchScriptKeyStore houses the methods related to fetching all information
// about a script key.
type FetchScriptKeyStore interface {
	// FetchScriptKeyByTweakedKey attempts to fetch the script key and
	// corresponding internal key from the database.
	FetchScriptKeyByTweakedKey(ctx context.Context,
		tweakedScriptKey []byte) (ScriptKey, error)
}

// fetchScriptKey attempts to fetch the full tweaked script key struct
// (including the key descriptor) for the given tweaked script key.
func fetchScriptKey(ctx context.Context, q FetchScriptKeyStore,
	tweakedScriptKey *btcec.PublicKey) (*asset.TweakedScriptKey, error) {

	dbKey, err := q.FetchScriptKeyByTweakedKey(
		ctx, tweakedScriptKey.SerializeCompressed(),
	)
	if err != nil {
		return nil, err
	}

	scriptKey, err := parseScriptKey(dbKey.InternalKey, dbKey.ScriptKey)
	if err != nil {
		return nil, err
	}

	return scriptKey.TweakedScriptKey, nil
}

// parseScriptKey maps a script key and internal key from the database into a
// ScriptKey struct. Both the internal raw public key and the tweaked public key
// must be set and valid.
func parseScriptKey(ik sqlc.InternalKey, sk sqlc.ScriptKey) (asset.ScriptKey,
	error) {

	var emptyKey asset.ScriptKey
	if len(sk.TweakedScriptKey) == 0 {
		return emptyKey, fmt.Errorf("tweaked script key is empty")
	}

	if len(ik.RawKey) == 0 {
		return emptyKey, fmt.Errorf("internal raw key is empty")
	}

	var (
		locator = keychain.KeyLocator{
			Index:  uint32(ik.KeyIndex),
			Family: keychain.KeyFamily(ik.KeyFamily),
		}
		result = asset.ScriptKey{
			TweakedScriptKey: &asset.TweakedScriptKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: locator,
				},
				Tweak: sk.Tweak,
				Type: extractSqlInt16[asset.ScriptKeyType](
					sk.KeyType,
				),
			},
		}
		err error
	)

	result.PubKey, err = btcec.ParsePubKey(sk.TweakedScriptKey)
	if err != nil {
		return emptyKey, fmt.Errorf("error parsing tweaked script "+
			"key: %w", err)
	}

	result.RawKey.PubKey, err = btcec.ParsePubKey(ik.RawKey)
	if err != nil {
		return emptyKey, fmt.Errorf("error parsing internal raw "+
			"key: %w", err)
	}

	return result, nil
}

// FetchGenesisStore houses the methods related to fetching genesis assets.
type FetchGenesisStore interface {
	// FetchGenesisByID returns a single genesis asset by its primary key
	// ID.
	FetchGenesisByID(ctx context.Context, assetID int64) (Genesis, error)
}

// fetchGenesis returns a fully populated genesis record from the database,
// identified by its primary key ID.
func fetchGenesis(ctx context.Context, q FetchGenesisStore,
	assetID int64) (asset.Genesis, error) {

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
		return asset.Genesis{}, fmt.Errorf("%w: %w", ErrReadOutpoint,
			err)
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
		genesisID int64) (sqlc.FetchGroupByGenesisRow, error)

	// FetchGroupByGroupKey fetches information on the asset group with
	// a matching group key.
	FetchGroupByGroupKey(ctx context.Context,
		groupKey []byte) (sqlc.FetchGroupByGroupKeyRow, error)
}

// fetchGroupByGenesis fetches the asset group created by the genesis referenced
// by the given ID.
func fetchGroupByGenesis(ctx context.Context, q GroupStore,
	genID int64) (*asset.AssetGroup, error) {

	groupInfo, err := q.FetchGroupByGenesis(ctx, genID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("%w: %w", ErrNoAssetGroup, err)
	case err != nil:
		return nil, err
	}

	groupGenesis, err := fetchGenesis(ctx, q, genID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGroupGenesisInfo, err)
	}

	groupKey, err := parseGroupKeyInfo(
		groupInfo.Version, groupInfo.TweakedGroupKey, groupInfo.RawKey,
		groupInfo.WitnessStack, groupInfo.TapscriptRoot,
		groupInfo.KeyFamily, groupInfo.KeyIndex,
		groupInfo.CustomSubtreeRoot,
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
		return nil, fmt.Errorf("%w: %w", ErrNoAssetGroup, err)
	case err != nil:
		return nil, err
	}

	groupGenesis, err := fetchGenesis(ctx, q, groupInfo.GenAssetID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGroupGenesisInfo, err)
	}

	groupKey, err := parseGroupKeyInfo(
		groupInfo.Version, groupKeyQuery, groupInfo.RawKey,
		groupInfo.WitnessStack, groupInfo.TapscriptRoot,
		groupInfo.KeyFamily, groupInfo.KeyIndex,
		groupInfo.CustomSubtreeRoot,
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
func parseGroupKeyInfo(version int32, tweakedKey, rawKey, witness,
	tapscriptRoot []byte, keyFamily, keyIndex int32,
	customSubtreeRoot []byte) (*asset.GroupKey, error) {

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

	// Parse group key version from database row.
	groupKeyVersion, err := asset.NewGroupKeyVersion(version)
	if err != nil {
		return nil, err
	}

	// Parse custom tapscript root if specified.
	var customSubtreeRootHash fn.Option[chainhash.Hash]
	if len(customSubtreeRoot) != 0 {
		var rootHash chainhash.Hash
		copy(rootHash[:], customSubtreeRoot)

		customSubtreeRootHash = fn.Some(rootHash)
	}

	return &asset.GroupKey{
		Version:             groupKeyVersion,
		RawKey:              groupRawKey,
		GroupPubKey:         *tweakedGroupKey,
		TapscriptRoot:       tapscriptRoot,
		Witness:             groupWitness,
		CustomTapscriptRoot: customSubtreeRootHash,
	}, nil
}

// maybeUpsertAssetMeta inserts a meta on disk and returns the primary key of
// that meta if metaReveal is non nil.
func maybeUpsertAssetMeta(ctx context.Context, db UpsertAssetStore,
	assetGen *asset.Genesis, metaReveal *proof.MetaReveal) (int64, error) {

	var (
		metaHash                [32]byte
		metaBlob                []byte
		metaType                sql.NullInt16
		metaDecimalDisplay      sql.NullInt32
		metaUniverseCommitments sql.NullBool
		metaCanonicalUniverses  []byte
		metaDelegationKey       []byte

		err error
	)

	switch {
	// If there's a meta reveal with this asset genesis, then we'll also be
	// inserting a blob and meta type.
	case metaReveal != nil:
		metaHash = metaReveal.MetaHash()
		metaBlob = metaReveal.Data
		metaType = sqlInt16(metaReveal.Type)
		metaDecimalDisplay = sqlOptInt32(metaReveal.DecimalDisplay)
		metaUniverseCommitments = sqlBool(
			metaReveal.UniverseCommitments,
		)
		metaReveal.CanonicalUniverses.WhenSome(func(u []url.URL) {
			urlStrings := fn.Map(u, func(u url.URL) string {
				return u.String()
			})
			metaCanonicalUniverses = []byte(
				strings.Join(urlStrings, "\x00"),
			)
		})
		metaReveal.DelegationKey.WhenSome(func(key btcec.PublicKey) {
			metaDelegationKey = key.SerializeCompressed()
		})

	// Otherwise, we'll just be inserting only the meta hash. At a later
	// time, the reveal/blob can also be inserted.
	case assetGen != nil:
		metaHash = assetGen.MetaHash

	// In the default case, there's no actual meta reveal, so we'll just
	// use the meta hash of all zeroes.
	default:
	}

	assetMetaID, err := db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash:            metaHash[:],
		MetaDataBlob:            metaBlob,
		MetaDataType:            metaType,
		MetaDecimalDisplay:      metaDecimalDisplay,
		MetaUniverseCommitments: metaUniverseCommitments,
		MetaCanonicalUniverses:  metaCanonicalUniverses,
		MetaDelegationKey:       metaDelegationKey,
	})
	if err != nil {
		return assetMetaID, err
	}

	return assetMetaID, nil
}

// TapscriptTreeStore houses the methods related to storing, fetching, and
// deleting tapscript trees.
type TapscriptTreeStore interface {
	// UpsertTapscriptTreeRootHash inserts a new tapscript tree root hash.
	UpsertTapscriptTreeRootHash(ctx context.Context,
		rootHash TapscriptTreeRootHash) (int64, error)

	// UpsertTapscriptTreeEdge inserts a new tapscript tree edge that
	// references both a tapscript tree node and a root hash.
	UpsertTapscriptTreeEdge(ctx context.Context,
		edge TapscriptTreeEdge) (int64, error)

	// UpsertTapscriptTreeNode inserts a new tapscript tree node.
	UpsertTapscriptTreeNode(ctx context.Context, node []byte) (int64, error)

	// FetchTapscriptTree fetches all child nodes of a tapscript tree root
	// hash, which can be used to reassemble the tapscript tree.
	FetchTapscriptTree(ctx context.Context,
		rootHash []byte) ([]TapscriptTreeNode, error)

	// DeleteTapscriptTreeEdges deletes all edges that reference the given
	// root hash.
	DeleteTapscriptTreeEdges(ctx context.Context, rootHash []byte) error

	// DeleteTapscriptTreeNodes deletes all nodes that are not referenced by
	// any edge.
	DeleteTapscriptTreeNodes(ctx context.Context) error

	// DeleteTapscriptTreeRoot deletes a tapscript tree root hash.
	DeleteTapscriptTreeRoot(ctx context.Context, rootHash []byte) error
}

// upsertTapscriptTree inserts a tapscript tree into the database, including the
// nodes and edges needed to reassemble the tree.
func upsertTapscriptTree(ctx context.Context, q TapscriptTreeStore,
	rootHash []byte, isBranch bool, nodes [][]byte) error {

	if len(rootHash) != chainhash.HashSize {
		return fmt.Errorf("root hash must be 32 bytes")
	}

	// Perform final sanity checks on the given tapscript tree nodes.
	nodeCount := len(nodes)
	switch {
	case nodeCount == 0:
		return fmt.Errorf("no tapscript tree nodes provided")

	case isBranch && nodeCount != 2:
		return asset.ErrInvalidTapBranch
	}

	// Insert the root hash first.
	treeRoot := TapscriptTreeRootHash{
		RootHash:   rootHash,
		BranchOnly: isBranch,
	}
	rootId, err := q.UpsertTapscriptTreeRootHash(ctx, treeRoot)
	if err != nil {
		return err
	}

	// Tree node ordering must be preserved. We'll use the loop counter as
	// the node index in the tapscript edges we insert.
	for i := 0; i < nodeCount; i++ {
		nodeId, err := q.UpsertTapscriptTreeNode(ctx, nodes[i])
		if err != nil {
			return err
		}

		// Link each node to the root hash inserted earlier.
		edge := TapscriptTreeEdge{
			RootHashID: rootId,
			NodeIndex:  int64(i),
			RawNodeID:  nodeId,
		}
		_, err = q.UpsertTapscriptTreeEdge(ctx, edge)
		if err != nil {
			return err
		}
	}

	return nil
}

// deleteTapscriptTree deletes a tapscript tree from the database, including the
// edges and all nodes not referenced by another tapscript tree.
func deleteTapscriptTree(ctx context.Context, q TapscriptTreeStore,
	rootHash []byte) error {

	// Delete the tree edges first, as they reference both tree nodes and
	// the root hash.
	err := q.DeleteTapscriptTreeEdges(ctx, rootHash)
	if err != nil {
		return err
	}

	// Any nodes not referenced by another tapscript tree will now not be
	// referenced by any edges. Delete all such nodes. This will only affect
	// nodes from this tree, as nodes in a properly inserted tree are
	// referenced by at least one edge.
	err = q.DeleteTapscriptTreeNodes(ctx)
	if err != nil {
		return err
	}

	// With all edges and nodes deleted, delete the root hash.
	err = q.DeleteTapscriptTreeRoot(ctx, rootHash)
	if err != nil {
		return err
	}

	return nil
}
