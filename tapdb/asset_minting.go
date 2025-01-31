package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"golang.org/x/exp/maps"
)

type (
	// BatchStateUpdate holds the arguments to update the state of a batch.
	BatchStateUpdate = sqlc.UpdateMintingBatchStateParams

	// InternalKey holds the arguments to update an internal key.
	InternalKey = sqlc.UpsertInternalKeyParams

	// AssetSeedlingShell holds the components of a seedling asset.
	AssetSeedlingShell = sqlc.InsertAssetSeedlingParams

	// AssetSeedlingItem is used to insert a seedling into an asset based
	// on the batch key of the batch.
	AssetSeedlingItem = sqlc.InsertAssetSeedlingIntoBatchParams

	// MintingBatchI is an alias for a minting batch including the internal
	// key info. This is used to query for batches where the state doesn't
	// match a certain value.
	MintingBatchI = sqlc.FetchMintingBatchesByInverseStateRow

	// MintingBatchF is an alias for a specific minting batch.
	MintingBatchF = sqlc.FetchMintingBatchRow

	// MintingBatchA is an alias for a minting batch returned when querying
	// for all minting batches.
	MintingBatchA = sqlc.AllMintingBatchesRow

	// AssetSeedling is an asset seedling.
	AssetSeedling = sqlc.AssetSeedling

	// AssetSeedlingTuple is used to look up the ID of a seedling.
	AssetSeedlingTuple = sqlc.FetchSeedlingIDParams

	// MintingBatchTuple is used to update a batch state based on the raw
	// key.
	MintingBatchTuple = sqlc.UpdateMintingBatchStateParams

	// AssetGroupKey is used to insert a new asset key group into the DB.
	AssetGroupKey = sqlc.UpsertAssetGroupKeyParams

	// BatchTapSiblingUpdate is used to update a batch with the root hash
	// of a tapscript sibling associated with it.
	BatchTapSiblingUpdate = sqlc.BindMintingBatchWithTapSiblingParams

	// BatchChainUpdate is used to update a batch with the minting
	// transaction associated with it.
	BatchChainUpdate = sqlc.BindMintingBatchWithTxParams

	// GenesisTxUpdate is used to update the existing batch TX associated
	// with a batch.
	GenesisTxUpdate = sqlc.UpdateBatchGenesisTxParams

	// RawManagedUTXO is used to insert a new managed UTXO into the
	// database.
	RawManagedUTXO = sqlc.UpsertManagedUTXOParams

	// SetAssetSpentParams is used to mark an asset as spent.
	SetAssetSpentParams = sqlc.SetAssetSpentParams

	// AssetAnchor is used to bind assets on disk with the transaction that
	// will create them on-chain.
	AssetAnchor = sqlc.AnchorPendingAssetsParams

	// GenesisPointAnchor is used to update the genesis point with the
	// final information w.r.t where it's confirmed on chain.
	GenesisPointAnchor = sqlc.AnchorGenesisPointParams

	// ChainTxParams is used to insert a new chain tx on disk.
	ChainTxParams = sqlc.UpsertChainTxParams

	// ChainTx is used to fetch a chain tx from disk.
	ChainTx = sqlc.ChainTxn

	// ChainTxConf is used to mark a chain tx as being confirmed.
	ChainTxConf = sqlc.ConfirmChainTxParams

	// GenesisAsset is used to insert the base information of an asset into
	// the DB.
	GenesisAsset = sqlc.UpsertGenesisAssetParams

	// AssetGroupWitness is used to insert the group key witness for a given
	// asset on disk.
	AssetGroupWitness = sqlc.UpsertAssetGroupWitnessParams

	// AssetSprout is used to fetch the set of assets from disk.
	AssetSprout = sqlc.FetchAssetsForBatchRow

	// MintingBatchInit is used to create a new minting batch.
	MintingBatchInit = sqlc.NewMintingBatchParams

	// ProofUpdateByID is used to update a proof file on disk by asset
	// database ID.
	ProofUpdateByID = sqlc.UpsertAssetProofByIDParams

	// FetchAssetID is used to fetch the primary key ID of an asset, by
	// outpoint and tweaked script key.
	FetchAssetID = sqlc.FetchAssetIDParams

	// NewScriptKey wraps the params needed to insert a new script key on
	// disk.
	NewScriptKey = sqlc.UpsertScriptKeyParams

	// NewAssetMeta wraps the params needed to insert a new asset meta on
	// disk.
	NewAssetMeta = sqlc.UpsertAssetMetaParams
)

// PendingAssetStore is a sub-set of the main sqlc.Querier interface that
// contains only the methods needed to drive the process of batching and
// creating a new set of assets.
type PendingAssetStore interface {
	// UpsertAssetStore houses the methods related to inserting/updating
	// assets.
	UpsertAssetStore

	// GroupStore houses the methods related to querying asset groups.
	GroupStore

	// FetchScriptKeyStore houses the methods related to fetching all
	// information about a script key.
	FetchScriptKeyStore

	// TapscriptTreeStore houses the methods related to storing, fetching,
	// and deleting tapscript trees.
	TapscriptTreeStore

	// NewMintingBatch creates a new minting batch.
	NewMintingBatch(ctx context.Context, arg MintingBatchInit) error

	// UpdateMintingBatchState updates the state of an existing minting
	// batch.
	UpdateMintingBatchState(ctx context.Context,
		arg BatchStateUpdate) error

	// InsertAssetSeedling inserts a new asset seedling (base description)
	// into the database.
	InsertAssetSeedling(ctx context.Context, arg AssetSeedlingShell) error

	// InsertAssetSeedlingIntoBatch inserts a new asset seedling into a
	// batch based on the batch key its included in.
	InsertAssetSeedlingIntoBatch(ctx context.Context,
		arg AssetSeedlingItem) error

	// AllMintingBatches is used to fetch all minting batches.
	AllMintingBatches(ctx context.Context) ([]MintingBatchA, error)

	// FetchMintingBatchesByInverseState is used to fetch minting batches
	// that don't have a particular state.
	FetchMintingBatchesByInverseState(ctx context.Context,
		batchState int16) ([]MintingBatchI, error)

	// FetchMintingBatch is used to fetch a single minting batch specified
	// by the batch key.
	FetchMintingBatch(ctx context.Context,
		rawKey []byte) (MintingBatchF, error)

	// FetchSeedlingsForBatch is used to fetch all the seedlings by the key
	// of the batch they're included in.
	FetchSeedlingsForBatch(ctx context.Context,
		rawKey []byte) ([]sqlc.FetchSeedlingsForBatchRow, error)

	// FetchSeedlingID is used to look up the ID of a specific seedling
	// in a batch.
	FetchSeedlingID(ctx context.Context, arg AssetSeedlingTuple) (int64,
		error)

	// FetchSeedlingByID is used to look up a specific seedling.
	FetchSeedlingByID(ctx context.Context,
		seedlingID int64) (AssetSeedling, error)

	// BindMintingBatchWithTapSibling adds a tapscript tree root hash to an
	// existing batch.
	BindMintingBatchWithTapSibling(ctx context.Context,
		arg BatchTapSiblingUpdate) error

	// BindMintingBatchWithTx adds the minting transaction to an existing
	// batch.
	BindMintingBatchWithTx(ctx context.Context, arg BatchChainUpdate) error

	// UpdateBatchGenesisTx updates the batch tx attached to an existing
	// batch.
	UpdateBatchGenesisTx(ctx context.Context, arg GenesisTxUpdate) error

	// UpsertManagedUTXO inserts a new or updates an existing managed UTXO
	// to disk and returns the primary key.
	UpsertManagedUTXO(ctx context.Context, arg RawManagedUTXO) (int64,
		error)

	// AnchorPendingAssets associated an asset on disk with the transaction
	// that once confirmed will mint the asset.
	AnchorPendingAssets(ctx context.Context, arg AssetAnchor) error

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTxParams) (int64, error)

	// ConfirmChainTx confirms an existing chain tx.
	ConfirmChainTx(ctx context.Context, arg ChainTxConf) error

	// FetchAssetsForBatch fetches all the assets created by a particular
	// batch.
	FetchAssetsForBatch(ctx context.Context, rawKey []byte) ([]AssetSprout,
		error)

	// FetchAssetID fetches the `asset_id` (primary key) from the assets
	// table for a given asset identified by `Outpoint` and
	// `TweakedScriptKey`.
	FetchAssetID(ctx context.Context, arg FetchAssetID) ([]int64, error)

	// UpsertAssetProofByID inserts a new or updates an existing asset
	// proof on disk.
	UpsertAssetProofByID(ctx context.Context, arg ProofUpdateByID) error

	// FetchAssetMetaForAsset fetches the asset meta for a given asset.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID []byte) (sqlc.FetchAssetMetaForAssetRow, error)
}

var (
	// ErrFetchMintingBatches is returned when fetching multiple minting
	// batches fails.
	ErrFetchMintingBatches = errors.New("unable to fetch minting batches")

	// ErrBatchParsing is returned when parsing a fetching minting batch
	// fails.
	ErrBatchParsing = errors.New("unable to parse batch")

	// ErrBindBatchTx is returned when binding a tx to a minting batch
	// fails.
	ErrBindBatchTx = errors.New("unable to bind batch tx")

	// ErrEcodePsbt is returned when serializing a PSBT fails.
	ErrEncodePsbt = errors.New("unable to encode psbt")
)

// AssetStoreTxOptions defines the set of db txn options the PendingAssetStore
// understands.
type AssetStoreTxOptions struct {
	// readOnly governs if a read only transaction is needed or not.
	readOnly bool
}

// ReadOnly returns true if the transaction should be read only.
//
// NOTE: This implements the TxOptions
func (r *AssetStoreTxOptions) ReadOnly() bool {
	return r.readOnly
}

// NewAssetStoreReadTx creates a new read transaction option set.
func NewAssetStoreReadTx() AssetStoreTxOptions {
	return AssetStoreTxOptions{
		readOnly: true,
	}
}

// BatchedPendingAssetStore combines the PendingAssetStore interface with the
// BatchedTx interface, allowing for multiple queries to be executed in a
// single SQL transaction.
type BatchedPendingAssetStore interface {
	PendingAssetStore

	BatchedTx[PendingAssetStore]
}

// AssetMintingStore is an implementation of the tapgarden.PlantingLog
// interface backed by a persistent database. The abstracted
// BatchedPendingAssetStore permits re-use of the main storage related business
// logic for any backend that can implement the specified interface.
type AssetMintingStore struct {
	db BatchedPendingAssetStore
}

// NewAssetMintingStore creates a new AssetMintingStore from the specified
// BatchedPendingAssetStore interface.
func NewAssetMintingStore(db BatchedPendingAssetStore) *AssetMintingStore {
	return &AssetMintingStore{
		db: db,
	}
}

// OptionalSeedlingFields contains database IDs for optional seedling fields
// that have been stored on disk.
type OptionalSeedlingFields struct {
	GroupInternalKeyID sql.NullInt64
	GroupGenesisID     sql.NullInt64
	GroupAnchorID      sql.NullInt64
}

// CommitMintingBatch commits a new minting batch to disk along with any
// seedlings specified as part of the batch. A new internal key is also
// created, with the batch referencing that internal key. This internal key
// will be used as the internal key which will mint all the assets in the
// batch.
func (a *AssetMintingStore) CommitMintingBatch(ctx context.Context,
	newBatch *tapgarden.MintingBatch) error {

	rawBatchKey := newBatch.BatchKey.PubKey.SerializeCompressed()

	var writeTxOpts AssetStoreTxOptions
	err := a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// First, we'll need to insert a new internal key which'll act
		// as the foreign key our batch references.
		batchID, err := q.UpsertInternalKey(ctx, InternalKey{
			RawKey:    rawBatchKey,
			KeyFamily: int32(newBatch.BatchKey.Family),
			KeyIndex:  int32(newBatch.BatchKey.Index),
		})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUpsertInternalKey, err)
		}

		// With our internal key inserted, we can now insert a new
		// batch which references the target internal key.
		if err := q.NewMintingBatch(ctx, MintingBatchInit{
			BatchID:          batchID,
			HeightHint:       int32(newBatch.HeightHint),
			CreationTimeUnix: newBatch.CreationTime.UTC(),
		}); err != nil {
			return fmt.Errorf("unable to insert minting "+
				"batch: %w", err)
		}

		// With the batch key and batch itself inserted, we can insert
		// the batch tapscript sibling if present.
		newBatchSibling := newBatch.TapSibling()
		if newBatchSibling != nil {
			tapSibling := BatchTapSiblingUpdate{
				RawKey:           rawBatchKey,
				TapscriptSibling: newBatchSibling,
			}
			err = q.BindMintingBatchWithTapSibling(ctx, tapSibling)
			if err != nil {
				return fmt.Errorf("unable to insert batch "+
					"sibling: %w", err)
			}
		}

		// If the batch is funded, we can also insert the batch TX and
		// batch genesis outpoint.
		if newBatch.GenesisPacket != nil {
			genesisPacket := newBatch.GenesisPacket
			genesisTx := genesisPacket.Pkt.UnsignedTx
			changeIdx := genesisPacket.ChangeOutputIndex
			genesisOutpoint := genesisTx.TxIn[0].PreviousOutPoint

			var psbtBuf bytes.Buffer
			err := genesisPacket.Pkt.Serialize(&psbtBuf)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrEncodePsbt, err)
			}

			genesisPointID, err := upsertGenesisPoint(
				ctx, q, genesisOutpoint,
			)
			if err != nil {
				return fmt.Errorf("%w: %w",
					ErrUpsertGenesisPoint, err)
			}

			err = q.BindMintingBatchWithTx(ctx, BatchChainUpdate{
				RawKey:            rawBatchKey,
				MintingTxPsbt:     psbtBuf.Bytes(),
				ChangeOutputIndex: sqlInt32(changeIdx),
				GenesisID:         sqlInt64(genesisPointID),
			})
			if err != nil {
				return fmt.Errorf("%w: %w", ErrBindBatchTx, err)
			}
		}

		// Now that our minting batch is in place, which references the
		// internal key inserted above, we can create the set of new
		// seedlings. We insert group anchors before other assets.
		orderedSeedlings := tapgarden.SortSeedlings(
			maps.Values(newBatch.Seedlings),
		)

		for _, seedlingName := range orderedSeedlings {
			seedling := newBatch.Seedlings[seedlingName]

			// If the seedling has a metadata field, we'll need to
			// insert that first so we can obtain meta primary key.
			assetMetaID, err := maybeUpsertAssetMeta(
				ctx, q, nil, seedling.Meta,
			)
			if err != nil {
				return err
			}

			dbSeedling := AssetSeedlingShell{
				BatchID:         batchID,
				AssetVersion:    int16(seedling.AssetVersion),
				AssetName:       seedling.AssetName,
				AssetType:       int16(seedling.AssetType),
				AssetSupply:     int64(seedling.Amount),
				AssetMetaID:     assetMetaID,
				EmissionEnabled: seedling.EnableEmission,
			}

			scriptKeyID, err := upsertScriptKey(
				ctx, seedling.ScriptKey, q,
			)
			if err != nil {
				return fmt.Errorf("unable to insert seedling "+
					"script key: %w", err)
			}

			dbSeedling.ScriptKeyID = sqlInt64(scriptKeyID)

			tapscriptRootSize := len(seedling.GroupTapscriptRoot)
			if tapscriptRootSize != 0 &&
				tapscriptRootSize != sha256.Size {

				return ErrTapscriptRootSize
			}

			dbSeedling.GroupTapscriptRoot = seedling.
				GroupTapscriptRoot

			optionalDbIDs, err := insertOptionalSeedlingParams(
				ctx, q, rawBatchKey, seedling,
			)
			if err != nil {
				return err
			}

			dbSeedling.GroupInternalKeyID =
				optionalDbIDs.GroupInternalKeyID
			dbSeedling.GroupGenesisID = optionalDbIDs.GroupGenesisID
			dbSeedling.GroupAnchorID = optionalDbIDs.GroupAnchorID

			err = q.InsertAssetSeedling(ctx, dbSeedling)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func insertOptionalSeedlingParams(ctx context.Context, q PendingAssetStore,
	batchKey []byte, seedling *tapgarden.Seedling) (OptionalSeedlingFields,
	error) {

	var (
		fieldIDs OptionalSeedlingFields
		err      error
	)

	if seedling.GroupInternalKey != nil {
		rawKeyBytes := seedling.GroupInternalKey.PubKey.
			SerializeCompressed()
		internalKeyID, err := q.UpsertInternalKey(ctx, InternalKey{
			RawKey:    rawKeyBytes,
			KeyFamily: int32(seedling.GroupInternalKey.Family),
			KeyIndex:  int32(seedling.GroupInternalKey.Index),
		})

		if err != nil {
			return fieldIDs, err
		}

		fieldIDs.GroupInternalKeyID = sqlInt64(internalKeyID)
	}

	// If this seedling is being issued to an existing group, we need to
	// reference the genesis that was first used to create the group.
	if seedling.HasGroupKey() {
		genesisID, err := fetchGenesisID(
			ctx, q, *seedling.GroupInfo.Genesis,
		)
		if err != nil {
			return fieldIDs, err
		}

		fieldIDs.GroupGenesisID = sqlInt64(genesisID)
	}

	// If this seedling is being issued to a group being created in this
	// batch, we need to reference the anchor seedling for the group.
	if seedling.GroupAnchor != nil {
		anchorID, err := fetchSeedlingID(
			ctx, q, batchKey, *seedling.GroupAnchor,
		)
		if err != nil {
			return fieldIDs, err
		}

		fieldIDs.GroupAnchorID = sqlInt64(anchorID)
	}

	return fieldIDs, err
}

// AddSeedlingsToBatch adds a new set of seedlings to an existing batch.
func (a *AssetMintingStore) AddSeedlingsToBatch(ctx context.Context,
	batchKey *btcec.PublicKey, seedlings ...*tapgarden.Seedling) error {

	rawBatchKey := batchKey.SerializeCompressed()

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// For each specified asset seedling, we'll insert them all
		// into the database in a single atomic transaction.
		//
		// TODO(roasbeef): can make sure to use the batch insert here
		// when postgres
		for _, seedling := range seedlings {
			// If the seedling has a metadata field, we'll need to
			// insert that first so we can obtain meta primary key.
			assetMetaID, err := maybeUpsertAssetMeta(
				ctx, q, nil, seedling.Meta,
			)
			if err != nil {
				return err
			}

			dbSeedling := AssetSeedlingItem{
				RawKey:          rawBatchKey,
				AssetVersion:    int16(seedling.AssetVersion),
				AssetName:       seedling.AssetName,
				AssetType:       int16(seedling.AssetType),
				AssetSupply:     int64(seedling.Amount),
				AssetMetaID:     assetMetaID,
				EmissionEnabled: seedling.EnableEmission,
			}

			scriptKeyID, err := upsertScriptKey(
				ctx, seedling.ScriptKey, q,
			)
			if err != nil {
				return fmt.Errorf("unable to insert seedling "+
					"script key: %w", err)
			}

			dbSeedling.ScriptKeyID = sqlInt64(scriptKeyID)

			tapscriptRootSize := len(seedling.GroupTapscriptRoot)
			if tapscriptRootSize != 0 &&
				tapscriptRootSize != sha256.Size {

				return ErrTapscriptRootSize
			}

			dbSeedling.GroupTapscriptRoot = seedling.
				GroupTapscriptRoot

			optionalDbIDs, err := insertOptionalSeedlingParams(
				ctx, q, rawBatchKey, seedling,
			)
			if err != nil {
				return err
			}

			dbSeedling.GroupInternalKeyID =
				optionalDbIDs.GroupInternalKeyID
			dbSeedling.GroupGenesisID = optionalDbIDs.GroupGenesisID
			dbSeedling.GroupAnchorID = optionalDbIDs.GroupAnchorID

			err = q.InsertAssetSeedlingIntoBatch(ctx, dbSeedling)
			if err != nil {
				return fmt.Errorf("unable to insert "+
					"seedling into db: %w", err)
			}
		}

		return nil
	})
}

// fetchSeedlingID attempts to fetch the ID for a seedling from a specific
// batch. This is performed within the context of a greater DB transaction.
func fetchSeedlingID(ctx context.Context, q PendingAssetStore, batchKey []byte,
	seedlingName string) (int64, error) {

	seedlingParams := AssetSeedlingTuple{
		SeedlingName: seedlingName,
		BatchKey:     batchKey,
	}

	return q.FetchSeedlingID(ctx, seedlingParams)
}

// fetchAssetSeedlings attempts to fetch a set of asset seedlings for a given
// batch. This is performed within the context of a greater DB transaction.
func fetchAssetSeedlings(ctx context.Context, q PendingAssetStore,
	rawBatchKey []byte) (map[string]*tapgarden.Seedling, error) {

	// Now that we have the main pieces of the batch, we'll fetch all the
	// seedlings for this batch and map them to the proper struct.
	dbSeedlings, err := q.FetchSeedlingsForBatch(
		ctx, rawBatchKey,
	)
	if err != nil {
		return nil, err
	}

	seedlings := make(map[string]*tapgarden.Seedling)
	for _, dbSeedling := range dbSeedlings {
		seedling := &tapgarden.Seedling{
			AssetVersion: asset.Version(dbSeedling.AssetVersion),
			AssetType: asset.Type(
				dbSeedling.AssetType,
			),
			AssetName: dbSeedling.AssetName,
			Amount: uint64(
				dbSeedling.AssetSupply,
			),
			EnableEmission: dbSeedling.EmissionEnabled,
		}

		if dbSeedling.TweakedScriptKey != nil {
			tweakedScriptKey, err := btcec.ParsePubKey(
				dbSeedling.TweakedScriptKey,
			)
			if err != nil {
				return nil, err
			}

			scriptKeyInternalPub, err := btcec.ParsePubKey(
				dbSeedling.ScriptKeyRaw,
			)
			if err != nil {
				return nil, err
			}

			scriptKeyLocator := keychain.KeyLocator{
				Index: extractSqlInt32[uint32](
					dbSeedling.ScriptKeyIndex,
				),
				Family: extractSqlInt32[keychain.KeyFamily](
					dbSeedling.ScriptKeyFam,
				),
			}

			scriptKeyRawKey := keychain.KeyDescriptor{
				KeyLocator: scriptKeyLocator,
				PubKey:     scriptKeyInternalPub,
			}
			scriptKeyTweak := dbSeedling.ScriptKeyTweak
			declaredKnown := extractBool(
				dbSeedling.ScriptKeyDeclaredKnown,
			)
			seedling.ScriptKey = asset.ScriptKey{
				PubKey: tweakedScriptKey,
				TweakedScriptKey: &asset.TweakedScriptKey{
					RawKey:        scriptKeyRawKey,
					Tweak:         scriptKeyTweak,
					DeclaredKnown: declaredKnown,
				},
			}
		}

		if dbSeedling.GroupKeyRaw != nil {
			groupKeyPub, err := btcec.ParsePubKey(
				dbSeedling.GroupKeyRaw,
			)
			if err != nil {
				return nil, err
			}

			groupKeyLocator := keychain.KeyLocator{
				Index: extractSqlInt32[uint32](
					dbSeedling.GroupKeyIndex,
				),
				Family: extractSqlInt32[keychain.KeyFamily](
					dbSeedling.GroupKeyFam,
				),
			}

			seedling.GroupInternalKey = &keychain.KeyDescriptor{
				KeyLocator: groupKeyLocator,
				PubKey:     groupKeyPub,
			}
		}

		if len(dbSeedling.GroupTapscriptRoot) != 0 {
			seedling.GroupTapscriptRoot = dbSeedling.
				GroupTapscriptRoot
		}

		// Fetch the group info for seedlings with a specific group.
		// There can only be one group per genesis.
		if dbSeedling.GroupGenesisID.Valid {
			genID := extractSqlInt64[int64](
				dbSeedling.GroupGenesisID,
			)
			seedlingGroup, err := fetchGroupByGenesis(ctx, q, genID)
			if err != nil {
				return nil, err
			}

			// Clear the group witness, which is for the group
			// anchor and not this seedling.
			seedlingGroup.Witness = nil

			seedling.GroupInfo = seedlingGroup
		}

		// Fetch the group anchor for seedlings with a group anchor set.
		if dbSeedling.GroupAnchorID.Valid {
			anchorID := extractSqlInt64[int64](
				dbSeedling.GroupAnchorID,
			)
			seedlingAnchor, err := q.FetchSeedlingByID(ctx, anchorID)
			if err != nil {
				return nil, err
			}

			seedling.GroupAnchor = &seedlingAnchor.AssetName
		}

		metaOpt, err := parseAssetMetaReveal(dbSeedling.AssetsMetum)
		if err != nil {
			return nil, fmt.Errorf("unable to parse asset meta: %w",
				err)
		}

		metaOpt.WhenSome(func(meta proof.MetaReveal) {
			seedling.Meta = &meta
		})

		seedlings[seedling.AssetName] = seedling
	}

	return seedlings, nil
}

// fetchAssetSprouts fetches all the asset sprouts, or unconfirmed assets
// associated with a given batch. The assets are them inserted into a Taproot
// Asset commitment for easy handling.
//
// NOTE: In order for this query to work properly, until
// https://github.com/kyleconroy/sqlc/issues/1334 is fixed in sqlc, after code
// generation, the GroupKeyFamily and GroupKeyIndex fields of the
// FetchAssetsForBatchRow need to be manually modified to be sql.NullInt32.
func fetchAssetSprouts(ctx context.Context, q PendingAssetStore,
	rawBatchKey, batchSibling, genScript []byte) (*commitment.TapCommitment,
	error) {

	dbSprout, err := q.FetchAssetsForBatch(ctx, rawBatchKey)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch batch assets: %w", err)
	}

	if len(dbSprout) == 0 {
		return nil, fmt.Errorf("no sprouts found for batch %x",
			rawBatchKey)
	}

	// We collect all the sprouts into fully grown assets, from which we'll
	// then create asset and tap level commitments.
	sprouts := make([]*asset.Asset, len(dbSprout))
	for i, sprout := range dbSprout {
		// First, we'll decode the script key which very asset must
		// specify, and populate the key locator information
		tweakedScriptKey, err := btcec.ParsePubKey(
			sprout.TweakedScriptKey,
		)
		if err != nil {
			return nil, err
		}

		internalScriptKey, err := btcec.ParsePubKey(
			sprout.ScriptKeyRaw,
		)
		if err != nil {
			return nil, err
		}

		scriptKeyDesc := keychain.KeyDescriptor{
			PubKey: internalScriptKey,
			KeyLocator: keychain.KeyLocator{
				Index:  uint32(sprout.ScriptKeyIndex),
				Family: keychain.KeyFamily(sprout.ScriptKeyFam),
			},
		}
		declaredKnown := extractBool(sprout.ScriptKeyDeclaredKnown)
		scriptKey := asset.ScriptKey{
			PubKey: tweakedScriptKey,
			TweakedScriptKey: &asset.TweakedScriptKey{
				RawKey:        scriptKeyDesc,
				Tweak:         sprout.Tweak,
				DeclaredKnown: declaredKnown,
			},
		}

		// Not all assets have a key group, so we only need to
		// populate this information for those that signalled the
		// requirement of on going emission.
		var groupKey *asset.GroupKey
		if sprout.TweakedGroupKey != nil {
			tweakedGroupKey, err := btcec.ParsePubKey(
				sprout.TweakedGroupKey,
			)
			if err != nil {
				return nil, err
			}
			rawGroupKey, err := btcec.ParsePubKey(sprout.GroupKeyRaw)
			if err != nil {
				return nil, err
			}
			groupWitness, err := asset.ParseGroupWitness(
				sprout.WitnessStack,
			)
			if err != nil {
				return nil, err
			}

			groupKey = &asset.GroupKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: rawGroupKey,
					KeyLocator: keychain.KeyLocator{
						Index: extractSqlInt32[uint32](
							sprout.GroupKeyIndex,
						),
						Family: extractSqlInt32[keychain.KeyFamily](
							sprout.GroupKeyFamily,
						),
					},
				},
				GroupPubKey: *tweakedGroupKey,
				Witness:     groupWitness,
			}

			if len(sprout.TapscriptRoot) != 0 {
				groupKey.TapscriptRoot = sprout.TapscriptRoot
			}
		}

		// Next, we'll populate the asset genesis information which
		// includes the genesis prev out, and the other information
		// needed to derive an asset ID.
		var genesisPrevOut wire.OutPoint
		if err := readOutPoint(
			bytes.NewReader(sprout.GenesisPrevOut), 0, 0,
			&genesisPrevOut,
		); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrReadOutpoint, err)
		}
		assetGenesis := asset.Genesis{
			FirstPrevOut: genesisPrevOut,
			Tag:          sprout.AssetTag,
			OutputIndex:  uint32(sprout.GenesisOutputIndex),
			Type:         asset.Type(sprout.AssetType),
		}

		if len(sprout.AssetsMetum.MetaDataHash) != 0 {
			copy(
				assetGenesis.MetaHash[:],
				sprout.AssetsMetum.MetaDataHash,
			)
		}

		// With the base information extracted, we'll use that to
		// create either a normal asset or a collectible.
		lockTime := extractSqlInt32[uint64](sprout.LockTime)
		relativeLocktime := extractSqlInt32[uint64](
			sprout.RelativeLockTime,
		)
		var amount uint64
		switch asset.Type(sprout.AssetType) {
		case asset.Normal:
			amount = uint64(sprout.Amount)
		case asset.Collectible:
			amount = 1
		}

		assetSprout, err := asset.New(
			assetGenesis, amount, lockTime, relativeLocktime,
			scriptKey, groupKey,
			asset.WithAssetVersion(asset.Version(sprout.Version)),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new sprout: "+
				"%w", err)
		}

		// TODO(roasbeef): need to update the above to set the
		// witnesses of a valid asset
		sprouts[i] = assetSprout
	}

	// Verify that we can reconstruct the genesis output script used in the
	// anchor TX.
	batchKey, err := btcec.ParsePubKey(rawBatchKey)
	if err != nil {
		return nil, err
	}

	var tapSibling *chainhash.Hash
	if len(batchSibling) != 0 {
		tapSibling, err = chainhash.NewHash(batchSibling)
		if err != nil {
			return nil, err
		}
	}

	return tapgarden.VerifyOutputScript(
		batchKey, tapSibling, genScript, sprouts,
	)
}

// fetchAssetMetas attempts to fetch the asset meta reveal for each of the
// passed assets.
func fetchAssetMetas(ctx context.Context, db PendingAssetStore,
	assets []*asset.Asset) (map[asset.SerializedKey]*proof.MetaReveal,
	error) {

	assetMetas := make(map[asset.SerializedKey]*proof.MetaReveal)
	for _, assetT := range assets {
		assetID := assetT.ID()

		assetMeta, err := fetchMetaByAssetID(ctx, db, assetID)
		if err != nil {
			return nil, err
		}

		// If the asset doesn't have a meta data reveal, then we can
		// skip it.
		if assetMeta == nil {
			continue
		}

		scriptKey := asset.ToSerialized(assetT.ScriptKey.PubKey)
		assetMetas[scriptKey] = assetMeta
	}

	return assetMetas, nil
}

// fetchMetaByAssetID fetches a single asset meta reveal.
func fetchMetaByAssetID(ctx context.Context, db PendingAssetStore,
	ID asset.ID) (*proof.MetaReveal, error) {

	assetMeta, err := db.FetchAssetMetaForAsset(ctx, ID[:])
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil

	case err != nil:
		return nil, err
	}

	// Parse the meta reveal from the database. We expect it to exist at
	// this point, as we didn't get an sql.ErrNoRows error above.
	metaOpt, err := parseAssetMetaReveal(assetMeta.AssetsMetum)
	if err != nil {
		return nil, fmt.Errorf("unable to parse asset meta: %w", err)
	}

	meta, err := metaOpt.UnwrapOrErr(ErrNoAssetMeta)
	if err != nil {
		return nil, err
	}

	return &meta, nil
}

// FetchAssetMeta fetches the meta reveal for an asset genesis.
func (a *AssetMintingStore) FetchAssetMeta(ctx context.Context,
	ID asset.ID) (*proof.MetaReveal, error) {

	var assetMeta *proof.MetaReveal

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		var err error
		assetMeta, err = fetchMetaByAssetID(ctx, q, ID)
		if err != nil {
			return err
		}

		return nil
	})

	if dbErr != nil {
		return nil, dbErr
	}

	return assetMeta, nil
}

// FetchNonFinalBatches fetches all the batches that aren't fully finalized on
// disk.
func (a *AssetMintingStore) FetchNonFinalBatches(
	ctx context.Context) ([]*tapgarden.MintingBatch, error) {

	var batches []*tapgarden.MintingBatch

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		// First, we'll fetch all batches that aren't in a final state.
		dbBatches, err := q.FetchMintingBatchesByInverseState(
			ctx, int16(tapgarden.BatchStateFinalized),
		)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFetchMintingBatches, err)
		}

		parseBatch := func(batch MintingBatchI) (*tapgarden.MintingBatch,
			error) {

			return marshalMintingBatch(ctx, q, MintingBatchF(batch))
		}

		batches, err = fn.MapErr(dbBatches, parseBatch)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBatchParsing, err)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return batches, nil
}

// FetchAllBatches fetches all batches on disk.
func (a *AssetMintingStore) FetchAllBatches(
	ctx context.Context) ([]*tapgarden.MintingBatch, error) {

	var batches []*tapgarden.MintingBatch

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		dbBatches, err := q.AllMintingBatches(ctx)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFetchMintingBatches, err)
		}

		parseBatch := func(batch MintingBatchA) (*tapgarden.MintingBatch,
			error) {

			return marshalMintingBatch(ctx, q, MintingBatchF(batch))
		}

		batches, err = fn.MapErr(dbBatches, parseBatch)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBatchParsing, err)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return batches, nil
}

// FetchMintingBatch fetches the single batch with the given batch key.
func (a *AssetMintingStore) FetchMintingBatch(ctx context.Context,
	batchKey *btcec.PublicKey) (*tapgarden.MintingBatch, error) {

	if batchKey == nil {
		return nil, fmt.Errorf("no batch key")
	}

	var batch *tapgarden.MintingBatch
	batchKeyBytes := batchKey.SerializeCompressed()

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		dbBatch, err := q.FetchMintingBatch(ctx, batchKeyBytes)
		if err != nil {
			return err
		}

		batch, err = marshalMintingBatch(ctx, q, dbBatch)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBatchParsing, err)
		}

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, fmt.Errorf("no batch with key %x", batchKeyBytes)
	case dbErr != nil:
		return nil, dbErr
	}

	return batch, nil
}

// marshalMintingBatch marshals a minting batch into its native type,
// and fetches the corresponding seedlings or root Taproot Asset commitment.
func marshalMintingBatch(ctx context.Context, q PendingAssetStore,
	dbBatch MintingBatchF) (*tapgarden.MintingBatch, error) {

	batchKey, err := btcec.ParsePubKey(dbBatch.RawKey)
	if err != nil {
		return nil, err
	}

	// For each batch, we'll assemble an intermediate batch struct, then
	// fill in all the seedlings with another sub-query.
	batch := &tapgarden.MintingBatch{
		BatchKey: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(
					dbBatch.KeyFamily,
				),
				Index: uint32(dbBatch.KeyIndex),
			},
			PubKey: batchKey,
		},
		HeightHint:   uint32(dbBatch.HeightHint),
		CreationTime: dbBatch.CreationTimeUnix.UTC(),
	}

	batchState, err := tapgarden.NewBatchState(uint8(dbBatch.BatchState))
	if err != nil {
		return nil, err
	}

	batch.UpdateState(batchState)

	if len(dbBatch.TapscriptSibling) != 0 {
		batchSibling, err := chainhash.NewHash(dbBatch.TapscriptSibling)
		if err != nil {
			return nil, err
		}

		batch.UpdateTapSibling(batchSibling)
	}

	if dbBatch.MintingTxPsbt != nil {
		genesisPkt, err := psbt.NewFromRawBytes(
			bytes.NewReader(dbBatch.MintingTxPsbt), false,
		)
		if err != nil {
			return nil, err
		}
		batch.GenesisPacket = &tapsend.FundedPsbt{
			Pkt: genesisPkt,
			ChangeOutputIndex: extractSqlInt32[int32](
				dbBatch.ChangeOutputIndex,
			),
		}
	}

	// Depending on what state this batch is in, we'll either return the set
	// of seedlings (asset descriptions w/ no real assets), or the set of
	// sprouts (full defined assets, but not yet mined). In all cases, we
	// start by fetching the batch seedlings.
	batchSeedlings, err := fetchAssetSeedlings(
		ctx, q, dbBatch.RawKey,
	)
	if err != nil {
		return nil, err
	}

	switch batchState {
	// A batch in these states will only have seedlings.
	case tapgarden.BatchStatePending,
		tapgarden.BatchStateFrozen,
		tapgarden.BatchStateSeedlingCancelled:

		batch.Seedlings = batchSeedlings

	// For finalized batches, we need to fetch the assets from the proof
	// archiver and not the DB. Set the batch seedlings here so they can be
	// used later to fetch those proofs.
	case tapgarden.BatchStateFinalized:
		// A finalized batch must have a populated genesis packet.
		if batch.GenesisPacket == nil {
			return nil, fmt.Errorf("sprouted batch missing " +
				"genesis packet")
		}

		batch.Seedlings = batchSeedlings

	default:
		if batch.GenesisPacket == nil {
			return nil, fmt.Errorf("sprouted batch missing " +
				"genesis packet")
		}

		anchorOutputIndex := uint32(0)
		if batch.GenesisPacket.ChangeOutputIndex == 0 {
			anchorOutputIndex = 1
		}
		genesisTx := batch.GenesisPacket.Pkt.UnsignedTx
		genesisScript := genesisTx.TxOut[anchorOutputIndex].PkScript
		tapscriptSibling := batch.TapSibling()
		batch.RootAssetCommitment, err = fetchAssetSprouts(
			ctx, q, dbBatch.RawKey, tapscriptSibling, genesisScript,
		)
		if err != nil {
			return nil, err
		}

		// Finally, for each asset contained in the root
		// commitment above, we'll fetch the meta reveal for
		// the asset, if it has one.
		assetRoot := batch.RootAssetCommitment
		assetsInBatch := assetRoot.CommittedAssets()
		batch.AssetMetas, err = fetchAssetMetas(
			ctx, q, assetsInBatch,
		)
		if err != nil {
			return nil, err
		}
	}

	return batch, nil
}

// UpdateBatchState updates the state of a batch based on the batch key.
func (a *AssetMintingStore) UpdateBatchState(ctx context.Context,
	batchKey *btcec.PublicKey, newState tapgarden.BatchState) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		return q.UpdateMintingBatchState(ctx, BatchStateUpdate{
			RawKey:     batchKey.SerializeCompressed(),
			BatchState: int16(newState),
		})
	})
}

// CommitBatchTapSibling updates the tapscript sibling of a batch based on the
// batch key.
func (a *AssetMintingStore) CommitBatchTapSibling(ctx context.Context,
	batchKey *btcec.PublicKey, batchSibling *chainhash.Hash) error {

	siblingUpdate := BatchTapSiblingUpdate{
		RawKey:           batchKey.SerializeCompressed(),
		TapscriptSibling: batchSibling[:],
	}

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		return q.BindMintingBatchWithTapSibling(ctx, siblingUpdate)
	})
}

// encodeOutpoint encodes the outpoint point in Bitcoin wire format, returning
// the final result.
func encodeOutpoint(outPoint wire.OutPoint) ([]byte, error) {
	var b bytes.Buffer
	err := wire.WriteOutPoint(&b, 0, 0, &outPoint)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// CommitBatchTx updates the genesis transaction of a batch based on the batch
// key.
func (a *AssetMintingStore) CommitBatchTx(ctx context.Context,
	batchKey *btcec.PublicKey, genesisPacket *tapsend.FundedPsbt) error {

	genesisOutpoint := genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	rawBatchKey := batchKey.SerializeCompressed()

	var psbtBuf bytes.Buffer
	if err := genesisPacket.Pkt.Serialize(&psbtBuf); err != nil {
		return fmt.Errorf("%w: %w", ErrEncodePsbt, err)
	}

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		genesisPointID, err := upsertGenesisPoint(
			ctx, q, genesisOutpoint,
		)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUpsertGenesisPoint, err)
		}

		return q.BindMintingBatchWithTx(ctx, BatchChainUpdate{
			RawKey:        rawBatchKey,
			MintingTxPsbt: psbtBuf.Bytes(),
			ChangeOutputIndex: sqlInt32(
				genesisPacket.ChangeOutputIndex,
			),
			GenesisID: sqlInt64(genesisPointID),
		})
	})
}

// AddSeedlingGroups stores the asset groups for seedlings associated with a
// batch.
func (a *AssetMintingStore) AddSeedlingGroups(ctx context.Context,
	genesisOutpoint wire.OutPoint, assetGroups []*asset.AssetGroup) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// fetch the outpoint ID inserted during funding
		genesisPointID, err := upsertGenesisPoint(
			ctx, q, genesisOutpoint,
		)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUpsertGenesisPoint, err)
		}

		// insert genesis and group key
		for idx := range assetGroups {
			genAssetID, err := upsertGenesis(
				ctx, q, genesisPointID,
				*assetGroups[idx].Genesis,
			)
			if err != nil {
				return fmt.Errorf("unable to upsert grouped "+
					"seedling genesis: %w", err)
			}

			_, err = upsertGroupKey(
				ctx, assetGroups[idx].GroupKey, q,
				genesisPointID, genAssetID,
			)
			if err != nil {
				return fmt.Errorf("unable to upsert group for "+
					"grouped seedling: %w", err)
			}
		}

		return nil
	})
}

// FetchSeedlingGroups is used to fetch the asset groups for seedlings
// associated with a funded batch.
func (a *AssetMintingStore) FetchSeedlingGroups(ctx context.Context,
	genPoint wire.OutPoint, anchorOutputIndex uint32,
	seedlings []*tapgarden.Seedling) ([]*asset.AssetGroup, error) {

	var (
		seedlingGroups []*asset.AssetGroup
		err            error
	)

	seedlingGens := fn.Map(seedlings,
		func(s *tapgarden.Seedling) *asset.Genesis {
			return fn.Ptr(s.Genesis(genPoint, anchorOutputIndex))
		},
	)

	// Read geneses and asset groups.
	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		seedlingGroups, err = fetchSeedlingGroups(ctx, q, seedlingGens)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return seedlingGroups, nil
}

// fetchSeedlingGroups fetches the asset groups for multiple geneses.
func fetchSeedlingGroups(ctx context.Context, q PendingAssetStore,
	gens []*asset.Genesis) ([]*asset.AssetGroup, error) {

	seedlingGroups := make([]*asset.AssetGroup, 0, len(gens))
	for _, gen := range gens {
		genID, err := fetchGenesisID(ctx, q, *gen)
		if err != nil {
			// Re-map the error about a missing asset
			// genesis so it can be better handled in the
			// planter.
			if errors.Is(err, ErrFetchGenesisID) {
				return nil, tapgarden.ErrNoGenesis
			}

			return nil, err
		}

		groupKey, err := fetchGroupByGenesis(ctx, q, genID)
		if err != nil {
			return nil, err
		}

		seedlingGroups = append(seedlingGroups, groupKey)
	}

	return seedlingGroups, nil
}

// AddSproutsToBatch updates a batch with the passed batch transaction and also
// binds the genesis transaction (which will create the set of assets in the
// batch) to the batch itself.
func (a *AssetMintingStore) AddSproutsToBatch(ctx context.Context,
	batchKey *btcec.PublicKey, genesisPacket *tapsend.FundedPsbt,
	assetRoot *commitment.TapCommitment) error {

	// Before we open the DB transaction below, we'll fetch the set of
	// assets committed to within the root commitment specified.
	assets := assetRoot.CommittedAssets()

	// Before we store any assets from the batch, we need to sort the assets
	// so that we insert group anchors before reissunces. This is required
	// to store the asset genesis as the group anchor. All future group
	// anchor verification depends on inserting group anchors before
	// reissuances here. We use the raw group anchor verifier since there
	// is not yet any stored asset group to reference in the verifier.
	anchorVerifier := tapgarden.GenRawGroupAnchorVerifier(ctx)
	anchorAssets, nonAnchorAssets, err := tapgarden.SortAssets(
		assets, anchorVerifier,
	)
	if err != nil {
		return fmt.Errorf("unable to sort assets: %w", err)
	}

	sortedAssets := append(anchorAssets, nonAnchorAssets...)

	genesisOutpoint := genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint

	rawBatchKey := batchKey.SerializeCompressed()

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		genesisPointID, _, err := upsertAssetsWithGenesis(
			ctx, q, genesisOutpoint, sortedAssets, nil,
		)
		if err != nil {
			return fmt.Errorf("error inserting assets with "+
				"genesis: %w", err)
		}

		// With all the assets inserted, we'll now update the
		// corresponding batch that references all these assets with
		// the genesis packet, and genesis point information.
		var psbtBuf bytes.Buffer
		if err := genesisPacket.Pkt.Serialize(&psbtBuf); err != nil {
			return fmt.Errorf("%w: %w", ErrEncodePsbt, err)
		}
		err = q.BindMintingBatchWithTx(ctx, BatchChainUpdate{
			RawKey:        rawBatchKey,
			MintingTxPsbt: psbtBuf.Bytes(),
			ChangeOutputIndex: sqlInt32(
				genesisPacket.ChangeOutputIndex,
			),
			GenesisID: sqlInt64(genesisPointID),
		})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBindBatchTx, err)
		}

		// Finally, update the batch state to BatchStateCommitted.
		return q.UpdateMintingBatchState(ctx, BatchStateUpdate{
			RawKey:     rawBatchKey,
			BatchState: int16(tapgarden.BatchStateCommitted),
		})
	})
}

// CommitSignedGenesisTx binds a fully signed genesis transaction to a pending
// batch on disk. The anchor output index and script root are also stored to
// ensure we can reconstruct the private key needed to sign for the batch. The
// genesis transaction itself is inserted as a new chain transaction, which all
// other components then reference.
//
// TODO(roasbeef): or could just re-read assets from disk and set the script
// root manually?
func (a *AssetMintingStore) CommitSignedGenesisTx(ctx context.Context,
	batchKey *btcec.PublicKey, genesisPkt *tapsend.FundedPsbt,
	anchorOutputIndex uint32, merkleRoot, tapTreeRoot []byte,
	tapSibling []byte) error {

	// The managed UTXO we'll insert only contains the raw tx of the
	// genesis packet, so we'll extract that now.
	//
	// TODO(roasbeef): lift all this above so don't need to encode, etc --
	// also below?
	var txBuf bytes.Buffer
	rawGenTx, err := psbt.Extract(genesisPkt.Pkt)
	if err != nil {
		return fmt.Errorf("unable to extract psbt packet: %w", err)
	}
	if err := rawGenTx.Serialize(&txBuf); err != nil {
		return err
	}

	genTXID := rawGenTx.TxHash()

	rawBatchKey := batchKey.SerializeCompressed()

	anchorOutput := rawGenTx.TxOut[anchorOutputIndex]
	anchorPoint := wire.OutPoint{
		Hash:  rawGenTx.TxHash(),
		Index: anchorOutputIndex,
	}
	anchorOutpoint, err := encodeOutpoint(anchorPoint)
	if err != nil {
		return err
	}

	genesisPoint := genesisPkt.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	genesisOutpoint, err := encodeOutpoint(genesisPoint)
	if err != nil {
		return err
	}

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// First, we'll update the genesis packet stored as part of the
		// batch, as this packet is now fully signed.
		var psbtBuf bytes.Buffer
		if err := genesisPkt.Pkt.Serialize(&psbtBuf); err != nil {
			return err
		}
		err := q.UpdateBatchGenesisTx(ctx, GenesisTxUpdate{
			RawKey:        rawBatchKey,
			MintingTxPsbt: psbtBuf.Bytes(),
		})
		if err != nil {
			return fmt.Errorf("unable to update genesis tx: %w",
				err)
		}

		// Before we can insert a managed UTXO, we'll need to insert a
		// chain transaction, as that chain transaction will be
		// referenced by the managed UTXO.
		chainTXID, err := q.UpsertChainTx(ctx, ChainTxParams{
			Txid:      genTXID[:],
			RawTx:     txBuf.Bytes(),
			ChainFees: genesisPkt.ChainFees,
		})
		if err != nil {
			return fmt.Errorf("unable to insert chain tx: %w", err)
		}

		// Now that the genesis tx has been updated within the main
		// batch, we'll create a new managed UTXO for this batch as
		// this is where all the assets will be anchored within.
		rootVersion := uint8(commitment.TapCommitmentV2)
		utxoID, err := q.UpsertManagedUTXO(ctx, RawManagedUTXO{
			RawKey:           rawBatchKey,
			Outpoint:         anchorOutpoint,
			AmtSats:          anchorOutput.Value,
			TaprootAssetRoot: tapTreeRoot,
			TapscriptSibling: tapSibling,
			MerkleRoot:       merkleRoot,
			TxnID:            chainTXID,
			RootVersion:      sqlInt16(rootVersion),
		})
		if err != nil {
			return fmt.Errorf("unable to insert managed utxo: %w",
				err)
		}

		// With the managed UTXO inserted, we also need to update all
		// the assets created in a prior step to also reference this
		// managed UTXO.
		err = q.AnchorPendingAssets(ctx, AssetAnchor{
			PrevOut:      genesisOutpoint,
			AnchorUtxoID: sqlInt64(utxoID),
		})
		if err != nil {
			return fmt.Errorf("unable to anchor pending assets: %w",
				err)
		}

		// Next, we'll anchor the genesis point-to-point to the chain
		// transaction we inserted above.
		if err := q.AnchorGenesisPoint(ctx, GenesisPointAnchor{
			PrevOut:    genesisOutpoint,
			AnchorTxID: sqlInt64(chainTXID),
		}); err != nil {
			return fmt.Errorf("unable to anchor genesis tx: %w",
				err)
		}

		// Finally, update the batch state to BatchStateBroadcast.
		return q.UpdateMintingBatchState(ctx, BatchStateUpdate{
			RawKey:     rawBatchKey,
			BatchState: int16(tapgarden.BatchStateBroadcast),
		})
	})
}

// MarkBatchConfirmed stores final confirmation information for a batch on
// disk.
func (a *AssetMintingStore) MarkBatchConfirmed(ctx context.Context,
	batchKey *btcec.PublicKey, blockHash *chainhash.Hash,
	blockHeight uint32, txIndex uint32,
	mintingProofs proof.AssetBlobs) error {

	rawBatchKey := batchKey.SerializeCompressed()

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// First, we'll update the state of the target batch to reflect
		// that the batch is fully finalized.
		err := q.UpdateMintingBatchState(ctx, BatchStateUpdate{
			RawKey:     rawBatchKey,
			BatchState: int16(tapgarden.BatchStateConfirmed),
		})
		if err != nil {
			return err
		}

		// Now that the batch has been confirmed, we'll add the chain
		// location information to the confirmed transaction.
		if err := q.ConfirmChainTx(ctx, ChainTxConf{
			RawKey:      rawBatchKey,
			BlockHeight: sqlInt32(blockHeight),
			BlockHash:   blockHash[:],
			TxIndex:     sqlInt32(txIndex),
		}); err != nil {
			return fmt.Errorf("unable to confirm chain tx: %w", err)
		}

		// As a final act, we'll now insert the proof files for each of
		// the assets that were fully confirmed with this block.
		for scriptKey, proofBlob := range mintingProofs {
			// We need to fetch the table primary key `asset_id`
			// first, as we need it to update the proof.
			dbAssetIds, err := q.FetchAssetID(ctx, FetchAssetID{
				TweakedScriptKey: scriptKey[:],
			})
			if err != nil {
				return err
			}

			// We should not have more than one `asset_id`.
			if len(dbAssetIds) > 1 {
				return fmt.Errorf("expected 1 asset id, found "+
					"%d with asset ids %v",
					len(dbAssetIds), dbAssetIds)
			}

			// Upload proof by the dbAssetId, which is the _primary
			// key_ of the asset in table assets, not the BIPS
			// concept of `asset_id`.
			err = q.UpsertAssetProofByID(ctx, ProofUpdateByID{
				AssetID:   dbAssetIds[0],
				ProofFile: proofBlob,
			})
			if err != nil {
				return fmt.Errorf("unable to insert proof "+
					"file: %w", err)
			}
		}
		return nil
	})
}

// FetchGroupByGenesis fetches the asset group created by the genesis referenced
// by the given ID.
func (a *AssetMintingStore) FetchGroupByGenesis(ctx context.Context,
	genesisID int64) (*asset.AssetGroup, error) {

	var (
		dbGroup *asset.AssetGroup
		err     error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(a PendingAssetStore) error {
		dbGroup, err = fetchGroupByGenesis(ctx, a, genesisID)
		return err
	})

	if dbErr != nil {
		return nil, dbErr
	}

	return dbGroup, nil
}

// FetchGroupByGroupKey fetches the asset group with a matching tweaked key,
// including the genesis information used to create the group.
func (a *AssetMintingStore) FetchGroupByGroupKey(ctx context.Context,
	groupKey *btcec.PublicKey) (*asset.AssetGroup, error) {

	var (
		dbGroup *asset.AssetGroup
		err     error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(a PendingAssetStore) error {
		dbGroup, err = fetchGroupByGroupKey(ctx, a, groupKey)
		return err
	})

	if dbErr != nil {
		return nil, dbErr
	}

	return dbGroup, nil
}

// FetchScriptKeyByTweakedKey fetches the populated script key given the tweaked
// script key.
func (a *AssetMintingStore) FetchScriptKeyByTweakedKey(ctx context.Context,
	tweakedKey *btcec.PublicKey) (*asset.TweakedScriptKey, error) {

	var (
		scriptKey *asset.TweakedScriptKey
		err       error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		scriptKey, err = fetchScriptKey(ctx, q, tweakedKey)
		return err
	})

	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, fmt.Errorf("script key not found")

	case dbErr != nil:
		return nil, err
	}

	return scriptKey, nil
}

// StoreTapscriptTree persists a Tapscript tree given a validated set of
// TapLeafs or a TapBranch. If the store succeeds, the root hash of the
// Tapscript tree is returned.
func (a *AssetMintingStore) StoreTapscriptTree(ctx context.Context,
	treeNodes asset.TapscriptTreeNodes) (*chainhash.Hash, error) {

	var (
		rootHash       chainhash.Hash
		isBranch       bool
		treeNodesBytes [][]byte
		err            error
	)

	asset.GetLeaves(treeNodes).WhenSome(func(tln asset.TapLeafNodes) {
		rootHash = asset.LeafNodesRootHash(tln)
		treeNodesBytes, err = asset.EncodeTapLeafNodes(tln)
	})
	if err != nil {
		return nil, err
	}

	// For a TapBranch, we must set isBranch to ensure that the branch data
	// will be decoded correctly.
	asset.GetBranch(treeNodes).WhenSome(func(tbn asset.TapBranchNodes) {
		isBranch = true
		rootHash = asset.BranchNodesRootHash(tbn)
		treeNodesBytes = asset.EncodeTapBranchNodes(tbn)
	})

	// If no tapscript tree data was encoded, the given tapscript tree was
	// malformed. Return before modifying the database.
	if len(treeNodesBytes) == 0 {
		return nil, fmt.Errorf("unable to encode tapscript tree")
	}

	var writeTxOpts AssetStoreTxOptions
	err = a.db.ExecTx(ctx, &writeTxOpts, func(a PendingAssetStore) error {
		return upsertTapscriptTree(
			ctx, a, rootHash[:], isBranch, treeNodesBytes,
		)
	})
	if err != nil {
		return nil, err
	}

	return &rootHash, nil
}

// LoadTapscriptTree loads the Tapscript tree with the given root hash, and
// decodes the tree into a TapscriptTreeNodes object.
func (a *AssetMintingStore) LoadTapscriptTree(ctx context.Context,
	rootHash chainhash.Hash) (*asset.TapscriptTreeNodes, error) {

	var (
		dbTreeNodes []TapscriptTreeNode
		err         error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(a PendingAssetStore) error {
		dbTreeNodes, err = a.FetchTapscriptTree(ctx, rootHash[:])
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// The query can return zero nodes without returning an error, so handle
	// that case explicitly here.
	if len(dbTreeNodes) == 0 {
		return nil, asset.ErrTreeNotFound
	}

	nodeBytes := fn.Map(dbTreeNodes, func(dbNode TapscriptTreeNode) []byte {
		return dbNode.RawNode
	})

	// Each node signals if the tree was stored as a set of leaves or a
	// branch, so we can read this flag from any node.
	isBranch := dbTreeNodes[0].BranchOnly
	if isBranch {
		// For a tree stored as a TapBranch, there can only be two nodes
		// returned.
		if len(dbTreeNodes) != 2 {
			return nil, asset.ErrInvalidTapBranch
		}

		branchNodes, err := asset.DecodeTapBranchNodes(nodeBytes)
		if err != nil {
			return nil, err
		}

		return fn.Ptr(asset.FromBranch(*branchNodes)), nil
	}

	// If the tree was not stored as a branch, it must be a set of leaves.
	leafNodes, err := asset.DecodeTapLeafNodes(nodeBytes)
	if err != nil {
		return nil, err
	}

	return fn.Ptr(asset.FromLeaves(*leafNodes)), nil
}

// DeleteTapscriptTree deletes the Tapscript tree with the given root hash,
// including all nodes and edges.
func (a *AssetMintingStore) DeleteTapscriptTree(ctx context.Context,
	rootHash chainhash.Hash) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(a PendingAssetStore) error {
		return deleteTapscriptTree(ctx, a, rootHash[:])
	})
}

// A compile-time assertion to ensure that AssetMintingStore meets the
// tapgarden.MintingStore interface.
var _ tapgarden.MintingStore = (*AssetMintingStore)(nil)
var _ asset.TapscriptTreeManager = (*AssetMintingStore)(nil)
