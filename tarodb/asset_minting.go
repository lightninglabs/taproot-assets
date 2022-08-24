package tarodb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb/sqlite"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/keychain"
)

type (
	// BatchStateUpdate holds the arguments to updated the state of a
	// batch.
	BatchStateUpdate = sqlite.UpdateMintingBatchStateParams

	// InternalKey holds the arguments to update an internal key.
	InternalKey = sqlite.InsertInternalKeyParams

	//  AssetSeedlingShell holds the components of a seedling asset.
	AssetSeedlingShell = sqlite.InsertAssetSeedlingParams

	// AssetSeedlingItem is used to insert a seedling into an asset based
	// on the batch key of the batch.
	AssetSeedlingItem = sqlite.InsertAssetSeedlingIntoBatchParams

	// MintingBatch is an alias for a minting batch including the internal
	// key info.
	MintingBatch = sqlite.FetchMintingBatchesByStateRow

	// MintingBatchI is an alias for a minting batch including the internal
	// key info. This is used to query for batches where the state doesn't
	// match a certain value.
	MintingBatchI = sqlite.FetchMintingBatchesByInverseStateRow

	// AssetSeedling is an asset seedling.
	AssetSeedling = sqlite.AssetSeedling

	// MintingBatchTuple is used to update a batch state based on the raw
	// key.
	MintingBatchTuple = sqlite.UpdateMintingBatchStateParams

	// AssetFamilyKey is used to insert a new asset key family into the DB.
	AssetFamilyKey = sqlite.InsertAssetFamilyKeyParams

	// BatchChainUpdate is used to update a batch with the minting
	// transaction associated with it.
	BatchChainUpdate = sqlite.BindMintingBatchWithTxParams

	// GenesisTxUpdate is used to update the existing batch TX associated
	// with a batch.
	GenesisTxUpdate = sqlite.UpdateBatchGenesisTxParams

	// RawManagedUTXO is used to insert a new managed UTXO into the
	// database.
	RawManagedUTXO = sqlite.InsertManagedUTXOParams

	// AssetAnchor is used to bind assets on disk with the transaction that
	// will create them on-chain.
	AssetAnchor = sqlite.AnchorPendingAssetsParams

	// GenesisPointAnchor is used to update the genesis point with the
	// final information w.r.t where its confirmed on chain.
	GenesisPointAnchor = sqlite.AnchorGenesisPointParams

	// ChainTx is used to insert a new chain tx on disk.
	ChainTx = sqlite.InsertChainTxParams

	// ChainTxConf is used to mark a chain tx as being confirmed.
	ChainTxConf = sqlite.ConfirmChainTxParams

	// GenesisAsset is used to insert the base information of an asset into
	// the DB.
	GenesisAsset = sqlite.InsertGenesisAssetParams

	// AssetFamSig is used to insert the family key signature for a given
	// asset on disk.
	AssetFamSig = sqlite.InsertAssetFamilySigParams

	// AssetSprout is used to fetch the set of assets from disk.
	AssetSprout = sqlite.FetchAssetsForBatchRow

	// MintingBatchInit is used to create a new minting batch.
	MintingBatchInit = sqlite.NewMintingBatchParams

	// ProofUpdate is used to update a proof file on disk.
	ProofUpdate = sqlite.UpdateAssetProofParams
)

// PendingAssetStore is a sub-set of the main sqlite.Querier interface that
// contains only the methods needed to drive the process of batching and
// creating a new set of assets.
type PendingAssetStore interface {
	// InsertInternalKey inserts a new internal key into the database.
	InsertInternalKey(ctx context.Context, arg InternalKey) (int32, error)

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
	InsertAssetSeedlingIntoBatch(ctx context.Context, arg AssetSeedlingItem) error

	// FetchMintingBatchesByState is used to fetch minting batches with a
	// particular state.
	FetchMintingBatchesByState(ctx context.Context, batchState int16) ([]MintingBatch, error)

	// FetchMintingBatchesByInverseState is used to fetch minting batches
	// that don't have a particular state.
	FetchMintingBatchesByInverseState(ctx context.Context, batchState int16) ([]MintingBatchI, error)

	// FetchSeedlingsForBatch is used to fetch all the seedlings by the key
	// of the batch they're included in.
	FetchSeedlingsForBatch(ctx context.Context, rawKey []byte) ([]AssetSeedling, error)

	// InsertGenesisPoint inserts a new genesis point on disk, and returns
	// the primary key.
	InsertGenesisPoint(ctx context.Context, prevOut []byte) (int32, error)

	// InsertAssetFamilyKey inserts a new family key on disk, and returns
	// the primary key.
	InsertAssetFamilyKey(ctx context.Context, arg AssetFamilyKey) (int32, error)

	// InsertNewAsset inserts a new asset on disk.
	InsertNewAsset(ctx context.Context, arg sqlite.InsertNewAssetParams) (int32, error)

	// BindMintingBatchWithTx adds the minting transaction to an existing
	// batch.
	BindMintingBatchWithTx(ctx context.Context, arg BatchChainUpdate) error

	// UpdateBatchGenesisTx updates the batch tx attached to an existing
	// batch.
	UpdateBatchGenesisTx(ctx context.Context, arg GenesisTxUpdate) error

	// InsertManagedUTXO adds a new managed UTXO to disk.
	InsertManagedUTXO(ctx context.Context, arg RawManagedUTXO) (int32, error)

	// AnchorPendingAssets associated an asset on disk with the transaction
	// that once confirmed will mint the asset.
	AnchorPendingAssets(ctx context.Context, arg AssetAnchor) error

	// AnchorGenesisPoint associates a genesis point with the transaction
	// that mints the associated assets on disk.
	AnchorGenesisPoint(ctx context.Context, arg GenesisPointAnchor) error

	// InsertChainTx insets a new chain tx into the DB.
	InsertChainTx(ctx context.Context, arg ChainTx) (int32, error)

	// ConfirmChainTx confirms an existing chain tx.
	ConfirmChainTx(ctx context.Context, arg ChainTxConf) error

	// InsertGenesisAsset inserts a new genesis asset (the base asset info)
	// into the DB.
	InsertGenesisAsset(ctx context.Context, arg GenesisAsset) (int32, error)

	// InsertAssetFamilySig inserts a new asset family sig into the DB.
	InsertAssetFamilySig(ctx context.Context, arg AssetFamSig) (int32, error)

	// FetchAssetsForBatch fetches all the assets created by a particular
	// batch.
	FetchAssetsForBatch(ctx context.Context, rawKey []byte) ([]AssetSprout, error)

	// UpdateAssetProof inserts a new asset proofon disk. If one already
	// exists, then the proof file is updated in place.
	//
	// TODO(roasbeef): move somewhere else??
	UpdateAssetProof(ctx context.Context,
		arg sqlite.UpdateAssetProofParams) error
}

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

	BatchedTx[PendingAssetStore, TxOptions]
}

// AssetMintingStore is an implementation of the tarogarden.PlantingLog
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

// CommitMintingBatch commits a new minting batch to disk along with any
// seedlings specified as part of the batch. A new internal key is also
// created, with the batch referencing that internal key. This internal key
// will be used as the internal key which will mint all the assets in the
// batch.
func (a *AssetMintingStore) CommitMintingBatch(ctx context.Context,
	newBatch *tarogarden.MintingBatch) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// First, we'll need to insert a new internal key which'll act
		// as the foreign key our batch references.
		batchID, err := q.InsertInternalKey(ctx, InternalKey{
			RawKey:    newBatch.BatchKey.PubKey.SerializeCompressed(),
			KeyFamily: int32(newBatch.BatchKey.Family),
			KeyIndex:  int32(newBatch.BatchKey.Index),
		})
		if err != nil {
			return fmt.Errorf("unable to insert internal "+
				"key: %w", err)
		}

		// With our internal key inserted, we can now insert a new
		// batch which references the target internal key.
		if err := q.NewMintingBatch(ctx, MintingBatchInit{
			BatchID:          batchID,
			CreationTimeUnix: newBatch.CreationTime,
		}); err != nil {
			return fmt.Errorf("unable to insert minting "+
				"batch: %w", err)
		}

		// Now that our minting batch is in place, which defences the
		// internal key inserted above, we can create the set of new
		// seedlings.
		for _, seedling := range newBatch.Seedlings {
			err := q.InsertAssetSeedling(ctx, AssetSeedlingShell{
				BatchID:         batchID,
				AssetName:       seedling.AssetName,
				AssetType:       int16(seedling.AssetType),
				AssetSupply:     int64(seedling.Amount),
				AssetMeta:       seedling.Metadata,
				EmissionEnabled: seedling.EnableEmission,
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// AddSeedlingsToBatch adds a new set of seedlings to an existing batch.
func (a *AssetMintingStore) AddSeedlingsToBatch(ctx context.Context,
	batchKey *btcec.PublicKey, seedlings ...*tarogarden.Seedling) error {

	rawKey := batchKey.SerializeCompressed()

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// For each specified asset seedling, we'll insert them all
		// into the database in a single atomic transaction.
		//
		// TODO(roasbeef): can make sure to use the batch insert here
		// when postgres
		for _, seedling := range seedlings {
			dbSeedling := AssetSeedlingItem{
				RawKey:          rawKey,
				AssetName:       seedling.AssetName,
				AssetType:       int16(seedling.AssetType),
				AssetSupply:     int64(seedling.Amount),
				AssetMeta:       seedling.Metadata,
				EmissionEnabled: seedling.EnableEmission,
			}
			err := q.InsertAssetSeedlingIntoBatch(ctx, dbSeedling)
			if err != nil {
				return fmt.Errorf("unable to insert "+
					"seedling into db: %v", err)
			}
		}

		return nil
	})
}

// fetchAssetSeedlings attempts to fetch a set of asset seedlings for a given
// batch. This is performed wtihin the context of a greater DB transaction.
func fetchAssetSeedlings(ctx context.Context, q PendingAssetStore,
	rawKey []byte) (map[string]*tarogarden.Seedling, error) {

	// Now that we have the main pieces of the batch, we'll fetch all the
	// seedlings for this batch and map them to the proper struct.
	dbSeedlings, err := q.FetchSeedlingsForBatch(
		ctx, rawKey,
	)
	if err != nil {
		return nil, err
	}

	seedlings := make(map[string]*tarogarden.Seedling)
	for _, seedling := range dbSeedlings {
		seedling := &tarogarden.Seedling{
			AssetType: asset.Type(
				seedling.AssetType,
			),
			AssetName: seedling.AssetName,
			Metadata:  seedling.AssetMeta,
			Amount: uint64(
				seedling.AssetSupply,
			),
			EnableEmission: seedling.EmissionEnabled,
		}

		seedlings[seedling.AssetName] = seedling
	}

	return seedlings, nil
}

// fetchAssetSprouts fetches all the asset sprouts, or unconfirmed assets
// associated with a given batch. The assets are them inserted into a Taro
// commitment for easy handling.
//
// NOTE: In order for this query to work properly, until
// https://github.com/kyleconroy/sqlc/issues/1334 is fixed in sqlc, after code
// generation, the FamKeyFamily and FamKeyIndex fields of the
// FetchAssetsForBatchRow need to be manually modified to be sql.NullInt32.
func fetchAssetSprouts(ctx context.Context, q PendingAssetStore,
	rawKey []byte) (*commitment.TaroCommitment, error) {

	dbSprout, err := q.FetchAssetsForBatch(ctx, rawKey)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch batch assets: %w", err)
	}

	// For each sprout, we'll create a new asset commitment which will be a
	// leaf at the top-level Taro commitment.
	assetCommitments := make([]*commitment.AssetCommitment, len(dbSprout))
	for i, sprout := range dbSprout {
		// First, we'll decode the script key which very asset must
		// specify, and populate the key locator information
		scriptKeyPub, err := btcec.ParsePubKey(sprout.ScriptKeyRaw)
		if err != nil {
			return nil, err
		}
		scriptKey := keychain.KeyDescriptor{
			PubKey: scriptKeyPub,
			KeyLocator: keychain.KeyLocator{
				Index:  uint32(sprout.ScriptKeyIndex),
				Family: keychain.KeyFamily(sprout.ScriptKeyFam),
			},
		}

		// Not all assets have a key family, so we only need to
		// populate this information for those that signalled the
		// requirement of on going emission.
		var familyKey *asset.FamilyKey
		if sprout.TweakedFamKey != nil {
			tweakedFamKey, err := btcec.ParsePubKey(
				sprout.TweakedFamKey,
			)
			if err != nil {
				return nil, err
			}
			rawFamKey, err := btcec.ParsePubKey(sprout.FamKeyRaw)
			if err != nil {
				return nil, err
			}
			famSig, err := schnorr.ParseSignature(sprout.GenesisSig)
			if err != nil {
				return nil, err
			}

			familyKey = &asset.FamilyKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: rawFamKey,
					KeyLocator: keychain.KeyLocator{
						Index: extractSqlInt32[uint32](
							sprout.FamKeyIndex,
						),
						Family: keychain.KeyFamily(
							extractSqlInt32[keychain.KeyFamily](
								sprout.FamKeyFamily,
							),
						),
					},
				},
				FamKey: *tweakedFamKey,
				Sig:    *famSig,
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
			return nil, fmt.Errorf("unable to read "+
				"outpoint: %w", err)
		}
		assetGenesis := asset.Genesis{
			FirstPrevOut: genesisPrevOut,
			Tag:          sprout.AssetTag,
			Metadata:     sprout.MetaData,
			OutputIndex:  uint32(sprout.GenesisOutputIndex),
			Type:         asset.Type(sprout.AssetType),
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
			scriptKey, familyKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new sprout: "+
				"%v", err)
		}

		// TODO(roasbeef): need to update the above to set the
		// witnesses of a valid asset

		// Finally make a new asset commitment from this sprout and
		// accumulate it along the rest of the assets.
		assetCommitment, err := commitment.NewAssetCommitment(
			assetSprout,
		)
		if err != nil {
			return nil, err
		}
		assetCommitments[i] = assetCommitment
	}

	return commitment.NewTaroCommitment(assetCommitments...), nil
}

// FetchNonFinalBatches fetches all the batches that aren't fully finalized on
// disk.
func (a *AssetMintingStore) FetchNonFinalBatches(ctx context.Context,
) ([]*tarogarden.MintingBatch, error) {

	var batches []*tarogarden.MintingBatch

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		// First, we'll fetch all batches that aren't in a final state.
		dbBatches, err := q.FetchMintingBatchesByInverseState(
			ctx, int16(tarogarden.BatchStateFinalized),
		)
		if err != nil {
			return fmt.Errorf("unable to fetch minting "+
				"batches: %v", err)
		}

		// For each batch returned, we'll assemble an intermediate
		// batch struct, then fill in all the seedlings with another
		// sub-query.
		batches = make([]*tarogarden.MintingBatch, len(dbBatches))
		for i, batch := range dbBatches {
			batchKey, err := btcec.ParsePubKey(batch.RawKey)
			if err != nil {
				return err
			}
			batches[i] = &tarogarden.MintingBatch{
				BatchState: tarogarden.BatchState(
					batch.BatchState,
				),
				BatchKey: keychain.KeyDescriptor{
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							batch.KeyFamily,
						),
						Index: uint32(batch.KeyIndex),
					},
					PubKey: batchKey,
				},
				CreationTime: batch.CreationTimeUnix,
			}

			if batch.MintingTxPsbt != nil {
				genesisPkt, err := psbt.NewFromRawBytes(
					bytes.NewReader(batch.MintingTxPsbt), false,
				)
				if err != nil {
					return err
				}
				batches[i].GenesisPacket = &tarogarden.FundedPsbt{
					Pkt: genesisPkt,
					ChangeOutputIndex: extractSqlInt16[uint32](
						batch.MintingOutputIndex,
					),
				}
			}

			// Depending on what state this batch is in, we'll
			// either fetch the set of seedlings (asset
			// descriptions w/ no real assets), or the set of
			// sprouts (full defined assets, but not yet mined).
			switch batches[i].BatchState {
			case tarogarden.BatchStatePending,
				tarogarden.BatchStateFrozen:
				// In this case we can just fetch the set of
				// descriptions of future assets to be.
				batches[i].Seedlings, err = fetchAssetSeedlings(
					ctx, q, batch.RawKey,
				)
				if err != nil {
					return err
				}

				continue
			}

			batches[i].RootAssetCommitment, err = fetchAssetSprouts(
				ctx, q, batch.RawKey,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return batches, nil
}

// UpdateBatchState updates the state of a batch based on the batch key.
func (a *AssetMintingStore) UpdateBatchState(ctx context.Context,
	batchKey *btcec.PublicKey, newState tarogarden.BatchState) error {

	return a.db.UpdateMintingBatchState(ctx, BatchStateUpdate{
		RawKey:     batchKey.SerializeCompressed(),
		BatchState: int16(newState),
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

// AddSproutsToBatch updates a batch with the passed batch transaction and also
// binds the genesis transaction (which will create the set of assets in the
// batch) to the batch itself.
func (a *AssetMintingStore) AddSproutsToBatch(ctx context.Context,
	batchKey *btcec.PublicKey, genesisPacket *tarogarden.FundedPsbt,
	assetRoot *commitment.TaroCommitment) error {

	// Before we open the DB transaction below, we'll fetch the set of
	// assets committed to within the root commitment specified.
	assets := assetRoot.CommittedAssets()

	genesisPoint, err := encodeOutpoint(
		genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
	)
	if err != nil {
		return fmt.Errorf("unable to encode genesis point: %w", err)
	}

	rawBatchKey := batchKey.SerializeCompressed()

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q PendingAssetStore) error {
		// First, we'll insert the component that ties together all the
		// assets in this batch: the genesis point.
		genesisPointID, err := q.InsertGenesisPoint(ctx, genesisPoint)
		if err != nil {
			return fmt.Errorf("unable to insert genesis "+
				"point: %w", err)
		}

		// With the genesis point inserted, we'll now insert each asset
		// into the database. Some assets have a key family, so we'll
		// need to insert them before we can insert the asset itself.
		for _, asset := range assets {
			// First, we'll insert the genesis_assets row which
			// tracks all the information that uniquely derives a
			// given asset ID.
			assetID := asset.Genesis.ID()
			genAssetID, err := q.InsertGenesisAsset(ctx, GenesisAsset{
				AssetID:        assetID[:],
				AssetTag:       asset.Genesis.Tag,
				MetaData:       asset.Genesis.Metadata,
				OutputIndex:    int32(asset.Genesis.OutputIndex),
				AssetType:      int16(asset.Type),
				GenesisPointID: genesisPointID,
			})
			if err != nil {
				return fmt.Errorf("unable to insert genesis "+
					"asset: %w", err)
			}

			// This asset has as key family so we'll insert it into
			// the database. If it doesn't exist, the UPSERT query
			// will still return the family_id we'll need.
			var familySigID sql.NullInt32
			if asset.FamilyKey != nil {
				// Before we can insert a new asset key family,
				// we'll also need to insert an internal key
				// which will be referenced by the key family.
				familyKey := asset.FamilyKey
				keyID, err := q.InsertInternalKey(ctx, InternalKey{
					RawKey:    familyKey.RawKey.PubKey.SerializeCompressed(),
					KeyFamily: int32(familyKey.RawKey.Family),
					KeyIndex:  int32(familyKey.RawKey.Index),
				})
				if err != nil {
					return fmt.Errorf("unable to insert internal "+
						"key: %w", err)
				}
				assetKey := AssetFamilyKey{
					TweakedFamKey:  familyKey.FamKey.SerializeCompressed(),
					InternalKeyID:  keyID,
					GenesisPointID: genesisPointID,
				}
				famID, err := q.InsertAssetFamilyKey(ctx, assetKey)
				if err != nil {
					return fmt.Errorf("unable to insert "+
						"family key: %w", err)
				}

				// With the statement above complete, we'll now
				// insert the asset_family_sig entry for this,
				// which has a one to many relation ship with
				// family keys (there can be many sigs for a
				// family key which link together otherwise
				// disparate asset IDs).
				famSigID, err := q.InsertAssetFamilySig(ctx, AssetFamSig{
					GenesisSig: familyKey.Sig.Serialize(),
					GenAssetID: genAssetID,
					KeyFamID:   famID,
				})
				if err != nil {
					return fmt.Errorf("unable to insert "+
						"fam sig: %w", err)
				}

				familySigID = sqlInt32(famSigID)
			}

			// With the key family potentially inserted, we'll now
			// insert the asset itself along with the necessary set
			// of sub tables.
			//
			// Just like above, we'll also need to insert a new
			// internal key which will be used later to look up the
			// key needed to spend this asset.
			scriptKeyID, err := q.InsertInternalKey(ctx, InternalKey{
				RawKey:    asset.ScriptKey.PubKey.SerializeCompressed(),
				KeyFamily: int32(asset.ScriptKey.Family),
				KeyIndex:  int32(asset.ScriptKey.Index),
			})
			if err != nil {
				return fmt.Errorf("unable to insert internal "+
					"key: %w", err)
			}
			_, err = q.InsertNewAsset(ctx, sqlite.InsertNewAssetParams{
				AssetID:          genAssetID,
				Version:          int32(asset.Version),
				ScriptKeyID:      scriptKeyID,
				AssetFamilySigID: familySigID,
				ScriptVersion:    int32(asset.ScriptVersion),
				Amount:           int64(asset.Amount),
			})
			if err != nil {
				return fmt.Errorf("unable to insert "+
					"asset: %w", err)
			}
		}

		// With all the assets inserted, we'll now update the
		// corresponding batch that references all these assets with
		// the genesis packet, and genesis point information.
		var psbtBuf bytes.Buffer
		if err := genesisPacket.Pkt.Serialize(&psbtBuf); err != nil {
			return fmt.Errorf("unable to encode psbt: %v", err)
		}
		err = q.BindMintingBatchWithTx(ctx, BatchChainUpdate{
			RawKey:        rawBatchKey,
			MintingTxPsbt: psbtBuf.Bytes(),
			MintingOutputIndex: sqlInt16(
				genesisPacket.ChangeOutputIndex,
			),
			GenesisID: sqlInt32(genesisPointID),
		})
		if err != nil {
			return fmt.Errorf("unable to add batch tx: %w", err)
		}

		// Finally, update the batch state to BatchStateCommitted.
		return q.UpdateMintingBatchState(ctx, BatchStateUpdate{
			RawKey:     rawBatchKey,
			BatchState: int16(tarogarden.BatchStateCommitted),
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
	batchKey *btcec.PublicKey, genesisPkt *tarogarden.FundedPsbt,
	anchorOutputIndex uint32, taroScriptRoot []byte) error {

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

	var anchorPointBuf bytes.Buffer
	anchorOutput := rawGenTx.TxOut[anchorOutputIndex]
	anchorPoint := wire.OutPoint{
		Hash:  rawGenTx.TxHash(),
		Index: anchorOutputIndex,
	}
	err = wire.WriteOutPoint(&anchorPointBuf, 0, 0, &anchorPoint)
	if err != nil {
		return err
	}

	var genesisPointBuf bytes.Buffer
	genesisPoint := genesisPkt.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	err = wire.WriteOutPoint(&genesisPointBuf, 0, 0, &genesisPoint)
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
			return fmt.Errorf("unable to update genesis tx: %w", err)
		}

		// Before we can insert a managed UTXO, we'll need to insert a
		// chain transaction, as that chain transaction will be
		// referenced by the managed UTXO.
		chainTXID, err := q.InsertChainTx(ctx, ChainTx{
			Txid:  genTXID[:],
			RawTx: txBuf.Bytes(),
		})
		if err != nil {
			return fmt.Errorf("unable to insert chain tx: %w", err)
		}

		// Now that the genesis tx has been updated within the main
		// batch, we'll create a new managed UTXO for this batch as
		// this is where all the assets will be anchored within.
		utxoID, err := q.InsertManagedUTXO(ctx, RawManagedUTXO{
			RawKey:   rawBatchKey,
			Outpoint: anchorPointBuf.Bytes(),
			AmtSats:  anchorOutput.Value,
			TaroRoot: taroScriptRoot,
			TxnID:    chainTXID,
		})
		if err != nil {
			return fmt.Errorf("unable to insert managed utxo: %w", err)
		}

		// With the managed UTXO inserted, we also need to update all
		// the assets created in a prior step to also reference this
		// managed UTXO.
		err = q.AnchorPendingAssets(ctx, AssetAnchor{
			PrevOut:      genesisPointBuf.Bytes(),
			AnchorUtxoID: sqlInt32(utxoID),
		})
		if err != nil {
			return fmt.Errorf("unable to anchor pending assets: %v", err)
		}

		// Next, we'll anchor the genesis point to point to the chain
		// transaction we inserted above.
		if err := q.AnchorGenesisPoint(ctx, GenesisPointAnchor{
			PrevOut:    genesisPointBuf.Bytes(),
			AnchorTxID: sqlInt32(chainTXID),
		}); err != nil {
			return fmt.Errorf("unable to anchor genesis tx: %w", err)
		}

		// Finally, update the batch state to BatchStateBroadcast.
		return q.UpdateMintingBatchState(ctx, BatchStateUpdate{
			RawKey:     rawBatchKey,
			BatchState: int16(tarogarden.BatchStateBroadcast),
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
			BatchState: int16(tarogarden.BatchStateConfirmed),
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
			err := q.UpdateAssetProof(ctx, ProofUpdate{
				RawKey:    scriptKey.SerializeCompressed(),
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

// A compile-time assertion to ensure that AssetMintingStore meets the
// tarogarden.MintingStore interface.
var _ tarogarden.MintingStore = (*AssetMintingStore)(nil)
