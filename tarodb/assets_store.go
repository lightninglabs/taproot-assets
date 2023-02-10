package tarodb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb/sqlc"
	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"golang.org/x/exp/maps"
)

type (
	// ConfirmedAsset is an asset that has been fully confirmed on chain.
	ConfirmedAsset = sqlc.QueryAssetsRow

	// RawAssetBalance holds a balance query result for a particular asset
	// or all assets tracked by this daemon.
	RawAssetBalance = sqlc.QueryAssetBalancesByAssetRow

	// RawAssetGroupBalance holds a balance query result for a particular
	// asset group or all asset groups tracked by this daemon.
	RawAssetGroupBalance = sqlc.QueryAssetBalancesByGroupRow

	// AssetProof is the asset proof for a given asset, identified by its
	// script key.
	AssetProof = sqlc.FetchAssetProofsRow

	// AssetProofI is identical to AssetProof but is used for the case
	// where the proofs for a specific asset are fetched.
	AssetProofI = sqlc.FetchAssetProofRow

	// PrevInput stores the full input information including the prev out,
	// and also the witness information itself.
	PrevInput = sqlc.InsertAssetWitnessParams

	// AssetWitness is the full prev input for an asset that also couples
	// along the asset ID that the witness belong to.
	AssetWitness = sqlc.FetchAssetWitnessesRow

	// RawGroupedAsset holds the human-readable fields of a single asset
	// with a non-nil group key.
	RawGroupedAsset = sqlc.FetchGroupedAssetsRow

	// QueryAssetFilters lets us query assets in the database based on some
	// set filters. This is useful to get the balance of a set of assets,
	// or for things like coin selection.
	QueryAssetFilters = sqlc.QueryAssetsParams

	// UtxoQuery lets us query a managed UTXO by either the transaction it
	// references, or the outpoint.
	UtxoQuery = sqlc.FetchManagedUTXOParams

	// AnchorPoint wraps a managed UTXO along with all the auxiliary
	// information it references.
	AnchorPoint = sqlc.FetchManagedUTXORow

	// ManagedUTXORow wraps a managed UTXO listing row.
	ManagedUTXORow = sqlc.FetchManagedUTXOsRow

	// AssetAnchorUpdate is used to update the managed UTXO pointer when
	// spending assets on chain.
	AssetAnchorUpdate = sqlc.ReanchorAssetsParams

	// AssetSpendDelta is used to update the script key and amount of an
	// existing asset.
	AssetSpendDelta = sqlc.ApplySpendDeltaParams

	// AnchorTxConf identifies an unconfirmed anchor tx to confirm.
	AnchorTxConf = sqlc.ConfirmChainAnchorTxParams

	// AssetDelta tracks the changes to an asset within the confines of a
	// transfer.
	AssetDelta = sqlc.FetchAssetDeltasRow

	// AssetDeltaWithProof tracks the changes to an asset within the
	// confines of a transfer, also containing the proofs for the change.
	AssetDeltaWithProof = sqlc.FetchAssetDeltasWithProofsRow

	// NewAssetDelta wraps the params needed to insert a new asset delta.
	NewAssetDelta = sqlc.InsertAssetDeltaParams

	// NewAssetTransfer wraps the params needed to insert a new asset
	// transfer.
	NewAssetTransfer = sqlc.InsertAssetTransferParams

	// AssetTransfer packages information related to an asset transfer.
	AssetTransfer = sqlc.QueryAssetTransfersRow

	// TransferQuery allows callers to filter out the set of transfers
	// based on set information.
	TransferQuery = sqlc.QueryAssetTransfersParams

	// NewSpendProof is used to insert new spend proofs for the
	// sender+receiver.
	NewSpendProof = sqlc.InsertSpendProofsParams
)

// ActiveAssetsStore is a sub-set of the main sqlc.Querier interface that
// contains methods related to querying the set of confirmed assets.
type ActiveAssetsStore interface {
	// UpsertAssetStore houses the methods related to inserting/updating
	// assets.
	UpsertAssetStore

	// QueryAssets fetches the set of fully confirmed assets.
	QueryAssets(context.Context, QueryAssetFilters) ([]ConfirmedAsset,
		error)

	// QueryAssetBalancesByAsset queries the balances for assets or
	// alternatively for a selected one that matches the passed asset ID
	// filter.
	QueryAssetBalancesByAsset(context.Context, []byte) ([]RawAssetBalance,
		error)

	// QueryAssetBalancesByGroup queries the asset balances for asset
	// groups or alternatively for a selected one that matches the passed
	// filter.
	QueryAssetBalancesByGroup(context.Context,
		[]byte) ([]RawAssetGroupBalance, error)

	// FetchGroupedAssets fetches all assets with non-nil group keys.
	FetchGroupedAssets(context.Context) ([]RawGroupedAsset, error)

	// FetchAssetProofs fetches all the asset proofs we have stored on
	// disk.
	FetchAssetProofs(ctx context.Context) ([]AssetProof, error)

	// FetchAssetProof fetches the asset proof for a given asset identified
	// by its script key.
	FetchAssetProof(ctx context.Context,
		scriptKey []byte) (AssetProofI, error)

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTx) (int32, error)

	// UpsertManagedUTXO inserts a new or updates an existing managed UTXO
	// to disk and returns the primary key.
	UpsertManagedUTXO(ctx context.Context, arg RawManagedUTXO) (int32,
		error)

	// UpsertAssetProof inserts a new or updates an existing asset proof on
	// disk.
	UpsertAssetProof(ctx context.Context,
		arg sqlc.UpsertAssetProofParams) error

	// InsertAssetWitness inserts a new prev input for an asset into the
	// database.
	InsertAssetWitness(context.Context, PrevInput) error

	// FetchAssetWitnesses attempts to fetch either all the asset witnesses
	// on disk (NULL param), or the witness for a given asset ID.
	FetchAssetWitnesses(context.Context, sql.NullInt32) ([]AssetWitness,
		error)

	// FetchManagedUTXO fetches a managed UTXO based on either the outpoint
	// or the transaction that anchors it.
	FetchManagedUTXO(context.Context, UtxoQuery) (AnchorPoint, error)

	// FetchManagedUTXOs fetches all managed UTXOs.
	FetchManagedUTXOs(context.Context) ([]ManagedUTXORow, error)

	// ReanchorAssets takes an old anchor point, then updates all assets
	// that point to that old anchor point-to-point to the new one.
	ReanchorAssets(ctx context.Context, arg AssetAnchorUpdate) error

	// ApplySpendDelta applies a sped delta (new amount and script key)
	// based on the existing script key of an asset.
	ApplySpendDelta(ctx context.Context, arg AssetSpendDelta) (int32, error)

	// DeleteManagedUTXO deletes the managed utxo identified by the passed
	// serialized outpoint.
	DeleteManagedUTXO(ctx context.Context, outpoint []byte) error

	// ConfirmChainAnchorTx marks a new anchor transaction that was
	// previously unconfirmed as confirmed.
	ConfirmChainAnchorTx(ctx context.Context, arg AnchorTxConf) error

	// FetchAssetDeltas fetches the asset deltas associated with a given
	// transfer id.
	FetchAssetDeltas(ctx context.Context,
		transferID int32) ([]AssetDelta, error)

	// FetchAssetDeltasWithProofs fetches the asset deltas including the
	// proofs associated with a given transfer id.
	FetchAssetDeltasWithProofs(ctx context.Context,
		transferID int32) ([]AssetDeltaWithProof, error)

	// InsertAssetDelta inserts a new asset delta into the DB.
	InsertAssetDelta(ctx context.Context, arg NewAssetDelta) error

	// InsertAssetTransfer inserts a new asset transfer into the DB.
	InsertAssetTransfer(ctx context.Context,
		arg NewAssetTransfer) (int32, error)

	// QueryAssetTransfers queries for a set of asset transfers in the db.
	QueryAssetTransfers(ctx context.Context,
		tranferQuery TransferQuery) ([]AssetTransfer, error)

	// DeleteAssetWitnesses deletes the witnesses on disk associated with a
	// given asset ID.
	DeleteAssetWitnesses(ctx context.Context, assetID int32) error

	// InsertSpendProofs is used to insert the new spend proofs after a
	// transfer into DB.
	InsertSpendProofs(ctx context.Context, arg NewSpendProof) (int32, error)

	// DeleteSpendProofs is used to delete the set of proofs on disk after
	// we apply a transfer.
	DeleteSpendProofs(ctx context.Context, transferID int32) error

	// FetchSpendProofs looks up the spend proofs for the given transfer
	// ID.
	FetchSpendProofs(ctx context.Context,
		transferID int32) (sqlc.FetchSpendProofsRow, error)

	// InsertReceiverProofTransferAttempt inserts a new receiver proof
	// transfer attempt record.
	InsertReceiverProofTransferAttempt(ctx context.Context,
		arg InsertRecvProofTxAttemptParams) error

	// QueryReceiverProofTransferAttempt returns timestamps which correspond
	// to receiver proof delivery attempts.
	QueryReceiverProofTransferAttempt(ctx context.Context,
		proofLocatorHash []byte) ([]time.Time, error)
}

type InsertRecvProofTxAttemptParams = sqlc.InsertReceiverProofTransferAttemptParams

// AssetBalance holds a balance query result for a particular asset or all
// assets tracked by this daemon.
type AssetBalance struct {
	ID           asset.ID
	Version      int32
	Balance      uint64
	Tag          string
	Meta         []byte
	Type         asset.Type
	GenesisPoint wire.OutPoint
	OutputIndex  uint32
}

// AssetGroupBalance holds abalance query result for a particular asset group
// or all asset groups tracked by this daemon.
type AssetGroupBalance struct {
	GroupKey *btcec.PublicKey
	Balance  uint64
}

// BatchedAssetStore combines the AssetStore interface with the BatchedTx
// interface, allowing for multiple queries to be executed in a single SQL
// transaction.
type BatchedAssetStore interface {
	ActiveAssetsStore

	BatchedTx[ActiveAssetsStore]
}

// AssetStore is used to query for the set of pending and confirmed assets.
type AssetStore struct {
	db BatchedAssetStore
}

// NewAssetStore creates a new AssetStore from the specified BatchedAssetStore
// interface.
func NewAssetStore(db BatchedAssetStore) *AssetStore {
	return &AssetStore{
		db: db,
	}
}

// ChainAsset is a wrapper around the base asset struct that includes
// information detailing where in the chain the asset is currently anchored.
type ChainAsset struct {
	*asset.Asset

	// AnchorTx is the transaction that anchors this chain asset.
	AnchorTx *wire.MsgTx

	// AnchorTxid is the TXID of the anchor tx.
	AnchorTxid chainhash.Hash

	// AnchorBlockHash is the blockhash that mined the anchor tx.
	AnchorBlockHash chainhash.Hash

	// AnchorOutpoint is the outpoint that commits to the asset.
	AnchorOutpoint wire.OutPoint

	// AnchorInternalKey is the raw internal key that was used to create the
	// anchor Taproot output key.
	AnchorInternalKey *btcec.PublicKey
}

// ManagedUTXO holds information about a given UTXO we manage.
type ManagedUTXO struct {
	// OutPoint is the outpoint of the UTXO.
	OutPoint wire.OutPoint

	// OutputValue is the satoshi output value of the UTXO.
	OutputValue btcutil.Amount

	// InternalKey is the internal key that's used to anchor the commitment
	// in the outpoint.
	InternalKey keychain.KeyDescriptor

	// TaroRoot is the taro commitment committed to by this outpoint.
	TaroRoot []byte

	// TapscriptSibling is the tapscript sibling of this asset. This will
	// usually be blank.
	TapscriptSibling []byte
}

// AssetHumanReadable is a subset of the base asset struct that only includes
// human-readable asset fields.
type AssetHumanReadable struct {
	// ID is the unique identifier for the asset.
	ID asset.ID

	// Amount is the number of units represented by the asset.
	Amount uint64

	// LockTime, if non-zero, restricts an asset from being moved prior to
	// the represented block height in the chain.
	LockTime uint64

	// RelativeLockTime, if non-zero, restricts an asset from being moved
	// until a number of blocks after the confirmation height of the latest
	// transaction for the asset is reached.
	RelativeLockTime uint64

	// Tag is the human-readable identifier for the asset.
	Tag string

	// Metadata encodes metadata related to the asset.
	Metadata []byte

	// Type uniquely identifies the type of Taro asset.
	Type asset.Type

	// GroupKey is the tweaked public key that is used to associate assets
	// together across distinct asset IDs.
	GroupKey *btcec.PublicKey
}

// assetWitnesses maps the primary key of an asset to a slice of its previous
// input (witness) information.
type assetWitnesses map[int32][]AssetWitness

// fetchAssetWitnesses attempts to fetch all the asset witnesses that belong to
// the set of passed asset IDs.
func fetchAssetWitnesses(ctx context.Context, db ActiveAssetsStore,
	assetIDs []int32) (assetWitnesses, error) {

	assetWitnesses := make(map[int32][]AssetWitness)
	for _, assetID := range assetIDs {
		witnesses, err := db.FetchAssetWitnesses(
			ctx, sqlInt32(assetID),
		)
		if err != nil {
			return nil, err
		}

		// We'll insert a nil witness for genesis asset, so we don't
		// add it to the map, which'll give it the genesis witness.
		if len(witnesses) == 0 {
			continue
		}

		assetWitnesses[assetID] = witnesses
	}

	return assetWitnesses, nil
}

// parseAssetWitness maps a witness stored in the database to something we can
// use directly.
func parseAssetWitness(input AssetWitness) (asset.Witness, error) {
	var (
		op      wire.OutPoint
		witness asset.Witness
	)

	err := readOutPoint(
		bytes.NewReader(input.PrevOutPoint), 0, 0, &op,
	)
	if err != nil {
		return witness, fmt.Errorf("unable to "+
			"read outpoint: %w", err)
	}

	var (
		zeroKey, scriptKey asset.SerializedKey
	)
	if !bytes.Equal(zeroKey[:], input.PrevScriptKey) {
		prevKey, err := btcec.ParsePubKey(input.PrevScriptKey)
		if err != nil {
			return witness, fmt.Errorf("unable to decode key: %w",
				err)
		}
		scriptKey = asset.ToSerialized(prevKey)
	}

	var assetID asset.ID
	copy(assetID[:], input.PrevAssetID)
	witness.PrevID = &asset.PrevID{
		OutPoint:  op,
		ID:        assetID,
		ScriptKey: scriptKey,
	}

	var buf [8]byte

	if len(input.WitnessStack) != 0 {
		err = asset.TxWitnessDecoder(
			bytes.NewReader(input.WitnessStack),
			&witness.TxWitness, &buf,
			uint64(len(input.WitnessStack)),
		)
		if err != nil {
			return witness, fmt.Errorf("unable to decode "+
				"witness: %w", err)
		}
	}

	if len(input.SplitCommitmentProof) != 0 {
		err := asset.SplitCommitmentDecoder(
			bytes.NewReader(input.SplitCommitmentProof),
			&witness.SplitCommitment, &buf,
			uint64(len(input.SplitCommitmentProof)),
		)
		if err != nil {
			return witness, fmt.Errorf("unable to decode split "+
				"commitment: %w", err)
		}
	}

	return witness, nil
}

// dbAssetsToChainAssets maps a set of confirmed assets in the database, and
// the witnesses of those assets to a set of normal ChainAsset structs needed
// by a higher level application.
func dbAssetsToChainAssets(dbAssets []ConfirmedAsset,
	witnesses assetWitnesses) ([]*ChainAsset, error) {

	chainAssets := make([]*ChainAsset, len(dbAssets))
	for i, sprout := range dbAssets {
		// First, we'll decode the script key which every asset must
		// specify, and populate the key locator information.
		rawScriptKeyPub, err := btcec.ParsePubKey(sprout.ScriptKeyRaw)
		if err != nil {
			return nil, err
		}
		rawScriptKeyDesc := keychain.KeyDescriptor{
			PubKey: rawScriptKeyPub,
			KeyLocator: keychain.KeyLocator{
				Index:  uint32(sprout.ScriptKeyIndex),
				Family: keychain.KeyFamily(sprout.ScriptKeyFam),
			},
		}

		// Not all assets have a key group, so we only need to
		// populate this information for those that signalled the
		// requirement of ongoing emission.
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
			groupSig, err := schnorr.ParseSignature(sprout.GenesisSig)
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
				Sig:         *groupSig,
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

		scriptKeyPub, err := btcec.ParsePubKey(sprout.TweakedScriptKey)
		if err != nil {
			return nil, err
		}
		scriptKey := asset.ScriptKey{
			PubKey: scriptKeyPub,
			TweakedScriptKey: &asset.TweakedScriptKey{
				RawKey: rawScriptKeyDesc,
				Tweak:  sprout.ScriptKeyTweak,
			},
		}

		assetSprout, err := asset.New(
			assetGenesis, amount, lockTime, relativeLocktime,
			scriptKey, groupKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new sprout: "+
				"%v", err)
		}

		if len(sprout.SplitCommitmentRootHash) != 0 {
			var nodeHash mssmt.NodeHash
			copy(nodeHash[:], sprout.SplitCommitmentRootHash)

			assetSprout.SplitCommitmentRoot = mssmt.NewComputedNode(
				nodeHash,
				uint64(sprout.SplitCommitmentRootValue.Int64),
			)
		}

		// With the asset created, we'll now emplace the set of
		// witnesses for the asset itself. If this is a genesis asset,
		// then it won't have a set of witnesses.
		assetInputs, ok := witnesses[sprout.AssetPrimaryKey]
		if ok {
			assetSprout.PrevWitnesses = make(
				[]asset.Witness, 0, len(assetInputs),
			)
			for _, input := range assetInputs {
				witness, err := parseAssetWitness(input)
				if err != nil {
					return nil, fmt.Errorf("unable to "+
						"parse witness: %w", err)
				}

				assetSprout.PrevWitnesses = append(
					assetSprout.PrevWitnesses, witness,
				)
			}
		}

		anchorTx := wire.NewMsgTx(2)
		err = anchorTx.Deserialize(bytes.NewBuffer(sprout.AnchorTx))
		if err != nil {
			return nil, fmt.Errorf("unable to decode tx: %w", err)
		}

		// An asset will only have an anchor block hash once it has
		// confirmed, so we'll only parse this if it exists.
		var anchorBlockHash chainhash.Hash
		if sprout.AnchorBlockHash != nil {
			anchorHash, err := chainhash.NewHash(
				sprout.AnchorBlockHash,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to extract block "+
					"hash: %w", err)
			}
			anchorBlockHash = *anchorHash
		}

		var anchorOutpoint wire.OutPoint
		err = readOutPoint(
			bytes.NewReader(sprout.AnchorOutpoint), 0, 0,
			&anchorOutpoint,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode "+
				"outpoint: %w", err)
		}

		anchorInternalKey, err := btcec.ParsePubKey(
			sprout.AnchorInternalKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse anchor "+
				"internal key: %w", err)
		}

		chainAssets[i] = &ChainAsset{
			Asset:             assetSprout,
			AnchorTx:          anchorTx,
			AnchorTxid:        anchorTx.TxHash(),
			AnchorBlockHash:   anchorBlockHash,
			AnchorOutpoint:    anchorOutpoint,
			AnchorInternalKey: anchorInternalKey,
		}
	}

	return chainAssets, nil
}

// constraintsToDbFilter maps application level constraints to the set of
// filters we use in the SQL queries.
func constraintsToDbFilter(query *AssetQueryFilters) QueryAssetFilters {
	var assetFilter QueryAssetFilters
	if query != nil {
		if query.MinAmt != 0 {
			assetFilter.MinAmt = sql.NullInt64{
				Int64: int64(query.MinAmt),
				Valid: true,
			}
		}
		if query.AssetID != nil {
			assetID := query.AssetID[:]
			assetFilter.AssetIDFilter = assetID
		}
		if query.GroupKey != nil {
			groupKey := query.GroupKey.SerializeCompressed()
			assetFilter.KeyGroupFilter = groupKey
		}
		// TODO(roasbeef): only want to allow asset ID or other and not
		// both?
	}

	return assetFilter
}

// specificAssetFilter maps the given asset parameters to the set of filters
// we use in the SQL queries.
func specificAssetFilter(id asset.ID, anchorPoint wire.OutPoint,
	groupKey *asset.GroupKey,
	scriptKey *asset.ScriptKey) (QueryAssetFilters, error) {

	anchorPointBytes, err := encodeOutpoint(anchorPoint)
	if err != nil {
		return QueryAssetFilters{}, fmt.Errorf("unable to encode "+
			"outpoint: %w", err)
	}

	filter := QueryAssetFilters{
		AssetIDFilter: id[:],
		AnchorPoint:   anchorPointBytes,
	}

	if groupKey != nil {
		key := groupKey.GroupPubKey
		filter.KeyGroupFilter = key.SerializeCompressed()
	}
	if scriptKey != nil {
		key := scriptKey.PubKey
		filter.TweakedScriptKey = key.SerializeCompressed()
	}

	return filter, nil
}

// fetchAssetsWithWitness fetches the set of assets in the backing store based
// on the set asset filter. A set of witnesses for each of the assets keyed by
// the primary key of the asset is also returned.
func fetchAssetsWithWitness(ctx context.Context, q ActiveAssetsStore,
	assetFilter QueryAssetFilters) ([]ConfirmedAsset, assetWitnesses,
	error) {

	// First, we'll fetch all the assets we know of on disk.
	dbAssets, err := q.QueryAssets(ctx, assetFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read db assets: %v", err)
	}

	assetIDs := fMap(dbAssets, func(a ConfirmedAsset) int32 {
		return a.AssetPrimaryKey
	})

	// With all the assets obtained, we'll now do a second query to
	// obtain all the witnesses we know of for each asset.
	assetWitnesses, err := fetchAssetWitnesses(ctx, q, assetIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch asset "+
			"witnesses: %w", err)
	}

	return dbAssets, assetWitnesses, nil
}

// AssetQueryFilters is a wrapper struct over the CommitmentConstraints struct
// which lets us filter the results of the set of assets returned.
type AssetQueryFilters struct {
	tarofreighter.CommitmentConstraints
}

// QueryBalancesByAsset queries the balances for assets or alternatively
// for a selected one that matches the passed asset ID filter.
func (a *AssetStore) QueryBalancesByAsset(ctx context.Context,
	assetID *asset.ID) (map[asset.ID]AssetBalance, error) {

	var assetFilter []byte
	if assetID != nil {
		assetFilter = assetID[:]
	}

	balances := make(map[asset.ID]AssetBalance)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		dbBalances, err := q.QueryAssetBalancesByAsset(ctx, assetFilter)
		if err != nil {
			return fmt.Errorf("unable to query asset "+
				"balances by asset: %w", err)
		}

		for _, assetBalance := range dbBalances {
			var assetID asset.ID
			copy(assetID[:], assetBalance.AssetID[:])

			assetIDBalance := AssetBalance{
				Version:     assetBalance.Version,
				Balance:     uint64(assetBalance.Balance),
				Tag:         assetBalance.AssetTag,
				Type:        asset.Type(assetBalance.AssetType),
				OutputIndex: uint32(assetBalance.OutputIndex),
			}

			err = readOutPoint(
				bytes.NewReader(assetBalance.GenesisPoint),
				0, 0, &assetIDBalance.GenesisPoint,
			)
			if err != nil {
				return err
			}

			copy(assetIDBalance.ID[:], assetBalance.AssetID)
			assetIDBalance.Meta = make(
				[]byte, len(assetBalance.MetaData),
			)
			copy(assetIDBalance.Meta, assetBalance.MetaData)

			balances[assetID] = assetIDBalance
		}

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return balances, nil
}

// QueryAssetBalancesByGroup queries the asset balances for asset groups or
// alternatively for a selected one that matches the passed filter.
func (a *AssetStore) QueryAssetBalancesByGroup(ctx context.Context,
	groupKey *btcec.PublicKey) (map[asset.SerializedKey]AssetGroupBalance,
	error) {

	var groupFilter []byte
	if groupKey != nil {
		groupKeySerialized := groupKey.SerializeCompressed()
		groupFilter = groupKeySerialized[:]
	}

	balances := make(map[asset.SerializedKey]AssetGroupBalance)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		dbBalances, err := q.QueryAssetBalancesByGroup(ctx, groupFilter)
		if err != nil {
			return fmt.Errorf("unable to query asset "+
				"balances by asset: %w", err)
		}

		for _, groupBalance := range dbBalances {
			var groupKey *btcec.PublicKey
			if groupBalance.TweakedGroupKey != nil {
				groupKey, err = btcec.ParsePubKey(
					groupBalance.TweakedGroupKey,
				)
				if err != nil {
					return err
				}
			}

			serializedKey := asset.ToSerialized(groupKey)
			balances[serializedKey] = AssetGroupBalance{
				GroupKey: groupKey,
				Balance:  uint64(groupBalance.Balance),
			}
		}

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return balances, nil
}

// FetchGroupedAssets fetches the set of assets with non-nil group keys.
func (a *AssetStore) FetchGroupedAssets(ctx context.Context) (
	[]*AssetHumanReadable, error) {

	var (
		dbAssets []RawGroupedAsset
		err      error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		dbAssets, err = q.FetchGroupedAssets(ctx)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	groupedAssets := make([]*AssetHumanReadable, len(dbAssets))
	for i, a := range dbAssets {
		amount := uint64(a.Amount)
		lockTime := extractSqlInt32[uint64](a.LockTime)
		relativeLockTime := extractSqlInt32[uint64](a.RelativeLockTime)
		assetType := asset.Type(a.AssetType)

		var assetID asset.ID
		copy(assetID[:], a.AssetID[:])

		groupKey, err := btcec.ParsePubKey(a.TweakedGroupKey)
		if err != nil {
			return nil, err
		}

		groupedAssets[i] = &AssetHumanReadable{
			ID:               assetID,
			Amount:           amount,
			LockTime:         lockTime,
			RelativeLockTime: relativeLockTime,
			Tag:              a.AssetTag,
			Metadata:         a.MetaData,
			Type:             assetType,
			GroupKey:         groupKey,
		}
	}

	return groupedAssets, nil
}

// FetchAllAssets fetches the set of confirmed assets stored on disk.
func (a *AssetStore) FetchAllAssets(ctx context.Context,
	query *AssetQueryFilters) ([]*ChainAsset, error) {

	var (
		dbAssets       []ConfirmedAsset
		assetWitnesses map[int32][]AssetWitness
		err            error
	)

	// We'll now map the application level filtering to the type of
	// filtering our database query understands.
	assetFilter := constraintsToDbFilter(query)

	// With the query constructed, we can now fetch the assets along w/
	// their witness information.
	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		dbAssets, assetWitnesses, err = fetchAssetsWithWitness(
			ctx, q, assetFilter,
		)

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return dbAssetsToChainAssets(dbAssets, assetWitnesses)
}

// FetchManagedUTXOs fetches all UTXOs we manage.
func (a *AssetStore) FetchManagedUTXOs(ctx context.Context) (
	[]*ManagedUTXO, error) {

	var (
		utxos []ManagedUTXORow
		err   error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		utxos, err = q.FetchManagedUTXOs(ctx)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	managedUtxos := make([]*ManagedUTXO, len(utxos))
	for i, u := range utxos {
		var anchorPoint wire.OutPoint
		err := readOutPoint(
			bytes.NewReader(u.Outpoint), 0, 0, &anchorPoint,
		)
		if err != nil {
			return nil, err
		}

		internalKey, err := btcec.ParsePubKey(u.RawKey)
		if err != nil {
			return nil, err
		}

		managedUtxos[i] = &ManagedUTXO{
			OutPoint:    anchorPoint,
			OutputValue: btcutil.Amount(u.AmtSats),
			InternalKey: keychain.KeyDescriptor{
				PubKey: internalKey,
				KeyLocator: keychain.KeyLocator{
					Index: uint32(u.KeyIndex),
					Family: keychain.KeyFamily(
						u.KeyFamily,
					),
				},
			},
			TaroRoot:         u.TaroRoot,
			TapscriptSibling: u.TapscriptSibling,
		}
	}

	return managedUtxos, nil
}

// FetchAssetProofs returns the latest proof file for either the set of target
// assets, or all assets if no script keys for an asset are passed in.
//
// TODO(roasbeef): potentially have a version that writes thru a reader
// instead?
func (a *AssetStore) FetchAssetProofs(ctx context.Context,
	targetAssets ...*btcec.PublicKey) (proof.AssetBlobs, error) {

	proofs := make(proof.AssetBlobs)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		// No target asset so we can just read them all from disk.
		if len(targetAssets) == 0 {
			assetProofs, err := q.FetchAssetProofs(ctx)
			if err != nil {
				return fmt.Errorf("unable to fetch asset "+
					"proofs: %w", err)
			}

			for _, p := range assetProofs {
				scriptKey, err := btcec.ParsePubKey(p.ScriptKey)
				if err != nil {
					return err
				}

				serializedKey := asset.ToSerialized(scriptKey)
				proofs[serializedKey] = p.ProofFile
			}

			return nil
		}

		// Otherwise, we'll need to issue a series of queries to fetch
		// each of the relevant proof files.
		//
		// TODO(roasbeef): can modify the query to use IN somewhere
		// instead? then would take input params and insert into
		// virtual rows to use
		for _, scriptKey := range targetAssets {
			scriptKey := scriptKey
			serializedKey := asset.ToSerialized(scriptKey)

			assetProof, err := q.FetchAssetProof(
				ctx, serializedKey[:],
			)
			if err != nil {
				return fmt.Errorf("unable to fetch asset "+
					"proof: %w", err)
			}

			proofs[serializedKey] = assetProof.ProofFile
		}
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return proofs, nil
}

// FetchProof fetches a proof for an asset uniquely identified by the passed
// ProofIdentifier.
//
// NOTE: This implements the proof.ArchiveBackend interface.
func (a *AssetStore) FetchProof(ctx context.Context,
	locator proof.Locator) (proof.Blob, error) {

	// We don't need anything else but the script key since we have an
	// on-disk index for all proofs we store.
	scriptKey := locator.ScriptKey

	var diskProof proof.Blob

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		assetProof, err := q.FetchAssetProof(
			ctx, scriptKey.SerializeCompressed(),
		)
		if err != nil {
			return fmt.Errorf("unable to fetch asset "+
				"proof: %w", err)
		}

		diskProof = assetProof.ProofFile

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, proof.ErrProofNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return diskProof, nil
}

// insertAssetWitnesses attempts to insert the set of asset witnesses in to the
// database, referencing the passed asset primary key.
func (a *AssetStore) insertAssetWitnesses(ctx context.Context,
	db ActiveAssetsStore, assetID int32, inputs []asset.Witness) error {

	var buf [8]byte
	for _, input := range inputs {
		prevID := input.PrevID

		prevOutpoint, err := encodeOutpoint(prevID.OutPoint)
		if err != nil {
			return fmt.Errorf("unable to write outpoint: %w", err)
		}

		var witnessStack []byte
		if len(input.TxWitness) != 0 {
			var b bytes.Buffer
			err = asset.TxWitnessEncoder(&b, &input.TxWitness, &buf)
			if err != nil {
				return fmt.Errorf("unable to encode "+
					"witness: %w", err)
			}

			witnessStack = make([]byte, b.Len())
			copy(witnessStack, b.Bytes())
		}

		var splitCommitmentProof []byte

		if input.SplitCommitment != nil {
			var b bytes.Buffer
			err := asset.SplitCommitmentEncoder(
				&b, &input.SplitCommitment, &buf,
			)
			if err != nil {
				return fmt.Errorf("unable to encode split "+
					"commitment: %w", err)
			}

			splitCommitmentProof = make([]byte, b.Len())
			copy(splitCommitmentProof, b.Bytes())
		}

		err = db.InsertAssetWitness(ctx, PrevInput{
			AssetID:              assetID,
			PrevOutPoint:         prevOutpoint,
			PrevAssetID:          prevID.ID[:],
			PrevScriptKey:        prevID.ScriptKey.CopyBytes(),
			WitnessStack:         witnessStack,
			SplitCommitmentProof: splitCommitmentProof,
		})
		if err != nil {
			return fmt.Errorf("unable to insert witness: %v", err)
		}
	}

	return nil
}

// importAssetFromProof imports a new asset into the database based on the
// information associated with the annotated proofs. This will result in a new
// asset inserted on disk, with all dependencies such as the asset witnesses
// inserted along the way.
func (a *AssetStore) importAssetFromProof(ctx context.Context,
	db ActiveAssetsStore, proof *proof.AnnotatedProof) error {

	// TODO(roasbeef): below needs to be updated to support asset splits

	// We already know where this lives on-chain, so we can go ahead and
	// insert the chain information now.
	//
	// From the final asset snapshot, we'll obtain the final "resting
	// place" of the asset and insert that into the DB.
	var anchorTxBuf bytes.Buffer
	if err := proof.AnchorTx.Serialize(&anchorTxBuf); err != nil {
		return err
	}
	anchorTXID := proof.AnchorTx.TxHash()
	chainTXID, err := db.UpsertChainTx(ctx, ChainTx{
		Txid:        anchorTXID[:],
		RawTx:       anchorTxBuf.Bytes(),
		BlockHeight: sqlInt32(proof.AnchorBlockHeight),
		BlockHash:   proof.AnchorBlockHash[:],
		TxIndex:     sqlInt32(proof.AnchorTxIndex),
	})
	if err != nil {
		return fmt.Errorf("unable to insert chain tx: %w", err)
	}

	anchorOutput := proof.AnchorTx.TxOut[proof.OutputIndex]
	anchorPoint, err := encodeOutpoint(wire.OutPoint{
		Hash:  anchorTXID,
		Index: proof.OutputIndex,
	})
	if err != nil {
		return fmt.Errorf("unable to encode outpoint: %w", err)
	}

	// Before we import the managed UTXO below, we'll make sure to insert
	// the internal key, though it might already exist here.
	_, err = db.UpsertInternalKey(ctx, InternalKey{
		RawKey: proof.InternalKey.SerializeCompressed(),
	})
	if err != nil {
		return fmt.Errorf("unable to insert internal key: %w", err)
	}

	// Next, we'll insert the managed UTXO that points to the output in our
	// control for the specified asset.
	//
	// TODO(roasbeef): also need to store sibling hash here?
	tapscriptRoot := proof.ScriptRoot.TapscriptRoot(nil)
	utxoID, err := db.UpsertManagedUTXO(ctx, RawManagedUTXO{
		RawKey:   proof.InternalKey.SerializeCompressed(),
		Outpoint: anchorPoint,
		AmtSats:  anchorOutput.Value,
		TaroRoot: tapscriptRoot[:],
		TxnID:    chainTXID,
	})
	if err != nil {
		return fmt.Errorf("unable to insert managed utxo: %w", err)
	}

	newAsset := proof.Asset

	// Insert/update the asset information in the database now.
	_, assetIDs, err := upsertAssetsWithGenesis(
		ctx, db, newAsset.Genesis.FirstPrevOut,
		[]*asset.Asset{newAsset}, []sql.NullInt32{sqlInt32(utxoID)},
	)
	if err != nil {
		return fmt.Errorf("error inserting asset with genesis: %w", err)
	}

	// Now that we have the asset inserted, we'll also insert all the
	// witness data associated with the asset in a new row.
	err = a.insertAssetWitnesses(
		ctx, db, assetIDs[0], newAsset.PrevWitnesses,
	)
	if err != nil {
		return fmt.Errorf("unable to insert asset witness: %w", err)
	}

	// As a final step, we'll insert the proof file we used to generate all
	// the above information.
	scriptKeyBytes := newAsset.ScriptKey.PubKey.SerializeCompressed()
	return db.UpsertAssetProof(ctx, ProofUpdate{
		TweakedScriptKey: scriptKeyBytes,
		ProofFile:        proof.Blob,
	})
}

// ImportProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
//
// NOTE: This implements the proof.ArchiveBackend interface.
func (a *AssetStore) ImportProofs(ctx context.Context,
	headerVerifier proof.HeaderVerifier,
	proofs ...*proof.AnnotatedProof) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		for _, proof := range proofs {
			err := a.importAssetFromProof(ctx, q, proof)
			if err != nil {
				return fmt.Errorf("unable to import asset: %w",
					err)
			}
		}

		return nil
	})
}

// queryChainAssets queries the database for assets matching the passed filter.
// The returned assets have all anchor and witness information populated.
func queryChainAssets(ctx context.Context, q ActiveAssetsStore,
	filter QueryAssetFilters) ([]*ChainAsset, error) {

	dbAssets, assetWitnesses, err := fetchAssetsWithWitness(
		ctx, q, filter,
	)
	if err != nil {
		return nil, err
	}
	matchingAssets, err := dbAssetsToChainAssets(dbAssets, assetWitnesses)
	if err != nil {
		return nil, err
	}

	return matchingAssets, nil
}

// FetchCommitment returns a specific commitment identified by the given asset
// parameters. If no commitment is found, ErrNoCommitment is returned.
func (a *AssetStore) FetchCommitment(ctx context.Context, id asset.ID,
	anchorPoint wire.OutPoint, groupKey *asset.GroupKey,
	scriptKey *asset.ScriptKey) (*tarofreighter.AnchoredCommitment, error) {

	filter, err := specificAssetFilter(id, anchorPoint, groupKey, scriptKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create filter: %w", err)
	}

	commitments, err := a.queryCommitments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("unable to query commitments: %w", err)
	}

	if len(commitments) != 1 {
		return nil, fmt.Errorf("expected 1 commitment, found %d",
			len(commitments))
	}

	return commitments[0], nil
}

// SelectCommitment takes the set of commitment contrarians and returns an
// AnchoredCommitment that returns all the information needed to use the
// commitment as an input to an on chain taro transaction.
//
// NOTE: This implements the tarofreighter.CommitmentSelector interface.
func (a *AssetStore) SelectCommitment(
	ctx context.Context, constraints tarofreighter.CommitmentConstraints) (
	[]*tarofreighter.AnchoredCommitment, error) {

	if constraints.MinAmt > math.MaxInt64 {
		return nil, fmt.Errorf("min amount overflow")
	}

	// First, we'll map the commitment constraints to our database query
	// filters.
	assetFilter := constraintsToDbFilter(&AssetQueryFilters{
		constraints,
	})

	return a.queryCommitments(ctx, assetFilter)
}

// queryCommitments queries the database for commitments matching the passed
// filter.
func (a *AssetStore) queryCommitments(ctx context.Context,
	assetFilter QueryAssetFilters) ([]*tarofreighter.AnchoredCommitment,
	error) {

	var (
		matchingAssets      []*ChainAsset
		chainAnchorToAssets = make(map[wire.OutPoint][]*ChainAsset)
		anchorPoints        = make(map[wire.OutPoint]AnchorPoint)
		err                 error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		// Now that we have the set of filters we need we'll query the
		// DB for the set of assets that matches them.
		matchingAssets, err = queryChainAssets(ctx, q, assetFilter)
		if err != nil {
			return err
		}

		if len(matchingAssets) == 0 {
			return tarofreighter.ErrNoPossibleAssetInputs
		}

		// At this point, we have the set of assets that match our
		// filter query, but we also need to be able to construct the
		// full Taro commitment for each asset so it can be used as an
		// input in a transaction.
		//
		// To obtain this, we'll first do another query to fetch all
		// the _other_ assets that are anchored at the anchor point for
		// each of the assets above.
		for _, matchingAsset := range matchingAssets {
			anchorPoint := matchingAsset.AnchorOutpoint
			anchorPointBytes, err := encodeOutpoint(
				matchingAsset.AnchorOutpoint,
			)
			if err != nil {
				return err
			}
			outpointQuery := QueryAssetFilters{
				AnchorPoint: anchorPointBytes,
			}

			anchoredAssets, err := queryChainAssets(
				ctx, q, outpointQuery,
			)
			if err != nil {
				return err
			}

			chainAnchorToAssets[anchorPoint] = anchoredAssets

			// In addition to the assets anchored at the target
			// UTXO, we'll also fetch the managed UTXO itself.
			anchorUTXO, err := q.FetchManagedUTXO(ctx, UtxoQuery{
				Outpoint: anchorPointBytes,
			})
			if err != nil {
				return err
			}

			anchorPoints[anchorPoint] = anchorUTXO
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// Our final query wants the complete taro commitment for each of the
	// managed UTXOs. Some of the assets that match our query might
	// actually be in the same Taro commitment, so we'll collect this now
	// to de-dup things early.
	anchorPointToCommitment := make(
		map[wire.OutPoint]*commitment.TaroCommitment,
	)
	for anchorPoint, anchoredAssets := range chainAnchorToAssets {
		// First, we need to group each of the assets according to
		// their asset.
		assetsByID := make(map[asset.ID][]*asset.Asset)
		for _, a := range anchoredAssets {
			assetID := a.ID()
			assetsByID[assetID] = append(
				assetsByID[assetID], a.Asset,
			)
		}

		// Now that we have each asset grouped by their asset ID, we
		// can make an asset commitment for each of them.
		assetCommitments := make(map[asset.ID]*commitment.AssetCommitment)
		for assetID, assets := range assetsByID {
			assetCommitment, err := commitment.NewAssetCommitment(
				assets...,
			)
			if err != nil {
				return nil, err
			}

			assetCommitments[assetID] = assetCommitment
		}

		// Finally, we'll construct the Taro commitment for this group
		// of assets.
		taroCommitment, err := commitment.NewTaroCommitment(
			maps.Values(assetCommitments)...,
		)
		if err != nil {
			return nil, err
		}

		anchorPointToCommitment[anchorPoint] = taroCommitment
	}

	// Now that we have all the matching assets, along w/ all the other
	// assets that are committed in the same outpoint, we can construct our
	// final response.
	selectedAssets := make(
		[]*tarofreighter.AnchoredCommitment, len(matchingAssets),
	)
	for i, matchingAsset := range matchingAssets {
		// Using the anchor point of the matching asset, we can obtain
		// the UTXO that anchors things, and then the internal key from
		// that.
		anchorPoint := matchingAsset.AnchorOutpoint

		anchorUTXO := anchorPoints[anchorPoint]
		internalKey, err := btcec.ParsePubKey(anchorUTXO.RawKey)
		if err != nil {
			return nil, err
		}

		selectedAssets[i] = &tarofreighter.AnchoredCommitment{
			AnchorPoint:       anchorPoint,
			AnchorOutputValue: btcutil.Amount(anchorUTXO.AmtSats),
			InternalKey: keychain.KeyDescriptor{
				PubKey: internalKey,
				KeyLocator: keychain.KeyLocator{
					Index: uint32(anchorUTXO.KeyIndex),
					Family: keychain.KeyFamily(
						anchorUTXO.KeyFamily,
					),
				},
			},
			TapscriptSibling: anchorUTXO.TapscriptSibling,
			Asset:            matchingAsset.Asset,
			Commitment:       anchorPointToCommitment[anchorPoint],
		}
	}

	return selectedAssets, nil
}

// LogPendingParcel marks an outbound parcel as pending on disk. This commits
// the set of changes to disk (the asset deltas) but doesn't mark the batched
// spend as being finalized.
//
// TODO(jhb): Update for new table
func (a *AssetStore) LogPendingParcel(ctx context.Context,
	spend *tarofreighter.OutboundParcelDelta) error {

	// Before we enter the DB transaction below, we'll use this space to
	// encode a few values outside the transaction closure.
	newAnchorTXID := spend.AnchorTx.TxHash()
	var txBuf bytes.Buffer
	if err := spend.AnchorTx.Serialize(&txBuf); err != nil {
		return err
	}

	anchorTxBytes := txBuf.Bytes()

	newAnchorPointBytes, err := encodeOutpoint(spend.NewAnchorPoint)
	if err != nil {
		return err
	}
	oldAnchorPointBytes, err := encodeOutpoint(spend.OldAnchorPoint)
	if err != nil {
		return err
	}

	internalKeyBytes := spend.NewInternalKey.PubKey.SerializeCompressed()

	anchorIndex := spend.NewAnchorPoint.Index
	anchorValue := spend.AnchorTx.TxOut[anchorIndex].Value

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		// First, we'll insert the new internal on disk, so we can
		// reference it later when we go to apply the new transfer.
		internalKeyID, err := q.UpsertInternalKey(ctx, InternalKey{
			RawKey:    internalKeyBytes,
			KeyFamily: int32(spend.NewInternalKey.Family),
			KeyIndex:  int32(spend.NewInternalKey.Index),
		})
		if err != nil {
			return fmt.Errorf("unable to insert internal "+
				"key: %w", err)
		}

		// Next, we'll insert the new transaction that anchors the new
		// anchor point (commits to the set of new outputs).
		txnID, err := q.UpsertChainTx(ctx, ChainTx{
			Txid:      newAnchorTXID[:],
			RawTx:     anchorTxBytes,
			ChainFees: spend.ChainFees,
		})
		if err != nil {
			return fmt.Errorf("unable to insert new chain "+
				"tx: %w", err)
		}

		// Now that the chain transaction been inserted, we can now
		// insert a _new_ managed UTXO which houses the information
		// related to the new anchor point of the transaction.
		newUtxoID, err := q.UpsertManagedUTXO(ctx, RawManagedUTXO{
			RawKey:           internalKeyBytes,
			Outpoint:         newAnchorPointBytes,
			AmtSats:          anchorValue,
			TaroRoot:         spend.TaroRoot,
			TapscriptSibling: spend.TapscriptSibling,
			TxnID:            txnID,
		})
		if err != nil {
			return fmt.Errorf("unable to insert new managed "+
				"utxo: %w", err)
		}

		// With the internal key inserted, we can now insert the asset
		// transfer body itself.
		transferID, err := q.InsertAssetTransfer(ctx, NewAssetTransfer{
			OldAnchorPoint:   oldAnchorPointBytes,
			NewInternalKey:   internalKeyID,
			NewAnchorUtxo:    newUtxoID,
			HeightHint:       int32(spend.AnchorTxHeightHint),
			TransferTimeUnix: spend.TransferTime,
		})
		if err != nil {
			return fmt.Errorf("unable to insert asset "+
				"transfer: %w", err)
		}

		// Now that the transfer itself has been inserted, we can
		// insert the deltas associated w/ each transfer.
		for _, assetDelta := range spend.AssetSpendDeltas {
			// With the main transfer inserted, we'll also insert
			// the proof for the sender and receiver.
			proofID, err := q.InsertSpendProofs(ctx, NewSpendProof{
				TransferID:    transferID,
				SenderProof:   assetDelta.SenderAssetProof,
				ReceiverProof: assetDelta.ReceiverAssetProof,
			})
			if err != nil {
				return fmt.Errorf("unable to insert spend "+
					"proof: %w", err)
			}

			var (
				witnessBuf bytes.Buffer
				buf        [8]byte
			)
			err = asset.WitnessEncoder(
				&witnessBuf, &assetDelta.WitnessData, &buf,
			)
			if err != nil {
				return fmt.Errorf("unable to encode witness: "+
					"%w", err)
			}

			// Before we can insert the asset delta, we need to
			// insert the new script key on disk.
			rawScriptKey := assetDelta.NewScriptKey.RawKey
			rawScriptKeyID, err := q.UpsertInternalKey(
				ctx, InternalKey{
					RawKey:    rawScriptKey.PubKey.SerializeCompressed(),
					KeyFamily: int32(rawScriptKey.Family),
					KeyIndex:  int32(rawScriptKey.Index),
				},
			)
			if err != nil {
				return fmt.Errorf("unable to insert internal "+
					"key: %w", err)
			}
			scriptKeyID, err := q.UpsertScriptKey(ctx, NewScriptKey{
				InternalKeyID:    rawScriptKeyID,
				TweakedScriptKey: assetDelta.NewScriptKey.PubKey.SerializeCompressed(),
				Tweak:            assetDelta.NewScriptKey.Tweak,
			})
			if err != nil {
				return fmt.Errorf("unable to insert script "+
					"key: %w", err)
			}

			delta := NewAssetDelta{
				OldScriptKey:        assetDelta.OldScriptKey.SerializeCompressed(),
				NewAmt:              int64(assetDelta.NewAmt),
				NewScriptKey:        scriptKeyID,
				SerializedWitnesses: witnessBuf.Bytes(),
				TransferID:          transferID,
				ProofID:             proofID,
			}

			// There might not have been a split.
			if assetDelta.SplitCommitmentRoot != nil {
				newCommitRoot := assetDelta.SplitCommitmentRoot
				splitRootHash := newCommitRoot.NodeHash()
				delta.SplitCommitmentRootHash = splitRootHash[:]
				delta.SplitCommitmentRootValue = sql.NullInt64{
					Int64: int64(newCommitRoot.NodeSum()),
					Valid: true,
				}
			}

			err = q.InsertAssetDelta(ctx, delta)
			if err != nil {
				return fmt.Errorf("unable to insert asset "+
					"delta: %w", err)
			}
		}

		return nil
	})
}

// StoreProofDeliveryAttempt logs a proof delivery attempt to disk.
func (a *AssetStore) StoreProofDeliveryAttempt(ctx context.Context,
	locator proof.Locator) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		// Log proof delivery attempt and timestamp using the current
		// time.
		proofLocatorHash := locator.Hash()
		err := q.InsertReceiverProofTransferAttempt(
			ctx, InsertRecvProofTxAttemptParams{
				ProofLocatorHash: proofLocatorHash[:],
				TimeUnix:         time.Now().UTC(),
			},
		)
		if err != nil {
			return fmt.Errorf("unable to insert receiver proof "+
				"transfer attempt log entry: %w", err)
		}

		return nil
	})
}

// QueryProofDeliveryLog returns timestamps which correspond to logged proof
// delivery attempts.
func (a *AssetStore) QueryProofDeliveryLog(ctx context.Context,
	locator proof.Locator) ([]time.Time, error) {

	var (
		timestamps []time.Time
		err        error
	)
	readOpts := NewAssetStoreReadTx()

	err = a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		proofLocatorHash := locator.Hash()
		timestamps, err = q.QueryReceiverProofTransferAttempt(
			ctx, proofLocatorHash[:],
		)
		if err != nil {
			return fmt.Errorf("unable to query receiver proof "+
				"transfer attempt log: %w", err)
		}

		return nil
	})
	return timestamps, err
}

// ConfirmParcelDelivery marks a spend event on disk as confirmed. This updates
// the on-chain reference information on disk to point to this new spend.
func (a *AssetStore) ConfirmParcelDelivery(ctx context.Context,
	conf *tarofreighter.AssetConfirmEvent) error {

	anchorPointBytes, err := encodeOutpoint(conf.AnchorPoint)
	if err != nil {
		return err
	}

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		// First, we'll fetch the asset transfer based on its outpoint
		// bytes so we can apply the delta it describes.
		assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
			NewAnchorPoint: anchorPointBytes,
		})
		if err != nil {
			return err
		}
		assetTransfer := assetTransfers[0]

		// Now that we have the new managed UTXO inserted, we'll update
		// the managed UTXO pointer for _all_ assets that were anchored
		// by the old managed UTXO.
		err = q.ReanchorAssets(ctx, AssetAnchorUpdate{
			OldOutpoint: assetTransfer.OldAnchorPoint,
			NewOutpointUtxoID: sqlInt32(
				assetTransfer.NewAnchorUtxoID,
			),
		})
		if err != nil {
			return err
		}

		// Now that we've re-anchored all the other assets, we also
		// need to fetch the set of deltas so we can apply to each
		// asset.
		assetDeltas, err := q.FetchAssetDeltas(
			ctx, assetTransfer.TransferID,
		)
		if err != nil {
			return err
		}
		for _, assetDelta := range assetDeltas {
			// First, we'll apply the spend delta to update the
			// amount and script key of all assets.
			assetIDKey, err := q.ApplySpendDelta(ctx, AssetSpendDelta{
				NewAmount:                int64(assetDelta.NewAmt),
				OldScriptKey:             assetDelta.OldScriptKey,
				NewScriptKeyID:           assetDelta.NewScriptKeyID,
				SplitCommitmentRootHash:  assetDelta.SplitCommitmentRootHash,
				SplitCommitmentRootValue: assetDelta.SplitCommitmentRootValue,
			})
			if err != nil {
				return fmt.Errorf("unable to update "+
					"spend delta: %w", err)
			}

			// With the delta applied, we'll delete the _old_ set
			// of witnesses, and re-insert new ones.
			err = q.DeleteAssetWitnesses(ctx, assetIDKey)
			if err != nil {
				return fmt.Errorf("unable to delete "+
					"witnesses: %v", err)
			}

			// With the old witnesses removed, we'll insert the new
			// set on disk.
			var witnessData []asset.Witness
			err = asset.WitnessDecoder(
				bytes.NewReader(assetDelta.SerializedWitnesses),
				&witnessData, &[8]byte{},
				uint64(len(assetDelta.SerializedWitnesses)),
			)
			if err != nil {
				return fmt.Errorf("unable to decode "+
					"witness: %v", err)
			}
			err = a.insertAssetWitnesses(
				ctx, q, assetIDKey, witnessData,
			)
			if err != nil {
				return fmt.Errorf("unable to insert asset "+
					"witnesses: %v", err)
			}

			// Now we can update the asset proof for the sender for
			// this given delta.
			err = q.UpsertAssetProof(ctx, ProofUpdate{
				TweakedScriptKey: assetDelta.NewScriptKeyBytes,
				ProofFile:        conf.FinalSenderProof,
			})
			if err != nil {
				return err
			}
		}

		// To confirm a delivery (successful send) all we need to do is
		// update the chain information for the transaction that
		// anchors the new anchor point.
		err = q.ConfirmChainAnchorTx(ctx, AnchorTxConf{
			Outpoint:    anchorPointBytes,
			BlockHash:   conf.BlockHash[:],
			BlockHeight: sqlInt32(conf.BlockHeight),
			TxIndex:     sqlInt32(conf.TxIndex),
		})
		if err != nil {
			return err
		}

		// Keep the old proofs as a reference for when we list past
		// transfers.

		// At this point we could delete the managed UTXO since it's no
		// longer an unspent output, however we'll keep it in order to
		// be able to reconstruct transfer history.

		return nil
	})
}

// PendingParcels returns the set of parcels that haven't yet been finalized.
// This can be used to query the set of unconfirmed
// transactions for re-broadcast.
func (a *AssetStore) PendingParcels(
	ctx context.Context) ([]*tarofreighter.OutboundParcelDelta, error) {

	return a.QueryParcels(ctx, true)
}

// QueryParcels returns the set of confirmed or unconfirmed parcels.
func (a *AssetStore) QueryParcels(ctx context.Context,
	pending bool) ([]*tarofreighter.OutboundParcelDelta, error) {

	var deltas []*tarofreighter.OutboundParcelDelta

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		// If we want every unconfirmed transfer, then we only pass in
		// the UnconfOnly field.
		assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
			UnconfOnly: pending,
		})
		if err != nil {
			return err
		}

		for _, xfer := range assetTransfers {
			var oldAnchorPoint, newAnchorPoint wire.OutPoint
			err := readOutPoint(
				bytes.NewReader(xfer.OldAnchorPoint), 0, 0,
				&oldAnchorPoint,
			)
			if err != nil {
				return err
			}
			err = readOutPoint(
				bytes.NewReader(xfer.NewAnchorPoint), 0, 0,
				&newAnchorPoint,
			)
			if err != nil {
				return err
			}

			internalKey, err := btcec.ParsePubKey(
				xfer.InternalKeyBytes,
			)
			if err != nil {
				return err
			}

			anchorTx := wire.NewMsgTx(2)
			err = anchorTx.Deserialize(bytes.NewBuffer(
				xfer.AnchorTxBytes,
			))
			if err != nil {
				return fmt.Errorf("unable to decode tx: %w",
					err)
			}

			assetDeltas, err := q.FetchAssetDeltasWithProofs(
				ctx, xfer.TransferID,
			)
			if err != nil {
				return err
			}
			spendDeltas := make(
				[]tarofreighter.AssetSpendDelta,
				len(assetDeltas),
			)
			for i, delta := range assetDeltas {
				oldScriptKey, err := btcec.ParsePubKey(
					delta.OldScriptKey,
				)
				if err != nil {
					return err
				}
				newScriptKey, err := btcec.ParsePubKey(
					delta.NewScriptKeyBytes,
				)
				if err != nil {
					return err
				}
				rawScriptKey, err := btcec.ParsePubKey(
					delta.NewRawScriptKeyBytes,
				)
				if err != nil {
					return err
				}

				var splitRootHash mssmt.NodeHash
				copy(splitRootHash[:], delta.SplitCommitmentRootHash)

				var witnessData []asset.Witness
				err = asset.WitnessDecoder(
					bytes.NewReader(delta.SerializedWitnesses),
					&witnessData, &[8]byte{},
					uint64(len(delta.SerializedWitnesses)),
				)
				if err != nil {
					return fmt.Errorf("unable to decode "+
						"witness: %v", err)
				}

				tweakedScriptKey := &asset.TweakedScriptKey{
					RawKey: keychain.KeyDescriptor{
						PubKey: rawScriptKey,
						KeyLocator: keychain.KeyLocator{
							Family: keychain.KeyFamily(
								delta.NewScriptKeyFamily,
							),
							Index: uint32(
								delta.NewScriptKeyIndex,
							),
						},
					},
					Tweak: delta.ScriptKeyTweak,
				}
				spendDeltas[i] = tarofreighter.AssetSpendDelta{
					OldScriptKey: *oldScriptKey,
					NewAmt:       uint64(delta.NewAmt),
					NewScriptKey: asset.ScriptKey{
						PubKey:           newScriptKey,
						TweakedScriptKey: tweakedScriptKey,
					},
					SplitCommitmentRoot: mssmt.NewComputedNode(
						splitRootHash,
						uint64(delta.SplitCommitmentRootValue.Int64),
					),
					WitnessData:        witnessData,
					SenderAssetProof:   delta.SenderProof,
					ReceiverAssetProof: delta.ReceiverProof,
				}
			}

			deltas = append(deltas, &tarofreighter.OutboundParcelDelta{
				OldAnchorPoint: oldAnchorPoint,
				NewAnchorPoint: newAnchorPoint,
				NewInternalKey: keychain.KeyDescriptor{
					PubKey: internalKey,
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(xfer.InternalKeyFam),
						Index:  uint32(xfer.InternalKeyIndex),
					},
				},
				TaroRoot:           xfer.TaroRoot,
				TapscriptSibling:   xfer.TapscriptSibling,
				AnchorTx:           anchorTx,
				AssetSpendDeltas:   spendDeltas,
				AnchorTxHeightHint: uint32(xfer.HeightHint),
				TransferTime:       xfer.TransferTimeUnix,
				ChainFees:          xfer.ChainFees,
			})
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return deltas, nil
}

// A compile-time constraint to ensure that AssetStore meets the proof.Archiver
// interface.
var _ proof.Archiver = (*AssetStore)(nil)

// A compile-time constraint to ensure that AssetStore meets the
// tarofreighter.CommitmentSelector interface.
var _ tarofreighter.CommitmentSelector = (*AssetStore)(nil)

// A compile-time constraint to ensure that AssetStore meets the
// tarofreighter.ExportLog interface.
var _ tarofreighter.ExportLog = (*AssetStore)(nil)
