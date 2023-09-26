package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
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

	// AssetProofByIDRow is the asset proof for a given asset, identified by
	// its asset ID.
	AssetProofByIDRow = sqlc.FetchAssetProofsByAssetIDRow

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

	// UpdateUTXOLease wraps the params needed to lease a managed UTXO.
	UpdateUTXOLease = sqlc.UpdateUTXOLeaseParams

	// ApplyPendingOutput is used to update the script key and amount of an
	// existing asset.
	ApplyPendingOutput = sqlc.ApplyPendingOutputParams

	// AnchorTxConf identifies an unconfirmed anchor tx to confirm.
	AnchorTxConf = sqlc.ConfirmChainAnchorTxParams

	// NewAssetTransfer wraps the params needed to insert a new asset
	// transfer.
	NewAssetTransfer = sqlc.InsertAssetTransferParams

	// AssetTransfer tracks an asset transfer.
	AssetTransfer = sqlc.AssetTransfer

	// TransferQuery allows callers to filter out the set of transfers
	// based on set information.
	TransferQuery = sqlc.QueryAssetTransfersParams

	// AssetTransferRow wraps a single transfer row.
	AssetTransferRow = sqlc.QueryAssetTransfersRow

	// TransferInput tracks the inputs to an asset transfer.
	TransferInput = sqlc.AssetTransferInput

	// TransferInputRow wraps a single transfer input row.
	TransferInputRow = sqlc.FetchTransferInputsRow

	// NewTransferInput wraps the params needed to insert a new transfer
	// input.
	NewTransferInput = sqlc.InsertAssetTransferInputParams

	// TransferOutput tracks the outputs to an asset transfer.
	TransferOutput = sqlc.AssetTransferOutput

	// TransferOutputRow wraps a single transfer output row.
	TransferOutputRow = sqlc.FetchTransferOutputsRow

	// NewTransferOutput wraps the params needed to insert a new transfer
	// output.
	NewTransferOutput = sqlc.InsertAssetTransferOutputParams

	// NewPassiveAsset wraps the params needed to insert a new passive
	// asset.
	NewPassiveAsset = sqlc.InsertPassiveAssetParams

	// PassiveAsset tracks a passive asset.
	PassiveAsset = sqlc.QueryPassiveAssetsRow

	// ReAnchorParams wraps the params needed to re-anchor a passive asset.
	ReAnchorParams = sqlc.ReAnchorPassiveAssetsParams
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

	// FetchAssetProofsByAssetID fetches all asset proofs for a given asset
	// ID.
	FetchAssetProofsByAssetID(ctx context.Context,
		assetID []byte) ([]AssetProofByIDRow, error)

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTxParams) (int32, error)

	// FetchChainTx fetches a chain tx from the DB.
	FetchChainTx(ctx context.Context, txid []byte) (ChainTx, error)

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

	// ApplyPendingOutput applies a transfer output (new amount and script
	// key) based on the existing script key of an asset.
	ApplyPendingOutput(ctx context.Context, arg ApplyPendingOutput) (int32,
		error)

	// DeleteManagedUTXO deletes the managed utxo identified by the passed
	// serialized outpoint.
	DeleteManagedUTXO(ctx context.Context, outpoint []byte) error

	// UpdateUTXOLease leases a managed UTXO identified by the passed
	// serialized outpoint.
	UpdateUTXOLease(ctx context.Context, arg UpdateUTXOLease) error

	// DeleteUTXOLease deletes the lease on a managed UTXO identified by
	// the passed serialized outpoint.
	DeleteUTXOLease(ctx context.Context, outpoint []byte) error

	// DeleteExpiredUTXOLeases deletes all expired UTXO leases.
	DeleteExpiredUTXOLeases(ctx context.Context, now sql.NullTime) error

	// ConfirmChainAnchorTx marks a new anchor transaction that was
	// previously unconfirmed as confirmed.
	ConfirmChainAnchorTx(ctx context.Context, arg AnchorTxConf) error

	// InsertAssetTransfer inserts a new asset transfer into the DB.
	InsertAssetTransfer(ctx context.Context,
		arg NewAssetTransfer) (int32, error)

	// InsertAssetTransferInput inserts a new asset transfer input into the
	// DB.
	InsertAssetTransferInput(ctx context.Context,
		arg NewTransferInput) error

	// InsertAssetTransferOutput inserts a new asset transfer output into
	// the DB.
	InsertAssetTransferOutput(ctx context.Context,
		arg NewTransferOutput) error

	// FetchTransferInputs fetches the inputs to a given asset transfer.
	FetchTransferInputs(ctx context.Context,
		transferID int32) ([]TransferInputRow, error)

	// FetchTransferOutputs fetches the outputs to a given asset transfer.
	FetchTransferOutputs(ctx context.Context,
		transferID int32) ([]TransferOutputRow, error)

	// QueryAssetTransfers queries for a set of asset transfers in the db.
	QueryAssetTransfers(ctx context.Context,
		query sqlc.QueryAssetTransfersParams) ([]AssetTransferRow,
		error)

	// DeleteAssetWitnesses deletes the witnesses on disk associated with a
	// given asset ID.
	DeleteAssetWitnesses(ctx context.Context, assetID int32) error

	// InsertReceiverProofTransferAttempt inserts a new receiver proof
	// transfer attempt record.
	InsertReceiverProofTransferAttempt(ctx context.Context,
		arg InsertRecvProofTxAttemptParams) error

	// QueryReceiverProofTransferAttempt returns timestamps which correspond
	// to receiver proof delivery attempts.
	QueryReceiverProofTransferAttempt(ctx context.Context,
		proofLocatorHash []byte) ([]time.Time, error)

	// InsertPassiveAsset inserts a new row which includes the data
	// necessary to re-anchor a passive asset.
	InsertPassiveAsset(ctx context.Context, arg NewPassiveAsset) error

	// QueryPassiveAssets returns the data required to re-anchor
	// pending passive assets that are anchored at the given outpoint.
	QueryPassiveAssets(ctx context.Context,
		transferID int32) ([]PassiveAsset, error)

	// ReAnchorPassiveAssets re-anchors the passive assets identified by
	// the passed params.
	ReAnchorPassiveAssets(ctx context.Context, arg ReAnchorParams) error

	// FetchAssetMetaByHash fetches the asset meta for a given meta hash.
	//
	// TODO(roasbeef): split into MetaStore?
	FetchAssetMetaByHash(ctx context.Context,
		metaDataHash []byte) (sqlc.FetchAssetMetaByHashRow, error)

	// FetchAssetMetaForAsset fetches the asset meta for a given asset.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID []byte) (sqlc.FetchAssetMetaForAssetRow, error)
}

type InsertRecvProofTxAttemptParams = sqlc.InsertReceiverProofTransferAttemptParams

// AssetBalance holds a balance query result for a particular asset or all
// assets tracked by this daemon.
type AssetBalance struct {
	ID           asset.ID
	Version      int32
	Balance      uint64
	Tag          string
	MetaHash     [asset.MetaHashLen]byte
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

	// eventDistributor is an event distributor that will be used to notify
	// subscribers about new proofs that are added to the archiver.
	eventDistributor *fn.EventDistributor[proof.Blob]

	clock clock.Clock
}

// NewAssetStore creates a new AssetStore from the specified BatchedAssetStore
// interface.
func NewAssetStore(db BatchedAssetStore, clock clock.Clock) *AssetStore {
	return &AssetStore{
		db:               db,
		eventDistributor: fn.NewEventDistributor[proof.Blob](),
		clock:            clock,
	}
}

// ChainAsset is a wrapper around the base asset struct that includes
// information detailing where in the chain the asset is currently anchored.
type ChainAsset struct {
	*asset.Asset

	// IsSpent indicates whether the above asset was previously spent.
	IsSpent bool

	// AnchorTx is the transaction that anchors this chain asset.
	AnchorTx *wire.MsgTx

	// AnchorTxid is the TXID of the anchor tx.
	AnchorTxid chainhash.Hash

	// AnchorBlockHash is the blockhash that mined the anchor tx.
	AnchorBlockHash chainhash.Hash

	// AnchorBlockHeight is the height of the block that mined the anchor
	// tx.
	AnchorBlockHeight uint32

	// AnchorOutpoint is the outpoint that commits to the asset.
	AnchorOutpoint wire.OutPoint

	// AnchorInternalKey is the raw internal key that was used to create the
	// anchor Taproot output key.
	AnchorInternalKey *btcec.PublicKey

	// AnchorMerkleRoot is the Taproot merkle root hash of the anchor output
	// the asset was committed to. If there is no Tapscript sibling, this is
	// equal to the Taproot Asset root commitment hash.
	AnchorMerkleRoot []byte

	// AnchorTapscriptSibling is the serialized preimage of a Tapscript
	// sibling, if there was one. If this is empty, then the
	// AnchorTapscriptSibling hash is equal to the Taproot root hash of the
	// anchor output.
	AnchorTapscriptSibling []byte

	// AnchorLeaseOwner is the identity of the application that currently
	// has a lease on this UTXO. If empty/nil, then the UTXO is not
	// currently leased. A lease means that the UTXO is being
	// reserved/locked to be spent in an upcoming transaction and that it
	// should not be available for coin selection through any of the wallet
	// RPCs.
	AnchorLeaseOwner [32]byte

	// AnchorLeaseExpiry is the expiry of the lease. If the expiry is nil or
	// the time is in the past, then the lease is not valid and the UTXO is
	// available for coin selection.
	AnchorLeaseExpiry *time.Time
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

	// TaprootAssetRoot is the Taproot Asset commitment root hash committed
	// to by this outpoint.
	TaprootAssetRoot []byte

	// MerkleRoot is the Taproot merkle root hash committed to by this
	// outpoint. If there is no Tapscript sibling, this is equal to
	// TaprootAssetRoot.
	MerkleRoot []byte

	// TapscriptSibling is the serialized tapscript sibling preimage of
	// this asset. This will usually be blank.
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

	// MetaHash is the hash of the meta data for this asset.
	MetaHash [asset.MetaHashLen]byte

	// Type uniquely identifies the type of Taproot asset.
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
func (a *AssetStore) dbAssetsToChainAssets(dbAssets []ConfirmedAsset,
	witnesses assetWitnesses) ([]*ChainAsset, error) {

	chainAssets := make([]*ChainAsset, len(dbAssets))
	for i := range dbAssets {
		sprout := dbAssets[i]

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
			OutputIndex:  uint32(sprout.GenesisOutputIndex),
			Type:         asset.Type(sprout.AssetType),
		}

		if len(sprout.MetaHash) != 0 {
			copy(assetGenesis.MetaHash[:], sprout.MetaHash)
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

		// We cannot use 0 as the amount when creating a new asset with
		// the New function above. But if this is a tombstone asset, we
		// actually have to set the amount to 0.
		if scriptKeyPub.IsEqual(asset.NUMSPubKey) && sprout.Amount == 0 {
			assetSprout.Amount = 0
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
			Asset:                  assetSprout,
			IsSpent:                sprout.Spent,
			AnchorTx:               anchorTx,
			AnchorTxid:             anchorTx.TxHash(),
			AnchorBlockHash:        anchorBlockHash,
			AnchorOutpoint:         anchorOutpoint,
			AnchorInternalKey:      anchorInternalKey,
			AnchorMerkleRoot:       sprout.AnchorMerkleRoot,
			AnchorTapscriptSibling: sprout.AnchorTapscriptSibling,
		}

		// We only set the lease info if the lease is actually still
		// valid and hasn't expired.
		owner := sprout.AnchorLeaseOwner
		expiry := sprout.AnchorLeaseExpiry
		if len(owner) > 0 && expiry.Valid &&
			expiry.Time.UTC().After(a.clock.Now().UTC()) {

			copy(chainAssets[i].AnchorLeaseOwner[:], owner)
			chainAssets[i].AnchorLeaseExpiry = &expiry.Time
		}
	}

	return chainAssets, nil
}

// constraintsToDbFilter maps application level constraints to the set of
// filters we use in the SQL queries.
func (a *AssetStore) constraintsToDbFilter(
	query *AssetQueryFilters) QueryAssetFilters {

	assetFilter := QueryAssetFilters{
		Now: sql.NullTime{
			Time:  a.clock.Now().UTC(),
			Valid: true,
		},
	}
	if query != nil {
		if query.MinAmt != 0 {
			assetFilter.MinAmt = sql.NullInt64{
				Int64: int64(query.MinAmt),
				Valid: true,
			}
		}
		if query.MinAnchorHeight != 0 {
			assetFilter.MinAnchorHeight = sqlInt32(
				query.MinAnchorHeight,
			)
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
func (a *AssetStore) specificAssetFilter(id asset.ID, anchorPoint wire.OutPoint,
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
		Now: sql.NullTime{
			Time:  a.clock.Now().UTC(),
			Valid: true,
		},
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
	tapfreighter.CommitmentConstraints

	// MinAnchorHeight is the minimum block height the asset's anchor tx
	// must have been confirmed at.
	MinAnchorHeight int32
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
			copy(assetIDBalance.MetaHash[:], assetBalance.MetaHash)

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
			Type:             assetType,
			GroupKey:         groupKey,
		}
		copy(groupedAssets[i].MetaHash[:], a.MetaHash)
	}

	return groupedAssets, nil
}

// FetchAllAssets fetches the set of confirmed assets stored on disk.
func (a *AssetStore) FetchAllAssets(ctx context.Context, includeSpent,
	includeLeased bool, query *AssetQueryFilters) ([]*ChainAsset, error) {

	var (
		dbAssets       []ConfirmedAsset
		assetWitnesses map[int32][]AssetWitness
		err            error
	)

	// We'll now map the application level filtering to the type of
	// filtering our database query understands.
	assetFilter := a.constraintsToDbFilter(query)

	// By default, the spent boolean is null, which means we'll fetch all
	// assets. Only if we should exclude spent assets, we'll set the spent
	// boolean to false.
	if !includeSpent {
		assetFilter.Spent = sqlBool(false)
	}

	// By default, we only show assets that are not leased.
	if !includeLeased {
		assetFilter.Leased = sqlBool(false)
	}

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

	return a.dbAssetsToChainAssets(dbAssets, assetWitnesses)
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
			TaprootAssetRoot: u.TaprootAssetRoot,
			MerkleRoot:       u.MerkleRoot,
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
// NOTE: This implements the proof.Archiver interface.
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

// FetchProofs fetches all proofs for assets uniquely identified by the passed
// asset ID.
//
// NOTE: This implements the proof.Archiver interface.
func (a *AssetStore) FetchProofs(ctx context.Context,
	id asset.ID) ([]*proof.AnnotatedProof, error) {

	var dbProofs []*proof.AnnotatedProof

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		assetProofs, err := q.FetchAssetProofsByAssetID(ctx, id[:])
		if err != nil {
			return fmt.Errorf("unable to fetch asset proofs: %w",
				err)
		}

		dbProofs, err = fn.MapErr(
			assetProofs,
			func(dbRow AssetProofByIDRow) (*proof.AnnotatedProof,
				error) {

				scriptKey, err := btcec.ParsePubKey(
					dbRow.ScriptKey,
				)
				if err != nil {
					return nil, fmt.Errorf("error parsing "+
						"script key: %w", err)
				}

				return &proof.AnnotatedProof{
					Locator: proof.Locator{
						AssetID:   &id,
						ScriptKey: *scriptKey,
					},
					Blob: dbRow.ProofFile,
				}, nil
			},
		)
		if err != nil {
			return fmt.Errorf("unable to map asset proofs: %w", err)
		}

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, proof.ErrProofNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return dbProofs, nil
}

// insertAssetWitnesses attempts to insert the set of asset witnesses in to the
// database, referencing the passed asset primary key.
//
// TODO(ffranr): Change insert function into an upsert.
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
	chainTXID, err := db.UpsertChainTx(ctx, ChainTxParams{
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

	// Calculate the Tapscript sibling hash (if there was a sibling).
	siblingBytes, siblingHash, err := commitment.MaybeEncodeTapscriptPreimage(
		proof.TapscriptSibling,
	)
	if err != nil {
		return fmt.Errorf("unable to encode tapscript preimage: %w",
			err)
	}

	// Next, we'll insert the managed UTXO that points to the output in our
	// control for the specified asset.
	merkleRoot := proof.ScriptRoot.TapscriptRoot(siblingHash)
	taprootAssetRoot := proof.ScriptRoot.TapscriptRoot(nil)
	utxoID, err := db.UpsertManagedUTXO(ctx, RawManagedUTXO{
		RawKey:           proof.InternalKey.SerializeCompressed(),
		Outpoint:         anchorPoint,
		AmtSats:          anchorOutput.Value,
		TaprootAssetRoot: taprootAssetRoot[:],
		MerkleRoot:       merkleRoot[:],
		TapscriptSibling: siblingBytes,
		TxnID:            chainTXID,
	})
	if err != nil {
		return fmt.Errorf("unable to insert managed utxo: %w", err)
	}

	newAsset := proof.Asset

	// If this proof also has a meta reveal (should only exist for genesis
	// assets, so we skip that validation here), then we'll insert this now
	// so the upsert below functions properly.
	_, err = maybeUpsertAssetMeta(
		ctx, db, &newAsset.Genesis, proof.MetaReveal,
	)
	if err != nil {
		return fmt.Errorf("unable to insert asset meta: %w", err)
	}

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

// upsertAssetProof updates the proof of an asset in the database, overwriting
// the previous proof if it exists. This includes updating the chain tx, as the
// only thing in a proof that can change is the block information.
func (a *AssetStore) upsertAssetProof(ctx context.Context,
	db ActiveAssetsStore, proof *proof.AnnotatedProof) error {

	// We expect the asset to already exist in the database, so the chain tx
	// should also already be there.
	anchorTXID := proof.AnchorTx.TxHash()

	chainTx, err := db.FetchChainTx(ctx, anchorTXID[:])
	if err != nil {
		return fmt.Errorf("unable to upsert asset proof, chain tx %v "+
			"does not exist: %w", anchorTXID.String(), err)
	}

	_, err = db.UpsertChainTx(ctx, ChainTxParams{
		Txid:        anchorTXID[:],
		RawTx:       chainTx.RawTx,
		ChainFees:   chainTx.ChainFees,
		BlockHeight: sqlInt32(proof.AnchorBlockHeight),
		BlockHash:   proof.AnchorBlockHash[:],
		TxIndex:     sqlInt32(proof.AnchorTxIndex),
	})
	if err != nil {
		return fmt.Errorf("unable to insert chain tx: %w", err)
	}

	// As a final step, we'll insert the proof file we used to generate all
	// the above information.
	scriptKeyBytes := proof.Asset.ScriptKey.PubKey.SerializeCompressed()
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
	headerVerifier proof.HeaderVerifier, groupVerifier proof.GroupVerifier,
	replace bool, proofs ...*proof.AnnotatedProof) error {

	var writeTxOpts AssetStoreTxOptions
	err := a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		for _, p := range proofs {
			if replace {
				err := a.upsertAssetProof(ctx, q, p)
				if err != nil {
					return fmt.Errorf("unable to upsert "+
						"asset proof: %w", err)
				}
			} else {
				err := a.importAssetFromProof(ctx, q, p)
				if err != nil {
					return fmt.Errorf("unable to import "+
						"asset: %w", err)
				}
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("unable to import proofs: %w", err)
	}

	// Notify any event subscribers that there are new proofs. We do this
	// outside of the transaction to avoid the subscribers trying to look up
	// the proofs before they are committed.
	proofBlobs := fn.Map(proofs, func(p *proof.AnnotatedProof) proof.Blob {
		return p.Blob
	})
	a.eventDistributor.NotifySubscribers(proofBlobs...)

	return nil
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (a *AssetStore) RegisterSubscriber(
	receiver *fn.EventReceiver[proof.Blob],
	deliverExisting bool, deliverFrom []*proof.Locator) error {

	a.eventDistributor.RegisterSubscriber(receiver)

	// No delivery of existing items requested, we're done here.
	if !deliverExisting {
		return nil
	}

	ctx := context.Background()
	for _, loc := range deliverFrom {
		blob, err := a.FetchProof(ctx, *loc)
		if err != nil {
			return err
		}

		// Deliver the found proof to the new item queue of the
		// subscriber.
		receiver.NewItemCreated.ChanIn() <- blob
	}

	return nil
}

// RemoveSubscriber removes the given subscriber and also stops it from
// processing events.
func (a *AssetStore) RemoveSubscriber(
	subscriber *fn.EventReceiver[proof.Blob]) error {

	return a.eventDistributor.RemoveSubscriber(subscriber)
}

// queryChainAssets queries the database for assets matching the passed filter.
// The returned assets have all anchor and witness information populated.
func (a *AssetStore) queryChainAssets(ctx context.Context, q ActiveAssetsStore,
	filter QueryAssetFilters) ([]*ChainAsset, error) {

	dbAssets, assetWitnesses, err := fetchAssetsWithWitness(
		ctx, q, filter,
	)
	if err != nil {
		return nil, err
	}
	matchingAssets, err := a.dbAssetsToChainAssets(dbAssets, assetWitnesses)
	if err != nil {
		return nil, err
	}

	return matchingAssets, nil
}

// FetchCommitment returns a specific commitment identified by the given asset
// parameters. If no commitment is found, ErrNoCommitment is returned. With
// mustBeLeased the caller decides whether the asset output should've been
// leased before or not. If mustBeLeased is false, then the state of the lease
// is not checked.
func (a *AssetStore) FetchCommitment(ctx context.Context, id asset.ID,
	anchorPoint wire.OutPoint, groupKey *asset.GroupKey,
	scriptKey *asset.ScriptKey,
	mustBeLeased bool) (*tapfreighter.AnchoredCommitment, error) {

	filter, err := a.specificAssetFilter(
		id, anchorPoint, groupKey, scriptKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create filter: %w", err)
	}

	// We only want to select unspent commitments.
	filter.Spent = sqlBool(false)

	// The caller decides whether the asset output should've been leased
	// before or not. If mustBeLeased is false, then the state of the lease
	// is not checked.
	if mustBeLeased {
		filter.Leased = sqlBool(true)
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

// ListEligibleCoins lists eligible commitments given a set of constraints.
//
// NOTE: This implements the tapfreighter.CoinLister interface.
func (a *AssetStore) ListEligibleCoins(ctx context.Context,
	constraints tapfreighter.CommitmentConstraints) (
	[]*tapfreighter.AnchoredCommitment, error) {

	if constraints.MinAmt > math.MaxInt64 {
		return nil, fmt.Errorf("min amount overflow")
	}

	// First, we'll map the commitment constraints to our database query
	// filters.
	assetFilter := a.constraintsToDbFilter(&AssetQueryFilters{
		CommitmentConstraints: constraints,
	})

	// We only want to select unspent and non-leased commitments.
	assetFilter.Spent = sqlBool(false)
	assetFilter.Leased = sqlBool(false)

	return a.queryCommitments(ctx, assetFilter)
}

// LeaseCoins leases/locks/reserves coins for the given lease owner until the
// given expiry. This is used to prevent multiple concurrent coin selection
// attempts from selecting the same coin(s).
func (a *AssetStore) LeaseCoins(ctx context.Context, leaseOwner [32]byte,
	expiry time.Time, utxoOutpoints ...wire.OutPoint) error {

	// We'll now update the managed UTXO entries to mark them as leased.
	var writeTxOpts AssetStoreTxOptions
	err := a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		for _, utxoOutpoint := range utxoOutpoints {
			outpoint, err := encodeOutpoint(utxoOutpoint)
			if err != nil {
				return err
			}

			err = q.UpdateUTXOLease(ctx, UpdateUTXOLease{
				LeaseOwner: leaseOwner[:],
				LeaseExpiry: sql.NullTime{
					Time:  expiry,
					Valid: true,
				},
				Outpoint: outpoint,
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("unable to lease coins: %w", err)
	}

	return nil
}

// ReleaseCoins releases/unlocks coins that were previously leased and makes
// them available for coin selection again.
func (a *AssetStore) ReleaseCoins(ctx context.Context,
	utxoOutpoints ...wire.OutPoint) error {

	// We'll now update the managed UTXO entries to mark them as leased.
	var writeTxOpts AssetStoreTxOptions
	err := a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		for _, utxoOutpoint := range utxoOutpoints {
			outpoint, err := encodeOutpoint(utxoOutpoint)
			if err != nil {
				return err
			}

			if err := q.DeleteUTXOLease(ctx, outpoint); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("unable to release coins: %w", err)
	}

	return nil
}

// DeleteExpiredLeases deletes all expired leases from the database.
func (a *AssetStore) DeleteExpiredLeases(ctx context.Context) error {
	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		return q.DeleteExpiredUTXOLeases(ctx, sql.NullTime{
			Time:  a.clock.Now().UTC(),
			Valid: true,
		})
	})
}

// queryCommitments queries the database for commitments matching the passed
// filter.
func (a *AssetStore) queryCommitments(ctx context.Context,
	assetFilter QueryAssetFilters) ([]*tapfreighter.AnchoredCommitment,
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
		matchingAssets, err = a.queryChainAssets(ctx, q, assetFilter)
		if err != nil {
			return err
		}

		if len(matchingAssets) == 0 {
			return tapfreighter.ErrMatchingAssetsNotFound
		}

		// At this point, we have the set of assets that match our
		// filter query, but we also need to be able to construct the
		// full Taproot Asset commitment for each asset, so it can be
		// used as an input in a transaction.
		//
		// To obtain this, we'll first do another query to fetch all
		// the _other_ assets that are anchored at the anchor point for
		// each of the assets above.
		for idx := range matchingAssets {
			matchingAsset := matchingAssets[idx]
			anchorPoint := matchingAsset.AnchorOutpoint
			anchorPointBytes, err := encodeOutpoint(
				matchingAsset.AnchorOutpoint,
			)
			if err != nil {
				return err
			}
			outpointQuery := QueryAssetFilters{
				AnchorPoint: anchorPointBytes,
				Now: sql.NullTime{
					Time:  a.clock.Now().UTC(),
					Valid: true,
				},
			}

			anchoredAssets, err := a.queryChainAssets(
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

	// Our final query wants the complete Taproot Asset commitment for each
	// of the managed UTXOs. Some of the assets that match our query might
	// actually be in the same Taproot Asset commitment, so we'll collect
	// this now to de-dup things early.
	anchorPointToCommitment := make(
		map[wire.OutPoint]*commitment.TapCommitment,
	)
	for anchorPoint := range chainAnchorToAssets {
		anchorPoint := anchorPoint
		anchoredAssets := chainAnchorToAssets[anchorPoint]

		// Fetch the asset leaves from each chain asset, and then
		// build a Taproot Asset commitment from this set of assets.
		fetchAsset := func(cAsset *ChainAsset) *asset.Asset {
			return cAsset.Asset
		}

		assets := fn.Map(anchoredAssets, fetchAsset)
		tapCommitment, err := commitment.FromAssets(assets...)
		if err != nil {
			return nil, err
		}

		anchorPointToCommitment[anchorPoint] = tapCommitment
	}

	// Now that we have all the matching assets, along w/ all the other
	// assets that are committed in the same outpoint, we can construct our
	// final response.
	selectedAssets := make(
		[]*tapfreighter.AnchoredCommitment, len(matchingAssets),
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

		tapscriptSibling, _, err := commitment.MaybeDecodeTapscriptPreimage(
			anchorUTXO.TapscriptSibling,
		)
		if err != nil {
			return nil, err
		}

		selectedAssets[i] = &tapfreighter.AnchoredCommitment{
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
			TapscriptSibling: tapscriptSibling,
			Asset:            matchingAsset.Asset,
			Commitment:       anchorPointToCommitment[anchorPoint],
		}
	}

	return selectedAssets, nil
}

// LogPendingParcel marks an outbound parcel as pending on disk. This commits
// the set of changes to disk (the pending inputs and outputs) but doesn't mark
// the batched spend as being finalized. The final lease owner and expiry are
// the lease parameters that are set on the input UTXOs, since we assume the
// parcel will be broadcast after this call. So we'll want to lock the input
// UTXOs for forever, which means the expiry should be far in the future.
func (a *AssetStore) LogPendingParcel(ctx context.Context,
	spend *tapfreighter.OutboundParcel, finalLeaseOwner [32]byte,
	finalLeaseExpiry time.Time) error {

	// Before we enter the DB transaction below, we'll use this space to
	// encode a few values outside the transaction closure.
	newAnchorTXID := spend.AnchorTx.TxHash()
	var txBuf bytes.Buffer
	if err := spend.AnchorTx.Serialize(&txBuf); err != nil {
		return err
	}
	anchorTxBytes := txBuf.Bytes()

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		// First, we'll insert the new transaction that anchors the new
		// anchor point (commits to the set of new outputs).
		txnID, err := q.UpsertChainTx(ctx, ChainTxParams{
			Txid:      newAnchorTXID[:],
			RawTx:     anchorTxBytes,
			ChainFees: spend.ChainFees,
		})
		if err != nil {
			return fmt.Errorf("unable to insert new chain "+
				"tx: %w", err)
		}

		// The transfer itself is just a shell which the inputs and
		// outputs will reference. We'll insert this next, so we can
		// use its ID.
		transferID, err := q.InsertAssetTransfer(ctx, NewAssetTransfer{
			HeightHint:       int32(spend.AnchorTxHeightHint),
			AnchorTxid:       newAnchorTXID[:],
			TransferTimeUnix: spend.TransferTime,
		})
		if err != nil {
			return fmt.Errorf("unable to insert asset transfer: "+
				"%w", err)
		}

		// Next, we'll insert the inputs to this transfer.
		for idx := range spend.Inputs {
			err := insertAssetTransferInput(
				ctx, q, transferID, spend.Inputs[idx],
				finalLeaseOwner, finalLeaseExpiry,
			)
			if err != nil {
				return fmt.Errorf("unable to insert asset "+
					"transfer input: %w", err)
			}
		}

		// And then finally the outputs.
		for idx := range spend.Outputs {
			err = insertAssetTransferOutput(
				ctx, q, transferID, txnID, spend.Outputs[idx],
				spend.PassiveAssets,
			)
			if err != nil {
				return fmt.Errorf("unable to insert asset "+
					"transfer output: %w", err)
			}
		}

		return nil
	})
}

// insertAssetTransferInput inserts a new asset transfer input into the DB.
func insertAssetTransferInput(ctx context.Context, q ActiveAssetsStore,
	transferID int32, input tapfreighter.TransferInput,
	finalLeaseOwner [32]byte, finalLeaseExpiry time.Time) error {

	anchorPointBytes, err := encodeOutpoint(input.OutPoint)
	if err != nil {
		return err
	}

	err = q.InsertAssetTransferInput(ctx, NewTransferInput{
		TransferID:  transferID,
		AnchorPoint: anchorPointBytes,
		AssetID:     input.ID[:],
		ScriptKey:   input.ScriptKey[:],
		Amount:      int64(input.Amount),
	})
	if err != nil {
		return fmt.Errorf("unable to insert transfer input: %w", err)
	}

	// From this point onward, we'll attempt to broadcast the anchor
	// transaction, even if we restart. So we need to make sure the UTXO is
	// leased for basically forever.
	return q.UpdateUTXOLease(ctx, UpdateUTXOLease{
		LeaseOwner: finalLeaseOwner[:],
		LeaseExpiry: sql.NullTime{
			Time:  finalLeaseExpiry,
			Valid: true,
		},
		Outpoint: anchorPointBytes,
	})
}

// fetchAssetTransferInputs fetches all the inputs for a given transfer ID.
func fetchAssetTransferInputs(ctx context.Context, q ActiveAssetsStore,
	transferID int32) ([]tapfreighter.TransferInput, error) {

	dbInputs, err := q.FetchTransferInputs(ctx, transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch transfer inputs: %w",
			err)
	}

	inputs := make([]tapfreighter.TransferInput, len(dbInputs))
	for idx := range dbInputs {
		dbInput := dbInputs[idx]

		inputs[idx] = tapfreighter.TransferInput{
			Amount: uint64(dbInput.Amount),
		}
		copy(inputs[idx].ID[:], dbInput.AssetID)

		err := readOutPoint(
			bytes.NewReader(dbInput.AnchorPoint), 0, 0,
			&inputs[idx].OutPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode input anchor "+
				"point: %w", err)
		}

		parsedScriptKey, err := btcec.ParsePubKey(dbInput.ScriptKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script key: "+
				"%w", err)
		}
		inputs[idx].ScriptKey = asset.ToSerialized(parsedScriptKey)
	}

	return inputs, nil
}

// insertAssetTransferOutput inserts a new asset transfer output into the DB
// and returns its ID.
func insertAssetTransferOutput(ctx context.Context, q ActiveAssetsStore,
	transferID, txnID int32, output tapfreighter.TransferOutput,
	passiveAssets []*tapfreighter.PassiveAssetReAnchor) error {

	anchor := output.Anchor
	anchorPointBytes, err := encodeOutpoint(anchor.OutPoint)
	if err != nil {
		return err
	}

	internalKeyBytes := anchor.InternalKey.PubKey.SerializeCompressed()

	// First, we'll insert the new internal on disk, so we can reference it
	// later when we go to apply the new transfer.
	_, err = q.UpsertInternalKey(ctx, InternalKey{
		RawKey:    internalKeyBytes,
		KeyFamily: int32(anchor.InternalKey.Family),
		KeyIndex:  int32(anchor.InternalKey.Index),
	})
	if err != nil {
		return fmt.Errorf("unable to upsert internal key: %w", err)
	}

	// Now that the chain transaction has been inserted, we can now insert
	// a _new_ managed UTXO which houses the information related to the new
	// anchor point of the transaction.
	newUtxoID, err := q.UpsertManagedUTXO(ctx, RawManagedUTXO{
		RawKey:           internalKeyBytes,
		Outpoint:         anchorPointBytes,
		AmtSats:          int64(anchor.Value),
		TaprootAssetRoot: anchor.TaprootAssetRoot,
		MerkleRoot:       anchor.MerkleRoot,
		TapscriptSibling: anchor.TapscriptSibling,
		TxnID:            txnID,
	})
	if err != nil {
		return fmt.Errorf("unable to insert new managed utxo: %w", err)
	}

	// Is this the output that will be used to re-anchor the passive asset?
	if output.Anchor.NumPassiveAssets > 0 {
		// And now that we know the ID of that new anchor TX, we can
		// store the passive assets, referencing that new UTXO.
		err = logPendingPassiveAssets(
			ctx, q, transferID, newUtxoID, passiveAssets,
		)
		if err != nil {
			return fmt.Errorf("unable to log passive assets: %w",
				err)
		}
	}

	var (
		witnessBuf bytes.Buffer
		scratch    [8]byte
	)
	err = asset.WitnessEncoder(&witnessBuf, &output.WitnessData, &scratch)
	if err != nil {
		return fmt.Errorf("unable to encode witness: %w", err)
	}

	// Before we can insert the actual output, we need to insert the new
	// script key on disk. If we don't have the tweaked script key, it means
	// we didn't derive it and need to store an unknown internal key.
	scriptInternalKey := keychain.KeyDescriptor{
		PubKey: output.ScriptKey.PubKey,
	}
	var tweak []byte
	if output.ScriptKey.TweakedScriptKey != nil {
		scriptInternalKey = output.ScriptKey.RawKey
		tweak = output.ScriptKey.Tweak
	}
	scriptInternalKeyID, err := q.UpsertInternalKey(ctx, InternalKey{
		RawKey:    scriptInternalKey.PubKey.SerializeCompressed(),
		KeyFamily: int32(scriptInternalKey.Family),
		KeyIndex:  int32(scriptInternalKey.Index),
	})
	if err != nil {
		return fmt.Errorf("unable to script insert internal key: %w",
			err)
	}
	scriptKeyID, err := q.UpsertScriptKey(ctx, NewScriptKey{
		InternalKeyID:    scriptInternalKeyID,
		TweakedScriptKey: output.ScriptKey.PubKey.SerializeCompressed(),
		Tweak:            tweak,
	})
	if err != nil {
		return fmt.Errorf("unable to insert script key: %w", err)
	}

	dbOutput := NewTransferOutput{
		TransferID:          transferID,
		AnchorUtxo:          newUtxoID,
		ScriptKey:           scriptKeyID,
		ScriptKeyLocal:      output.ScriptKeyLocal,
		Amount:              int64(output.Amount),
		SerializedWitnesses: witnessBuf.Bytes(),
		ProofSuffix:         output.ProofSuffix,
		NumPassiveAssets:    int32(output.Anchor.NumPassiveAssets),
		OutputType:          int16(output.Type),
		ProofCourierAddr:    output.ProofCourierAddr,
	}

	// There might not have been a split, so we can't rely on the split root
	// to be present.
	if output.SplitCommitmentRoot != nil {
		splitRootHash := output.SplitCommitmentRoot.NodeHash()
		dbOutput.SplitCommitmentRootHash = splitRootHash[:]
		dbOutput.SplitCommitmentRootValue = sql.NullInt64{
			Int64: int64(output.SplitCommitmentRoot.NodeSum()),
			Valid: true,
		}
	}

	err = q.InsertAssetTransferOutput(ctx, dbOutput)
	if err != nil {
		return fmt.Errorf("unable to insert transfer output: %w", err)
	}

	return nil
}

// fetchAssetTransferOutputs fetches all the outputs for a given transfer ID.
func fetchAssetTransferOutputs(ctx context.Context, q ActiveAssetsStore,
	transferID int32) ([]tapfreighter.TransferOutput, error) {

	dbOutputs, err := q.FetchTransferOutputs(ctx, transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch transfer outputs: %w",
			err)
	}

	var scratch [8]byte
	outputs := make([]tapfreighter.TransferOutput, len(dbOutputs))
	for idx := range dbOutputs {
		dbOut := dbOutputs[idx]

		internalKey, err := btcec.ParsePubKey(
			dbOut.InternalKeyRawKeyBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode internal "+
				"key: %w", err)
		}

		scriptKey, err := btcec.ParsePubKey(dbOut.ScriptKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script key: "+
				"%w", err)
		}

		rawScriptKey, err := btcec.ParsePubKey(
			dbOut.ScriptKeyRawKeyBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode raw script "+
				"key: %w", err)
		}

		scriptKeyLocator := keychain.KeyLocator{
			Family: keychain.KeyFamily(
				dbOut.ScriptKeyFamily,
			),
			Index: uint32(
				dbOut.ScriptKeyIndex,
			),
		}

		var splitRootHash mssmt.NodeHash
		copy(splitRootHash[:], dbOut.SplitCommitmentRootHash)

		var witnessData []asset.Witness
		err = asset.WitnessDecoder(
			bytes.NewReader(dbOut.SerializedWitnesses),
			&witnessData, &scratch,
			uint64(len(dbOut.SerializedWitnesses)),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode witness: %w",
				err)
		}

		outputs[idx] = tapfreighter.TransferOutput{
			Anchor: tapfreighter.Anchor{
				Value: btcutil.Amount(
					dbOut.AnchorValue,
				),
				InternalKey: keychain.KeyDescriptor{
					PubKey: internalKey,
					KeyLocator: keychain.KeyLocator{
						Family: keychain.KeyFamily(
							dbOut.InternalKeyFamily,
						),
						Index: uint32(
							dbOut.InternalKeyIndex,
						),
					},
				},
				TaprootAssetRoot: dbOut.AnchorTaprootAssetRoot,
				MerkleRoot:       dbOut.AnchorMerkleRoot,
				TapscriptSibling: dbOut.AnchorTapscriptSibling,
				NumPassiveAssets: uint32(
					dbOut.NumPassiveAssets,
				),
			},
			Amount: uint64(dbOut.Amount),
			ScriptKey: asset.ScriptKey{
				PubKey: scriptKey,
				TweakedScriptKey: &asset.TweakedScriptKey{
					RawKey: keychain.KeyDescriptor{
						PubKey:     rawScriptKey,
						KeyLocator: scriptKeyLocator,
					},
					Tweak: dbOut.ScriptKeyTweak,
				},
			},
			ScriptKeyLocal: dbOut.ScriptKeyLocal,
			WitnessData:    witnessData,
			SplitCommitmentRoot: mssmt.NewComputedNode(
				splitRootHash,
				uint64(dbOut.SplitCommitmentRootValue.Int64),
			),
			ProofSuffix:      dbOut.ProofSuffix,
			Type:             tappsbt.VOutputType(dbOut.OutputType),
			ProofCourierAddr: dbOut.ProofCourierAddr,
		}

		err = readOutPoint(
			bytes.NewReader(dbOut.AnchorOutpoint), 0, 0,
			&outputs[idx].Anchor.OutPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode output "+
				"anchor point: %w", err)
		}
	}

	return outputs, nil
}

// logPendingPassiveAssets logs passive assets re-anchoring data to disk.
func logPendingPassiveAssets(ctx context.Context,
	q ActiveAssetsStore, transferID, newUtxoID int32,
	passiveAssets []*tapfreighter.PassiveAssetReAnchor) error {

	for _, passiveAsset := range passiveAssets {
		// Encode new witness data.
		var (
			newWitnessBuf bytes.Buffer
			buf           [8]byte
		)
		err := asset.WitnessEncoder(
			&newWitnessBuf, &passiveAsset.NewWitnessData, &buf,
		)
		if err != nil {
			return fmt.Errorf("unable to encode witness: "+
				"%w", err)
		}

		// Encode new proof.
		var newProofBuf bytes.Buffer
		err = passiveAsset.NewProof.Encode(&newProofBuf)
		if err != nil {
			return fmt.Errorf("unable to encode new passive "+
				"asset proof: %w", err)
		}

		// Encode previous anchor outpoint.
		prevOutpointBytes, err := encodeOutpoint(
			passiveAsset.PrevAnchorPoint,
		)
		if err != nil {
			return fmt.Errorf("unable to encode prev outpoint: "+
				"%w", err)
		}

		// Encode script key.
		scriptKey := passiveAsset.ScriptKey
		scriptKeyBytes := scriptKey.PubKey.SerializeCompressed()

		err = q.InsertPassiveAsset(
			ctx, sqlc.InsertPassiveAssetParams{
				TransferID:      transferID,
				NewAnchorUtxo:   newUtxoID,
				NewWitnessStack: newWitnessBuf.Bytes(),
				NewProof:        newProofBuf.Bytes(),
				PrevOutpoint:    prevOutpointBytes,
				ScriptKey:       scriptKeyBytes,
				AssetGenesisID:  passiveAsset.GenesisID[:],
			},
		)
		if err != nil {
			return fmt.Errorf("unable to log pending passive "+
				"asset: %w", err)
		}
	}

	return nil
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
				TimeUnix:         a.clock.Now().UTC(),
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
	conf *tapfreighter.AssetConfirmEvent) error {

	var (
		writeTxOpts    AssetStoreTxOptions
		localProofKeys []asset.SerializedKey
	)
	err := a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		// First, we'll fetch the asset transfer based on its outpoint
		// bytes, so we can apply the delta it describes.
		assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
			AnchorTxHash: conf.AnchorTXID[:],
		})
		if err != nil {
			return fmt.Errorf("unable to query asset transfers: %w",
				err)
		}
		assetTransfer := assetTransfers[0]

		// Next, we'll mark all input assets as spent. But we need to
		// fetch the inputs first to do that.
		inputs, err := q.FetchTransferInputs(ctx, assetTransfer.ID)
		if err != nil {
			return fmt.Errorf("unable to fetch transfer inputs: %w",
				err)
		}

		// We'll keep around the IDs of the assets that we set to being
		// spent. We'll need one of them as our template to create the
		// new assets.
		spentAssetIDs := make([]int32, len(inputs))
		for idx := range inputs {
			spentAssetIDs[idx], err = q.SetAssetSpent(
				ctx, SetAssetSpentParams{
					ScriptKey:  inputs[idx].ScriptKey,
					GenAssetID: inputs[idx].AssetID,
				},
			)
			if err != nil {
				return fmt.Errorf("unable to set asset spent: "+
					"%w", err)
			}
		}

		// Now is the time to fetch our outputs and create new assets
		// for them.
		outputs, err := q.FetchTransferOutputs(ctx, assetTransfer.ID)
		if err != nil {
			return fmt.Errorf("unable to fetch transfer outputs: "+
				"%w", err)
		}
		for idx := range outputs {
			out := outputs[idx]

			isNumsKey := bytes.Equal(
				out.ScriptKeyBytes, asset.NUMSBytes,
			)
			isTombstone := isNumsKey &&
				out.Amount == 0 &&
				out.OutputType != int16(
					tappsbt.TypePassiveAssetsOnly,
				)

			// If this is an outbound transfer (meaning that our
			// node doesn't control the script key), we don't create
			// an asset entry in the DB. The transfer will be the
			// only reference to the asset leaving the node. The
			// same goes for outputs that are only used to anchor
			// passive assets, which are handled separately.
			if !isTombstone && !out.ScriptKeyLocal {
				continue
			}

			// Since we define that a transfer can only move assets
			// within the same asset ID, we can take any of the
			// inputs as a template for the new asset, since the
			// genesis and group key will be the same. We'll
			// overwrite all other fields.
			//
			// TODO(guggero): This will need an update once we want
			// to support full lock_time and relative_lock_time
			// support.
			templateID := spentAssetIDs[0]
			params := ApplyPendingOutput{
				ScriptKeyID: out.ScriptKeyID,
				AnchorUtxoID: sqlInt32(
					out.AnchorUtxoID,
				),
				Amount:                   out.Amount,
				SplitCommitmentRootHash:  out.SplitCommitmentRootHash,
				SplitCommitmentRootValue: out.SplitCommitmentRootValue,
				SpentAssetID:             templateID,
				Spent:                    isTombstone,
			}
			newAssetID, err := q.ApplyPendingOutput(ctx, params)
			if err != nil {
				return fmt.Errorf("unable to apply pending "+
					"output: %w", err)
			}

			// With the old witnesses removed, we'll insert the new
			// set on disk.
			var witnessData []asset.Witness
			err = asset.WitnessDecoder(
				bytes.NewReader(out.SerializedWitnesses),
				&witnessData, &[8]byte{},
				uint64(len(out.SerializedWitnesses)),
			)
			if err != nil {
				return fmt.Errorf("unable to decode "+
					"witness: %w", err)
			}
			err = a.insertAssetWitnesses(
				ctx, q, newAssetID, witnessData,
			)
			if err != nil {
				return fmt.Errorf("unable to insert asset "+
					"witnesses: %w", err)
			}

			var scriptKey asset.SerializedKey
			copy(scriptKey[:], out.ScriptKeyBytes)
			receiverProof, ok := conf.FinalProofs[scriptKey]
			if !ok {
				return fmt.Errorf("no proof found for output "+
					"with script key %x",
					out.ScriptKeyBytes)
			}
			localProofKeys = append(localProofKeys, scriptKey)

			// Now we can update the asset proof for the sender for
			// this given delta.
			err = q.UpsertAssetProof(ctx, ProofUpdate{
				TweakedScriptKey: out.ScriptKeyBytes,
				ProofFile:        receiverProof.Blob,
			})
			if err != nil {
				return err
			}
		}

		// Before we confirm the anchor TX, let's re-anchor the passive
		// to that new UTXO.
		err = a.reAnchorPassiveAssets(
			ctx, q, assetTransfer.ID, conf.PassiveAssetProofFiles,
		)
		if err != nil {
			return fmt.Errorf("failed to re-anchor passive "+
				"assets: %w", err)
		}

		// To confirm a delivery (successful send) all we need to do is
		// update the chain information for the transaction that
		// anchors the new anchor point.
		err = q.ConfirmChainAnchorTx(ctx, AnchorTxConf{
			Txid:        conf.AnchorTXID[:],
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
	if err != nil {
		return fmt.Errorf("failed to confirm transfer: %w", err)
	}

	// Notify any event subscribers that there are new proofs. We do this
	// outside of the transaction to avoid the subscribers trying to look up
	// the proofs before they are committed.
	for idx := range localProofKeys {
		localKey := localProofKeys[idx]
		finalProof := conf.FinalProofs[localKey]
		a.eventDistributor.NotifySubscribers(finalProof.Blob)
	}
	for idx := range conf.PassiveAssetProofFiles {
		passiveProof := conf.PassiveAssetProofFiles[idx]
		a.eventDistributor.NotifySubscribers(passiveProof)
	}

	return nil
}

// reAnchorPassiveAssets re-anchors all passive assets that were anchored by
// the given transfer output.
func (a *AssetStore) reAnchorPassiveAssets(ctx context.Context,
	q ActiveAssetsStore, transferID int32,
	proofFiles map[[32]byte]proof.Blob) error {

	passiveAssets, err := q.QueryPassiveAssets(ctx, transferID)
	if err != nil {
		return fmt.Errorf("failed to query passive assets: %w", err)
	}

	log.Debugf("Re-anchoring %d passive assets", len(passiveAssets))
	for _, passiveAsset := range passiveAssets {
		// Parse genesis ID.
		var assetID asset.ID
		copy(assetID[:], passiveAsset.GenesisID)

		// Parse the script key.
		scriptKey, err := btcec.ParsePubKey(passiveAsset.ScriptKey)
		if err != nil {
			return fmt.Errorf("failed to parse script key: %w", err)
		}

		// Fetch the proof file for this asset.
		locator := proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *scriptKey,
		}
		proofFile := proofFiles[locator.Hash()]
		if proofFile == nil {
			return fmt.Errorf("failed to find proof file for " +
				"passive asset")
		}

		// Delete the old set of witnesses, and re-insert new ones.
		err = q.DeleteAssetWitnesses(ctx, passiveAsset.AssetID)
		if err != nil {
			return fmt.Errorf("unable to delete witnesses: %w", err)
		}

		// With the old witnesses removed, we'll insert the new
		// set on disk.
		var witnessData []asset.Witness
		err = asset.WitnessDecoder(
			bytes.NewReader(passiveAsset.NewWitnessStack),
			&witnessData, &[8]byte{},
			uint64(len(passiveAsset.NewWitnessStack)),
		)
		if err != nil {
			return fmt.Errorf("unable to decode witness: %w", err)
		}
		err = a.insertAssetWitnesses(
			ctx, q, passiveAsset.AssetID, witnessData,
		)
		if err != nil {
			return fmt.Errorf("unable to insert asset "+
				"witnesses: %w", err)
		}

		// Update the asset proof.
		err = q.UpsertAssetProof(ctx, ProofUpdate{
			AssetID:   sqlInt32(passiveAsset.AssetID),
			ProofFile: proofFile,
		})
		if err != nil {
			return fmt.Errorf("unable to update passive asset "+
				"proof file: %w", err)
		}

		// And finally, update the anchor UTXO of the asset in question.
		err = q.ReAnchorPassiveAssets(ctx, ReAnchorParams{
			NewAnchorUtxoID: sqlInt32(passiveAsset.NewAnchorUtxo),
			AssetID:         passiveAsset.AssetID,
		})
		if err != nil {
			return fmt.Errorf("unable to re-anchor passive "+
				"asset: %w", err)
		}
	}

	return nil
}

// PendingParcels returns the set of parcels that haven't yet been finalized.
// This can be used to query the set of unconfirmed
// transactions for re-broadcast.
func (a *AssetStore) PendingParcels(
	ctx context.Context) ([]*tapfreighter.OutboundParcel, error) {

	return a.QueryParcels(ctx, true)
}

// QueryParcels returns the set of confirmed or unconfirmed parcels.
func (a *AssetStore) QueryParcels(ctx context.Context,
	pending bool) ([]*tapfreighter.OutboundParcel, error) {

	var transfers []*tapfreighter.OutboundParcel

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		// If we want every unconfirmed transfer, then we only pass in
		// the UnconfOnly field.
		dbTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
			UnconfOnly: pending,
		})
		if err != nil {
			return err
		}

		for idx := range dbTransfers {
			dbT := dbTransfers[idx]

			inputs, err := fetchAssetTransferInputs(ctx, q, dbT.ID)
			if err != nil {
				return fmt.Errorf("unable to fetch transfer "+
					"inputs: %w", err)
			}

			outputs, err := fetchAssetTransferOutputs(
				ctx, q, dbT.ID,
			)
			if err != nil {
				return fmt.Errorf("unable to fetch transfer "+
					"outputs: %w", err)
			}

			// We know that the anchor transaction is the same for
			// each output, we can just fetch the first.
			if len(outputs) == 0 {
				return fmt.Errorf("no outputs for transfer")
			}

			anchorTXID := outputs[0].Anchor.OutPoint.Hash[:]
			dbAnchorTx, err := q.FetchChainTx(ctx, anchorTXID)
			if err != nil {
				return fmt.Errorf("unable to fetch chain tx: "+
					"%w", err)
			}

			anchorTx := wire.NewMsgTx(2)
			err = anchorTx.Deserialize(bytes.NewReader(
				dbAnchorTx.RawTx,
			))
			if err != nil {
				return fmt.Errorf("unable to deserialize "+
					"anchor tx: %w", err)
			}

			transfer := &tapfreighter.OutboundParcel{
				AnchorTx:           anchorTx,
				AnchorTxHeightHint: uint32(dbT.HeightHint),
				TransferTime:       dbT.TransferTimeUnix.UTC(),
				ChainFees:          dbAnchorTx.ChainFees,
				Inputs:             inputs,
				Outputs:            outputs,
			}
			transfers = append(transfers, transfer)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return transfers, nil
}

// ErrAssetMetaNotFound is returned when an asset meta is not found in the
// database.
var ErrAssetMetaNotFound = fmt.Errorf("asset meta not found")

// FetchAssetMetaForAsset attempts to fetch an asset meta based on an asset ID.
func (a *AssetStore) FetchAssetMetaForAsset(ctx context.Context,
	assetID asset.ID) (*proof.MetaReveal, error) {

	var assetMeta *proof.MetaReveal

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		dbMeta, err := q.FetchAssetMetaForAsset(ctx, assetID[:])
		if err != nil {
			return err
		}

		assetMeta = &proof.MetaReveal{
			Data: dbMeta.MetaDataBlob,
			Type: proof.MetaType(dbMeta.MetaDataType.Int16),
		}

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, ErrAssetMetaNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return assetMeta, nil
}

// FetchAssetMetaByHash attempts to fetch an asset meta based on an asset hash.
func (a *AssetStore) FetchAssetMetaByHash(ctx context.Context,
	metaHash [asset.MetaHashLen]byte) (*proof.MetaReveal, error) {

	var assetMeta *proof.MetaReveal

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		dbMeta, err := q.FetchAssetMetaByHash(ctx, metaHash[:])
		if err != nil {
			return err
		}

		assetMeta = &proof.MetaReveal{
			Data: dbMeta.MetaDataBlob,
			Type: proof.MetaType(dbMeta.MetaDataType.Int16),
		}

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, ErrAssetMetaNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return assetMeta, nil
}

// A compile-time constraint to ensure that AssetStore meets the
// proof.NotifyArchiver interface.
var _ proof.NotifyArchiver = (*AssetStore)(nil)

// A compile-time constraint to ensure that AssetStore meets the
// tapfreighter.CoinLister interface.
var _ tapfreighter.CoinLister = (*AssetStore)(nil)

// A compile-time constraint to ensure that AssetStore meets the
// tapfreighter.ExportLog interface.
var _ tapfreighter.ExportLog = (*AssetStore)(nil)
