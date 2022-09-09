package tarodb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb/sqlite"
	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightningnetwork/lnd/keychain"
)

type (
	// ConfirmedAsset is an asset that has been fully confirmed on chain.
	ConfirmedAsset = sqlite.FetchAllAssetsRow

	// AssetProof is the asset proof for a given asset, identified by its
	// script key.
	AssetProof = sqlite.FetchAssetProofsRow

	// AssetProofI is identical to AssetProof but is used for the case
	// where the proofs for a specific asset are fetched.
	AssetProofI = sqlite.FetchAssetProofRow

	// PrevInput stores the full input information including the prev out,
	// and also the witness information itself.
	PrevInput = sqlite.InsertAssetWitnessParams

	// AssetWitness is the full prev input for an asset that also couples
	// along the asset ID that the witness belong to.
	AssetWitness = sqlite.FetchAssetWitnessesRow

	// FetchAssetFilters lets us query assets in the database based on some
	// set filters. This is useful to get the balance of a set of assets,
	// or for things like coin selection.
	FetchAssetFilters = sqlite.FetchAllAssetsParams
)

// ActiveAssetsStore is a sub-set of the main sqlite.Querier interface that
// contains methods related to querying the set of confirmed assets.
type ActiveAssetsStore interface {
	// FetchAllAssets fetches the set of fully confirmed assets.
	FetchAllAssets(context.Context, FetchAssetFilters) ([]ConfirmedAsset, error)

	// FetchAssetProofs fetches all the asset proofs we have stored on
	// disk.
	FetchAssetProofs(ctx context.Context) ([]AssetProof, error)

	// FetchAssetProof fetches the asset proof for a given asset identified
	// by its script key.
	FetchAssetProof(ctx context.Context,
		scriptKey []byte) (AssetProofI, error)

	// UpsertGenesisPoint inserts a new or updates an existing genesis point
	// on disk, and returns the primary key.
	UpsertGenesisPoint(ctx context.Context, prevOut []byte) (int32, error)

	// InsertGenesisAsset inserts a new genesis asset (the base asset info)
	// into the DB.
	//
	// TODO(roasbeef): hybrid version of the main tx interface that an
	// accept two diff storage interfaces?
	//
	//  * or use a sort of mix-in type?
	InsertGenesisAsset(ctx context.Context, arg GenesisAsset) (int32, error)

	// UpsertInternalKey inserts a new or updates an existing internal key
	// into the database.
	UpsertInternalKey(ctx context.Context, arg InternalKey) (int32, error)

	// InsertAssetFamilySig inserts a new asset family sig into the DB.
	InsertAssetFamilySig(ctx context.Context, arg AssetFamSig) (int32, error)

	// UpsertAssetFamilyKey inserts a new or updates an existing family key
	// on disk, and returns the primary key.
	UpsertAssetFamilyKey(ctx context.Context, arg AssetFamilyKey) (int32,
		error)

	// InsertNewAsset inserts a new asset on disk.
	InsertNewAsset(ctx context.Context, arg sqlite.InsertNewAssetParams) (int32, error)

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTx) (int32, error)

	// UpsertManagedUTXO inserts a new or updates an existing managed UTXO
	// to disk and returns the primary key.
	UpsertManagedUTXO(ctx context.Context, arg RawManagedUTXO) (int32, error)

	// UpsertAssetProof inserts a new or updates an existing asset proof on
	// disk.
	UpsertAssetProof(ctx context.Context,
		arg sqlite.UpsertAssetProofParams) error

	// InsertAssetWitness inserts a new prev input for an asset into the
	// database.
	InsertAssetWitness(context.Context, PrevInput) error

	// FetchAssetWitnesses attempts to fetch either all the asset witnesses
	// on disk (NULL param), or the witness for a given asset ID.
	FetchAssetWitnesses(context.Context, sql.NullInt32) ([]AssetWitness, error)
}

// BatchedAssetStore combines the AssetStore interface with the BatchedTx
// interface, allowing for multiple queries to be executed in a single SQL
// transaction.
type BatchedAssetStore interface {
	ActiveAssetsStore

	BatchedTx[ActiveAssetsStore, TxOptions]
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
}

// fetchAssetWitnesses attempts to fetch all the asset witnesses that belong to
// the set of passed asset IDs.
func fetchAssetWitnesses(ctx context.Context,
	db ActiveAssetsStore, assetIDs []int32) (map[int32][]AssetWitness, error) {

	assetWitnesses := make(map[int32][]AssetWitness)
	for _, assetID := range assetIDs {
		witnesses, err := db.FetchAssetWitnesses(
			ctx, sqlInt32(assetID),
		)
		if err != nil {
			return nil, err
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
		zeroKey   [32]byte
		scriptKey btcec.PublicKey
	)
	if !bytes.Equal(zeroKey[:], input.PrevScriptKey[1:]) {
		prevKey, err := btcec.ParsePubKey(input.PrevScriptKey)
		if err != nil {
			return witness, fmt.Errorf("unable to decode key: %w", err)
		}
		scriptKey = *prevKey
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

// AssetQueryFilters is a wrapper struct over the CommitmentConstraints struct
// which lets us filter the results of the set of assets returned.
type AssetQueryFilters struct {
	tarofreighter.CommitmentConstraints
}

// FetchAllAssets fetches the set of confirmed assets stored on disk.
func (a *AssetStore) FetchAllAssets(ctx context.Context,
	query *AssetQueryFilters) ([]*ChainAsset, error) {

	var (
		dbAssets []ConfirmedAsset

		assetWitnesses map[int32][]AssetWitness

		err error
	)

	// We'll ow map the application level filtering to the type of
	// filtering our database query understands.
	var assetFilter FetchAssetFilters
	if query != nil {
		if query.Amt != 0 {
			assetFilter.MinAmt = sql.NullInt64{
				Int64: int64(query.Amt),
				Valid: true,
			}
		}
		if query.AssetID != nil {
			assetID := query.AssetID[:]
			assetFilter.AssetIDFilter = assetID
		}
		if query.FamilyKey != nil {
			famKey := query.FamilyKey.SerializeCompressed()
			assetFilter.KeyFamFilter = famKey
		}
	}

	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		// First, we'll fetch all the assets we know of on disk.
		dbAssets, err = q.FetchAllAssets(ctx, assetFilter)
		if err != nil {
			return fmt.Errorf("unable to read db assets: %v", err)
		}

		assetIDs := fMap(dbAssets, func(a ConfirmedAsset) int32 {
			return a.AssetID
		})

		// With all the assets obtained, we'll now do a second query to
		// obtain all the witnesses we know of for each asset.
		assetWitnesses, err = fetchAssetWitnesses(ctx, q, assetIDs)
		if err != nil {
			return fmt.Errorf("unable to fetch asset "+
				"witnesses: %w", err)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	chainAssets := make([]*ChainAsset, len(dbAssets))
	for i, sprout := range dbAssets {
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
						Family: extractSqlInt32[keychain.KeyFamily](
							sprout.FamKeyFamily,
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

		// With the asset created, we'll now emplace the set of
		// witnesses for the asset itself. If this is a genesis asset,
		// then it won't have a set of witnesses.
		assetInputs, ok := assetWitnesses[sprout.AssetID]
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

		chainAssets[i] = &ChainAsset{
			Asset:           assetSprout,
			AnchorTx:        anchorTx,
			AnchorTxid:      anchorTx.TxHash(),
			AnchorBlockHash: anchorBlockHash,
			AnchorOutpoint:  anchorOutpoint,
		}
	}

	return chainAssets, nil
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

			for _, proof := range assetProofs {
				scriptKey, err := btcec.ParsePubKey(
					proof.ScriptKey,
				)
				if err != nil {
					return err
				}

				proofs[*scriptKey] = proof.ProofFile
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

			assetProof, err := q.FetchAssetProof(
				ctx, scriptKey.SerializeCompressed(),
			)
			if err != nil {
				return fmt.Errorf("unable to fetch asset "+
					"proof: %w", err)
			}

			proofs[*scriptKey] = assetProof.ProofFile
		}
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return proofs, nil
}

// FetchProof fetches a proof for an asset uniquely idenfitied by the passed
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

		prevScriptKey := prevID.ScriptKey.SerializeCompressed()
		err = db.InsertAssetWitness(ctx, PrevInput{
			AssetID:              assetID,
			PrevOutPoint:         prevOutpoint,
			PrevAssetID:          prevID.ID[:],
			PrevScriptKey:        prevScriptKey,
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
//
// TODO(roasbeef): reduce duplication w/ pending asset store
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

	genesisPoint, err := encodeOutpoint(
		newAsset.Genesis.FirstPrevOut,
	)
	if err != nil {
		return fmt.Errorf("unable to encode genesis point: %w", err)
	}

	// Next, we'll attempt to import the genesis point for this asset.
	// This might already exist if we have the same assetID/keyFamily.
	genesisPointID, err := db.UpsertGenesisPoint(ctx, genesisPoint)
	if err != nil {
		return fmt.Errorf("unable to insert genesis "+
			"point: %w", err)
	}

	// Next, we'll insert the genesis_asset row which holds the base
	// information for this asset.
	assetID := newAsset.ID()
	genAssetID, err := db.InsertGenesisAsset(ctx, GenesisAsset{
		AssetID:        assetID[:],
		AssetTag:       newAsset.Genesis.Tag,
		MetaData:       newAsset.Genesis.Metadata,
		OutputIndex:    int32(newAsset.Genesis.OutputIndex),
		AssetType:      int16(newAsset.Type),
		GenesisPointID: genesisPointID,
	})
	if err != nil {
		return fmt.Errorf("unable to insert genesis asset: %w", err)
	}

	// With the base asset information inserted, we we'll now add the
	// information for the asset family
	//
	// TODO(roasbeef): sig here doesn't actually matter?
	//   * don't have the key desc information here neccesrily
	//   * inserting the fam key rn, which is ok as its external w/ no key
	//     desc info
	var sqlFamilySigID sql.NullInt32
	familyKey := newAsset.FamilyKey
	if familyKey != nil {
		keyID, err := db.UpsertInternalKey(ctx, InternalKey{
			RawKey: familyKey.FamKey.SerializeCompressed(),
		})
		if err != nil {
			return fmt.Errorf("unable to insert internal key: %w", err)
		}
		assetKey := AssetFamilyKey{
			TweakedFamKey:  familyKey.FamKey.SerializeCompressed(),
			InternalKeyID:  keyID,
			GenesisPointID: genesisPointID,
		}
		famID, err := db.UpsertAssetFamilyKey(ctx, assetKey)
		if err != nil {
			return fmt.Errorf("unable to insert family key: %w", err)
		}
		famSigID, err := db.InsertAssetFamilySig(ctx, AssetFamSig{
			GenesisSig: familyKey.Sig.Serialize(),
			GenAssetID: genAssetID,
			KeyFamID:   famID,
		})
		if err != nil {
			return fmt.Errorf("unable to insert fam sig: %w", err)
		}

		sqlFamilySigID = sqlInt32(famSigID)
	}

	// With the family key information inserted, we'll now insert the
	// internal key we'll be using for the script key itself.
	scriptKeyBytes := newAsset.ScriptKey.PubKey.SerializeCompressed()
	scriptKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    scriptKeyBytes,
		KeyFamily: int32(newAsset.ScriptKey.Family),
		KeyIndex:  int32(newAsset.ScriptKey.Index),
	})
	if err != nil {
		return fmt.Errorf("unable to insert internal key: %w", err)
	}

	// With all the dependent data inserted, we can now insert the base
	// asset information itself.
	assetPrimary, err := db.InsertNewAsset(ctx, sqlite.InsertNewAssetParams{
		AssetID:          genAssetID,
		Version:          int32(newAsset.Version),
		ScriptKeyID:      scriptKeyID,
		AssetFamilySigID: sqlFamilySigID,
		ScriptVersion:    int32(newAsset.ScriptVersion),
		Amount:           int64(newAsset.Amount),
		LockTime:         sqlInt32(newAsset.LockTime),
		RelativeLockTime: sqlInt32(newAsset.RelativeLockTime),
		AnchorUtxoID:     sqlInt32(utxoID),
	})
	if err != nil {
		return fmt.Errorf("unable to insert "+
			"asset: %w", err)
	}

	// Now that we have the asset inserted, we'll also insert all the
	// witness data associated with the asset in a new row.
	err = a.insertAssetWitnesses(
		ctx, db, assetPrimary, newAsset.PrevWitnesses,
	)
	if err != nil {
		return fmt.Errorf("unable to insert asset witness: %w", err)
	}

	// As a final step, we'll insert the proof file we used to generate all
	// the above information.
	return db.UpsertAssetProof(ctx, ProofUpdate{
		RawKey:    scriptKeyBytes,
		ProofFile: proof.Blob,
	})
}

// ImportProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
//
// NOTE: This implements the proof.ArchiveBackend interface.
func (a *AssetStore) ImportProofs(ctx context.Context,
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

// A compile-time constant to ensure that AssetStore meets the proof.Archiver
// interface.
var _ proof.Archiver = (*AssetStore)(nil)
