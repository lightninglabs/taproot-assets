package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
)

type (
	// UniverseRoot is the root of a universe tree.
	UniverseRoot = sqlc.FetchUniverseRootRow

	// UpsertUniverseLeaf is used to upsert universe leaves.
	UpsertUniverseLeaf = sqlc.UpsertUniverseLeafParams

	// NewUniverseRoot is used to insert a new universe root.
	NewUniverseRoot = sqlc.UpsertUniverseRootParams

	// UniverseLeafQuery allows callers to query for a set of leaves based
	// on the minting point or the script key.
	UniverseLeafQuery = sqlc.QueryUniverseLeavesParams

	// UniverseKeys is the set of leaf keys inserted into a universe.
	UniverseKeys = sqlc.FetchUniverseKeysRow

	// UniverseLeaf is a universe leaf.
	UniverseLeaf = sqlc.QueryUniverseLeavesRow
)

// BaseUniverseStore is the main interface for the Taproot Asset universe store.
// This is a composite of the capabilities to insert new asset genesis, update
// the SMT tree, and finally fetch a genesis. We then combine that with Universe
// specific information to implement all the required interaction.
type BaseUniverseStore interface {
	UpsertAssetStore

	TreeStore

	FetchGenesisStore

	GroupStore

	// QueryUniverseLeaves is used to query for the set of leaves that
	// reside in a universe tree.
	QueryUniverseLeaves(ctx context.Context,
		arg UniverseLeafQuery) ([]UniverseLeaf, error)

	// DeleteUniverseLeaves is used to delete leaves that reside in a
	// universe tree.
	DeleteUniverseLeaves(ctx context.Context, namespace string) error

	// DeleteUniverseRoot is used to delete the root of a universe tree.
	DeleteUniverseRoot(ctx context.Context, namespace string) error

	// DeleteUniverseEvents is used to delete a universe sync event.
	DeleteUniverseEvents(ctx context.Context, namespace string) error

	// FetchUniverseRoot fetches the root of a universe based on the
	// namespace key, which is a function of the asset ID and the group
	// key.
	FetchUniverseRoot(ctx context.Context,
		namespace string) (UniverseRoot, error)

	// UpsertUniverseLeaf upserts a Universe leaf in the database.
	UpsertUniverseLeaf(ctx context.Context, arg UpsertUniverseLeaf) error

	// UpsertUniverseRoot attempts to insert a universe root, returning the
	// existing primary key of the root if already exists.
	UpsertUniverseRoot(ctx context.Context, arg NewUniverseRoot) (int32, error)

	// FetchUniverseKeys fetches the set of keys that are currently stored
	// for a given namespace.
	FetchUniverseKeys(ctx context.Context,
		namespace string) ([]UniverseKeys, error)
}

// BaseUniverseStoreOptions is the set of options for universe tree queries.
type BaseUniverseStoreOptions struct {
	readOnly bool
}

// ReadOnly returns true if the transaction is read-only.
func (b *BaseUniverseStoreOptions) ReadOnly() bool {
	return b.readOnly
}

// NewBaseUniverseReadTx creates a new read-only transaction for the base
// universe.
func NewBaseUniverseReadTx() BaseUniverseStoreOptions {
	return BaseUniverseStoreOptions{
		readOnly: true,
	}
}

// BatchedUniverseTree is a wrapper around the base universe tree that allows us
// to perform batch queries with all the relevant query interfaces.
type BatchedUniverseTree interface {
	BaseUniverseStore

	BatchedTx[BaseUniverseStore]
}

// BaseUniverseTree implements the persistent storage for the Base universe for
// a given asset. The minting outpoints stored of the asset are used to key
// into the universe tree.
//
// NOTE: This implements the universe.Base interface.
type BaseUniverseTree struct {
	db BatchedUniverseTree

	id universe.Identifier

	registrationMtx sync.Mutex

	smtNamespace string
}

// NewBaseUniverseTree creates a new base Universe tree.
func NewBaseUniverseTree(db BatchedUniverseTree,
	id universe.Identifier) *BaseUniverseTree {

	return &BaseUniverseTree{
		db:           db,
		id:           id,
		smtNamespace: id.String(),
	}
}

// RootNode returns the root node of a universe tree.
func (b *BaseUniverseTree) RootNode(ctx context.Context) (mssmt.Node, string,
	error) {

	var universeRoot UniverseRoot

	readTx := NewBaseUniverseReadTx()

	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		dbRoot, err := db.FetchUniverseRoot(ctx, b.smtNamespace)
		if err != nil {
			return err
		}

		universeRoot = dbRoot
		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, "", universe.ErrNoUniverseRoot
	case dbErr != nil:
		return nil, "", dbErr
	}

	var nodeHash mssmt.NodeHash
	copy(nodeHash[:], universeRoot.RootHash[:])

	return mssmt.NewComputedNode(
		nodeHash, uint64(universeRoot.RootSum),
	), universeRoot.AssetName, nil
}

// treeStoreWrapperTx is a wrapper around the BaseUniverseStore that allows us
// to re-use the internal transaction with the transaction SMT store.
type treeStoreWrapperTx struct {
	universeTx BaseUniverseStore
	namespace  string
}

// newTreeStoreWrapperTx makes a new wrapper tx.
func newTreeStoreWrapperTx(universeTx BaseUniverseStore,
	namespace string) *treeStoreWrapperTx {

	return &treeStoreWrapperTx{
		universeTx: universeTx,
		namespace:  namespace,
	}
}

// Update re-uses an existing transaction to update the SMT tree.
func (t *treeStoreWrapperTx) Update(ctx context.Context,
	update func(tx mssmt.TreeStoreUpdateTx) error) error {

	updateTx := &taprootAssetTreeStoreTx{
		ctx:       ctx,
		dbTx:      t.universeTx,
		namespace: t.namespace,
	}

	return update(updateTx)
}

// View re-uses an existing transaction to view the SMT tree.
func (t *treeStoreWrapperTx) View(ctx context.Context,
	view func(tx mssmt.TreeStoreViewTx) error) error {

	viewTx := &taprootAssetTreeStoreTx{
		ctx:       ctx,
		dbTx:      t.universeTx,
		namespace: t.namespace,
	}

	return view(viewTx)
}

// upsertAssetGen attempts to insert an asset genesis if it doesn't already
// exist. Otherwise, the primary key of the existing asset ID is returned.
func upsertAssetGen(ctx context.Context, db UpsertAssetStore,
	assetGen asset.Genesis, groupKey *asset.GroupKey,
	genesisProof proof.Blob) (int32, error) {

	// First, given the genesis point in the passed genesis, we'll insert a
	// new genesis point in the DB.
	genPointID, err := upsertGenesisPoint(ctx, db, assetGen.FirstPrevOut)
	if err != nil {
		return 0, err
	}

	// With the genesis point inserted, we can now insert a genesis for the
	// given asset.
	genAssetID, err := upsertGenesis(ctx, db, genPointID, assetGen)
	if err != nil {
		return 0, err
	}

	// Finally, if there's a group key associated with the asset, then
	// we'll insert that now as well.
	if groupKey != nil {
		_, err := upsertGroupKey(
			ctx, groupKey, db, genPointID, genAssetID,
		)
		if err != nil {
			return 0, err
		}
	}

	genProof := &proof.Proof{}
	err = genProof.Decode(bytes.NewReader(genesisProof))
	if err != nil {
		return 0, fmt.Errorf("unable to decode genesis proof: %w", err)
	}

	var txBuf bytes.Buffer
	if err := genProof.AnchorTx.Serialize(&txBuf); err != nil {
		return 0, fmt.Errorf("unable to serialize anchor tx: %w", err)
	}

	genTXID := genProof.AnchorTx.TxHash()
	genBlockHash := genProof.BlockHeader.BlockHash()
	chainTXID, err := db.UpsertChainTx(ctx, ChainTxParams{
		Txid:        genTXID[:],
		RawTx:       txBuf.Bytes(),
		BlockHeight: sqlInt32(genProof.BlockHeight),
		BlockHash:   genBlockHash[:],
	})
	if err != nil {
		return 0, fmt.Errorf("unable to upsert chain tx: %w", err)
	}

	// Finally, we'll anchor the genesis point to link to the chain
	// transaction we upserted above.
	genesisPoint, err := encodeOutpoint(assetGen.FirstPrevOut)
	if err != nil {
		return 0, fmt.Errorf("unable to encode genesis point: %w", err)
	}
	if err := db.AnchorGenesisPoint(ctx, GenesisPointAnchor{
		PrevOut:    genesisPoint,
		AnchorTxID: sqlInt32(chainTXID),
	}); err != nil {
		return 0, fmt.Errorf("unable to anchor genesis tx: %w", err)
	}

	// TODO(roasbeef): need to mark that this is a imported gen?

	return genAssetID, nil
}

// RegisterIssuance inserts a new minting leaf within the universe tree, stored
// at the base key.
func (b *BaseUniverseTree) RegisterIssuance(ctx context.Context,
	key universe.BaseKey, leaf *universe.MintingLeaf,
	metaReveal *proof.MetaReveal) (*universe.IssuanceProof, error) {

	var (
		writeTx BaseUniverseStoreOptions

		err           error
		issuanceProof *universe.IssuanceProof
	)

	// Limit to a single writer at a time.
	b.registrationMtx.Lock()
	defer b.registrationMtx.Unlock()

	dbErr := b.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		issuanceProof, _, err = universeRegisterIssuance(
			ctx, dbTx, b.id, key, leaf, metaReveal,
		)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return issuanceProof, nil
}

// universeRegisterIssuance upserts a minting leaf within the universe tree,
// stored at the base key.
//
// This function returns the newly registered issuance proof and the new
// universe root.
//
// NOTE: This function accepts a db transaction, as it's used when making
// broader DB updates.
func universeRegisterIssuance(ctx context.Context, dbTx BaseUniverseStore,
	id universe.Identifier, key universe.BaseKey,
	leaf *universe.MintingLeaf,
	metaReveal *proof.MetaReveal) (*universe.IssuanceProof, mssmt.Node,
	error) {

	namespace := id.String()

	// With the tree store created, we'll now obtain byte representation of
	// the minting key, as that'll be the key in the SMT itself.
	smtKey := key.UniverseKey()

	// The value stored in the MS-SMT will be the serialized MintingLeaf,
	// so we'll convert that into raw bytes now.
	leafNode := leaf.SmtLeafNode()

	var groupKeyBytes []byte
	if id.GroupKey != nil {
		groupKeyBytes = schnorr.SerializePubKey(id.GroupKey)
	}

	mintingPointBytes, err := encodeOutpoint(key.MintingOutpoint)
	if err != nil {
		return nil, nil, err
	}

	var (
		leafInclusionProof *mssmt.Proof
		universeRoot       mssmt.Node
	)

	// First, we'll instantiate a new compact tree instance from the
	// backing tree store.
	universeTree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(dbTx, namespace),
	)

	// Now that we have a tree instance linked to this DB
	// transaction, we'll insert the leaf into the tree based on
	// its SMT key.
	_, err = universeTree.Insert(ctx, smtKey, leafNode)
	if err != nil {
		return nil, nil, err
	}

	// Next, we'll upsert the universe root in the DB, which gives
	// us the root ID that we'll use to insert the universe leaf
	// overlay.
	universeRootID, err := dbTx.UpsertUniverseRoot(ctx, NewUniverseRoot{
		NamespaceRoot: namespace,
		AssetID:       fn.ByteSlice(leaf.ID()),
		GroupKey:      groupKeyBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	// Before we insert the asset genesis, we'll insert the meta
	// first. The reveal may or may not be populated, which'll also
	// insert the opaque meta blob on disk.
	_, err = maybeUpsertAssetMeta(
		ctx, dbTx, &leaf.Genesis, metaReveal,
	)
	if err != nil {
		return nil, nil, err
	}

	assetGenID, err := upsertAssetGen(
		ctx, dbTx, leaf.Genesis, leaf.GroupKey, leaf.GenesisProof,
	)
	if err != nil {
		return nil, nil, err
	}

	scriptKeyBytes := schnorr.SerializePubKey(key.ScriptKey.PubKey)
	err = dbTx.UpsertUniverseLeaf(ctx, UpsertUniverseLeaf{
		AssetGenesisID:    assetGenID,
		ScriptKeyBytes:    scriptKeyBytes,
		UniverseRootID:    universeRootID,
		LeafNodeKey:       smtKey[:],
		LeafNodeNamespace: namespace,
		MintingPoint:      mintingPointBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	// Finally, we'll obtain the merkle proof from the tree for the
	// leaf we just inserted.
	leafInclusionProof, err = universeTree.MerkleProof(ctx, smtKey)
	if err != nil {
		return nil, nil, err
	}

	// With the insertion complete, we'll now fetch the root of the tree as
	// it stands and return it to the caller.
	universeRoot, err = universeTree.Root(ctx)
	if err != nil {
		return nil, nil, err
	}

	return &universe.IssuanceProof{
		MintingKey:     key,
		UniverseRoot:   universeRoot,
		InclusionProof: leafInclusionProof,
		Leaf:           leaf,
	}, universeRoot, nil
}

// FetchIssuanceProof returns an issuance proof for the target key. If the key
// doesn't have a script key specified, then all the proofs for the minting
// outpoint will be returned. If neither are specified, then proofs for all the
// inserted leaves will be returned.
func (b *BaseUniverseTree) FetchIssuanceProof(ctx context.Context,
	universeKey universe.BaseKey) ([]*universe.IssuanceProof, error) {

	var (
		readTx = NewBaseUniverseReadTx()
		proofs []*universe.IssuanceProof
	)

	dbErr := b.db.ExecTx(ctx, &readTx, func(dbTx BaseUniverseStore) error {
		var err error
		proofs, err = universeFetchIssuanceProof(
			ctx, b.id, universeKey, dbTx,
		)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return proofs, nil
}

// universeFetchIssuanceProof returns issuance proofs for the target universe.
//
// If the given universe key doesn't have a script key specified, then a proof
// will be returned for each minting outpoint.
//
// NOTE: This function accepts a database transaction and is called when making
// broader DB updates.
func universeFetchIssuanceProof(ctx context.Context,
	id universe.Identifier, universeKey universe.BaseKey,
	dbTx BaseUniverseStore) ([]*universe.IssuanceProof, error) {

	namespace := id.String()

	// Depending on the universeKey, we'll either be fetching the details of
	// a specific issuance, or each issuance for that minting outpoint.
	var targetScriptKey []byte
	if universeKey.ScriptKey != nil {
		targetScriptKey = schnorr.SerializePubKey(
			universeKey.ScriptKey.PubKey,
		)
	}

	mintingPointBytes, err := encodeOutpoint(universeKey.MintingOutpoint)
	if err != nil {
		return nil, err
	}

	var proofs []*universe.IssuanceProof

	// First, we'll make a new instance of the universe tree, as we'll query
	// it directly to obtain the set of leaves we care about.
	universeTree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(dbTx, namespace),
	)

	// Each response will include a merkle proof of inclusion for the root,
	// so we'll obtain that now.
	rootNode, err := universeTree.Root(ctx)
	if err != nil {
		return nil, err
	}

	// Now that we have the tree, we'll query the set of Universe leaves we
	// have directly to determine which ones we care about.
	//
	// If the script key is blank, then we'll fetch all the leaves in the
	// tree.
	universeLeaves, err := dbTx.QueryUniverseLeaves(
		ctx, UniverseLeafQuery{
			MintingPointBytes: mintingPointBytes,
			ScriptKeyBytes:    targetScriptKey,
			Namespace:         namespace,
		},
	)
	if err != nil {
		return nil, err
	}

	if len(universeLeaves) == 0 {
		return nil, universe.ErrNoUniverseProofFound
	}

	// Now that we have all the leaves we need to query, we'll look each up
	// them up in the universe tree, obtaining a merkle proof for each of
	// them along the way.
	err = fn.ForEachErr(universeLeaves, func(leaf UniverseLeaf) error {
		scriptPub, err := schnorr.ParsePubKey(leaf.ScriptKeyBytes)
		if err != nil {
			return err
		}
		scriptKey := asset.NewScriptKey(scriptPub)

		// Next, we'll fetch the leaf node from the tree and also obtain
		// a merkle proof for the leaf alongside it.
		universeKey := universe.BaseKey{
			MintingOutpoint: universeKey.MintingOutpoint,
			ScriptKey:       &scriptKey,
		}
		smtKey := universeKey.UniverseKey()
		leafProof, err := universeTree.MerkleProof(
			ctx, smtKey,
		)
		if err != nil {
			return err
		}

		leafAssetGen, err := fetchGenesis(
			ctx, dbTx, leaf.GenAssetID,
		)
		if err != nil {
			return err
		}

		issuanceProof := &universe.IssuanceProof{
			MintingKey:     universeKey,
			UniverseRoot:   rootNode,
			InclusionProof: leafProof,
			Leaf: &universe.MintingLeaf{
				GenesisWithGroup: universe.GenesisWithGroup{
					Genesis: leafAssetGen,
				},
				GenesisProof: leaf.GenesisProof,
				Amt:          uint64(leaf.SumAmt),
			},
		}
		if id.GroupKey != nil {
			leafAssetGroup, err := fetchGroupByGenesis(
				ctx, dbTx, leaf.GenAssetID,
			)
			if err != nil {
				return err
			}

			issuanceProof.Leaf.GroupKey = &asset.GroupKey{
				GroupPubKey: *id.GroupKey,
				Sig:         leafAssetGroup.Sig,
			}
		}

		proofs = append(proofs, issuanceProof)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

// MintingKeys returns all the keys inserted in the universe.
func (b *BaseUniverseTree) MintingKeys(ctx context.Context,
) ([]universe.BaseKey, error) {

	var baseKeys []universe.BaseKey

	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		universeKeys, err := db.FetchUniverseKeys(ctx, b.smtNamespace)
		if err != nil {
			return err
		}

		return fn.ForEachErr(universeKeys, func(key UniverseKeys) error {
			scriptKeyPub, err := schnorr.ParsePubKey(
				key.ScriptKeyBytes,
			)
			if err != nil {
				return err
			}
			scriptKey := asset.NewScriptKey(scriptKeyPub)

			var genPoint wire.OutPoint
			err = readOutPoint(
				bytes.NewReader(key.MintingPoint), 0, 0,
				&genPoint,
			)
			if err != nil {
				return err
			}

			baseKeys = append(baseKeys, universe.BaseKey{
				MintingOutpoint: genPoint,
				ScriptKey:       &scriptKey,
			})

			return nil
		})
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return baseKeys, nil
}

// MintingLeaves returns all the minting leaves inserted into the universe.
func (b *BaseUniverseTree) MintingLeaves(ctx context.Context,
) ([]universe.MintingLeaf, error) {

	var leaves []universe.MintingLeaf

	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// First, we'll query the set of Universe leaves we have
		// directly to determine which ones we care about. We only
		// filter on the namespace here, as we want all the leaves for
		// this tree.
		universeLeaves, err := db.QueryUniverseLeaves(
			ctx, UniverseLeafQuery{
				Namespace: b.smtNamespace,
			},
		)
		if err != nil {
			return err
		}

		return fn.ForEachErr(universeLeaves, func(dbLeaf UniverseLeaf) error {
			// For each leaf, we'll decode the proof, and then also
			// fetch the genesis asset information for that leaf.
			leafAssetGen, err := fetchGenesis(
				ctx, db, dbLeaf.GenAssetID,
			)
			if err != nil {
				return err
			}

			// Now that we have the leaves, we'll encode them all
			// into the set of minting leaves.
			leaf := universe.MintingLeaf{
				GenesisWithGroup: universe.GenesisWithGroup{
					Genesis: leafAssetGen,
				},
				GenesisProof: dbLeaf.GenesisProof,
				Amt:          uint64(dbLeaf.SumAmt),
			}
			if b.id.GroupKey != nil {
				leaf.GroupKey = &asset.GroupKey{
					GroupPubKey: *b.id.GroupKey,
				}
			}

			leaves = append(leaves, leaf)

			return nil
		})
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return leaves, nil
}

// DeleteUniverse deletes the entire universe tree.
func (b *BaseUniverseTree) DeleteUniverse(ctx context.Context) (string, error) {
	var writeTx BaseUniverseStoreOptions

	dbErr := b.db.ExecTx(ctx, &writeTx, func(db BaseUniverseStore) error {
		// Instantiate a compact tree so we can delete the MS-SMT
		// backing the universe.
		universeTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, b.smtNamespace),
		)

		// Delete all MS-SMT nodes backing the universe tree.
		err := universeTree.DeleteAllNodes(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete universe MS-SMT"+
				"nodes: %w", err)
		}

		// Delete all leaves in the universe table.
		err = db.DeleteUniverseLeaves(ctx, b.smtNamespace)
		if err != nil {
			return fmt.Errorf("failed to delete universe leaves: %w",
				err)
		}

		// Delete the root node of the MS-SMT backing the universe.
		err = universeTree.DeleteRoot(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete universe MS-SMT"+
				"tree root: %w", err)
		}

		// Delete any events related to this universe.
		err = db.DeleteUniverseEvents(ctx, b.smtNamespace)
		if err != nil {
			return fmt.Errorf("failed to delete universe events: "+
				"%w", err)
		}

		// Delete the universe root from the universe table.
		err = db.DeleteUniverseRoot(ctx, b.smtNamespace)
		if err != nil {
			return fmt.Errorf("failed to delete universe root: %w",
				err)
		}

		return nil
	})

	return b.smtNamespace, dbErr
}

var _ universe.BaseBackend = (*BaseUniverseTree)(nil)
