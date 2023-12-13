package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/keychain"
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

	// UniverseLeafKeysQuery is used to query for the set of keys that are
	// currently stored for a given namespace.
	UniverseLeafKeysQuery = sqlc.FetchUniverseKeysParams

	// UpsertMultiverseRoot is used to upsert a multiverse root.
	UpsertMultiverseRoot = sqlc.UpsertMultiverseRootParams

	// UpsertMultiverseLeaf is used to upsert a multiverse leaf.
	UpsertMultiverseLeaf = sqlc.UpsertMultiverseLeafParams

	// DeleteMultiverseLeaf is used to delete a multiverse leaf.
	DeleteMultiverseLeaf = sqlc.DeleteMultiverseLeafParams
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
	UpsertUniverseRoot(ctx context.Context, arg NewUniverseRoot) (int64,
		error)

	// FetchUniverseKeys fetches the set of keys that are currently stored
	// for a given namespace.
	FetchUniverseKeys(ctx context.Context,
		arg UniverseLeafKeysQuery) ([]UniverseKeys, error)

	// UpsertMultiverseRoot upserts a multiverse root in the database.
	UpsertMultiverseRoot(ctx context.Context,
		arg UpsertMultiverseRoot) (int64, error)

	// UpsertMultiverseLeaf upserts a multiverse leaf in the database.
	UpsertMultiverseLeaf(ctx context.Context,
		arg UpsertMultiverseLeaf) (int64, error)

	// DeleteMultiverseLeaf deletes a multiverse leaf from the database.
	DeleteMultiverseLeaf(ctx context.Context,
		arg DeleteMultiverseLeaf) error
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
	genesisProof *proof.Proof) (int64, error) {

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
		// Every group-related issuance must be accompanied by a group
		// witness.
		groupWitness := genesisProof.Asset.PrevWitnesses[0].TxWitness
		fullGroupKey := &asset.GroupKey{
			GroupPubKey: groupKey.GroupPubKey,
			Witness:     groupWitness,
		}

		// If a group key reveal is present, then this asset is a group
		// anchor and we must insert extra information about the group
		// key.
		if genesisProof.GroupKeyReveal != nil {
			reveal := genesisProof.GroupKeyReveal
			rawKey, err := reveal.RawKey.ToPubKey()
			if err != nil {
				return 0, err
			}

			fullGroupKey.RawKey = keychain.KeyDescriptor{
				PubKey: rawKey,
			}
			fullGroupKey.TapscriptRoot = reveal.TapscriptRoot
		}
		_, err = upsertGroupKey(
			ctx, fullGroupKey, db, genPointID, genAssetID,
		)
		if err != nil {
			return 0, err
		}
	}

	var txBuf bytes.Buffer
	if err := genesisProof.AnchorTx.Serialize(&txBuf); err != nil {
		return 0, fmt.Errorf("unable to serialize anchor tx: %w", err)
	}

	genTXID := genesisProof.AnchorTx.TxHash()
	genBlockHash := genesisProof.BlockHeader.BlockHash()
	chainTXID, err := db.UpsertChainTx(ctx, ChainTxParams{
		Txid:        genTXID[:],
		RawTx:       txBuf.Bytes(),
		BlockHeight: sqlInt32(genesisProof.BlockHeight),
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
		AnchorTxID: sqlInt64(chainTXID),
	}); err != nil {
		return 0, fmt.Errorf("unable to anchor genesis tx: %w", err)
	}

	// TODO(roasbeef): need to mark that this is a imported gen?

	return genAssetID, nil
}

// RegisterIssuance inserts a new minting leaf within the universe tree, stored
// at the base key.
func (b *BaseUniverseTree) RegisterIssuance(ctx context.Context,
	key universe.LeafKey, leaf *universe.Leaf,
	metaReveal *proof.MetaReveal) (*universe.Proof, error) {

	var (
		writeTx BaseUniverseStoreOptions

		err           error
		issuanceProof *universe.Proof
	)
	dbErr := b.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		issuanceProof, err = universeUpsertProofLeaf(
			ctx, dbTx, b.id, key, leaf, metaReveal,
		)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return issuanceProof, nil
}

// universeUpsertProofLeaf upserts a proof leaf within the universe tree (stored
// at the proof leaf key).
//
// This function returns the inserted/updated proof leaf and the new universe
// root.
//
// NOTE: This function accepts a db transaction, as it's used when making
// broader DB updates.
func universeUpsertProofLeaf(ctx context.Context, dbTx BaseUniverseStore,
	id universe.Identifier, key universe.LeafKey, leaf *universe.Leaf,
	metaReveal *proof.MetaReveal) (*universe.Proof, error) {

	namespace := id.String()

	// With the tree store created, we'll now obtain byte representation of
	// the minting key, as that'll be the key in the SMT itself.
	smtKey := key.UniverseKey()

	// The value stored in the MS-SMT will be the serialized Leaf, so we'll
	// convert that into raw bytes now.
	leafNode := leaf.SmtLeafNode()

	var groupKeyBytes []byte
	if id.GroupKey != nil {
		groupKeyBytes = schnorr.SerializePubKey(id.GroupKey)
	}

	mintingPointBytes, err := encodeOutpoint(key.OutPoint)
	if err != nil {
		return nil, err
	}

	var (
		leafInclusionProof *mssmt.Proof
		universeRoot       mssmt.Node
	)

	// First, we'll instantiate a new compact tree instance from the backing
	// tree store.
	universeTree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(dbTx, namespace),
	)

	// Now that we have a tree instance linked to this DB transaction, we'll
	// insert the leaf into the tree based on its SMT key.
	_, err = universeTree.Insert(ctx, smtKey, leafNode)
	if err != nil {
		return nil, err
	}

	// Next, we'll upsert the universe root in the DB, which gives us the
	// root ID that we'll use to insert the universe leaf overlay.
	universeRootID, err := dbTx.UpsertUniverseRoot(ctx, NewUniverseRoot{
		NamespaceRoot: namespace,
		AssetID:       fn.ByteSlice(leaf.ID()),
		GroupKey:      groupKeyBytes,
		ProofType:     id.ProofType.String(),
	})
	if err != nil {
		return nil, err
	}

	// Before we insert the asset genesis, we'll insert the meta first. The
	// reveal may or may not be populated, which'll also insert the opaque
	// meta blob on disk.
	_, err = maybeUpsertAssetMeta(ctx, dbTx, &leaf.Genesis, metaReveal)
	if err != nil {
		return nil, err
	}

	var leafProof proof.Proof
	err = leafProof.Decode(bytes.NewReader(leaf.RawProof))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof: %w", err)
	}

	assetGenID, err := upsertAssetGen(
		ctx, dbTx, leaf.Genesis, leaf.GroupKey, &leafProof,
	)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// Finally, we'll obtain the merkle proof from the tree for the leaf we
	// just inserted.
	leafInclusionProof, err = universeTree.MerkleProof(ctx, smtKey)
	if err != nil {
		return nil, err
	}

	// With the insertion complete, we'll now fetch the root of the tree as
	// it stands and return it to the caller.
	universeRoot, err = universeTree.Root(ctx)
	if err != nil {
		return nil, err
	}

	// The next step is to insert the multiverse leaf, which is a leaf in
	// the multiverse tree that points to the universe leaf we just created.
	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return nil, err
	}

	// Retrieve a handle to the multiverse tree so that we can update the
	// tree by inserting a new issuance.
	multiverseTree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(dbTx, multiverseNS),
	)

	// Construct a leaf node for insertion into the multiverse tree. The
	// leaf node includes a reference to the lower tree via the lower tree
	// root hash.
	universeRootHash := universeRoot.NodeHash()
	assetGroupSum := universeRoot.NodeSum()

	if id.ProofType == universe.ProofTypeIssuance {
		assetGroupSum = 1
	}

	uniLeafNode := mssmt.NewLeafNode(universeRootHash[:], assetGroupSum)

	// Use asset ID (or asset group hash) as the upper tree leaf node key.
	// This is the same as the asset specific universe ID.
	uniLeafNodeKey := id.Bytes()

	_, err = multiverseTree.Insert(ctx, uniLeafNodeKey, uniLeafNode)
	if err != nil {
		return nil, err
	}

	// Now that we've inserted the leaf into the multiverse tree, we'll also
	// make sure the corresponding multiverse roots and leaves are created.
	multiverseRootID, err := dbTx.UpsertMultiverseRoot(
		ctx, UpsertMultiverseRoot{
			NamespaceRoot: multiverseNS,
			ProofType:     id.ProofType.String(),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to upsert multiverse root: %w",
			err)
	}

	var assetIDBytes []byte
	if id.GroupKey == nil {
		assetIDBytes = id.AssetID[:]
	}

	_, err = dbTx.UpsertMultiverseLeaf(ctx, UpsertMultiverseLeaf{
		MultiverseRootID:  multiverseRootID,
		AssetID:           assetIDBytes,
		GroupKey:          groupKeyBytes,
		LeafNodeKey:       uniLeafNodeKey[:],
		LeafNodeNamespace: multiverseNS,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to upsert multiverse leaf: %w",
			err)
	}

	// Retrieve the multiverse root and asset specific inclusion proof for
	// the leaf node.
	multiverseRoot, err := multiverseTree.Root(ctx)
	if err != nil {
		return nil, err
	}

	multiverseInclusionProof, err := multiverseTree.MerkleProof(
		ctx, uniLeafNodeKey,
	)
	if err != nil {
		return nil, err
	}

	return &universe.Proof{
		LeafKey:                  key,
		UniverseRoot:             universeRoot,
		UniverseInclusionProof:   leafInclusionProof,
		MultiverseRoot:           multiverseRoot,
		MultiverseInclusionProof: multiverseInclusionProof,
		Leaf:                     leaf,
	}, nil
}

// FetchIssuanceProof returns an issuance proof for the target key. If the key
// doesn't have a script key specified, then all the proofs for the minting
// outpoint will be returned. If neither are specified, then proofs for all the
// inserted leaves will be returned.
func (b *BaseUniverseTree) FetchIssuanceProof(ctx context.Context,
	universeKey universe.LeafKey) ([]*universe.Proof, error) {

	var (
		readTx = NewBaseUniverseReadTx()
		proofs []*universe.Proof
	)

	dbErr := b.db.ExecTx(ctx, &readTx, func(dbTx BaseUniverseStore) error {
		var err error
		proofs, err = universeFetchProofLeaf(
			ctx, b.id, universeKey, dbTx,
		)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return proofs, nil
}

// universeFetchProofLeaf returns proof leaves for the target universe.
//
// If the given universe leaf key doesn't have a script key specified, then a
// proof will be returned for each minting outpoint.
//
// NOTE: This function accepts a database transaction and is called when making
// broader DB updates.
func universeFetchProofLeaf(ctx context.Context,
	id universe.Identifier, universeKey universe.LeafKey,
	dbTx BaseUniverseStore) ([]*universe.Proof, error) {

	namespace := id.String()

	// Depending on the universeKey, we'll either be fetching the details of
	// a specific issuance, or each issuance for that minting outpoint.
	var targetScriptKey []byte
	if universeKey.ScriptKey != nil {
		targetScriptKey = schnorr.SerializePubKey(
			universeKey.ScriptKey.PubKey,
		)
	}

	mintingPointBytes, err := encodeOutpoint(universeKey.OutPoint)
	if err != nil {
		return nil, err
	}

	var proofs []*universe.Proof

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
	universeLeaves, err := dbTx.QueryUniverseLeaves(ctx, UniverseLeafQuery{
		MintingPointBytes: mintingPointBytes,
		ScriptKeyBytes:    targetScriptKey,
		Namespace:         namespace,
	})
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
		universeKey := universe.LeafKey{
			OutPoint:  universeKey.OutPoint,
			ScriptKey: &scriptKey,
		}
		smtKey := universeKey.UniverseKey()
		leafProof, err := universeTree.MerkleProof(ctx, smtKey)
		if err != nil {
			return err
		}

		leafAssetGen, err := fetchGenesis(ctx, dbTx, leaf.GenAssetID)
		if err != nil {
			return err
		}

		// We only need to obtain the asset at this point, so we'll do
		// a sparse decode here to decode only the asset record.
		var leafAsset asset.Asset
		assetRecord := proof.AssetLeafRecord(&leafAsset)
		err = proof.SparseDecode(
			bytes.NewReader(leaf.GenesisProof), assetRecord,
		)
		if err != nil {
			return fmt.Errorf("unable to decode proof: %w", err)
		}

		issuanceProof := &universe.Proof{
			LeafKey:                universeKey,
			UniverseRoot:           rootNode,
			UniverseInclusionProof: leafProof,
			Leaf: &universe.Leaf{
				GenesisWithGroup: universe.GenesisWithGroup{
					Genesis: leafAssetGen,
				},
				RawProof: leaf.GenesisProof,
				Asset:    &leafAsset,
				Amt:      uint64(leaf.SumAmt),
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
				Witness:     leafAssetGroup.Witness,
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

// mintingKeys returns all the leaf keys in the target universe.
func mintingKeys(ctx context.Context, dbTx BaseUniverseStore,
	q universe.UniverseLeafKeysQuery,
	namespace string) ([]universe.LeafKey, error) {

	universeKeys, err := dbTx.FetchUniverseKeys(
		ctx, UniverseLeafKeysQuery{
			Namespace:     namespace,
			SortDirection: sqlInt16(q.SortDirection),
			NumOffset:     q.Offset,
			NumLimit: func() int32 {
				if q.Limit == 0 {
					return universe.MaxPageSize
				}

				return q.Limit
			}(),
		},
	)
	if err != nil {
		return nil, err
	}

	var leafKeys []universe.LeafKey
	err = fn.ForEachErr(universeKeys, func(key UniverseKeys) error {
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

		leafKeys = append(leafKeys, universe.LeafKey{
			OutPoint:  genPoint,
			ScriptKey: &scriptKey,
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	return leafKeys, nil
}

// MintingKeys returns all the keys inserted in the universe.
func (b *BaseUniverseTree) MintingKeys(ctx context.Context,
	q universe.UniverseLeafKeysQuery) ([]universe.LeafKey, error) {

	var leafKeys []universe.LeafKey

	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		dbLeaves, err := mintingKeys(ctx, db, q, b.smtNamespace)
		if err != nil {
			return err
		}

		leafKeys = dbLeaves

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return leafKeys, nil
}

// MintingLeaves returns all the minting leaves inserted into the universe.
func (b *BaseUniverseTree) MintingLeaves(
	ctx context.Context) ([]universe.Leaf, error) {

	var leaves []universe.Leaf

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

			var genProof proof.Proof
			err = genProof.Decode(bytes.NewReader(
				dbLeaf.GenesisProof,
			))
			if err != nil {
				return fmt.Errorf("unable to decode proof: %w",
					err)
			}

			// Now that we have the leaves, we'll encode them all
			// into the set of minting leaves.
			leaf := universe.Leaf{
				GenesisWithGroup: universe.GenesisWithGroup{
					Genesis: leafAssetGen,
				},
				RawProof: dbLeaf.GenesisProof,
				Asset:    &genProof.Asset,
				Amt:      uint64(dbLeaf.SumAmt),
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

// deleteUniverses deletes the entire universe for a given namespace.
func deleteUniverseTree(ctx context.Context,
	db BaseUniverseStore, id universe.Identifier) error {

	namespace := id.String()

	// Instantiate a compact tree so we can delete the MS-SMT
	// backing the universe.
	universeTree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(db, namespace),
	)

	// Delete all MS-SMT nodes backing the universe tree.
	err := universeTree.DeleteAllNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete universe MS-SMT"+
			"nodes: %w", err)
	}

	// Delete all leaves in the universe table.
	err = db.DeleteUniverseLeaves(ctx, namespace)
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
	err = db.DeleteUniverseEvents(ctx, namespace)
	if err != nil {
		return fmt.Errorf("failed to delete universe events: "+
			"%w", err)
	}

	// Delete the universe root from the universe table.
	err = db.DeleteUniverseRoot(ctx, namespace)
	if err != nil {
		return fmt.Errorf("failed to delete universe root: %w",
			err)
	}

	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return err
	}
	err = db.DeleteMultiverseLeaf(ctx, DeleteMultiverseLeaf{
		Namespace:   multiverseNS,
		LeafNodeKey: fn.ByteSlice(id.Bytes()),
	})
	if err != nil {
		return fmt.Errorf("unable to upsert multiverse leaf: %w", err)
	}

	return nil
}

// DeleteUniverse deletes the entire universe tree.
func (b *BaseUniverseTree) DeleteUniverse(ctx context.Context) (string, error) {
	var writeTx BaseUniverseStoreOptions

	dbErr := b.db.ExecTx(ctx, &writeTx, func(db BaseUniverseStore) error {
		return deleteUniverseTree(ctx, db, b.id)
	})

	return b.smtNamespace, dbErr
}

var _ universe.BaseBackend = (*BaseUniverseTree)(nil)
