package tarodb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/tarodb/sqlc"
	"github.com/lightninglabs/taro/universe"
)

type (
	// UniverseRoot...
	UniverseRoot = sqlc.FetchUniverseRootRow

	// NewUniverseLeaf...
	NewUniverseLeaf = sqlc.InsertUniverseLeafParams

	// NeUniverseRoot...
	NewUniverseRoot = sqlc.InsertUniverseRootParams
)

// BaseUniverseStore...
type BaseUniverseStore interface {
	TreeStore

	// FetchUniverseRoot...
	FetchUniverseRoot(ctx context.Context,
		namespace string) (UniverseRoot, error)

	// InsertUniverseLeaf...
	InsertUniverseLeaf(ctx context.Context, arg NewUniverseLeaf) error

	// InsertUniverseRoot...
	InsertUniverseRoot(ctx context.Context, arg NewUniverseRoot) (int32, error)
}

// BaseUniverseStoreOptions...
type BaseUniverseStoreOptions struct {
	readOnly bool
}

// ReadOnly...
func (b *BaseUniverseStoreOptions) ReadOnly() bool {
	return b.readOnly
}

func NewBaseUniverseReadTx() BaseUniverseStoreOptions {
	return BaseUniverseStoreOptions{
		readOnly: true,
	}
}

// BasedUniverseTree...
type BatchedUniverseTree interface {
	BaseUniverseStore

	BatchedTx[BaseUniverseStore]
}

// BaseUniverseTree...
type BaseUniverseTree struct {
	db BatchedUniverseTree

	id universe.Identifier

	smtNamespace string
}

func idToNameSpace(id universe.Identifier) string {
	if id.GroupKey != nil {
		h := sha256.Sum256(schnorr.SerializePubKey(id.GroupKey))
		return hex.EncodeToString(h[:])
	}

	return hex.EncodeToString(id.AssetID[:])
}

// NewBaseUniverseTree...
func NewBaseUniverseTree(db BatchedUniverseTree,
	id universe.Identifier) *BaseUniverseTree {

	namespace := idToNameSpace(id)

	return &BaseUniverseTree{
		db:           db,
		id:           id,
		smtNamespace: namespace,
	}
}

// RootNode...
//   - namespace is groupKey/assetID?
func (b *BaseUniverseTree) RootNode(ctx context.Context) (mssmt.Node, error) {
	var universeRoot UniverseRoot

	readTx := NewBaseUniverseReadTx()

	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		dbRoot, err := db.FetchUniverseRoot(ctx, b.smtNamespace)
		if err != nil {
			return nil
		}

		universeRoot = dbRoot
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	var nodeHash mssmt.NodeHash
	copy(nodeHash[:], universeRoot.RootHash[:])

	return mssmt.NewComputedNode(
		nodeHash, uint64(universeRoot.RootSum),
	), nil
}

// TODO(roasbeef): iterate over all keys, etc, etc.

// treeStoreWrapperTx...
type treeStoreWrapperTx struct {
	universeTx BaseUniverseStore
	namespace  string
}

// newTreeStoreWrapperTx...
func newTreeStoreWrapperTx(universeTx BaseUniverseStore,
	namespace string) *treeStoreWrapperTx {

	return &treeStoreWrapperTx{
		universeTx: universeTx,
		namespace:  namespace,
	}
}

// Update...
func (t *treeStoreWrapperTx) Update(ctx context.Context,
	update func(tx mssmt.TreeStoreUpdateTx) error) error {

	updateTx := &taroTreeStoreTx{
		ctx:       ctx,
		dbTx:      t.universeTx,
		namespace: t.namespace,
	}

	return update(updateTx)
}

// View...
func (t *treeStoreWrapperTx) View(ctx context.Context,
	update func(tx mssmt.TreeStoreViewTx) error) error {

	viewTx := &taroTreeStoreTx{
		ctx:       ctx,
		dbTx:      t.universeTx,
		namespace: t.namespace,
	}

	return update(viewTx)
}

// RegisterIssuance...
//
// TODO(roasbeef): move to below?
func (b *BaseUniverseTree) RegisterIssuance(ctx context.Context,
	key universe.BaseKey,
	leaf *universe.MintingLeaf) (*universe.IssuanceProof, error) {

	// With the tree store created, we'll now obtain byte representation of
	// the minting key, as that'll be the key in the SMT itself.
	smtKey := key.UniverseKey()

	// The value stored in the MS-SMT will be the serialized MintingLeaf,
	// so we'll convert that into raw bytes now.
	var leafBuf bytes.Buffer
	if err := leaf.GenesisProof.Encode(&leafBuf); err != nil {
		return nil, err
	}

	assetID := leaf.ID()
	leafNode := mssmt.NewLeafNode(leafBuf.Bytes(), uint64(leaf.Amt))
	leafNodeHash := leafNode.NodeHash()

	groupKeyBytes := schnorr.SerializePubKey(&leaf.GroupKey.GroupPubKey)

	var (
		writeTx BaseUniverseStoreOptions

		leafInclusionProof *mssmt.Proof
		universeRoot       mssmt.Node
	)
	dbErr := b.db.ExecTx(ctx, &writeTx, func(db BaseUniverseStore) error {
		// First, we'll instantiate a new compact tree instance from the
		// backing tree store.
		universeTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, b.smtNamespace),
		)

		// Now that we have a tree instance linked to this DB
		// transaction, we'll insert the leaf into the tree based on
		// its SMT key.
		_, err := universeTree.Insert(ctx, smtKey, leafNode)
		if err != nil {
			return err
		}

		// With the insertion complete, we'll now fetch the root of the
		// tree as it stands, as we need to create a matching entry in
		// the universe table pointing to this root.
		rootNode, err := universeTree.Root(ctx)
		if err != nil {
			return err
		}

		// Next, we'll insert the root, which returns the root ID we'll
		// need to insert the matching universe leaf that points to our
		// newly inserted minting leaf.
		dbRootNode, err := db.FetchRootNode(ctx, b.smtNamespace)
		if err != nil {
			return err
		}
		universeRootID, err := db.InsertUniverseRoot(ctx, NewUniverseRoot{
			RootNodeID: dbRootNode.ID,
			AssetID:    assetID[:],
			GroupKey:   groupKeyBytes,
		})
		if err != nil {
			return err
		}

		// TODO(roasbeef): insert group key sig and gen ID
		assetGenID, err := upsertAssetGen(
			ctx, leaf.Genesis, leaf.GroupKey,
		)
		if err != nil {
			return err
		}

		err = db.InsertUniverseLeaf(ctx, NewUniverseLeaf{
			AssetGenesisID: assetGenID,
			UniverseRootID: universeRootID,
			LeafNodeID:     leafNodeHash[:],
		})
		if err != nil {
			return err
		}

		// Finally, we'll obtain the merkle proof from the tree for the
		// leaf we just inserted.
		leafInclusionProof, err = universeTree.MerkleProof(ctx, smtKey)
		if err != nil {
			return err
		}

		universeRoot = rootNode

		// get inclusion proof from db
		// add to resp
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return &universe.IssuanceProof{
		MintingKey:     key,
		UniverseRoot:   universeRoot,
		InclusionProof: leafInclusionProof,
		Leaf:           leaf,
	}, nil
}

// FetchIssuanceProof...
//   - if script key not set, then fetch all
func (b *BaseUniverseTree) FetchIssuanceProof(ctx context.Context,
	key universe.BaseKey) ([]*universe.IssuanceProof, error) {

	return nil, nil
}

// MintingKeys...
func (b *BaseUniverseTree) MintingKeys(ctx context.Context,
) ([]universe.BaseKey, error) {

	return nil, nil
}

// MintingLeaves...
func (b *BaseUniverseTree) MintingLeaves(ctx context.Context,
) ([]universe.MintingLeaf, error) {

	return nil, nil
}

var _ universe.BaseBackend = (*BaseUniverseTree)(nil)
