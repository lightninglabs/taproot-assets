package tapdb

import (
	"context"
	"database/sql"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

func randUniverseID(t *testing.T, forceGroup bool) universe.Identifier {
	t.Helper()

	var id universe.Identifier
	test.RandRead(t, id.AssetID[:])

	// 50/50 chance to also add a group key, or if we're forcing it.
	if forceGroup || rand.Intn(2) == 0 {
		groupKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		id.GroupKey = groupKey.PubKey()
	}

	return id
}

func newTestUniverse(t *testing.T,
	id universe.Identifier) (*BaseUniverseTree, sqlc.Querier) {

	db := NewTestDB(t)

	dbTxer := NewTransactionExecutor(db,
		func(tx *sql.Tx) BaseUniverseStore {
			return db.WithTx(tx)
		},
	)

	return NewBaseUniverseTree(dbTxer, id), db
}

func newTestUniverseWithDb(db *BaseDB,
	id universe.Identifier) (*BaseUniverseTree, sqlc.Querier) {

	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseUniverseStore {
			return db.WithTx(tx)
		},
	)

	return NewBaseUniverseTree(dbTxer, id), db
}

// TestUniverseEmptyTree tests that an empty Universe tree returns the expected
// error.
func TestUniverseEmptyTree(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t, false)
	baseUniverse, _ := newTestUniverse(t, id)

	_, _, err := baseUniverse.RootNode(ctx)
	require.ErrorIs(t, err, universe.ErrNoUniverseRoot)
}

func randBaseKey(t *testing.T) universe.BaseKey {
	return universe.BaseKey{
		MintingOutpoint: test.RandOp(t),
		ScriptKey: fn.Ptr(
			asset.NewScriptKey(test.RandPubKey(t)),
		),
	}
}

func randProof(t *testing.T) *proof.Proof {
	return &proof.Proof{
		PrevOut: wire.OutPoint{},
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(rand.Int63(), 0),
		},
		AnchorTx: wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				Witness: [][]byte{[]byte("foo")},
			}},
		},
		TxMerkleProof: proof.TxMerkleProof{},
		Asset:         *asset.RandAsset(t, asset.Normal),
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
		},
	}
}

func randMintingLeaf(t *testing.T, assetGen asset.Genesis,
	groupKey *btcec.PublicKey) universe.MintingLeaf {

	leaf := universe.MintingLeaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGen,
		},
		GenesisProof: randProof(t),
		Amt:          uint64(rand.Int31()),
	}
	if groupKey != nil {
		leaf.GroupKey = &asset.GroupKey{
			GroupPubKey: *groupKey,
		}
	}

	return leaf
}

// leaWithKey is a two tuple that associates new minting leaf with a key.
type leafWithKey struct {
	universe.BaseKey

	universe.MintingLeaf
}

// TestUniverseIssuanceProofs tests that we're able to insert issuance proofs
// for a given asset ID, and then retrieve them all with proper inclusion
// proofs.
func TestUniverseIssuanceProofs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t, false)
	baseUniverse, _ := newTestUniverse(t, id)

	const numLeaves = 4

	// All the leaves will be under the same base universe tree, so we want
	// them to have the same asset ID.
	assetGen := asset.RandGenesis(t, asset.Normal)

	// We'll start by making a series of random minting key (outpoint,
	// scriptKey) leaf pairs.
	testLeaves := make([]leafWithKey, numLeaves)
	for i := 0; i < numLeaves; i++ {
		targetKey := randBaseKey(t)
		leaf := randMintingLeaf(t, assetGen, id.GroupKey)

		testLeaves[i] = leafWithKey{targetKey, leaf}
	}

	// Next, with each leaf and key created, we'll now attempt to add them
	// to the tree by registering the issuance event.
	var leafSum uint64
	for _, testLeaf := range testLeaves {
		// Each new leaf should add to the accumulated sum.
		leafSum += testLeaf.Amt

		targetKey := testLeaf.BaseKey
		leaf := testLeaf.MintingLeaf

		issuanceProof, err := baseUniverse.RegisterIssuance(
			ctx, targetKey, &leaf, nil,
		)
		require.NoError(t, err)

		// The root should now reflect a proper sum value.
		rootNode, assetName, err := baseUniverse.RootNode(ctx)
		require.NoError(t, err)
		require.Equal(t, leafSum, rootNode.NodeSum())
		require.Equal(t, testLeaf.Tag, assetName)

		// The root returned in the proof should match the one we just
		// fetched.
		require.True(
			t,
			mssmt.IsEqualNode(rootNode, issuanceProof.UniverseRoot),
		)

		// We should be able to verify the issuance proof given the
		// root of the SMT.
		node, err := leaf.SmtLeafNode()
		require.NoError(t, err)
		proofRoot := issuanceProof.InclusionProof.Root(
			targetKey.UniverseKey(), node,
		)
		require.True(t, mssmt.IsEqualNode(rootNode, proofRoot))

		// We should be able to fetch the issuance proof now, using
		// that very same target key generated.
		dbProof, err := baseUniverse.FetchIssuanceProof(ctx, targetKey)
		require.NoError(t, err)

		uniProof := dbProof[0]

		// The proof should have the proper values populated.
		require.Equal(t, targetKey, uniProof.MintingKey)
		require.True(
			t, mssmt.IsEqualNode(rootNode, uniProof.UniverseRoot),
		)

		// The issuance proof we obtained should have a valid inclusion
		// proof.
		node, err = uniProof.Leaf.SmtLeafNode()
		require.NoError(t, err)
		dbProofRoot := uniProof.InclusionProof.Root(
			uniProof.MintingKey.UniverseKey(), node,
		)
		require.True(
			t, mssmt.IsEqualNode(uniProof.UniverseRoot, dbProofRoot),
		)
	}

	// Next, we'll query for all the available keys, this should match the
	// number of insertions we just did.
	mintingKeys, err := baseUniverse.MintingKeys(ctx)
	require.NoError(t, err)
	require.Equal(t, numLeaves, len(mintingKeys))

	// The set of leaves we created above should match what was returned.
	require.True(t, fn.All(mintingKeys, func(key universe.BaseKey) bool {
		return fn.Any(testLeaves, func(testLeaf leafWithKey) bool {
			return reflect.DeepEqual(key, testLeaf.BaseKey)
		})
	}))

	// We should be able to query for the complete set of leaves,
	// which matches what we inserted above.
	dbLeaves, err := baseUniverse.MintingLeaves(ctx)
	require.NoError(t, err)
	require.Equal(t, numLeaves, len(dbLeaves))
	require.True(t, fn.All(dbLeaves, func(leaf universe.MintingLeaf) bool {
		return fn.All(testLeaves, func(testLeaf leafWithKey) bool {
			return leaf.Genesis.ID() ==
				testLeaf.MintingLeaf.Genesis.ID()
		})
	}))

	// Record the current root, so we can make sure updating the proofs
	// results in a new root.
	previousRoot, _, err := baseUniverse.RootNode(ctx)
	require.NoError(t, err)

	// Next, we'll attempt to update the issuance proofs for each of the
	// leaves we just inserted.
	for idx := range testLeaves {
		testLeaf := &testLeaves[idx]
		testLeaf.MintingLeaf.GenesisProof = randProof(t)

		targetKey := testLeaf.BaseKey
		issuanceProof, err := baseUniverse.RegisterIssuance(
			ctx, targetKey, &testLeaf.MintingLeaf, nil,
		)
		require.NoError(t, err)

		// The root should still reflect a proper sum value but an
		// updated root.
		rootNode, assetName, err := baseUniverse.RootNode(ctx)
		require.NoError(t, err)
		require.Equal(t, leafSum, rootNode.NodeSum())
		require.Equal(t, testLeaf.Tag, assetName)

		// The root returned in the proof should match the one we just
		// fetched.
		require.True(
			t,
			mssmt.IsEqualNode(rootNode, issuanceProof.UniverseRoot),
		)

		// Make sure the root has changed.
		require.False(t, mssmt.IsEqualNode(previousRoot, rootNode))
		previousRoot = rootNode
	}

	// Finally, we should be able to delete this universe and all included
	// keys and leaves, as well as the root node.
	_, err = baseUniverse.DeleteUniverse(ctx)
	require.NoError(t, err)

	mintingKeys, err = baseUniverse.MintingKeys(ctx)
	require.NoError(t, err)
	require.Len(t, mintingKeys, 0)

	dbLeaves, err = baseUniverse.MintingLeaves(ctx)
	require.NoError(t, err)
	require.Len(t, dbLeaves, 0)

	rootNode, _, err := baseUniverse.RootNode(ctx)
	require.Nil(t, rootNode)
	require.ErrorIs(t, err, universe.ErrNoUniverseRoot)
}

// TestUniverseMetaBlob tests that leaves inserted with a meta reveal can be
// properly retrieved.
func TestUniverseMetaBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t, false)
	baseUniverse, _ := newTestUniverse(t, id)

	// We'll start by generating a random asset genesis.
	assetGen := asset.RandGenesis(t, asset.Normal)

	// Next, we'll modify the genesis to include a meta hash that matches a
	// real meta blob.
	meta := &proof.MetaReveal{
		Data: test.RandBytes(50)[:],
	}

	assetGen.MetaHash = meta.MetaHash()

	// With the meta constructed, we can insert a test leaf into the DB
	// now.
	targetKey := randBaseKey(t)
	leaf := randMintingLeaf(t, assetGen, id.GroupKey)

	_, err := baseUniverse.RegisterIssuance(ctx, targetKey, &leaf, meta)
	require.NoError(t, err)

	// We should be able to fetch the leaf based on the base key we used
	// above.
	dbProof, err := baseUniverse.FetchIssuanceProof(ctx, targetKey)
	require.NoError(t, err)

	uniProof := dbProof[0]

	// The proof should have the same genesis that we inserted above.
	require.Equal(t, assetGen.ID(), uniProof.Leaf.Genesis.ID())
}

func insertRandLeaf(t *testing.T, ctx context.Context, tree *BaseUniverseTree,
	assetGen *asset.Genesis) (*universe.IssuanceProof, error) {

	var targetGen asset.Genesis
	if assetGen != nil {
		targetGen = *assetGen
	} else {
		targetGen = asset.RandGenesis(t, asset.Normal)
	}

	targetKey := randBaseKey(t)
	leaf := randMintingLeaf(t, targetGen, tree.id.GroupKey)

	return tree.RegisterIssuance(ctx, targetKey, &leaf, nil)
}

// TestUniverseTreeIsolation tests that each Universe tree is properly isolated
// from the other.
func TestUniverseTreeIsolation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	db := NewTestDB(t)

	// For this test, we'll create two different Universes: one based on a
	// group key, and the other with a plain asset ID.
	idGroup := randUniverseID(t, true)
	groupUniverse, _ := newTestUniverseWithDb(db.BaseDB, idGroup)

	idNormal := randUniverseID(t, false)
	normalUniverse, _ := newTestUniverseWithDb(db.BaseDB, idNormal)

	// For each of the Universes, we'll now insert a random leaf that
	// should be inserted with the target ID.
	groupLeaf, err := insertRandLeaf(t, ctx, groupUniverse, nil)
	require.NoError(t, err)

	normalLeaf, err := insertRandLeaf(t, ctx, normalUniverse, nil)
	require.NoError(t, err)

	// We should be able to get the roots for both of the trees.
	groupRoot, _, err := groupUniverse.RootNode(ctx)
	require.NoError(t, err)

	normalRoot, _, err := normalUniverse.RootNode(ctx)
	require.NoError(t, err)

	// The sum of each root should match the value of the sole leaf we've
	// inserted.
	require.Equal(t, groupLeaf.Leaf.Amt, groupRoot.NodeSum())
	require.Equal(t, normalLeaf.Leaf.Amt, normalRoot.NodeSum())

	// If we make a new multiverse, then we should be able to fetch both the
	// roots above.
	multiverseDB := NewTransactionExecutor(db,
		func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverse := NewBaseMultiverse(multiverseDB)

	rootNodes, err := multiverse.RootNodes(ctx)
	require.NoError(t, err)

	// We should be able to find both of the roots we've inserted above.
	require.True(t, fn.All(rootNodes, func(rootNode universe.BaseRoot) bool {
		for _, rootNode := range rootNodes {
			if mssmt.IsEqualNode(rootNode.Node, groupRoot) {
				return true
			}
			if mssmt.IsEqualNode(rootNode.Node, normalRoot) {
				return true
			}
		}
		return false
	}))

	// We should be able to delete one Universe with no effect on the other.
	normalNamespace, err := normalUniverse.DeleteUniverse(ctx)
	require.NoError(t, err)
	require.Equal(t, idNormal.String(), normalNamespace)

	// A deleted universe should have no root stored.
	normalRoot, _, err = normalUniverse.RootNode(ctx)
	require.Nil(t, normalRoot)
	require.ErrorIs(t, err, universe.ErrNoUniverseRoot)

	// The deleted universe should not be present in the multiverse.
	rootNodes, err = multiverse.RootNodes(ctx)
	require.NoError(t, err)
	require.Len(t, rootNodes, 1)
	require.True(t, mssmt.IsEqualNode(rootNodes[0].Node, groupRoot))
}

// TestUniverseLeafQuery tests that we're able to properly query for the set of
// leaves in a Universe based on either the outpoint or the script key.
func TestUniverseLeafQuery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t, false)
	assetGen := asset.RandGenesis(t, asset.Normal)

	baseUniverse, _ := newTestUniverse(t, id)

	const numLeafs = 3

	// We'll create three new leaves, all of them will share the exact same
	// minting outpoint, but will have distinct script keys.
	rootMintingPoint := randBaseKey(t).MintingOutpoint

	leafToScriptKey := make(map[asset.SerializedKey]universe.MintingLeaf)
	for i := 0; i < numLeafs; i++ {
		targetKey := randBaseKey(t)
		targetKey.MintingOutpoint = rootMintingPoint

		leaf := randMintingLeaf(t, assetGen, id.GroupKey)

		scriptKey := asset.ToSerialized(targetKey.ScriptKey.PubKey)

		leafToScriptKey[scriptKey] = leaf

		_, err := baseUniverse.RegisterIssuance(
			ctx, targetKey, &leaf, nil,
		)
		require.NoError(t, err)
	}

	// If we query for only the minting point, then all three leaves should
	// be returned.
	proofs, err := baseUniverse.FetchIssuanceProof(ctx, universe.BaseKey{
		MintingOutpoint: rootMintingPoint,
	})
	require.NoError(t, err)
	require.Len(t, proofs, numLeafs)

	// We should be able to retreive all the leafs based on their script
	// keys.
	for scriptKeyBytes, leaf := range leafToScriptKey {
		scriptKey, err := btcec.ParsePubKey(scriptKeyBytes[:])
		require.NoError(t, err)

		p, err := baseUniverse.FetchIssuanceProof(ctx, universe.BaseKey{
			MintingOutpoint: rootMintingPoint,
			ScriptKey: &asset.ScriptKey{
				PubKey: scriptKey,
			},
		})
		require.NoError(t, err)
		require.Len(t, p, 1)

		// We can't compare the raw leaves as the proofs looks slightly
		// differently after an encode->decode cycle (nil vs. empty
		// slices and so on).
		require.Equal(
			t, leaf.GenesisWithGroup, p[0].Leaf.GenesisWithGroup,
		)

		expectedNode, err := leaf.SmtLeafNode()
		require.NoError(t, err)

		actualNode, err := p[0].Leaf.SmtLeafNode()
		require.NoError(t, err)

		require.True(t, mssmt.IsEqualNode(expectedNode, actualNode))
	}
}
