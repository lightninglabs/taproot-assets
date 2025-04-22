package tapdb

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"math"
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

type universeIdOptions struct {
	proofType universe.ProofType
}

func defaultUniverseIdOptions() *universeIdOptions {
	return &universeIdOptions{
		proofType: universe.ProofTypeIssuance,
	}
}

type universeIDOptFunc func(*universeIdOptions)

func withProofType(proofType universe.ProofType) universeIDOptFunc {
	return func(opts *universeIdOptions) {
		opts.proofType = proofType
	}
}

func randUniverseID(t testing.TB, forceGroup bool,
	optFunctions ...universeIDOptFunc) universe.Identifier {

	opts := defaultUniverseIdOptions()
	for _, optFunc := range optFunctions {
		optFunc(opts)
	}

	t.Helper()

	var id universe.Identifier
	test.RandRead(t, id.AssetID[:])

	// 50/50 chance to also add a group key, or if we're forcing it.
	if forceGroup || rand.Intn(2) == 0 {
		groupKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		id.GroupKey = groupKey.PubKey()
	}

	// Set universe proof type. This is the leaf proof type that will be
	// used for all leaves in this universe.
	id.ProofType = opts.proofType

	return id
}

func newTestUniverse(t *testing.T,
	id universe.Identifier) (*BaseUniverseTree, sqlc.Querier) {

	db := NewTestDB(t)

	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseUniverseStore {
			return db.WithTx(tx)
		},
	)

	return NewBaseUniverseTree(dbTxer, id), db
}

func newTestMultiverse(t *testing.T) (*MultiverseStore, sqlc.Querier) {
	db := NewTestDB(t)

	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)

	return NewMultiverseStore(dbTxer, DefaultMultiverseStoreConfig()), db
}

func newTestMultiverseWithDb(db *BaseDB) (*MultiverseStore, sqlc.Querier) {
	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)

	return NewMultiverseStore(dbTxer, DefaultMultiverseStoreConfig()), db
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

func assertIDInList(t *testing.T, leaves []universe.MultiverseLeaf,
	id universe.Identifier) {

	require.True(t, fn.Any(leaves, func(l universe.MultiverseLeaf) bool {
		switch {
		case l.ID.AssetID != asset.ID{}:
			return l.ID.AssetID == id.AssetID

		case l.ID.GroupKey != nil:
			if id.GroupKey == nil {
				return false
			}

			return test.SchnorrKeysEqual(
				t, l.ID.GroupKey, id.GroupKey,
			)

		default:
			require.Fail(t, "invalid leaf")
		}

		return false
	}))
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

func randLeafKey(t *testing.T) universe.LeafKey {
	return universe.BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(t))),
	}
}

func randProof(t *testing.T, argAsset *asset.Asset) *proof.Proof {
	proofAsset := *asset.RandAsset(t, asset.Normal)
	if argAsset != nil {
		proofAsset = *argAsset
	}

	var witnessData [32]byte
	_, err := crand.Read(witnessData[:])
	require.NoError(t, err)

	var pkScript [32]byte
	_, err = crand.Read(pkScript[:])
	require.NoError(t, err)

	return &proof.Proof{
		PrevOut: wire.OutPoint{},
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(rand.Int63(), 0),
		},
		AnchorTx: wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				Witness: [][]byte{witnessData[:]},
			}},
			TxOut: []*wire.TxOut{{
				PkScript: pkScript[:],
				Value:    1000,
			}},
		},
		TxMerkleProof: proof.TxMerkleProof{},
		Asset:         proofAsset,
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
		},
		AltLeaves: asset.ToAltLeaves(asset.RandAltLeaves(t, true)),
	}
}

func randMintingLeaf(t *testing.T, assetGen asset.Genesis,
	groupKey *btcec.PublicKey) universe.Leaf {

	randProof := randProof(t, nil)

	leaf := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGen,
		},
		Amt: uint64(rand.Int31()),
	}

	// The asset within the genesis proof is random; reset the asset genesis
	// and group key to match the universe minting leaf.
	randProof.Asset.Genesis = assetGen
	randProof.GenesisReveal = &assetGen

	if groupKey != nil {
		assetGroupKey := &asset.GroupKey{
			GroupPubKey: *groupKey,
			Witness:     randProof.Asset.GroupKey.Witness,
		}

		leaf.GroupKey = assetGroupKey
		randProof.Asset.GroupKey = assetGroupKey
		randProof.GroupKeyReveal = asset.NewGroupKeyRevealV0(
			asset.ToSerialized(groupKey), nil,
		)
	}

	leaf.Asset = &randProof.Asset

	proofBytes, err := randProof.Bytes()
	require.NoError(t, err)

	leaf.RawProof = proofBytes

	return leaf
}

// leafWithKey is a two tuple that associates universe leaf key with a leaf.
type leafWithKey struct {
	universe.LeafKey

	universe.Leaf
}

// TestUniverseIssuanceProofs tests that we're able to insert issuance proofs
// for a given asset ID, and then retrieve them all with proper inclusion
// proofs.
func TestUniverseIssuanceProofs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(
		t, false, withProofType(universe.ProofTypeIssuance),
	)
	db := NewTestDB(t)
	baseUniverse, _ := newTestUniverseWithDb(db.BaseDB, id)
	multiverse, _ := newTestMultiverseWithDb(db.BaseDB)

	const numLeaves = 4

	// The multiverse tree should be empty at this point.
	issuanceLeaves, err := multiverse.FetchLeaves(
		ctx, nil, universe.ProofTypeIssuance,
	)
	require.NoError(t, err)
	require.Len(t, issuanceLeaves, 0)
	transferLeaves, err := multiverse.FetchLeaves(
		ctx, nil, universe.ProofTypeTransfer,
	)
	require.NoError(t, err)
	require.Len(t, transferLeaves, 0)

	// All the leaves will be under the same base universe tree, so we want
	// them to have the same asset ID.
	assetGen := asset.RandGenesis(t, asset.Normal)

	// We'll start by making a series of random minting key (outpoint,
	// scriptKey) leaf pairs.
	testLeaves := make([]leafWithKey, numLeaves)
	for i := 0; i < numLeaves; i++ {
		targetKey := randLeafKey(t)
		leaf := randMintingLeaf(t, assetGen, id.GroupKey)

		testLeaves[i] = leafWithKey{targetKey, leaf}
	}

	// Next, with each leaf and key created, we'll now attempt to add them
	// to the tree by registering the issuance event.
	var leafSum uint64
	for _, testLeaf := range testLeaves {
		// Each new leaf should add to the accumulated sum.
		leafSum += testLeaf.Amt

		targetKey := testLeaf.LeafKey
		leaf := testLeaf.Leaf

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
		node := leaf.SmtLeafNode()
		proofRoot := issuanceProof.UniverseInclusionProof.Root(
			targetKey.UniverseKey(), node,
		)
		require.True(t, mssmt.IsEqualNode(rootNode, proofRoot))

		// We should be able to fetch the issuance proof now, using
		// that very same target key generated.
		dbProof, err := baseUniverse.FetchIssuanceProof(ctx, targetKey)
		require.NoError(t, err)

		uniProof := dbProof[0]

		// The proof should have the proper values populated.
		require.Equal(t, targetKey, uniProof.LeafKey)
		require.True(
			t, mssmt.IsEqualNode(rootNode, uniProof.UniverseRoot),
		)

		// The issuance proof we obtained should have a valid inclusion
		// proof.
		node = uniProof.Leaf.SmtLeafNode()
		dbProofRoot := uniProof.UniverseInclusionProof.Root(
			uniProof.LeafKey.UniverseKey(), node,
		)
		require.True(
			t, mssmt.IsEqualNode(uniProof.UniverseRoot, dbProofRoot),
		)
	}

	// The multiverse tree should just have a single leaf, since we inserted
	// proofs into the same universe.
	multiverseLeaves, err := multiverse.FetchLeaves(
		ctx, nil, id.ProofType,
	)
	require.NoError(t, err)
	require.Len(t, multiverseLeaves, 1)

	// And we should actually find the leaf we just inserted.
	assertIDInList(t, multiverseLeaves, id)

	// Next, we'll query for all the available keys, this should match the
	// number of insertions we just did.
	mintingKeys, err := baseUniverse.MintingKeys(
		ctx, universe.UniverseLeafKeysQuery{},
	)
	require.NoError(t, err)
	require.Equal(t, numLeaves, len(mintingKeys))

	// The set of leaves we created above should match what was returned.
	require.True(t, fn.All(mintingKeys, func(key universe.LeafKey) bool {
		return fn.Any(testLeaves, func(testLeaf leafWithKey) bool {
			return reflect.DeepEqual(key, testLeaf.LeafKey)
		})
	}))

	// We should be able to query for the complete set of leaves,
	// which matches what we inserted above.
	dbLeaves, err := baseUniverse.MintingLeaves(ctx)
	require.NoError(t, err)
	require.Equal(t, numLeaves, len(dbLeaves))
	require.True(t, fn.All(dbLeaves, func(leaf universe.Leaf) bool {
		return fn.All(testLeaves, func(testLeaf leafWithKey) bool {
			return leaf.Genesis.ID() ==
				testLeaf.Leaf.Genesis.ID()
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

		randProof := randProof(t, nil)

		randProofBytes, err := randProof.Bytes()
		require.NoError(t, err)

		testLeaf.Leaf.RawProof = randProofBytes

		targetKey := testLeaf.LeafKey
		issuanceProof, err := baseUniverse.RegisterIssuance(
			ctx, targetKey, &testLeaf.Leaf, nil,
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

	mintingKeys, err = baseUniverse.MintingKeys(
		ctx, universe.UniverseLeafKeysQuery{},
	)
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
	targetKey := randLeafKey(t)
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
	assetGen *asset.Genesis) (*universe.Proof, error) {

	var targetGen asset.Genesis
	if assetGen != nil {
		targetGen = *assetGen
	} else {
		targetGen = asset.RandGenesis(t, asset.Normal)
	}

	targetKey := randLeafKey(t)
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
	//
	// One will be an issuance tree, while the other a transfer tree.
	idGroup := randUniverseID(
		t, true, withProofType(universe.ProofTypeIssuance),
	)
	groupUniverse, _ := newTestUniverseWithDb(db.BaseDB, idGroup)

	idNormal := randUniverseID(
		t, false, withProofType(universe.ProofTypeTransfer),
	)
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
	multiverse := NewMultiverseStore(
		multiverseDB, DefaultMultiverseStoreConfig(),
	)

	rootNodes, err := multiverse.RootNodes(
		ctx, universe.RootNodesQuery{
			WithAmountsById: true,
		},
	)
	require.NoError(t, err)

	// We should be able to find both of the roots we've inserted above.
	require.True(t, fn.All(rootNodes, func(rootNode universe.Root) bool {
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

	// Similarly, each of the roots should have the proper proof type set.
	require.True(t, fn.All(rootNodes, func(root universe.Root) bool {
		switch root.ID.ProofType {
		case universe.ProofTypeIssuance:
			return mssmt.IsEqualNode(root.Node, groupRoot)
		case universe.ProofTypeTransfer:
			return mssmt.IsEqualNode(root.Node, normalRoot)
		default:
			return false
		}
	}))

	// Finally, the grouped root should have the GroupedAssets field
	// properly set.
	for _, root := range rootNodes {
		if mssmt.IsEqualNode(root.Node, groupRoot) {
			require.True(t, len(root.GroupedAssets) != 0)

			groupAmt, ok := root.GroupedAssets[groupLeaf.Leaf.ID()]
			require.True(t, ok)
			require.Equal(t, groupLeaf.Leaf.Amt, groupAmt)
		}
	}

	// We should be able to delete one Universe with no effect on the other.
	normalNamespace, err := normalUniverse.DeleteUniverse(ctx)
	require.NoError(t, err)
	require.Equal(t, idNormal.String(), normalNamespace)

	// A deleted universe should have no root stored.
	normalRoot, _, err = normalUniverse.RootNode(ctx)
	require.Nil(t, normalRoot)
	require.ErrorIs(t, err, universe.ErrNoUniverseRoot)

	for _, rootNode := range rootNodes {
		// TODO(roasbeef): need base universe -> universe cache
		// invalidation or delete thru multiverse
		multiverse.rootNodeCache.wipeCache()
		multiverse.proofCache.delProofsForAsset(rootNode.ID)
	}

	// The deleted universe should not be present in the multiverse.
	rootNodes, err = multiverse.RootNodes(
		ctx, universe.RootNodesQuery{
			WithAmountsById: true,
		},
	)
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
	var sharedWitness wire.TxWitness

	// We'll create three new leaves, all of them will share the exact same
	// minting outpoint, but will have distinct script keys.
	rootMintingPoint := randLeafKey(t).LeafOutPoint()

	leafToScriptKey := make(map[asset.SerializedKey]universe.Leaf)
	for i := 0; i < numLeafs; i++ {
		baseKey := randLeafKey(t).(universe.BaseLeafKey)
		baseKey.OutPoint = rootMintingPoint
		targetKey := baseKey

		leaf := randMintingLeaf(t, assetGen, id.GroupKey)
		if id.GroupKey != nil {
			// All assets are sharing the same genesis and group
			// key, so they must also share the same group witness.
			switch {
			case sharedWitness == nil:
				sharedWitness = leaf.GroupKey.Witness
			default:
				leaf.GroupKey.Witness = sharedWitness

				//nolint:lll
				// leaf.Proof.Asset.GroupKey.Witness = sharedWitness
				leaf.Asset.GroupKey.Witness = sharedWitness
				// TODO(roasbeef): circle back
			}
		}

		scriptKey := asset.ToSerialized(
			targetKey.LeafScriptKey().PubKey,
		)

		leafToScriptKey[scriptKey] = leaf

		_, err := baseUniverse.RegisterIssuance(
			ctx, targetKey, &leaf, nil,
		)
		require.NoError(t, err)
	}

	// If we query for only the minting point, then all three leaves should
	// be returned.
	proofs, err := baseUniverse.FetchIssuanceProof(
		ctx, universe.BaseLeafKey{
			OutPoint: rootMintingPoint,
		},
	)
	require.NoError(t, err)
	require.Len(t, proofs, numLeafs)

	// We should be able to retrieve all the leafs based on their script
	// keys.
	for scriptKeyBytes := range leafToScriptKey {
		leaf := leafToScriptKey[scriptKeyBytes]
		scriptKey, err := btcec.ParsePubKey(scriptKeyBytes[:])
		require.NoError(t, err)

		p, err := baseUniverse.FetchIssuanceProof(
			ctx, universe.BaseLeafKey{
				OutPoint: rootMintingPoint,
				ScriptKey: &asset.ScriptKey{
					PubKey: scriptKey,
				},
			},
		)
		require.NoError(t, err)
		require.Len(t, p, 1)

		// We can't compare the raw leaves as the proofs looks slightly
		// differently after an encode->decode cycle (nil vs. empty
		// slices and so on).
		require.Equal(
			t, leaf.GenesisWithGroup, p[0].Leaf.GenesisWithGroup,
		)

		expectedNode := leaf.SmtLeafNode()
		require.NoError(t, err)

		actualNode := p[0].Leaf.SmtLeafNode()
		require.NoError(t, err)

		require.True(t, mssmt.IsEqualNode(expectedNode, actualNode))
	}
}

// TestUniverseLeafOverflow tests that the insertion into the universe will
// fail if we try to add a leaf that'll cause the root some to overflow.
func TestUniverseLeafOverflow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t, false)
	baseUniverse, _ := newTestUniverse(t, id)

	// We'll start by generating a random asset genesis.
	assetGen := asset.RandGenesis(t, asset.Normal)

	// With the base gen above, we'll now create a random minting leaf and
	// key to insert.
	targetKey := randLeafKey(t)
	leaf := randMintingLeaf(t, assetGen, id.GroupKey)

	// We'll modify the leaf value to actually be a very large number, 1
	// value away from overflowing.
	leaf.Amt = math.MaxUint64 - 1

	// We should be able to insert this np.
	_, err := baseUniverse.RegisterIssuance(ctx, targetKey, &leaf, nil)
	require.NoError(t, err)

	// We should be able to fetch the leaf based on the base key we used
	// above.
	_, err = baseUniverse.FetchIssuanceProof(ctx, targetKey)
	require.NoError(t, err)

	// If we try to insert another, then this should fail, as the tree will
	// overflow.
	targetKey2 := randLeafKey(t)
	leaf2 := randMintingLeaf(t, assetGen, id.GroupKey)

	_, err = baseUniverse.RegisterIssuance(ctx, targetKey2, &leaf2, nil)
	require.ErrorIs(t, err, mssmt.ErrIntegerOverflow)

	// We should still be able to fetch the original issuance proof.
	_, err = baseUniverse.FetchIssuanceProof(ctx, targetKey)
	require.NoError(t, err)
}

// TestUniverseRootSum tests that the root sum and leaves for an issuance and
// transfer universe are computed as expected.
func TestUniverseRootSum(t *testing.T) {
	t.Parallel()

	type leaf struct {
		sumAmt uint64
	}

	testCases := []struct {
		name      string
		finalSum  uint64
		proofType universe.ProofType
		leaves    []leaf
	}{
		// If we insert to transfers into a transfer tree, the sum
		// should be 2. The leaf sum in this case isn't actually used.
		{
			name:      "transfer sum",
			finalSum:  2,
			proofType: universe.ProofTypeTransfer,
			leaves: []leaf{
				{
					sumAmt: 54,
				},
				{
					sumAmt: 50,
				},
			},
		},

		// If we insert to issuance events into the issuance tree, the
		// root sum should be the sum of the issuance values.
		{
			name:      "issuance sum",
			finalSum:  34,
			proofType: universe.ProofTypeIssuance,
			leaves: []leaf{
				{
					sumAmt: 14,
				},
				{
					sumAmt: 20,
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			id := randUniverseID(
				t, false, withProofType(testCase.proofType),
			)

			ctx := context.Background()
			baseUniverse, _ := newTestUniverse(t, id)

			assetGen := asset.RandGenesis(t, asset.Normal)

			leaves := make([]universe.Leaf, len(testCase.leaves))
			keys := make([]universe.LeafKey, len(testCase.leaves))
			for i, testLeaf := range testCase.leaves {
				leaf := randMintingLeaf(
					t, assetGen, id.GroupKey,
				)
				leaf.Amt = testLeaf.sumAmt

				leaves[i] = leaf

				targetKey := randLeafKey(t)

				// For transfer proofs, we'll modify the
				// witness asset proof to look more like a
				// transfer.
				if testCase.proofType ==
					universe.ProofTypeTransfer {

					//nolint:lll
					leaf.Asset.PrevWitnesses[0].TxWitness = [][]byte{
						{1}, {1}, {1},
					}
					//nolint:lll
					leaf.Asset.PrevWitnesses[0].PrevID.OutPoint.Hash = [32]byte{1}
				}

				keys[i] = targetKey

				_, err := baseUniverse.RegisterIssuance(
					ctx, targetKey, &leaf, nil,
				)
				require.NoError(t, err)
			}

			// If we fetch the root value of the tree, it should
			// match the root sum.
			rootNode, _, err := baseUniverse.RootNode(ctx)
			require.NoError(t, err)

			require.Equal(t, testCase.finalSum, rootNode.NodeSum())

			// Each of the leaves inserted should have the proper
			// value as well.
			for i, key := range keys {
				proofs, err := baseUniverse.FetchIssuanceProof(
					ctx, key,
				)
				require.NoError(t, err)

				sumAmt := testCase.leaves[i].sumAmt
				if testCase.proofType ==
					universe.ProofTypeTransfer {

					sumAmt = 1
				}

				require.Equal(t, int(sumAmt), int(proofs[0].Leaf.Amt))
			}
		})
	}
}

// TestMultiverseRootSum tests that the root sum and leaves for an issuance and
// transfer multiverse trees are computed as expected.
func TestMultiverseRootSum(t *testing.T) {
	t.Parallel()

	type leaf struct {
		sumAmt uint64
	}

	type testCase struct {
		name      string
		finalSum  uint64
		proofType universe.ProofType
		doubleUp  bool
		leaves    []leaf
	}

	testCases := []testCase{
		// If we insert two transfers into a transfer tree, then the sum
		// should be the sum of the leaf values. The leaf value here is
		// itself the root sum of a transfer tree, or the number of
		// transfers in a transfer tree.
		{
			name:      "transfer sum",
			finalSum:  4,
			proofType: universe.ProofTypeTransfer,
			doubleUp:  true,
			leaves: []leaf{
				{
					sumAmt: 10,
				},
				{
					sumAmt: 8,
				},
			},
		},

		// If we insert to issuance events into the issuance tree, root
		// sum should just be the total amount of leaves. So we ignore
		// the leaf sum, and instead just tally 1.
		{
			name:      "issuance sum",
			finalSum:  2,
			proofType: universe.ProofTypeIssuance,
			leaves: []leaf{
				{
					sumAmt: 14,
				},
				{
					sumAmt: 20,
				},
			},
		},

		// We also want to make sure we can insert both transfer and
		// issuance proofs at the same time without any conflicts.
		{
			name:     "transfer and issuance sum",
			finalSum: 3,
			// By specifying this as "unspecified" we signal we want
			// both transfer and issuance proofs. The final sum will
			// therefore be the same for both trees.
			proofType: universe.ProofTypeUnspecified,
			leaves: []leaf{
				{
					sumAmt: 14,
				},
				{
					sumAmt: 20,
				},
				{
					sumAmt: 20,
				},
			},
		},
	}

	runTestCase := func(t *testing.T, tc testCase) {
		multiverse, _ := newTestMultiverse(t)

		ctx := context.Background()

		// The multiverse tree should be empty at this point.
		issuanceLeaves, err := multiverse.FetchLeaves(
			ctx, nil, universe.ProofTypeIssuance,
		)
		require.NoError(t, err)
		require.Len(t, issuanceLeaves, 0)
		transferLeaves, err := multiverse.FetchLeaves(
			ctx, nil, universe.ProofTypeTransfer,
		)
		require.NoError(t, err)
		require.Len(t, transferLeaves, 0)

		ids := make([]universe.Identifier, 0, len(tc.leaves))
		for range tc.leaves {
			ids = append(ids, randUniverseID(t, false))
		}

		insertLeaves := func(proofType universe.ProofType) {
			for i, testLeaf := range tc.leaves {
				id := ids[i]
				id.ProofType = proofType

				assetGen := asset.RandGenesis(t, asset.Normal)
				leaf := randMintingLeaf(
					t, assetGen, id.GroupKey,
				)
				leaf.Amt = testLeaf.sumAmt

				targetKey := randLeafKey(t)

				// For transfer proofs, we'll modify the witness
				// asset proof to look more like a transfer.
				if proofType == universe.ProofTypeTransfer {
					prevWitnesses := leaf.Asset.PrevWitnesses
					prevWitnesses[0].TxWitness = [][]byte{
						{1}, {1}, {1},
					}
					prevID := prevWitnesses[0].PrevID
					prevID.OutPoint.Hash = [32]byte{1}
				}

				_, err := multiverse.UpsertProofLeaf(
					ctx, id, targetKey, &leaf, nil,
				)
				require.NoError(t, err)

				// If we should add more than one under this ID,
				// then we'll generate another instance.
				if tc.doubleUp {
					targetKey = randLeafKey(t)

					_, err := multiverse.UpsertProofLeaf(
						ctx, id, targetKey, &leaf, nil,
					)
					require.NoError(t, err)
				}

				// The multiverse tree should now have one more
				// leaf.
				multiverseLeaves, err := multiverse.FetchLeaves(
					ctx, nil, proofType,
				)
				require.NoError(t, err)
				require.Len(t, multiverseLeaves, i+1)

				// And we should actually find the leaf we just
				// inserted.
				assertIDInList(t, multiverseLeaves, id)
			}
		}

		checkSum := func(proofType universe.ProofType) {
			rootNode, err := multiverse.MultiverseRootNode(
				ctx, proofType,
			)
			require.NoError(t, err)

			rootNode.WhenSome(
				func(rootNode universe.MultiverseRoot) {
					require.EqualValues(
						t, tc.finalSum,
						rootNode.NodeSum(),
					)
				},
			)

			// We now delete the whole universe and expect the
			// multiverse leave to also disappear.
			id := ids[0]
			id.ProofType = proofType
			_, err = multiverse.DeleteUniverse(ctx, id)
			require.NoError(t, err)

			multiverseLeaves, err := multiverse.FetchLeaves(
				ctx, nil, proofType,
			)
			require.NoError(t, err)
			require.Len(t, multiverseLeaves, len(ids)-1)
		}

		// If we fetch the root value of the tree, it should be the same
		// as the finalSum.
		if tc.proofType == universe.ProofTypeUnspecified {
			insertLeaves(universe.ProofTypeIssuance)
			insertLeaves(universe.ProofTypeTransfer)

			checkSum(universe.ProofTypeIssuance)
			checkSum(universe.ProofTypeTransfer)
		} else {
			insertLeaves(tc.proofType)
			checkSum(tc.proofType)
		}
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runTestCase(t, testCase)
		})
	}
}
