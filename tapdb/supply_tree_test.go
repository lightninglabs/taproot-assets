package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func randRapidLeafKey(t *rapid.T) universe.UniqueLeafKey { //nolint:unused
	scriptKey := asset.ScriptKeyGen.Draw(t, "script_key")
	return universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  asset.OutPointGen.Draw(t, "outpoint"),
			ScriptKey: &scriptKey,
		},
		AssetID: asset.AssetIDGen.Draw(t, "asset_id"),
	}
}

func randProofGen(t *rapid.T, argAsset *asset.Asset) *proof.Proof {
	proofAsset := asset.AssetGen.Draw(t, "asset")
	if argAsset != nil {
		proofAsset = *argAsset
	}

	sliceGen := rapid.SliceOfN(rapid.Byte(), 32, 32)

	witnessData := sliceGen.Draw(t, "witness_data")

	pkScript := sliceGen.Draw(t, "pk_script")

	altAssets := rapid.SliceOfN[asset.Asset](
		asset.AltLeafGen(t), 1, 5,
	).Draw(t, "alt_leaves")

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
			InternalKey: asset.PubKeyGen.Draw(t, "internal_key"),
		},
		AltLeaves: asset.ToAltLeaves(
			lfn.Map(altAssets, lnutils.Ptr),
		),
	}
}

func randMintingLeafGen(t *rapid.T, assetGen asset.Genesis,
	groupKey *btcec.PublicKey) universe.Leaf {

	randProof := randProofGen(t, nil)

	leaf := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGen,
		},
		Amt: randProof.Asset.Amount,
	}

	// The asset within the genesis proof is random; reset the asset genesis
	// and group key to match the universe minting leaf.
	randProof.Asset.Genesis = assetGen
	randProof.GenesisReveal = &assetGen

	if groupKey != nil {
		// If the universe leaf needs a group key, the asset inside the
		// proof must also have one. We might need to generate a witness
		// if the randomly generated proof asset didn't have one.
		var witness wire.TxWitness
		if randProof.Asset.GroupKey != nil {
			witness = randProof.Asset.GroupKey.Witness
		} else {
			// Generate a witness since the proof asset didn't have
			// one.
			witness = asset.TxWitnessGen.Draw(t, "group_witness")

			randProof.Asset.PrevWitnesses = []asset.Witness{{
				PrevID:    &asset.PrevID{},
				TxWitness: witness,
			}}
		}

		assetGroupKey := &asset.GroupKey{
			GroupPubKey: *groupKey,
			Witness:     witness,
		}

		leaf.GroupKey = assetGroupKey
		randProof.Asset.GroupKey = assetGroupKey
		randProof.GroupKeyReveal = asset.NewGroupKeyRevealV0(
			asset.ToSerialized(groupKey), nil,
		)
	}

	leaf.Asset = &randProof.Asset

	var proofBuf bytes.Buffer
	require.NoError(t, randProof.Encode(&proofBuf))
	leaf.RawProof = proofBuf.Bytes()

	return leaf
}

// randMintEventGen generates a random NewMintEvent. It requires the group
// public key to correctly populate the leaf.
func randMintEventGen(groupPubKey *btcec.PublicKey,
) *rapid.Generator[supplycommit.SupplyUpdateEvent] {

	return rapid.Custom(func(t *rapid.T) supplycommit.SupplyUpdateEvent {
		mintGenesis := asset.GenesisGen.Draw(t, "genesis")
		mintLeaf := randMintingLeafGen(t, mintGenesis, groupPubKey)

		var p proof.Proof
		require.NoError(t, p.Decode(bytes.NewReader(mintLeaf.RawProof)))

		mintKey := universe.AssetLeafKey{
			BaseLeafKey: universe.BaseLeafKey{
				OutPoint:  p.OutPoint(),
				ScriptKey: &p.Asset.ScriptKey,
			},
			AssetID: p.Asset.ID(),
		}

		return &supplycommit.NewMintEvent{
			LeafKey:       mintKey,
			IssuanceProof: mintLeaf,
		}
	})
}

func burnAssetGen(t *rapid.T) *asset.Asset {
	a := asset.AssetGen.Draw(t, "asset")

	// Make sure it has two prev witness fields to ensure it isn't mistaken
	// as a genesis asset.
	a.PrevWitnesses = nil
	a.PrevWitnesses = append(
		a.PrevWitnesses, asset.Witness{}, asset.Witness{},
	)

	// Assign a non-zero PrevID that doesn't look like a genesis asset.
	nonZeroPrevID := asset.NonGenesisPrevIDGen.Draw(t, "burn_prev_id")
	a.PrevWitnesses[0].PrevID = &nonZeroPrevID

	a.ScriptKey = asset.NewScriptKey(
		asset.DeriveBurnKey(*a.PrevWitnesses[0].PrevID),
	)

	return &a
}

// randBurnEventGen generates a random NewBurnEvent. It requires the base
// genesis and group key to correctly populate the leaf, and the DB interface to
// ensure the genesis exists.
func randBurnEventGen(baseGenesis asset.Genesis, groupKey *asset.GroupKey,
	db BatchedUniverseTree) *rapid.Generator[supplycommit.SupplyUpdateEvent] { //nolint:lll

	return rapid.Custom(func(t *rapid.T) supplycommit.SupplyUpdateEvent {
		// Use the base genesis for burn events.
		burnAsset := burnAssetGen(t)
		burnAsset.Amount = uint64(
			rapid.Int32Range(1, 1_000).Draw(t, "burn_amt"),
		)

		burnAsset.Genesis = baseGenesis
		if groupKey != nil {
			burnAsset.GroupKey = groupKey
		}
		burnProof := randProofGen(t, burnAsset)
		burnProof.GenesisReveal = &baseGenesis

		burnLeaf := &universe.BurnLeaf{
			UniverseKey: universe.AssetLeafKey{
				BaseLeafKey: universe.BaseLeafKey{
					OutPoint:  burnProof.OutPoint(),
					ScriptKey: &burnProof.Asset.ScriptKey,
				},
				AssetID: burnProof.Asset.ID(),
			},
			BurnProof: burnProof,
		}

		// Ensure genesis exists for this burn leaf in the DB.
		ctx := context.Background()
		genesisPointID, err := upsertGenesisPoint(
			ctx, db, burnAsset.Genesis.FirstPrevOut,
		)
		require.NoError(t, err)
		_, err = upsertGenesis(
			ctx, db, genesisPointID, burnAsset.Genesis,
		)
		require.NoError(t, err)

		return &supplycommit.NewBurnEvent{
			BurnLeaf: *burnLeaf,
		}
	})
}

func randIgnoreTupleGen(t *rapid.T,
	db BatchedUniverseTree) universe.SignedIgnoreTuple {

	scriptKey := asset.ScriptKeyGen.Draw(t, "script_key")

	ctx := context.Background()

	op := asset.OutPointGen.Draw(t, "outpoint")

	genesis := asset.GenesisGen.Draw(t, "genesis")

	assetID := genesis.ID()

	ignoreTuple := &universe.IgnoreTuple{
		PrevID: asset.PrevID{
			ID:        assetID,
			ScriptKey: asset.ToSerialized(scriptKey.PubKey),
			OutPoint:  op,
		},
		Amount:      100,
		BlockHeight: rapid.Uint32Range(1, 1000).Draw(t, "block_height"),
	}

	// Create a signature for the ignore tuple.
	testSchnorrSigStr, err := hex.DecodeString(
		"04e7f9037658a92afeb4f25bae5339e3ddca81a353493827d26f16d92308" +
			"e49e2a25e92208678a2df86970da91b03a8af8815a8a60498b35" +
			"8daf560b347aa557",
	)
	require.NoError(t, err)
	testSchnorrSig, _ := lnwire.NewSigFromSchnorrRawSignature(
		testSchnorrSigStr,
	)
	testSchnorrSig.ForceSchnorr()
	sig, err := testSchnorrSig.ToSignature()
	require.NoError(t, err)

	signature, ok := sig.(*schnorr.Signature)
	require.True(t, ok)

	genesisOutpoint := genesis.FirstPrevOut

	genesisPointID, err := upsertGenesisPoint(ctx, db, genesisOutpoint)
	require.NoError(t, err)
	_, err = upsertGenesis(ctx, db, genesisPointID, genesis)
	require.NoError(t, err)

	// Create a SignedIgnoreTuple.
	return universe.NewSignedIgnoreTuple(
		*ignoreTuple, universe.IgnoreSig{Signature: *signature},
	)
}

// randIgnoreEventGen generates a random NewIgnoreEvent. It requires the base
// asset ID and the DB interface to ensure the genesis exists.
func randIgnoreEventGen(baseAssetID asset.ID,
	db BatchedUniverseTree) *rapid.Generator[supplycommit.SupplyUpdateEvent] { //nolint:lll

	return rapid.Custom(func(t *rapid.T) supplycommit.SupplyUpdateEvent {
		signedTuple := randIgnoreTupleGen(t, db)
		signedTuple.IgnoreTuple.Val.ID = baseAssetID

		return &supplycommit.NewIgnoreEvent{
			SignedIgnoreTuple: signedTuple,
		}
	})
}

// randSupplyUpdateEventGen creates a composite generator that randomly selects
// one of the specific event type generators.
func randSupplyUpdateEventGen(baseGenesis asset.Genesis,
	groupKey *asset.GroupKey,
	db BatchedUniverseTree) *rapid.Generator[supplycommit.SupplyUpdateEvent] { //nolint:lll

	var groupPubKey *btcec.PublicKey
	if groupKey != nil {
		groupPubKey = &groupKey.GroupPubKey
	}

	return rapid.OneOf(
		randMintEventGen(groupPubKey),
		randBurnEventGen(baseGenesis, groupKey, db),
		randIgnoreEventGen(baseGenesis.ID(), db),
	)
}

// setupSupplyTreeTestForProps sets up a test environment for property-based
// testing of SupplyTreeStore. It returns the store, specifier, base genesis,
// group key, and the composite event generator.
func setupSupplyTreeTestForProps(t *testing.T) (*SupplyTreeStore,
	asset.Specifier, *rapid.Generator[supplycommit.SupplyUpdateEvent]) {

	sqlDB := NewTestDB(t)
	dbTxer := NewTransactionExecutor(
		sqlDB, func(tx *sql.Tx) BaseUniverseStore {
			return sqlDB.WithTx(tx)
		},
	)
	supplyStore := NewSupplyTreeStore(dbTxer)
	ctx := context.Background()

	// Generate a random group key for testing.
	groupPrivKey := asset.PrivKeyGen.Example()
	require.NotNil(t, groupPrivKey)

	groupPub := groupPrivKey.PubKey()
	groupKey := &asset.GroupKey{
		GroupPubKey: *groupPub,
	}

	baseGenesis := asset.GenesisGen.Example()

	// Create a base genesis and insert it. This will be referenced by
	// burn/ignore events.
	baseAssetID := baseGenesis.ID()
	genesisOutpoint := baseGenesis.FirstPrevOut
	genesisPointID, err := upsertGenesisPoint(ctx, dbTxer, genesisOutpoint)
	require.NoError(t, err)
	genAssetID, err := upsertGenesis(
		ctx, dbTxer, genesisPointID, baseGenesis,
	)
	require.NoError(t, err)
	_, err = upsertGroupKey(
		ctx, groupKey, dbTxer, genesisPointID, genAssetID,
	)
	require.NoError(t, err)

	// Create an asset specifier with the group key.
	spec, err := asset.NewSpecifier(
		&baseAssetID, &groupKey.GroupPubKey, nil, true,
	)
	require.NoError(t, err)

	// Create the composite generator.
	eventGen := randSupplyUpdateEventGen(baseGenesis, groupKey, dbTxer)

	return supplyStore, spec, eventGen
}

// createMintEventWithHeight creates a mint event with a specific block height.
func createMintEventWithHeight(t *testing.T, groupKey *btcec.PublicKey,
	height uint32) *supplycommit.NewMintEvent {

	mintAsset := asset.RandAsset(t, asset.Normal)
	mintAsset.GroupKey = &asset.GroupKey{GroupPubKey: *groupKey}
	mintAsset.GroupKey.Witness = mintAsset.PrevWitnesses[0].TxWitness

	mintProof := randProof(t, mintAsset)
	mintProof.BlockHeight = height
	mintProof.GroupKeyReveal = asset.NewGroupKeyRevealV0(
		asset.ToSerialized(groupKey), nil,
	)

	var proofBuf bytes.Buffer
	require.NoError(t, mintProof.Encode(&proofBuf))

	mintLeaf := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  mintAsset.Genesis,
			GroupKey: mintAsset.GroupKey,
		},
		Asset:    &mintProof.Asset,
		Amt:      mintProof.Asset.Amount,
		RawProof: proofBuf.Bytes(),
	}

	mintKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  mintProof.OutPoint(),
			ScriptKey: &mintProof.Asset.ScriptKey,
		},
		AssetID: mintProof.Asset.ID(),
	}

	return &supplycommit.NewMintEvent{
		LeafKey:       mintKey,
		IssuanceProof: mintLeaf,
	}
}

// createBurnEventWithHeight creates a burn event with a specific block height.
func createBurnEventWithHeight(t *testing.T, baseGenesis asset.Genesis,
	groupKey *asset.GroupKey, db BatchedUniverseTree,
	height uint32) *supplycommit.NewBurnEvent {

	burnAsset := createBurnAsset(t)
	burnAsset.Genesis = baseGenesis
	burnAsset.GroupKey = groupKey

	burnProof := randProof(t, burnAsset)
	burnProof.BlockHeight = height
	burnProof.GenesisReveal = &baseGenesis

	// Ensure genesis exists for this burn leaf in the DB.
	ctx := context.Background()
	genesisPointID, err := upsertGenesisPoint(
		ctx, db, burnAsset.Genesis.FirstPrevOut,
	)
	require.NoError(t, err)
	_, err = upsertGenesis(
		ctx, db, genesisPointID, burnAsset.Genesis,
	)
	require.NoError(t, err)

	burnLeaf := &universe.BurnLeaf{
		UniverseKey: universe.AssetLeafKey{
			BaseLeafKey: universe.BaseLeafKey{
				OutPoint:  burnProof.OutPoint(),
				ScriptKey: &burnProof.Asset.ScriptKey,
			},
			AssetID: burnProof.Asset.ID(),
		},
		BurnProof: burnProof,
	}

	return &supplycommit.NewBurnEvent{
		BurnLeaf: *burnLeaf,
	}
}

// createIgnoreEventWithHeight creates an ignore event with a specific block
// height.
func createIgnoreEventWithHeight(t *testing.T, baseAssetID asset.ID,
	db BatchedUniverseTree, height uint32) *supplycommit.NewIgnoreEvent {

	signedTuple := randIgnoreTuple(t, db)
	signedTuple.IgnoreTuple.Val.ID = baseAssetID
	signedTuple.IgnoreTuple.Val.BlockHeight = height

	return &supplycommit.NewIgnoreEvent{
		SignedIgnoreTuple: signedTuple,
	}
}

// TestSupplyTreeStoreApplySupplyUpdates tests that the ApplySupplyUpdates meets
// a series of key invariant via property based testing.
func TestSupplyTreeStoreApplySupplyUpdates(t *testing.T) {
	t.Parallel()

	supplyStore, spec, eventGen := setupSupplyTreeTestForProps(t)
	ctxb := context.Background()

	// Draw a random list of supply update events. Limit the number
	// of events to keep test execution time reasonable.
	updates := rapid.SliceOfN(eventGen, 1, 20).Example()

	// Apply the updates.
	finalRootSupplyRoot, err := supplyStore.ApplySupplyUpdates(
		ctxb, spec, updates,
	)
	require.NoError(t, err)

	// First, we'll make a series of maps so we can easily verify
	// the expected sub-tree roots and sums.
	expectedSubRoots := make(map[supplycommit.SupplySubTree]mssmt.Node)
	expectedSubSums := make(map[supplycommit.SupplySubTree]uint64)
	tempTrees := make(map[supplycommit.SupplySubTree]mssmt.Tree)

	// To do this, we'll first create temporary trees for each
	// sub-tree. If we didn't have an update type for a given tree,
	// it'll be the empty tree.
	for _, treeType := range allSupplyTreeTypes {
		tempTrees[treeType] = mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		)
		expectedSubRoots[treeType] = mssmt.NewComputedBranch(
			mssmt.EmptyTreeRootHash, 0,
		)
	}

	// Next, we'll apply each of the updates to the proper tree
	// based on the sub-tree type.
	for _, update := range updates {
		treeType := update.SupplySubTreeType()

		tree, ok := tempTrees[treeType]
		require.True(t, ok, "missing tree for %v", treeType)

		updateKey := update.UniverseLeafKey()
		updateLeaf, err := update.UniverseLeafNode()
		require.NoError(t, err)

		_, err = tree.Insert(
			ctxb, updateKey.UniverseKey(), updateLeaf,
		)
		require.NoError(t, err)

		// Update expected root and sum for this sub-tree.
		root, err := tree.Root(ctxb)
		require.NoError(t, err)
		expectedSubRoots[treeType] = root
		expectedSubSums[treeType] = root.NodeSum()
	}

	// Now that the verification trees have been populated, we can
	// start verifying the results. We'll start by verifying the
	// sub-tree results.
	var totalExpectedRootSum uint64
	for treeType, expectedRoot := range expectedSubRoots {
		treeRes := supplyStore.FetchSubTree(
			ctxb, spec, treeType,
		)
		actualTree, err := treeRes.Unpack()
		require.NoError(t, err)

		actualRoot, err := actualTree.Root(ctxb)
		require.NoError(t, err)

		require.Equal(
			t, expectedRoot.NodeHash(),
			actualRoot.NodeHash(),
			"sub-tree root hash mismatch for %v", treeType,
		)
		require.Equal(
			t, expectedRoot.NodeSum(),
			actualRoot.NodeSum(),
			"sub-tree root sum mismatch for %v", treeType,
		)
		totalExpectedRootSum += actualRoot.NodeSum()
	}

	// We know the sub-tree roots are correct, now we'll verify the
	// root sum.
	require.NotNil(t, finalRootSupplyRoot)
	require.Equal(
		t, int64(totalExpectedRootSum),
		int64(finalRootSupplyRoot.NodeSum()),
		"final root supply tree sum mismatch",
	)

	// With the checks above, we know that the sub-trees are
	// correct, we'll now verify the root supply tree itself.
	rootTreeRes := supplyStore.FetchRootSupplyTree(ctxb, spec)
	rootTree, err := rootTreeRes.Unpack()
	require.NoError(t, err)

	for treeType, expectedSubRoot := range expectedSubRoots {
		// Only check inclusion if the sub-tree was actually
		// modified.
		if expectedSubRoot.NodeHash() ==
			mssmt.EmptyTreeRootHash {

			continue
		}

		// We'll create a merkle proof for the sub-tree, based
		// on the root tree we've read from the DB.
		leafKey := treeType.UniverseKey()
		dbProof, err := rootTree.MerkleProof(ctxb, leafKey)
		require.NoError(t, err)

		// Fetch the actual sub-tree root *after* updates.
		actualSubTreeRes := supplyStore.FetchSubTree(
			ctxb, spec, treeType,
		)
		actualSubTree, err := actualSubTreeRes.Unpack()
		require.NoError(t, err)
		actualSubTreeRoot, err := actualSubTree.Root(ctxb)
		require.NoError(t, err)

		// Construct the expected leaf node for the root tree.
		expectedLeafNode := mssmt.NewLeafNode(
			lnutils.ByteSlice(actualSubTreeRoot.NodeHash()),
			actualSubTreeRoot.NodeSum(),
		)

		// Verify the proof.
		valid := mssmt.VerifyMerkleProof(
			leafKey, expectedLeafNode, dbProof,
			finalRootSupplyRoot,
		)
		require.True(
			t, valid, "root supply tree inclusion proof "+
				"invalid for %v", treeType,
		)
	}

	// If we apply the same set of updates, we should get the same
	// result.
	idempotentRoot, err := supplyStore.ApplySupplyUpdates(
		ctxb, spec, updates,
	)
	require.NoError(t, err)
	require.Equal(
		t, finalRootSupplyRoot.NodeHash(),
		idempotentRoot.NodeHash(),
		"idempotency check failed: root hash mismatch",
	)
	require.Equal(
		t, finalRootSupplyRoot.NodeSum(),
		idempotentRoot.NodeSum(),
		"idempotency check failed: root sum mismatch",
	)

	// Read out an additional set of updates, we should be able to
	// without any issues.
	updates = rapid.SliceOfN(eventGen, 1, 20).Example()
	_, err = supplyStore.ApplySupplyUpdates(
		ctxb, spec, updates,
	)
	require.NoError(t, err)
}

// TestSupplyTreeStoreFetchSupplyLeavesByHeight tests the
// FetchSupplyLeavesByHeight method.
func TestSupplyTreeStoreFetchSupplyLeavesByHeight(t *testing.T) {
	t.Parallel()

	supplyStore, spec, _ := setupSupplyTreeTestForProps(t)
	ctxb := context.Background()
	dbTxer := supplyStore.db

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	require.NoError(t, err)
	assetID := spec.UnwrapIdToPtr()

	fullGroupKey := &asset.GroupKey{
		GroupPubKey: *groupKey,
	}

	// Create events with specific block heights, we'll use these heights
	// below to ensure that the new leaf height is properly set/read all the
	// way down the call stack.
	mintEvent100 := createMintEventWithHeight(t, groupKey, 100)
	burnEvent200 := createBurnEventWithHeight(
		t, asset.RandGenesis(t, asset.Normal), fullGroupKey, dbTxer,
		200,
	)
	ignoreEvent300 := createIgnoreEventWithHeight(t, *assetID, dbTxer, 300)
	mintEvent400 := createMintEventWithHeight(t, groupKey, 400)

	updates := []supplycommit.SupplyUpdateEvent{
		mintEvent100, burnEvent200, ignoreEvent300, mintEvent400,
	}

	// Apply updates.
	_, err = supplyStore.ApplySupplyUpdates(ctxb, spec, updates)
	require.NoError(t, err)

	testCases := []struct {
		name            string
		startHeight     uint32
		endHeight       uint32
		expectedCount   int
		expectedHeights []uint32
	}{
		{
			name:            "range including first",
			startHeight:     0,
			endHeight:       150,
			expectedCount:   1,
			expectedHeights: []uint32{100},
		},
		{
			name:            "range including second",
			startHeight:     150,
			endHeight:       250,
			expectedCount:   1,
			expectedHeights: []uint32{200},
		},
		{
			name:            "range including all",
			startHeight:     0,
			endHeight:       500,
			expectedCount:   4,
			expectedHeights: []uint32{100, 200, 300, 400},
		},
		{
			name:            "exact range",
			startHeight:     100,
			endHeight:       400,
			expectedCount:   4,
			expectedHeights: []uint32{100, 200, 300, 400},
		},
		{
			name:            "inner range",
			startHeight:     101,
			endHeight:       399,
			expectedCount:   2,
			expectedHeights: []uint32{200, 300},
		},
		{
			name:            "range after all",
			startHeight:     501,
			endHeight:       1000,
			expectedCount:   0,
			expectedHeights: nil,
		},
		{
			name:            "range before all",
			startHeight:     0,
			endHeight:       99,
			expectedCount:   0,
			expectedHeights: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			leaves, err := supplyStore.FetchSupplyLeavesByHeight(
				ctxb, spec, tc.startHeight, tc.endHeight,
			).Unpack()
			require.NoError(t, err)

			// Check that the number of leaves matches the expected
			// count.
			totalLeavesCount := len(leaves.IssuanceLeafEntries) +
				len(leaves.BurnLeafEntries) +
				len(leaves.IgnoreLeafEntries)
			require.Equal(t, totalLeavesCount, tc.expectedCount)

			var heights []uint32

			for _, leaf := range leaves.IssuanceLeafEntries {
				heights = append(heights, leaf.BlockHeight())
			}

			for _, leaf := range leaves.BurnLeafEntries {
				heights = append(heights, leaf.BlockHeight())
			}

			for _, leaf := range leaves.IgnoreLeafEntries {
				heights = append(heights, leaf.BlockHeight())
			}

			require.ElementsMatch(t, tc.expectedHeights, heights)
		})
	}
}

// TestFetchSupplyLeavesByHeightZeroHeights tests that when both start and end
// heights are zero, all results are returned from FetchSupplyLeavesByHeight
// because zero heights are treated as NULL (no limit).
func TestFetchSupplyLeavesByHeightZeroHeights(t *testing.T) {
	t.Parallel()

	supplyStore, spec, _ := setupSupplyTreeTestForProps(t)
	ctxb := context.Background()

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	require.NoError(t, err)

	mintEvent := createMintEventWithHeight(t, groupKey, 100)

	_, err = supplyStore.ApplySupplyUpdates(
		ctxb, spec, []supplycommit.SupplyUpdateEvent{mintEvent},
	)
	require.NoError(t, err)

	// Query with both start and end heights set to zero.
	leaves, err := supplyStore.FetchSupplyLeavesByHeight(
		ctxb, spec, 0, 0,
	).Unpack()
	require.NoError(t, err)

	// Verify that results are returned because zero heights are treated as
	// NULL (no limit), so all leaves should be returned.
	totalLeavesCount := len(leaves.IssuanceLeafEntries) +
		len(leaves.BurnLeafEntries) +
		len(leaves.IgnoreLeafEntries)
	require.Equal(t, 1, totalLeavesCount)

	// Verify the returned leaf has the expected height.
	require.Len(t, leaves.IssuanceLeafEntries, 1)
	require.Equal(
		t, uint32(100), leaves.IssuanceLeafEntries[0].BlockHeight(),
	)

	// We test that we get the same result if we query the leaves by tree
	// type.
	for _, treeType := range allSupplyTreeTypes {
		res, err := supplyStore.FetchSupplyLeavesByType(
			ctxb, spec, treeType, 0, 0,
		).Unpack()
		require.NoError(t, err)

		switch treeType {
		case supplycommit.MintTreeType:
			require.ElementsMatch(
				t, leaves.IssuanceLeafEntries,
				res.IssuanceLeafEntries,
			)

		case supplycommit.BurnTreeType:
			require.ElementsMatch(
				t, leaves.BurnLeafEntries,
				res.BurnLeafEntries,
			)

		case supplycommit.IgnoreTreeType:
			require.ElementsMatch(
				t, leaves.IgnoreLeafEntries,
				res.IgnoreLeafEntries,
			)
		}
	}
}

// TestQuerySupplyLeavesByHeightDirectZeroHeights tests the SQL-level
// QuerySupplyLeavesByHeight function directly with sqlInt32(0) values,
// which should return no results because no records satisfy both
// block_height >= 0 AND block_height <= 0 (unless block_height is exactly 0).
func TestQuerySupplyLeavesByHeightDirectZeroHeights(t *testing.T) {
	t.Parallel()

	supplyStore, spec, _ := setupSupplyTreeTestForProps(t)
	ctxb := context.Background()

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	require.NoError(t, err)

	// Create a mint event with height 100.
	mintEvent := createMintEventWithHeight(t, groupKey, 100)
	_, err = supplyStore.ApplySupplyUpdates(
		ctxb, spec, []supplycommit.SupplyUpdateEvent{mintEvent},
	)
	require.NoError(t, err)

	// Test by calling QuerySupplyLeavesByHeight directly with sqlInt32(0)
	// values (not Go zero values that get converted to SQL NULL).
	readTx := NewBaseUniverseReadTx()
	err = supplyStore.db.ExecTx(
		ctxb, &readTx, func(db BaseUniverseStore) error {
			// Get the namespace for the mint tree.
			namespace := subTreeNamespace(
				groupKey, supplycommit.MintTreeType,
			)

			// Call QuerySupplyLeavesByHeight directly with
			// sqlInt32(0) which is a valid SQL integer 0, not NULL.
			leaves, queryErr := db.QuerySupplyLeavesByHeight(
				ctxb, sqlc.QuerySupplyLeavesByHeightParams{
					Namespace:   namespace,
					StartHeight: sqlInt32(0),
					EndHeight:   sqlInt32(0),
				},
			)
			if queryErr != nil {
				return queryErr
			}

			// Should return no results because no records satisfy
			// block_height >= 0 AND block_height <= 0 (unless
			// block_height is 0).
			require.Len(t, leaves, 0, "Expected no results when "+
				"querying with start=0 and end=0")

			// Now test with SQL NULL values which should return
			// results because NULL means "no limit". We
			// could leave these fields unset, but it's clearer to
			// set them explicitly.
			var startHeight, endHeight sql.NullInt32
			nullLeaves, queryErr := db.QuerySupplyLeavesByHeight(
				ctxb, sqlc.QuerySupplyLeavesByHeightParams{
					Namespace:   namespace,
					StartHeight: startHeight,
					EndHeight:   endHeight,
				},
			)
			if queryErr != nil {
				return queryErr
			}

			// Should return results because NULL heights mean
			// "no limit", so all leaves should be returned.
			require.Len(t, nullLeaves, 1, "Expected 1 result "+
				"when querying with NULL start and end heights")

			return nil
		},
	)

	require.NoError(t, err)
}
