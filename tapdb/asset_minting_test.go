package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// newAssetStore makes a new instance of the AssetMintingStore backed by sqlite
// by default.
func newAssetStore(t *testing.T) (*AssetMintingStore, *AssetStore,
	sqlc.Querier) {

	// First, Make a new test database.
	db := NewTestDB(t)

	mintStore, assetStore := newAssetStoreFromDB(db.BaseDB)
	return mintStore, assetStore, db
}

// newAssetStoreFromDB makes a new instance of the AssetMintingStore backed by
// the passed database.
func newAssetStoreFromDB(db *BaseDB) (*AssetMintingStore, *AssetStore) {
	// TODO(roasbeef): can use another layer of type params since
	// duplicated?
	txCreator := func(tx *sql.Tx) PendingAssetStore {
		return db.WithTx(tx)
	}
	activeTxCreator := func(tx *sql.Tx) ActiveAssetsStore {
		return db.WithTx(tx)
	}

	metaTxCreator := func(tx *sql.Tx) MetaStore {
		return db.WithTx(tx)
	}

	assetMintingDB := NewTransactionExecutor(db, txCreator)
	assetsDB := NewTransactionExecutor(db, activeTxCreator)
	metaDB := NewTransactionExecutor(db, metaTxCreator)

	testClock := clock.NewTestClock(time.Now())

	return NewAssetMintingStore(assetMintingDB),
		NewAssetStore(assetsDB, metaDB, testClock, db.Backend())
}

func assertBatchState(t *testing.T, batch *tapgarden.MintingBatch,
	state tapgarden.BatchState) {

	require.Equal(t, state, batch.State())
}

func assertBatchSibling(t *testing.T, batch *tapgarden.MintingBatch,
	sibling chainhash.Hash) {

	require.Equal(t, sibling[:], batch.TapSibling())
}

func assertBatchEqual(t *testing.T, a, b *tapgarden.MintingBatch) {
	t.Helper()

	require.Equal(t, a.CreationTime.Unix(), b.CreationTime.Unix())
	require.Equal(t, a.State(), b.State())
	require.Equal(t, a.TapSibling(), b.TapSibling())
	require.Equal(t, a.BatchKey, b.BatchKey)
	require.Equal(t, a.Seedlings, b.Seedlings)
	assertPsbtEqual(
		t, &a.GenesisPacket.FundedPsbt, &b.GenesisPacket.FundedPsbt,
	)
	require.Equal(t, a.RootAssetCommitment, b.RootAssetCommitment)
}

func assertSeedlingBatchLen(t *testing.T, batches []*tapgarden.MintingBatch,
	numBatches, numSeedlings int) {

	require.Len(t, batches, numBatches)
	if numBatches == 0 {
		return
	}
	require.Len(t, batches[0].Seedlings, numSeedlings)
}

// assertGroupEqual asserts that two asset groups are equal when ignoring the
// group signatures. Signatures are not returned by queries under the GroupStore
// interface so we need more permissive equality checking.
func assertGroupEqual(t *testing.T, a, b *asset.AssetGroup) {
	require.Equal(t, a.Genesis, b.Genesis)
	require.Equal(t, a.GroupKey.RawKey, b.GroupKey.RawKey)
	require.Equal(t, a.GroupKey.GroupPubKey, b.GroupKey.GroupPubKey)
}

// storeGroupGenesis generates a group genesis asset and inserts it into the DB.
// The group genesis asset information needs to be in the DB before reissuance.
func storeGroupGenesis(t *testing.T, ctx context.Context, initGen asset.Genesis,
	currentGen *asset.Genesis, store *AssetMintingStore,
	privDesc keychain.KeyDescriptor,
	groupPriv *btcec.PrivateKey) (uint64, *btcec.PrivateKey,
	*asset.AssetGroup) {

	// Generate the signature for our group genesis asset.
	genSigner := asset.NewMockGenesisSigner(groupPriv)
	genTxBuilder := asset.MockGroupTxBuilder{}

	// Select the correct genesis for the new asset.
	assetGen := initGen
	if currentGen != nil {
		assetGen = *currentGen
	}
	genProtoAsset := asset.RandAssetWithValues(
		t, assetGen, nil, asset.RandScriptKey(t),
	)
	groupReq := asset.NewGroupKeyRequestNoErr(
		t, privDesc, fn.None[asset.ExternalKey](), initGen,
		genProtoAsset, nil, fn.None[chainhash.Hash](),
	)
	genTx, err := groupReq.BuildGroupVirtualTx(&genTxBuilder)
	require.NoError(t, err)

	groupKey, err := asset.DeriveGroupKey(genSigner, *genTx, *groupReq, nil)
	require.NoError(t, err)

	initialAsset := asset.RandAssetWithValues(
		t, assetGen, groupKey, asset.RandScriptKey(t),
	)

	// Insert the group genesis asset, which will also insert the group key
	// and genesis info needed for reissuance.
	upsertAsset := func(q PendingAssetStore) error {
		_, err = maybeUpsertAssetMeta(ctx, q, &assetGen, nil)
		require.NoError(t, err)

		// Insert a random managed UTXO.
		utxoID := addRandomManagedUTXO(t, ctx, q, initialAsset)

		_, _, err = upsertAssetsWithGenesis(
			ctx, q, assetGen.FirstPrevOut,
			[]*asset.Asset{initialAsset},
			[]sql.NullInt64{sqlInt64(utxoID)},
		)
		require.NoError(t, err)
		return nil
	}

	var writeTxOpts AssetStoreTxOptions
	err = store.db.ExecTx(ctx, &writeTxOpts, upsertAsset)
	require.NoError(t, err)

	return initialAsset.Amount, groupPriv, &asset.AssetGroup{
		Genesis:  &assetGen,
		GroupKey: groupKey,
	}
}

// addRandomManagedUTXO is a helper function that will create a random managed
// UTXO for a given asset.
func addRandomManagedUTXO(t *testing.T, ctx context.Context,
	db PendingAssetStore, asset *asset.Asset) int64 {

	// Create the taproot asset root for the given asset.
	assetRoot, err := commitment.NewAssetCommitment(asset)
	require.NoError(t, err)

	commitVersion := test.RandFlip(nil, fn.Ptr(commitment.TapCommitmentV2))
	taprootAssetCommitment, err := commitment.NewTapCommitment(
		commitVersion, assetRoot,
	)
	taprootAssetRoot := taprootAssetCommitment.TapscriptRoot(nil)
	require.NoError(t, err)

	// Create an anchor transaction.
	var blockHash chainhash.Hash
	_, err = rand.Read(blockHash[:])
	require.NoError(t, err)

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    10,
	})

	// We'll add the chain transaction to the database
	var anchorTxBuf bytes.Buffer
	err = anchorTx.Serialize(&anchorTxBuf)
	require.NoError(t, err)
	anchorTXID := anchorTx.TxHash()
	chainTXID, err := db.UpsertChainTx(ctx, ChainTxParams{
		Txid:        anchorTXID[:],
		RawTx:       anchorTxBuf.Bytes(),
		BlockHeight: sqlInt32(20),
		BlockHash:   blockHash[:],
		TxIndex:     sqlInt32(0),
	})
	require.NoError(t, err, "unable to insert chain tx: %w", err)

	anchorPoint := wire.OutPoint{
		Hash:  anchorTx.TxHash(),
		Index: 0,
	}
	outpointBytes, err := encodeOutpoint(anchorPoint)
	require.NoError(t, err)

	randPubKey := test.RandPubKey(t)

	// Insert an internal key.
	_, err = db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    randPubKey.SerializeCompressed(),
		KeyFamily: 1,
		KeyIndex:  2,
	})
	require.NoError(t, err)

	// Insert the managed UTXO.
	managedUTXO := RawManagedUTXO{
		RawKey:           randPubKey.SerializeCompressed(),
		Outpoint:         outpointBytes,
		AmtSats:          10,
		TaprootAssetRoot: taprootAssetRoot[:],
		RootVersion: sql.NullInt16{
			Int16: int16(1),
			Valid: true,
		},
		MerkleRoot:       taprootAssetRoot[:],
		TapscriptSibling: []byte{},
		TxnID:            chainTXID,
	}
	utxoID, err := db.UpsertManagedUTXO(ctx, managedUTXO)
	require.NoError(t, err)

	return utxoID
}

// treeFromLeaves generates a tapscript tree in multiple forms from a list of
// tapscript leaves.
func treeFromLeaves(t *testing.T, leaves []txscript.TapLeaf) (chainhash.Hash,
	asset.TapscriptTreeNodes, [][]byte) {

	tree, err := asset.TapTreeNodesFromLeaves(leaves)
	require.NoError(t, err)

	checkedLeaves := asset.GetLeaves(*tree).UnwrapToPtr()
	require.NotNil(t, checkedLeaves)

	treeBytes, err := asset.EncodeTapLeafNodes(*checkedLeaves)
	require.NoError(t, err)

	return asset.LeafNodesRootHash(*checkedLeaves), *tree, treeBytes
}

// treeFromBranch generates a tapscript tree in multiple forms from a set of
// byte slices.
func treeFromBranch(t *testing.T, children [][]byte) (chainhash.Hash,
	asset.TapscriptTreeNodes, [][]byte) {

	branch, err := asset.DecodeTapBranchNodes(children)
	require.NoError(t, err)

	tree := asset.FromBranch(*branch)
	treeBytes := asset.EncodeTapBranchNodes(*branch)

	return asset.BranchNodesRootHash(*branch), tree, treeBytes
}

// storeTapscriptTreeWrapper wraps a DB transaction that stores a tapscript
// tree.
func storeTapscriptTreeWrapper(ctx context.Context, isBranch bool,
	store *AssetMintingStore, rootHash []byte, nodes [][]byte) error {

	var writeTxOpts AssetStoreTxOptions
	return store.db.ExecTx(ctx, &writeTxOpts,
		func(q PendingAssetStore) error {
			return upsertTapscriptTree(
				ctx, q, rootHash, isBranch, nodes,
			)
		})
}

// fetchTapscriptTreeWrapper wraps a DB transaction that fetches a tapscript
// tree.
func fetchTapscriptTreeWrapper(ctx context.Context, rootHash []byte,
	store *AssetMintingStore) ([]TapscriptTreeNode, error) {

	var (
		dbTreeNodes []TapscriptTreeNode
		err         error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := store.db.ExecTx(ctx, &readOpts,
		func(q PendingAssetStore) error {
			dbTreeNodes, err = q.FetchTapscriptTree(ctx, rootHash)
			return err
		})

	return dbTreeNodes, dbErr
}

// deleteTapscriptTreeWrapper wraps a DB transaction that deletes a tapscript
// tree.
func deleteTapscriptTreeWrapper(ctx context.Context, rootHash []byte,
	store *AssetMintingStore) error {

	var writeTxOpts AssetStoreTxOptions
	return store.db.ExecTx(ctx, &writeTxOpts,
		func(q PendingAssetStore) error {
			return deleteTapscriptTree(ctx, q, rootHash[:])
		})
}

// assertTreeDeletion asserts that a tapscript tree has been deleted properly.
func assertTreeDeletion(t *testing.T, ctx context.Context, rootHash []byte,
	store *AssetMintingStore) {

	dbTree, err := fetchTapscriptTreeWrapper(ctx, rootHash, store)
	require.NoError(t, err)
	require.Empty(t, dbTree)
}

// assertStoredTreeEqual asserts that the tapscript tree fetched with a root
// hash matches the expected bytes.
func assertStoredTreeEqual(t *testing.T, ctx context.Context, isBranch bool,
	store *AssetMintingStore, rootHash []byte, expected [][]byte) {

	dbTree, err := fetchTapscriptTreeWrapper(ctx, rootHash, store)
	require.NoError(t, err)

	require.True(t, fn.All(dbTree, func(node TapscriptTreeNode) bool {
		return node.BranchOnly == isBranch
	}))
	dbTreeBytes := fn.Map(dbTree, func(node TapscriptTreeNode) []byte {
		return node.RawNode
	})
	require.Equal(t, expected, dbTreeBytes)
}

// storeTapscriptTreeChecked asserts that we can store a tapscript tree, and
// that the root hash returned matches the one calculated from the tree.
func storeTapscriptTreeChecked(t *testing.T, ctx context.Context,
	store *AssetMintingStore, tree asset.TapscriptTreeNodes,
	hash chainhash.Hash) {

	dbRootHash, err := store.StoreTapscriptTree(ctx, tree)
	require.NoError(t, err)
	require.True(t, hash.IsEqual(dbRootHash))
}

// loadTapscriptTreeChecked asserts that we can load a tapscript tree, and that
// the tapscript tree returned matches the initial tree.
func loadTapscriptTreeChecked(t *testing.T, ctx context.Context,
	store *AssetMintingStore, tree asset.TapscriptTreeNodes,
	hash chainhash.Hash) {

	dbTree, err := store.LoadTapscriptTree(ctx, hash)
	require.NoError(t, err)
	require.NotNil(t, dbTree)
	require.Equal(t, tree, *dbTree)
}

// deleteTapscriptTreeChecked asserts that we can delete a tapscript tree, and
// that future attempts to load the deleted tree return the expected error.
func deleteTapscriptTreeChecked(t *testing.T, ctx context.Context,
	store *AssetMintingStore, hash chainhash.Hash) {

	err := store.DeleteTapscriptTree(ctx, hash)
	require.NoError(t, err)

	dbTree, err := store.LoadTapscriptTree(ctx, hash)
	require.Empty(t, dbTree)
	require.ErrorIs(t, err, asset.ErrTreeNotFound)
}

// addRandGroupToBatch selects a random seedling, generates an asset genesis to
// match that seedling, and stores that genesis so that the seedling can be
// minted into an existing group. The seedling is updated with the group key
// and mapped to the key needed to sign for the reissuance.
func addRandGroupToBatch(t *testing.T, store *AssetMintingStore,
	ctx context.Context, seedlings map[string]*tapgarden.Seedling) (uint64,
	map[string]*btcec.PrivateKey, *asset.AssetGroup) {

	// Pick a random seedling.
	randIndex := rand.Int31n(int32(len(seedlings)))
	randAssetName := maps.Keys(seedlings)[randIndex]
	randAssetType := seedlings[randAssetName].AssetType

	// Generate a random genesis and group to use as a group anchor
	// for this seedling.
	privDesc, groupPriv := test.RandKeyDesc(t)
	randGenesis := asset.RandGenesis(t, randAssetType)
	genesisAmt, groupPriv, group := storeGroupGenesis(
		t, ctx, randGenesis, nil, store, privDesc, groupPriv,
	)

	// Modify the seedling to specify membership in an existing group.
	// Unset the group signature since seedlings will not have one
	// when fetched.
	targetSeedling := seedlings[randAssetName]
	targetSeedling.EnableEmission = false
	targetSeedling.GroupInfo = group
	targetSeedling.GroupInfo.GroupKey.Witness = nil

	// Associate the asset name and group private key so that a new group
	// signature can be made for the selected seedling.
	seedlingGroups := map[string]*btcec.PrivateKey{randAssetName: groupPriv}

	return genesisAmt, seedlingGroups, group
}

// addRandSiblingToBatch generates a random hash and adds it to the given batch.
func addRandSiblingToBatch(t *testing.T, batch *tapgarden.MintingBatch) (
	commitment.TapscriptPreimage, chainhash.Hash) {

	tapSiblingSingleLeaf := test.RandTapLeaf(nil)
	siblingPreimage, err := commitment.NewPreimageFromLeaf(
		tapSiblingSingleLeaf,
	)
	require.NoError(t, err)
	tapSibling, err := siblingPreimage.TapHash()
	require.NoError(t, err)
	batch.UpdateTapSibling(tapSibling)

	return *siblingPreimage, *tapSibling
}

// addMultiAssetGroupToBatch selects a random seedling pair, where neither
// seedling is being issued into an existing group, and creates a multi-asset
// group. Specifically, one seedling will have emission enabled, and the other
// seedling will reference the first seedling as its group anchor.
func addMultiAssetGroupToBatch(seedlings map[string]*tapgarden.Seedling) (
	string, string) {

	seedlingNames := maps.Keys(seedlings)
	seedlingCount := len(seedlingNames)
	var anchorSeedling, groupedSeedling *tapgarden.Seedling

	// We want to find two spots in the random seedling list, where neither
	// seedling was modified to be minted into an existing group.
	for {
		randIndex := rand.Int31n(int32(seedlingCount))
		anchorSeedling = seedlings[seedlingNames[randIndex]]
		if anchorSeedling.GroupInfo != nil {
			continue
		}

		secondInd := (randIndex + 1) % int32(seedlingCount)
		groupedSeedling = seedlings[seedlingNames[secondInd]]
		if groupedSeedling.GroupInfo != nil {
			continue
		}

		break
	}

	// The anchor asset must have emission enabled, and the second asset
	// must specify the first as its group anchor.
	anchorSeedling.EnableEmission = true
	anchorSeedling.GroupTapscriptRoot = test.RandBytes(32)
	groupedSeedling.AssetType = anchorSeedling.AssetType
	groupedSeedling.EnableEmission = false
	groupedSeedling.GroupAnchor = &anchorSeedling.AssetName

	return anchorSeedling.AssetName, groupedSeedling.AssetName
}

// TestCommitMintingBatchSeedlings tests that we're able to properly write and
// read a base minting batch on disk. This test covers the state when a batch
// only has seedlings, without any fully formed assets.
func TestCommitMintingBatchSeedlings(t *testing.T) {
	t.Parallel()

	assetStore, _, _ := newAssetStore(t)

	ctx := context.Background()
	const numSeedlings = 5

	// First, we'll write a new minting batch to disk, including an
	// internal key and a set of seedlings. One random seedling will
	// be a reissuance into a specific group.
	mintingBatch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(numSeedlings),
	)
	_, randGroup, _ := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)
	_, randSiblingHash := addRandSiblingToBatch(t, mintingBatch)
	err := assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err)

	batchKey := mintingBatch.BatchKey.PubKey

	// With the batch written, we should be able to read out the batch, and
	// have it be exactly the same as what we wrote.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings)
	require.NotNil(t, mintingBatches[0].GenesisPacket)
	assertBatchEqual(t, mintingBatch, mintingBatches[0])
	assertBatchSibling(t, mintingBatch, randSiblingHash)

	mintingBatchKeyed, err := assetStore.FetchMintingBatch(ctx, batchKey)
	require.NoError(t, err)
	assertBatchEqual(t, mintingBatch, mintingBatchKeyed)

	// The batch should also still be in the pending state.
	assertBatchState(t, mintingBatches[0], tapgarden.BatchStatePending)

	// Now we'll add an additional set of seedlings.
	seedlings := tapgarden.RandSeedlings(t, numSeedlings)

	// Pick a random seedling and give it a specific group.
	_, secondGroup, _ := addRandGroupToBatch(t, assetStore, ctx, seedlings)
	mintingBatch.Seedlings = mergeMap(mintingBatch.Seedlings, seedlings)
	require.NoError(t, assetStore.AddSeedlingsToBatch(
		ctx, batchKey, maps.Values(seedlings)...,
	))

	// If we read the batch from disk again, then we should have 10 total
	// seedlings, and the batch still matches what we wrote to disk.
	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings*2)
	assertBatchEqual(t, mintingBatches[0], mintingBatch)

	// Finally update the state of the batch, and asset that when we read
	// it from disk again, it has transitioned to being frozen.
	require.NoError(t, assetStore.UpdateBatchState(
		ctx, batchKey, tapgarden.BatchStateFrozen,
	))

	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings*2)
	assertBatchState(t, mintingBatches[0], tapgarden.BatchStateFrozen)

	// If we finalize the batch, then the next query to
	// FetchNonFinalBatches should return zero batches.
	require.NoError(t, assetStore.UpdateBatchState(
		ctx, batchKey, tapgarden.BatchStateFinalized,
	))
	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 0, 0)

	// Insert the batch seedlings as assets before fetching the finalized
	// batch. This test won't check if these were stored correctly, but
	// batches cannot be finalized without any sprouted assets.
	genesisPacket := mintingBatch.GenesisPacket
	randGroup = mergeMap(randGroup, secondGroup)
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, randGroup,
	)
	genesisScript, err := tapscript.PayToAddrScript(
		*batchKey, &randSiblingHash, *assetRoot,
	)
	require.NoError(t, err)

	genesisPacket.Pkt.UnsignedTx.TxOut[0].PkScript = genesisScript

	// Adding sprouts updates the batch state to committed, so we'll set it
	// back to finalized.
	require.NoError(t, assetStore.AddSproutsToBatch(
		ctx, batchKey, genesisPacket, assetRoot,
	))
	require.NoError(t, assetStore.UpdateBatchState(
		ctx, batchKey, tapgarden.BatchStateFinalized,
	))

	// We should still be able to fetch the finalized batch from disk.
	mintingBatchKeyed, err = assetStore.FetchMintingBatch(ctx, batchKey)
	require.NoError(t, err)
	require.NotNil(t, mintingBatchKeyed)
	assertBatchState(t, mintingBatchKeyed, tapgarden.BatchStateFinalized)

	// We should not be able to fetch a non-existent batch.
	badBatchKeyBytes := batchKey.SerializeCompressed()
	badBatchKeyBytes[0] ^= 0x01
	badBatchKey, err := btcec.ParsePubKey(badBatchKeyBytes)
	require.NoError(t, err)
	emptyBatch, err := assetStore.FetchMintingBatch(ctx, badBatchKey)
	require.Nil(t, emptyBatch)
	require.ErrorContains(t, err, "no batch with key")

	// Insert another normal batch into the database. We should get this
	// batch back if we query for the set of non-final batches.
	mintingBatch = tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(numSeedlings),
	)
	err = assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err)
	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings)
}

// seedlingsToAssetRoot maps a set of seedlings to an asset root.
//
// TODO(roasbeef): same func in tapgarden can just re-use?
func seedlingsToAssetRoot(t *testing.T, genesisPoint wire.OutPoint,
	seedlings map[string]*tapgarden.Seedling,
	groupKeys map[string]*btcec.PrivateKey) *commitment.TapCommitment {

	orderedSeedlings := tapgarden.SortSeedlings(maps.Values(seedlings))
	assetRoots := make([]*commitment.AssetCommitment, 0, len(seedlings))
	newGroupPrivs := make(map[string]*btcec.PrivateKey)
	newGroupInfo := make(map[string]*asset.AssetGroup)

	for _, seedlingName := range orderedSeedlings {
		seedling := seedlings[seedlingName]

		assetGen := asset.Genesis{
			FirstPrevOut: genesisPoint,
			Tag:          seedling.AssetName,
			OutputIndex:  0,
			Type:         seedling.AssetType,
		}

		if seedling.Meta != nil {
			assetGen.MetaHash = seedling.Meta.MetaHash()
		}

		var (
			genTxBuilder = tapscript.GroupTxBuilder{}
			groupPriv    *btcec.PrivateKey
			groupKey     *asset.GroupKey
			groupInfo    *asset.AssetGroup
			protoAsset   *asset.Asset
			amount       uint64
			ok           bool
			err          error
		)

		switch seedling.AssetType {
		case asset.Normal:
			amount = seedling.Amount
		case asset.Collectible:
			amount = 1
		}

		if seedling.HasGroupKey() {
			groupPriv, ok = groupKeys[seedling.AssetName]
			require.True(t, ok)
			groupInfo = seedling.GroupInfo
		}

		if seedling.GroupAnchor != nil {
			groupPriv, ok = newGroupPrivs[*seedling.GroupAnchor]
			require.True(t, ok)
			groupInfo, ok = newGroupInfo[*seedling.GroupAnchor]
			require.True(t, ok)
		}

		if groupInfo != nil || seedling.EnableEmission {
			protoAsset, err = asset.New(
				assetGen, amount, 0, 0, seedling.ScriptKey, nil,
			)
			require.NoError(t, err)
		}

		if groupInfo != nil {
			groupReq := asset.NewGroupKeyRequestNoErr(
				t, groupInfo.GroupKey.RawKey,
				fn.None[asset.ExternalKey](),
				*groupInfo.Genesis, protoAsset,
				groupInfo.GroupKey.TapscriptRoot,
				fn.None[chainhash.Hash](),
			)
			genTx, err := groupReq.BuildGroupVirtualTx(
				&genTxBuilder,
			)
			require.NoError(t, err)

			groupKey, err = asset.DeriveGroupKey(
				asset.NewMockGenesisSigner(groupPriv),
				*genTx, *groupReq, nil,
			)
			require.NoError(t, err)
		}

		if seedling.EnableEmission {
			groupKeyRaw, newGroupPriv := test.RandKeyDesc(t)
			genSigner := asset.NewMockGenesisSigner(newGroupPriv)
			groupReq := asset.NewGroupKeyRequestNoErr(
				t, groupKeyRaw, fn.None[asset.ExternalKey](),
				assetGen, protoAsset,
				seedling.GroupTapscriptRoot,
				fn.None[chainhash.Hash](),
			)
			genTx, err := groupReq.BuildGroupVirtualTx(
				&genTxBuilder,
			)
			require.NoError(t, err)

			groupKey, err = asset.DeriveGroupKey(
				genSigner, *genTx, *groupReq, nil,
			)
			require.NoError(t, err)
			newGroupPrivs[seedling.AssetName] = newGroupPriv
			newGroupInfo[seedling.AssetName] = &asset.AssetGroup{
				Genesis:  &assetGen,
				GroupKey: groupKey,
			}
		}

		require.NoError(t, err)

		newAsset, err := asset.New(
			assetGen, amount, 0, 0, seedling.ScriptKey, groupKey,
			asset.WithAssetVersion(seedling.AssetVersion),
		)
		require.NoError(t, err)

		// Finally, make a new asset commitment (the inner SMT tree) for
		// this newly created asset.
		assetRoot, err := commitment.NewAssetCommitment(newAsset)
		require.NoError(t, err)

		assetRoots = append(assetRoots, assetRoot)
	}

	tapCommitment, err := commitment.NewTapCommitment(nil, assetRoots...)
	require.NoError(t, err)

	return tapCommitment
}

func assertPsbtEqual(t *testing.T, a, b *tapsend.FundedPsbt) {
	require.Equal(t, a.ChangeOutputIndex, b.ChangeOutputIndex)
	require.Equal(t, a.ChainFees, b.ChainFees)
	require.Equal(t, a.LockedUTXOs, b.LockedUTXOs)

	var aBuf, bBuf bytes.Buffer

	err := a.Pkt.Serialize(&aBuf)
	require.NoError(t, err)

	err = b.Pkt.Serialize(&bBuf)
	require.NoError(t, err)

	require.Equal(t, aBuf.Bytes(), bBuf.Bytes())
}

func assertAssetsEqual(t *testing.T, a, b *commitment.TapCommitment) {
	// The CommittedAssets() returns values from a map, which means that
	// order isn't guaranteed. As a result, we can't just use require.Equal
	// on the entire thing. To get around this, we use a good ol' double
	// for-loop to compare the values that should match up.
	var numFound int
	memAssets := a.CommittedAssets()
	dbAssets := b.CommittedAssets()
	for _, memAsset := range memAssets {
		for _, dbAsset := range dbAssets {
			if memAsset.Genesis.Tag == dbAsset.Genesis.Tag {
				require.Equal(t, memAsset, dbAsset)
				numFound++
				break
			}
		}
	}

	require.Equal(t, numFound, len(memAssets))

	// Finally, we should get the exact same tapscript commitment with both
	// versions.
	require.Equal(t, a.TapscriptRoot(nil), b.TapscriptRoot(nil))
}

// TestAddSproutsToBatch tests that if we add some sprouts (actual assets) to
// a batch, then we'll be able to read them out again will all the values
// populated.
func TestAddSproutsToBatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const numSeedlings = 5
	assetStore, _, _ := newAssetStore(t)

	// First, we'll create a new batch, then add some sample seedlings.
	// One random seedling will be a reissuance into a specific group.
	mintingBatch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(numSeedlings),
	)
	_, seedlingGroups, _ := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)

	// Modify a random seedling to not actually have a meta reveal. This
	// lets us test the logic that detects if an asset doesn't actually
	// have an asset meta reveal.
	for k := range mintingBatch.Seedlings {
		mintingBatch.Seedlings[k].Meta = nil
		break
	}

	// First, we'll create a new batch, then add some sample seedlings.
	require.NoError(t, assetStore.CommitMintingBatch(ctx, mintingBatch))

	batchKey := mintingBatch.BatchKey.PubKey

	// Now that the batch is on disk, we'll map those seedlings to an
	// actual asset commitment, then insert them into the DB as sprouts.
	genesisPacket := mintingBatch.GenesisPacket
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, seedlingGroups,
	)

	// Update the pkScript of the anchor output in the genesis packet to
	// make sure the validation doesn't fail when reading the batch from the
	// DB again.
	anchorOutputIndex := uint32(0)
	if mintingBatch.GenesisPacket.ChangeOutputIndex == 0 {
		anchorOutputIndex = 1
	}

	script, err := tapscript.PayToAddrScript(
		*mintingBatch.BatchKey.PubKey, nil, *assetRoot,
	)
	require.NoError(t, err)
	genesisPacket.Pkt.UnsignedTx.TxOut[anchorOutputIndex].PkScript = script

	require.NoError(t, assetStore.AddSproutsToBatch(
		ctx, batchKey, genesisPacket, assetRoot,
	))

	// Now we'll query for that same batch, and assert that the set of
	// assets we just inserted into the database matches up.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)

	// We should have no seedlings in this batch, since we added sprouts
	// above. We also expect that the batch is in the BatchStateCommitted
	// state.
	assertSeedlingBatchLen(t, mintingBatches, 1, 0)
	assertBatchState(t, mintingBatches[0], tapgarden.BatchStateCommitted)
	assertPsbtEqual(
		t, &genesisPacket.FundedPsbt,
		&mintingBatches[0].GenesisPacket.FundedPsbt,
	)
	assertAssetsEqual(t, assetRoot, mintingBatches[0].RootAssetCommitment)

	// We also expect that for each of the assets we created above, we're
	// able to obtain the asset meta for them all.
	require.Len(t, mintingBatches[0].AssetMetas, numSeedlings)

	// The number of assets in the batch should match the seedlings we
	// inserted.
	allAssets := mintingBatches[0].RootAssetCommitment.CommittedAssets()
	require.Equal(t, numSeedlings, len(allAssets))

	// For each inserted asset, the asset version should match the
	// corresponding seedling.
	require.True(t, fn.All(allAssets, func(a *asset.Asset) bool {
		seedling, ok := mintingBatch.Seedlings[a.Genesis.Tag]
		if !ok {
			// We should find the seedlings.
			return false
		}

		return a.Version == seedling.AssetVersion
	}))
}

type randAssetCtx struct {
	batchKey        *btcec.PublicKey
	groupKey        *btcec.PublicKey
	groupGenAmt     uint64
	genesisPkt      *tapsend.FundedPsbt
	assetRoot       *commitment.TapCommitment
	merkleRoot      []byte
	scriptRoot      []byte
	tapSiblingBytes []byte
	tapSiblingHash  chainhash.Hash
	mintingBatch    *tapgarden.MintingBatch
	groupGenesis    *asset.Genesis
}

func addRandAssets(t *testing.T, ctx context.Context,
	assetStore *AssetMintingStore, numAssets int) randAssetCtx {

	mintingBatch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(numAssets),
	)
	genAmt, seedlingGroups, group := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)
	randSibling, randSiblingHash := addRandSiblingToBatch(t, mintingBatch)
	batchKey := mintingBatch.BatchKey.PubKey
	require.NoError(t, assetStore.CommitMintingBatch(ctx, mintingBatch))

	genesisPacket := mintingBatch.GenesisPacket
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, seedlingGroups,
	)

	// Update the pkScript of the anchor output in the genesis packet to
	// make sure the validation doesn't fail when reading the batch from the
	// DB again.
	anchorOutputIndex := uint32(0)
	if mintingBatch.GenesisPacket.ChangeOutputIndex == 0 {
		anchorOutputIndex = 1
	}

	mintingBatch.RootAssetCommitment = assetRoot
	mintingOutputKey, _, err := mintingBatch.MintingOutputKey(&randSibling)
	require.NoError(t, err)

	script, err := txscript.PayToTaprootScript(mintingOutputKey)
	require.NoError(t, err)

	genesisPacket.Pkt.UnsignedTx.TxOut[anchorOutputIndex].PkScript = script

	require.NoError(t, assetStore.AddSproutsToBatch(
		ctx, batchKey, genesisPacket, assetRoot,
	))

	merkleRoot := assetRoot.TapscriptRoot(&randSiblingHash)
	scriptRoot := assetRoot.TapscriptRoot(nil)
	siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		&randSibling,
	)
	require.NoError(t, err)

	return randAssetCtx{
		batchKey:        batchKey,
		groupKey:        &group.GroupKey.GroupPubKey,
		groupGenAmt:     genAmt,
		genesisPkt:      &genesisPacket.FundedPsbt,
		assetRoot:       assetRoot,
		merkleRoot:      merkleRoot[:],
		scriptRoot:      scriptRoot[:],
		tapSiblingBytes: siblingBytes,
		tapSiblingHash:  randSiblingHash,
		mintingBatch:    mintingBatch,
		groupGenesis:    group.Genesis,
	}
}

// TestCommitBatchChainActions tests that we're able to properly write a signed
// genesis transaction to disk, update all dependent tables along the way, and
// also transition the batch to the BatchStateBroadcast state. Finally we test
// that if we mark the batch as confirmed on chain, then the confirmed
// transaction is updated accordingly.
func TestCommitBatchChainActions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const numSeedlings = 5
	assetStore, confAssets, db := newAssetStore(t)

	// First, we'll create a new batch, then add some sample seedlings, and
	// then those seedlings as assets.
	randAssetCtx := addRandAssets(t, ctx, assetStore, numSeedlings)

	// The packet needs to be finalized, so we'll insert a fake
	// FinalScriptSig. The FinalScriptSig doesn't need to be well formed,
	// so we get by w/ this.
	//
	// TODO(roasbeef): move the tx extraction up one layer?
	randAssetCtx.genesisPkt.Pkt.Inputs[0].FinalScriptSig = []byte{}

	// With our assets inserted, we'll now commit the signed genesis packet
	// to disk, along with the Taproot Asset script root that's stored
	// alongside any managed UTXOs.
	require.NoError(t, assetStore.CommitSignedGenesisTx(
		ctx, randAssetCtx.batchKey, randAssetCtx.genesisPkt, 0,
		randAssetCtx.merkleRoot, randAssetCtx.scriptRoot,
		randAssetCtx.tapSiblingBytes,
	))

	// The batch updated above should be found, with the batch state
	// updated, and also the genesis transaction updated to match what we
	// "signed" above.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertBatchState(
		t, mintingBatches[0], tapgarden.BatchStateBroadcast,
	)
	assertPsbtEqual(
		t, randAssetCtx.genesisPkt,
		&mintingBatches[0].GenesisPacket.FundedPsbt,
	)
	assertBatchSibling(t, mintingBatches[0], randAssetCtx.tapSiblingHash)

	var rawTxBytes bytes.Buffer
	rawGenTx, err := psbt.Extract(randAssetCtx.genesisPkt.Pkt)
	require.NoError(t, err)
	require.NoError(t, rawGenTx.Serialize(&rawTxBytes))

	// Next, we'll verify that we're able to query for the chain
	// transaction we just inserted above.
	//
	// The chain TXID returned should match the transaction above.
	genTXID := rawGenTx.TxHash()
	dbGenTx, err := db.FetchChainTx(ctx, genTXID[:])
	require.NoError(t, err)
	require.Equal(t, genTXID[:], dbGenTx.Txid[:])
	require.Equal(t, rawTxBytes.Bytes(), dbGenTx.RawTx)
	require.Equal(t, randAssetCtx.genesisPkt.ChainFees, dbGenTx.ChainFees)

	// Now that we have the primary key for the chain transaction inserted
	// above, we'll use that to confirm that the managed UTXO has been
	// updated accordingly.
	managedUTXO, err := db.FetchManagedUTXO(ctx, sqlc.FetchManagedUTXOParams{
		TxnID: sqlInt64(dbGenTx.TxnID),
	})
	require.NoError(t, err)
	require.Equal(t, randAssetCtx.merkleRoot, managedUTXO.MerkleRoot)
	require.Equal(t, randAssetCtx.scriptRoot, managedUTXO.TaprootAssetRoot)
	require.Equal(
		t, randAssetCtx.tapSiblingBytes, managedUTXO.TapscriptSibling,
	)

	// Next, we'll confirm that all the assets inserted previously now are
	// able to be queried according to the anchor UTXO primary key.
	anchoredAssets, err := db.FetchAssetsByAnchorTx(
		ctx, sqlInt64(managedUTXO.UtxoID),
	)
	require.NoError(t, err)
	require.Equal(t, numSeedlings, len(anchoredAssets))

	// Finally, we'll verify that the genesis point also points to the
	// inserted chain transaction.
	_, err = db.FetchGenesisPointByAnchorTx(ctx, sqlInt64(dbGenTx.TxnID))
	require.NoError(t, err)

	// For each asset created above, we'll make a fake proof file for it.
	assetProofs := make(proof.AssetBlobs)
	for _, a := range randAssetCtx.assetRoot.CommittedAssets() {
		blob := make([]byte, 100)
		_, err := rand.Read(blob[:])
		require.NoError(t, err)

		assetProofs[asset.ToSerialized(a.ScriptKey.PubKey)] = blob
	}

	// We'll now conclude the lifetime of a batch by marking it confirmed
	// on disk, while also committing all the relevant asset proof files.
	fakeBlockHash := chainhash.Hash(sha256.Sum256([]byte("fake")))
	blockHeight := uint32(20)
	txIndex := uint32(5)
	require.NoError(t, assetStore.MarkBatchConfirmed(
		ctx, randAssetCtx.batchKey, &fakeBlockHash, blockHeight,
		txIndex, assetProofs,
	))

	// We'll now fetch the chain transaction again, to confirm that all the
	// field have been properly updated.
	dbGenTx, err = db.FetchChainTx(ctx, genTXID[:])
	require.NoError(t, err)
	require.Equal(t, fakeBlockHash[:], dbGenTx.BlockHash[:])
	require.Equal(
		t, blockHeight, extractSqlInt32[uint32](dbGenTx.BlockHeight),
	)
	require.Equal(t, txIndex, extractSqlInt32[uint32](dbGenTx.TxIndex))

	// If we query for the set of all active assets, then we should get back
	// the number of seedlings AND also the genesis asset we have created
	// with `addRandAssets`.
	//
	// TODO(roasbeef): move into isolated test
	assets, err := confAssets.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)
	require.Equal(t, numSeedlings+1, len(assets))

	// Count the number of assets with a group key. Each grouped asset
	// should have a grouped genesis witness.
	groupCount := fn.Count(assets, func(a *asset.ChainAsset) bool {
		return a.GroupKey != nil
	})
	groupWitnessCount := fn.Count(assets, func(a *asset.ChainAsset) bool {
		return a.HasGenesisWitnessForGroup()
	})
	require.Equal(t, groupCount, groupWitnessCount)

	// All the assets returned should have the genesis prev ID set up.
	ungroupedCount := len(assets) - groupCount
	genesisWitnessCount := fn.Count(assets, func(a *asset.ChainAsset) bool {
		return a.HasGenesisWitness()
	})
	require.Equal(t, ungroupedCount, genesisWitnessCount)

	// All the assets should also have a matching asset version as the
	// seedlings we created.
	mintingBatch := randAssetCtx.mintingBatch
	randomGenesisTag := randAssetCtx.groupGenesis.Tag
	require.True(t, fn.All(assets, func(dbAsset *asset.ChainAsset) bool {
		seedling, ok := mintingBatch.Seedlings[dbAsset.Genesis.Tag]
		if !ok {
			// The only asset that doesn't have a seedling is the
			// random genesis asset created by `addRandAssets`
			if dbAsset.Genesis.Tag == randomGenesisTag {
				return true
			}
			t.Logf("seedling for %v not found",
				dbAsset.Genesis.Tag)
			return ok
		}

		if seedling.AssetVersion != dbAsset.Version {
			t.Logf("asset version mismatch for %v: expected %v, "+
				"got %v", dbAsset.Genesis.Tag,
				seedling.AssetVersion, dbAsset.Version)
			return false
		}

		return true
	}))

	// Now that the batch has been committed on disk, we should be able to
	// obtain all the proofs we just committed.
	diskProofs, err := confAssets.FetchAssetProofs(ctx)
	require.NoError(t, err)
	require.Equal(t, assetProofs, diskProofs)

	// If we look up all the proofs by their specific script key, we should
	// get the same set of proofs.
	proofLocators := fMapKeys(
		assetProofs, func(k asset.SerializedKey) proof.Locator {
			parsedScriptKey, err := btcec.ParsePubKey(k.CopyBytes())
			require.NoError(t, err)

			return proof.Locator{
				ScriptKey: *parsedScriptKey,
			}
		},
	)
	diskProofs, err = confAssets.FetchAssetProofs(ctx, proofLocators...)
	require.NoError(t, err)
	require.Equal(t, assetProofs, diskProofs)

	mintedAssets := randAssetCtx.assetRoot.CommittedAssets()

	// We'll now query for the set of balances to ensure they all line up
	// with the assets we just created, including the group genesis asset.
	assetBalances, err := confAssets.QueryBalancesByAsset(ctx, nil, false)
	require.NoError(t, err)
	require.Equal(t, numSeedlings+1, len(assetBalances))

	for _, newAsset := range mintedAssets {
		assetBalance, ok := assetBalances[newAsset.ID()]
		require.True(t, ok)

		require.Equal(t, newAsset.Amount, assetBalance.Balance)
	}

	// We'll also now ensure that if we group by key group, then we're
	// also able to verify the correct balances.
	keyGroupSumReducer := func(count int, asset *asset.Asset) int {
		if asset.GroupKey != nil {
			return count + 1
		}

		return count
	}
	numKeyGroups := fn.Reduce(mintedAssets, keyGroupSumReducer)
	assetBalancesByGroup, err := confAssets.QueryAssetBalancesByGroup(
		ctx, nil, false,
	)
	require.NoError(t, err)
	require.Equal(t, numKeyGroups, len(assetBalancesByGroup))
	existingGroupKey := asset.ToSerialized(randAssetCtx.groupKey)

	for _, newAsset := range mintedAssets {
		if newAsset.GroupKey == nil {
			continue
		}

		groupKey := asset.ToSerialized(&newAsset.GroupKey.GroupPubKey)
		assetBalance, ok := assetBalancesByGroup[groupKey]
		require.True(t, ok)

		// One asset was minted into an existing group, so the value
		// of the group genesis asset must be deducted from the group
		// balance before comparing to the minted asset.
		if bytes.Equal(groupKey[:], existingGroupKey[:]) {
			assetBalance.Balance -= randAssetCtx.groupGenAmt
		}

		require.Equal(t, newAsset.Amount, assetBalance.Balance)
	}
}

// TestDuplicateGroupKey tests that if we attempt to insert a group key with
// the exact same tweaked key blob, then the noop UPSERT logic triggers, and we
// get the ID of that same key.
func TestDuplicateGroupKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// First, we'll open up a new asset store, we only need the raw DB
	// pointer, as we'll be doing some lower level access in this test.
	_, _, db := newAssetStore(t)

	// Now that we have the DB, we'll insert a new random internal key, and
	// then a key family linked to that internal key.
	keyDesc, _ := test.RandKeyDesc(t)
	rawKey := keyDesc.PubKey.SerializeCompressed()

	keyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    rawKey,
		KeyFamily: int32(keyDesc.Family),
		KeyIndex:  int32(keyDesc.Index),
	})
	require.NoError(t, err)

	// Before we can insert the group key, we also need to insert a valid
	// genesis point as well. We'll just use the key again as uniqueness is
	// what matters.
	genesisPointID, err := db.UpsertGenesisPoint(ctx, rawKey)
	require.NoError(t, err)

	// We'll just use the same group key here as it doesn't really matter
	// what it is. What matters is that it's unique.
	assetKey := AssetGroupKey{
		TweakedGroupKey: rawKey,
		TapscriptRoot:   test.RandBytes(32),
		InternalKeyID:   keyID,
		GenesisPointID:  genesisPointID,
	}
	groupID, err := db.UpsertAssetGroupKey(ctx, assetKey)
	require.NoError(t, err)

	// Now we'll try to insert that same key group again. We should get no
	// error, and the same groupID back.
	groupID2, err := db.UpsertAssetGroupKey(ctx, assetKey)
	require.NoError(t, err)
	require.Equal(t, groupID, groupID2)
}

// TestGroupStore tests all the queries exposed via the GroupStore interface,
// including fetching asset groups via genesis ID or group key.
func TestGroupStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// First, we'll open up a new asset store. We only need the mintingStore
	// pointer, as we're only testing the GroupStore functionality here.
	assetStore, _, _ := newAssetStore(t)

	// Now we generate and store one group of two assets, and
	// a collectible in its own group.
	privDesc1, groupPriv1 := test.RandKeyDesc(t)
	gen1 := asset.RandGenesis(t, asset.Normal)
	_, _, group1 := storeGroupGenesis(
		t, ctx, gen1, nil, assetStore, privDesc1, groupPriv1,
	)
	privDesc2, groupPriv2 := test.RandKeyDesc(t)
	gen2 := asset.RandGenesis(t, asset.Collectible)
	_, _, group2 := storeGroupGenesis(
		t, ctx, gen2, nil, assetStore, privDesc2, groupPriv2,
	)
	gen3 := asset.RandGenesis(t, asset.Normal)
	_, _, group3 := storeGroupGenesis(
		t, ctx, gen1, &gen3, assetStore, privDesc1, groupPriv1,
	)
	require.Equal(
		t, group1.GroupKey.GroupPubKey.SerializeCompressed(),
		group3.GroupKey.GroupPubKey.SerializeCompressed(),
	)

	mintGroups := []*asset.AssetGroup{group1, group2, group3}

	// Next, we'll fetch the DB ID for each genesis, to check that they
	// match the order the geneses were inserted.
	fetchGenID := func(q PendingAssetStore) error {
		for i, groupInfo := range mintGroups {
			genID, err := fetchGenesisID(ctx, q, *groupInfo.Genesis)
			require.NoError(t, err)
			expectedID := int64(i + 1)
			require.Equal(t, expectedID, genID)
		}

		return nil
	}

	var writeTxOpts AssetStoreTxOptions
	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, fetchGenID)

	// Lookup of a missing genesis should return a wrapped error.
	invalidGen := gen1
	invalidGen.Tag = ""

	fetchInvalidGen := func(q PendingAssetStore) error {
		_, err := fetchGenesisID(ctx, q, invalidGen)
		require.ErrorContains(t, err, "unable to fetch genesis")
		return nil
	}

	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, fetchInvalidGen)

	// We should also be able to look up each asset group with a genesis ID.
	fetchGroupByGenID := func(q PendingAssetStore) error {
		for i, groupInfo := range mintGroups {
			genID := int64(i + 1)
			dbGroup, err := fetchGroupByGenesis(ctx, q, genID)
			require.NoError(t, err)
			assertGroupEqual(t, groupInfo, dbGroup)
		}

		// The returned group for the group anchor asset and reissued
		// asset should be the same.
		anchorGenID := int64(1)
		reissueGenID := int64(3)
		anchorGroup, err := fetchGroupByGenesis(ctx, q, anchorGenID)
		require.NoError(t, err)
		reissueGroup, err := fetchGroupByGenesis(ctx, q, reissueGenID)
		require.NoError(t, err)

		require.Equal(
			t, anchorGroup.GroupKey.RawKey,
			reissueGroup.GroupKey.RawKey,
		)
		require.Equal(
			t, anchorGroup.GroupKey.GroupPubKey,
			reissueGroup.GroupKey.GroupPubKey,
		)
		require.NotEqual(
			t, anchorGroup.GroupKey.Witness,
			reissueGroup.GroupKey.Witness,
		)

		return nil
	}

	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, fetchGroupByGenID)

	// Lookup of an invalid genesis ID should return a wrapped error.
	invalidGenID := int64(len(mintGroups) + 1)
	fetchInvalidGenID := func(q PendingAssetStore) error {
		dbGroup, err := fetchGroupByGenesis(ctx, q, invalidGenID)
		require.Nil(t, dbGroup)
		require.ErrorContains(t, err, "no matching asset group")
		return nil
	}

	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, fetchInvalidGenID)

	// We should also be able to look up each asset group with a group key.
	fetchGroupByKey := func(q PendingAssetStore) error {
		for i, groupInfo := range mintGroups {
			groupKey := groupInfo.GroupKey.GroupPubKey
			dbGroup, err := fetchGroupByGroupKey(ctx, q, &groupKey)
			require.NoError(t, err)

			// If we are looking up the group of the reissued asset,
			// the genesis returned will be of the group anchor
			// asset, not the reissued asset.
			if i == len(mintGroups)-1 {
				assertGroupEqual(t, mintGroups[0], dbGroup)
				continue
			}
			assertGroupEqual(t, groupInfo, dbGroup)
		}

		return nil
	}

	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, fetchGroupByKey)

	// Lookup of a missing group key should return a wrapped error.
	invalidGroupKey := groupPriv2.PubKey()
	fetchInvalidGroupKey := func(q PendingAssetStore) error {
		dbGroup, err := fetchGroupByGroupKey(ctx, q, invalidGroupKey)
		require.Nil(t, dbGroup)
		require.ErrorContains(t, err, "no matching asset group")
		return nil
	}

	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, fetchInvalidGroupKey)
}

// TestGroupAnchors tests that we can create a minting batch with a multi-asset
// group, and that we can write and read the group anchor reference correctly.
func TestGroupAnchors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const numSeedlings = 10
	assetStore, _, _ := newAssetStore(t)
	groupVerifier := tapgarden.GenGroupVerifier(ctx, assetStore)
	groupAnchorVerifier := tapgarden.GenGroupAnchorVerifier(ctx, assetStore)
	rawGroupAnchorVerifier := tapgarden.GenRawGroupAnchorVerifier(ctx)

	// First, we'll write a new minting batch to disk, including an
	// internal key and a set of seedlings. One random seedling will
	// be a reissuance into a specific group. Two other seedlings will form
	// a multi-asset group.
	mintingBatch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(numSeedlings),
	)
	_, seedlingGroups, _ := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)
	addMultiAssetGroupToBatch(mintingBatch.Seedlings)
	err := assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err)

	batchKey := mintingBatch.BatchKey.PubKey

	// With the batch written, we should be able to read out the batch, and
	// have it be exactly the same as what we wrote.
	mintingBatchKeyed, err := assetStore.FetchMintingBatch(ctx, batchKey)
	require.NoError(t, err)
	assertBatchEqual(t, mintingBatch, mintingBatchKeyed)

	// Now we'll add an additional set of seedlings with
	// another multi-asset group.
	seedlings := tapgarden.RandSeedlings(t, numSeedlings)
	secondAnchor, secondGrouped := addMultiAssetGroupToBatch(seedlings)

	// We add seedlings one at a time, in order, as the planter does.
	mintingBatch.Seedlings = mergeMap(mintingBatch.Seedlings, seedlings)
	orderedSeedlings := tapgarden.SortSeedlings(maps.Values(seedlings))
	for _, seedlingName := range orderedSeedlings {
		seedling := seedlings[seedlingName]
		require.NoError(t, assetStore.AddSeedlingsToBatch(
			ctx, batchKey, seedling,
		))
	}

	// If we read the batch from disk again, then we should have 20 total
	// seedlings, and the batch still matches what we wrote to disk.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings*2)
	assertBatchEqual(t, mintingBatches[0], mintingBatch)

	// Adding a seedling with an invalid group anchor should fail.
	badGrouped := seedlings[secondGrouped]
	badAnchorName := secondAnchor + secondGrouped
	badGrouped.GroupAnchor = &badAnchorName
	require.ErrorContains(
		t, assetStore.AddSeedlingsToBatch(ctx, batchKey, badGrouped),
		"no rows in result set",
	)
	seedlings[secondGrouped].GroupAnchor = &secondAnchor

	// Record the number of seedlings set as group anchors and members.
	// These counts should not change after sprouting.
	batchSeedlings := maps.Values(mintingBatch.Seedlings)
	isGroupAnchor := func(s *tapgarden.Seedling) bool {
		return s.EnableEmission == true
	}
	isGroupMember := func(s *tapgarden.Seedling) bool {
		return s.GroupAnchor != nil || s.GroupInfo != nil
	}

	anchorCount := fn.Count(batchSeedlings, isGroupAnchor)
	memberCount := fn.Count(batchSeedlings, isGroupMember)

	// Now we'll map these seedlings to an asset commitment and insert them
	// into the DB as sprouts.
	genesisPacket := mintingBatch.GenesisPacket
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, seedlingGroups,
	)

	// Update the pkScript of the anchor output in the genesis packet to
	// make sure the validation doesn't fail when reading the batch from the
	// DB again.
	anchorOutputIndex := uint32(0)
	if mintingBatch.GenesisPacket.ChangeOutputIndex == 0 {
		anchorOutputIndex = 1
	}

	script, err := tapscript.PayToAddrScript(
		*mintingBatch.BatchKey.PubKey, nil, *assetRoot,
	)
	require.NoError(t, err)
	genesisPacket.Pkt.UnsignedTx.TxOut[anchorOutputIndex].PkScript = script

	require.NoError(t, assetStore.AddSproutsToBatch(
		ctx, batchKey, genesisPacket, assetRoot,
	))

	// Now we'll query for that same batch, and assert that the set of
	// assets we just inserted into the database matches up.
	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)

	// We should have no seedlings in this batch, since we added sprouts
	// above. We also expect that the batch is in the BatchStateCommitted
	// state.
	assertSeedlingBatchLen(t, mintingBatches, 1, 0)
	assertBatchState(t, mintingBatches[0], tapgarden.BatchStateCommitted)
	assertPsbtEqual(
		t, &genesisPacket.FundedPsbt,
		&mintingBatches[0].GenesisPacket.FundedPsbt,
	)
	assertAssetsEqual(t, assetRoot, mintingBatches[0].RootAssetCommitment)

	// Check that the number of group anchors and members matches the batch
	// state when frozen.
	storedAssets := mintingBatches[0].RootAssetCommitment.CommittedAssets()
	groupedAssets := fn.Filter(storedAssets, func(a *asset.Asset) bool {
		return a.GroupKey != nil
	})
	require.Equal(t, anchorCount+memberCount, len(groupedAssets))
	require.True(t, fn.All(groupedAssets, func(a *asset.Asset) bool {
		return groupVerifier(&a.GroupKey.GroupPubKey) == nil
	}))

	// Both group anchor verifiers must return the same result.
	groupAnchors := fn.Filter(groupedAssets, func(a *asset.Asset) bool {
		return groupAnchorVerifier(&a.Genesis, a.GroupKey) == nil
	})
	require.Equal(t, anchorCount, len(groupAnchors))

	rawGroupAnchors := fn.Filter(groupAnchors, func(a *asset.Asset) bool {
		return rawGroupAnchorVerifier(&a.Genesis, a.GroupKey) == nil
	})
	require.Equal(t, anchorCount, len(rawGroupAnchors))
	require.Equal(t, groupAnchors, rawGroupAnchors)
}

// TestTapscriptTreeStore tests the functions that use the queries of the
// TapscriptTreeStore interface.
func TestTapscriptTreeStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// First, we'll open up a new asset store. We only need the mintingStore
	// pointer, as we're only testing the TapscriptTreeStore functionality
	// here.
	assetStore, _, _ := newAssetStore(t)

	// Now we generate a set of tapLeafs and tapBranches to store.
	randLeafCount := 4
	var tapLeaves []txscript.TapLeaf
	for i := 0; i < randLeafCount; i++ {
		leaf := test.RandTapLeaf(nil)
		tapLeaves = append(tapLeaves, leaf)
	}

	// Let's add a duplicate tapLeaf as well.
	dupeNode := txscript.NewBaseTapLeaf(tapLeaves[1].Script)
	tapLeaves = append(tapLeaves, dupeNode)

	branchChildCount := 3
	var tapBranchChildren [][]byte
	for i := 0; i < branchChildCount; i++ {
		tapBranchChildren = append(
			tapBranchChildren, test.RandBytes(chainhash.HashSize),
		)
	}

	// Now, let's compute root hashes for the trees we'll load and store.
	// We will use 5 trees total, as drawn below.
	//
	// tree 1: tapLeaves[0]
	// tree 2: tapLeaves[:3] (first three nodes)
	// tree 3; tapLeaves[:] (five nodes, including a duplicate from tree 2)
	// tree 4: tapBranchChildren[:2] (first two branch nodes)
	// tree 5: tapBranchChildren[1:] (last two branch nodes)

	tree1Hash, _, tree1 := treeFromLeaves(
		t, []txscript.TapLeaf{tapLeaves[0]},
	)
	tree2Hash, _, tree2 := treeFromLeaves(t, tapLeaves[:3])
	tree3Hash, _, tree3 := treeFromLeaves(t, tapLeaves[:])
	tree4Hash, _, tree4 := treeFromBranch(t, tapBranchChildren[:2])
	tree5Hash, _, tree5 := treeFromBranch(t, tapBranchChildren[1:])

	// Start with the cases where tree insertion should fail.
	badRootHashErr := storeTapscriptTreeWrapper(
		ctx, false, assetStore, tree1Hash[1:], tree1,
	)
	require.ErrorContains(t, badRootHashErr, "must be 32 bytes")

	emptyTreeErr := storeTapscriptTreeWrapper(
		ctx, false, assetStore, tree1Hash[:], nil,
	)
	require.ErrorContains(t, emptyTreeErr, "no tapscript tree nodes")

	invalidBranchErr := storeTapscriptTreeWrapper(
		ctx, true, assetStore, tree4Hash[:], tree3,
	)
	require.ErrorContains(t, invalidBranchErr, "must be 2 nodes")

	// Now, let's insert the first tree, and then assert that we can fetch
	// and decode an identical tree.
	err := storeTapscriptTreeWrapper(
		ctx, false, assetStore, tree1Hash[:], tree1,
	)
	require.NoError(t, err)

	assertStoredTreeEqual(t, ctx, false, assetStore, tree1Hash[:], tree1)

	// If we try to fetch a tree with a different root hash, that will not
	// return an error, but the results should be empty.
	dbTree2, err := fetchTapscriptTreeWrapper(ctx, tree2Hash[:], assetStore)
	require.Empty(t, dbTree2)
	require.Nil(t, err)

	// Trying to delete a tree we haven't inserted yet will not err.
	err = deleteTapscriptTreeWrapper(ctx, tree2Hash[:], assetStore)
	require.Nil(t, err)

	// Insert the second tree, which has one node already inserted.
	err = storeTapscriptTreeWrapper(
		ctx, false, assetStore, tree2Hash[:], tree2,
	)
	require.NoError(t, err)

	// Fetching both trees should still work.
	assertStoredTreeEqual(t, ctx, false, assetStore, tree1Hash[:], tree1)
	assertStoredTreeEqual(t, ctx, false, assetStore, tree2Hash[:], tree2)

	// If we delete the first tree, we should still be able to fetch the
	// second tree intact.
	err = deleteTapscriptTreeWrapper(ctx, tree1Hash[:], assetStore)
	require.NoError(t, err)
	assertTreeDeletion(t, ctx, tree1Hash[:], assetStore)

	assertStoredTreeEqual(t, ctx, false, assetStore, tree2Hash[:], tree2)

	// Let's insert the third tree, which contains a node that's a duplicate
	// of an already-inserted node.
	err = storeTapscriptTreeWrapper(
		ctx, false, assetStore, tree3Hash[:], tree3,
	)
	require.NoError(t, err)

	// Fetching the second and third trees should succeed.
	assertStoredTreeEqual(t, ctx, false, assetStore, tree2Hash[:], tree2)
	assertStoredTreeEqual(t, ctx, false, assetStore, tree3Hash[:], tree3)

	// Deleting the third tree should not affect the second tree.
	err = deleteTapscriptTreeWrapper(ctx, tree3Hash[:], assetStore)
	require.NoError(t, err)
	assertTreeDeletion(t, ctx, tree1Hash[:], assetStore)

	assertStoredTreeEqual(t, ctx, false, assetStore, tree2Hash[:], tree2)

	// Let's also test handling of tapscript branches.
	err = storeTapscriptTreeWrapper(
		ctx, true, assetStore, tree4Hash[:], tree4,
	)
	require.NoError(t, err)

	assertStoredTreeEqual(t, ctx, true, assetStore, tree4Hash[:], tree4)

	// The second tapscript branch shares a node with the first.
	err = storeTapscriptTreeWrapper(
		ctx, true, assetStore, tree5Hash[:], tree5,
	)
	require.NoError(t, err)

	assertStoredTreeEqual(t, ctx, true, assetStore, tree4Hash[:], tree4)
	assertStoredTreeEqual(t, ctx, true, assetStore, tree5Hash[:], tree5)

	// Deleting the first set of branches should not affect the second.
	err = deleteTapscriptTreeWrapper(ctx, tree4Hash[:], assetStore)
	require.NoError(t, err)
	assertTreeDeletion(t, ctx, tree4Hash[:], assetStore)

	assertStoredTreeEqual(t, ctx, true, assetStore, tree5Hash[:], tree5)
}

// TestTapscriptTreeManager tests the functions that implement the
// TapscriptTreeManager interface. This follows the same actions as
// TestTapscriptTreeStore, but with higher-level functions.
func TestTapscriptTreeManager(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// First, we'll open up a new asset store. We only need the mintingStore
	// pointer, as we're only testing the TapscriptTreeStore functionality
	// here.
	assetStore, _, _ := newAssetStore(t)

	// Now we generate a set of tapLeafs and tapBranches to store.
	randLeafCount := 4
	var tapLeaves []txscript.TapLeaf
	for i := 0; i < randLeafCount; i++ {
		leaf := test.RandTapLeaf(nil)
		tapLeaves = append(tapLeaves, leaf)
	}

	// Let's add a duplicate tapLeaf as well.
	dupeNode := txscript.NewBaseTapLeaf(tapLeaves[1].Script)
	tapLeaves = append(tapLeaves, dupeNode)

	branchChildCount := 3
	var tapBranchChildren [][]byte
	for i := 0; i < branchChildCount; i++ {
		tapBranchChildren = append(
			tapBranchChildren, test.RandBytes(chainhash.HashSize),
		)
	}

	// Now, let's compute root hashes for the trees we'll load and store.
	// We will use 5 trees total, as drawn below.
	//
	// tree 1: tapLeaves[0]
	// tree 2: tapLeaves[:3] (first three nodes)
	// tree 3; tapLeaves[:] (five nodes, including a duplicate from tree 2)
	// tree 4: tapBranchChildren[:2] (first two branch nodes)
	// tree 5: tapBranchChildren[1:] (last two branch nodes)

	tree1Hash, tree1, _ := treeFromLeaves(
		t, []txscript.TapLeaf{tapLeaves[0]},
	)
	tree2Hash, tree2, _ := treeFromLeaves(t, tapLeaves[:3])
	tree3Hash, tree3, _ := treeFromLeaves(t, tapLeaves[:])
	tree4Hash, tree4, _ := treeFromBranch(t, tapBranchChildren[:2])
	tree5Hash, tree5, _ := treeFromBranch(t, tapBranchChildren[1:])

	// Now, let's insert the first tree, and then assert that we can fetch
	// and decode an identical tree.
	storeTapscriptTreeChecked(t, ctx, assetStore, tree1, tree1Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree1, tree1Hash)

	// If we try to fetch a tree with a different root hash, that will
	// return an error.
	tree2empty, err := assetStore.LoadTapscriptTree(ctx, tree2Hash)
	require.ErrorContains(t, err, "tree not found")
	require.Nil(t, tree2empty)

	// Trying to delete a tree we haven't inserted yet will not err.
	err = assetStore.DeleteTapscriptTree(ctx, tree2Hash)
	require.Nil(t, err)

	// Insert the second tree, which has one node already inserted.
	storeTapscriptTreeChecked(t, ctx, assetStore, tree2, tree2Hash)

	// Fetching both trees should still work.
	loadTapscriptTreeChecked(t, ctx, assetStore, tree1, tree1Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree2, tree2Hash)

	// If we delete the first tree, we should still be able to fetch the
	// second tree intact.
	deleteTapscriptTreeChecked(t, ctx, assetStore, tree1Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree2, tree2Hash)

	// Let's insert the third tree, which contains a node that's a duplicate
	// of an already-inserted node.
	storeTapscriptTreeChecked(t, ctx, assetStore, tree3, tree3Hash)

	// Fetching the second and third trees should succeed.
	loadTapscriptTreeChecked(t, ctx, assetStore, tree2, tree2Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree3, tree3Hash)

	// Deleting the third tree should not affect the second tree.
	deleteTapscriptTreeChecked(t, ctx, assetStore, tree3Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree2, tree2Hash)

	// Let's also test handling of tapscript branches.
	storeTapscriptTreeChecked(t, ctx, assetStore, tree4, tree4Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree4, tree4Hash)

	// The second tapscript branch shares a node with the first.
	storeTapscriptTreeChecked(t, ctx, assetStore, tree5, tree5Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree4, tree4Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree5, tree5Hash)

	// Deleting the first set of branches should not affect the second.
	deleteTapscriptTreeChecked(t, ctx, assetStore, tree4Hash)
	loadTapscriptTreeChecked(t, ctx, assetStore, tree5, tree5Hash)
}

// storeMintAnchorUniCommitment stores a mint anchor commitment in the DB.
func storeMintAnchorUniCommitment(t *testing.T, assetStore AssetMintingStore,
	batchID int32, txOutputIndex int32, taprootInternalKey []byte,
	groupKey []byte) {

	ctx := context.Background()

	var writeTxOpts AssetStoreTxOptions
	upsertMintAnchorPreCommit := func(q PendingAssetStore) error {
		_, err := q.UpsertMintAnchorUniCommitment(
			ctx, sqlc.UpsertMintAnchorUniCommitmentParams{
				BatchID:            batchID,
				TxOutputIndex:      txOutputIndex,
				TaprootInternalKey: taprootInternalKey,
				GroupKey:           groupKey,
			},
		)
		require.NoError(t, err)

		return nil
	}
	_ = assetStore.db.ExecTx(ctx, &writeTxOpts, upsertMintAnchorPreCommit)
}

// assertMintAnchorUniCommitment is a helper function that reads a mint anchor
// commitment from the DB and asserts that it matches the expected values.
func assertMintAnchorUniCommitment(t *testing.T, assetStore AssetMintingStore,
	batchID int32, txOutputIndex int32, preCommitInternalKeyBytes,
	groupPubKeyBytes []byte) {

	ctx := context.Background()
	readOpts := NewAssetStoreReadTx()

	var mintAnchorCommitment *sqlc.MintAnchorUniCommitment
	readMintAnchorCommitment := func(q PendingAssetStore) error {
		res, err := q.FetchMintAnchorUniCommitment(ctx, batchID)
		require.NoError(t, err)

		mintAnchorCommitment = &res
		return nil
	}
	_ = assetStore.db.ExecTx(ctx, &readOpts, readMintAnchorCommitment)

	// Ensure the mint anchor commitment matches the one we inserted.
	require.NotNil(t, mintAnchorCommitment)
	require.Equal(t, batchID, mintAnchorCommitment.BatchID)
	require.Equal(t, txOutputIndex, mintAnchorCommitment.TxOutputIndex)
	require.Equal(
		t, preCommitInternalKeyBytes,
		mintAnchorCommitment.TaprootInternalKey,
	)
	require.Equal(t, groupPubKeyBytes, mintAnchorCommitment.GroupKey)
}

// TestUpsertMintAnchorUniCommitment tests the UpsertMintAnchorUniCommitment
// FetchMintAnchorUniCommitment and SQL queries. In particular, it tests that
// upsert works correctly.
func TestUpsertMintAnchorUniCommitment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	assetStore, _, _ := newAssetStore(t)

	// Create a new batch with one asset group seedling.
	mintingBatch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(1),
	)
	mintingBatch.UniverseCommitments = true

	_, _, group := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)

	// Commit batch.
	require.NoError(t, assetStore.CommitMintingBatch(ctx, mintingBatch))

	// Retrieve the batch ID of the batch we just inserted.
	var batchID int32
	readOpts := NewAssetStoreReadTx()
	_ = assetStore.db.ExecTx(
		ctx, &readOpts, func(q PendingAssetStore) error {
			batches, err := q.AllMintingBatches(ctx)
			require.NoError(t, err)
			require.Len(t, batches, 1)

			batchID = int32(batches[0].BatchID)
			return nil
		},
	)

	// Serialize keys into bytes for easier handling.
	preCommitInternalKey := test.RandPubKey(t)
	preCommitInternalKeyBytes := preCommitInternalKey.SerializeCompressed()

	groupPubKeyBytes := group.GroupPubKey.SerializeCompressed()

	// Upsert a mint anchor commitment for the batch.
	txOutputIndex := int32(2)
	storeMintAnchorUniCommitment(
		t, *assetStore, batchID, txOutputIndex,
		preCommitInternalKeyBytes, groupPubKeyBytes,
	)

	// Retrieve and inspect the mint anchor commitment we just inserted.
	assertMintAnchorUniCommitment(
		t, *assetStore, batchID, txOutputIndex,
		preCommitInternalKeyBytes, groupPubKeyBytes,
	)

	// Upsert-ing a new taproot internal key for the same batch should
	// overwrite the existing one.
	internalKey2 := test.RandPubKey(t)
	internalKey2Bytes := internalKey2.SerializeCompressed()

	storeMintAnchorUniCommitment(
		t, *assetStore, batchID, txOutputIndex, internalKey2Bytes,
		groupPubKeyBytes,
	)

	assertMintAnchorUniCommitment(
		t, *assetStore, batchID, txOutputIndex, internalKey2Bytes,
		groupPubKeyBytes,
	)

	// Upsert-ing a new group key for the same batch should overwrite the
	// existing one.
	groupPubKey2 := test.RandPubKey(t)
	groupPubKey2Bytes := groupPubKey2.SerializeCompressed()

	storeMintAnchorUniCommitment(
		t, *assetStore, batchID, txOutputIndex, internalKey2Bytes,
		groupPubKey2Bytes,
	)

	assertMintAnchorUniCommitment(
		t, *assetStore, batchID, txOutputIndex, internalKey2Bytes,
		groupPubKey2Bytes,
	)
}

// TestCommitMintingBatchSeedlings tests that we're able to properly write and
// read a base minting batch on disk. This test covers the state when a batch
// only has seedlings, without any fully formed assets.
func TestBlah(t *testing.T) {
	t.Parallel()

	assetStore, _, _ := newAssetStore(t)

	ctx := context.Background()
	const numSeedlings = 5

	// First, we'll write a new minting batch to disk, including an
	// internal key and a set of seedlings. One random seedling will
	// be a reissuance into a specific group.
	mintingBatch := tapgarden.RandMintingBatch(
		t, tapgarden.WithTotalSeedlings(1),
		tapgarden.WithTotalGroups([]int{1}),
		tapgarden.WithUniverseCommitments(true),
	)
	//_, randGroup, _ := addRandGroupToBatch(
	//	t, assetStore, ctx, mintingBatch.Seedlings,
	//)
	//_, randSiblingHash := addRandSiblingToBatch(t, mintingBatch)
	err := assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err)
}

func init() {
	rand.Seed(time.Now().Unix())

	logWriter := build.NewRotatingLogWriter()
	logger := logWriter.GenSubLogger(Subsystem, func() {})
	logWriter.RegisterSubLogger(Subsystem, logger)
	UseLogger(logger)
}
