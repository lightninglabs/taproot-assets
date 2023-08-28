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
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
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

	// TODO(roasbeef): can use another layer of type params since
	// duplicated?
	txCreator := func(tx *sql.Tx) PendingAssetStore {
		return db.WithTx(tx)
	}
	activeTxCreator := func(tx *sql.Tx) ActiveAssetsStore {
		return db.WithTx(tx)
	}

	assetMintingDB := NewTransactionExecutor(db, txCreator)
	assetsDB := NewTransactionExecutor(db, activeTxCreator)
	testClock := clock.NewTestClock(time.Now())

	return NewAssetMintingStore(assetMintingDB),
		NewAssetStore(assetsDB, testClock), db
}

func assertBatchState(t *testing.T, batch *tapgarden.MintingBatch,
	state tapgarden.BatchState) {

	require.Equal(t, state, batch.State())
}

func assertBatchEqual(t *testing.T, a, b *tapgarden.MintingBatch) {
	t.Helper()

	require.Equal(t, a.CreationTime.Unix(), b.CreationTime.Unix())
	require.Equal(t, a.State(), b.State())
	require.Equal(t, a.BatchKey, b.BatchKey)
	require.Equal(t, a.Seedlings, b.Seedlings)
	require.Equal(t, a.GenesisPacket, b.GenesisPacket)
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
	genSigner := asset.NewRawKeyGenesisSigner(groupPriv)
	groupKey, err := asset.DeriveGroupKey(
		genSigner, privDesc, initGen, currentGen,
	)
	require.NoError(t, err)

	// Select the correct genesis for the new asset.
	assetGen := initGen
	if currentGen != nil {
		assetGen = *currentGen
	}

	initialAsset := asset.RandAssetWithValues(
		t, assetGen, groupKey, asset.RandScriptKey(t),
	)

	// Insert the group genesis asset, which will also insert the group key
	// and genesis info needed for reissuance.
	upsertAsset := func(q PendingAssetStore) error {
		_, err = maybeUpsertAssetMeta(ctx, q, &assetGen, nil)
		require.NoError(t, err)

		_, _, err := upsertAssetsWithGenesis(
			ctx, q, assetGen.FirstPrevOut,
			[]*asset.Asset{initialAsset}, nil,
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
	privDesc, groupPriv := randKeyDesc(t)
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

// addMultiAssetGroupToBatch selects a random seedling pair, where neither
// seedling is being issued into an existing group, and creates a multi-asset
// group. Specifically, one seedling will have emission enabled, and the other
// seedling will reference the first seedling as its group anchor.
func addMultiAssetGroupToBatch(t *testing.T,
	seedlings map[string]*tapgarden.Seedling) (string, string) {

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
	mintingBatch := tapgarden.RandSeedlingMintingBatch(t, numSeedlings)
	addRandGroupToBatch(t, assetStore, ctx, mintingBatch.Seedlings)
	err := assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err, "unable to write batch: %v", err)

	batchKey := mintingBatch.BatchKey.PubKey

	// With the batch written, we should be able to read out the batch, and
	// have it be exactly the same as what we wrote.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings)
	assertBatchEqual(t, mintingBatch, mintingBatches[0])

	mintingBatchKeyed, err := assetStore.FetchMintingBatch(ctx, batchKey)
	require.NoError(t, err)
	assertBatchEqual(t, mintingBatch, mintingBatchKeyed)

	// The batch should also still be in the pending state.
	assertBatchState(t, mintingBatches[0], tapgarden.BatchStatePending)

	// Now we'll add an additional set of seedlings.
	seedlings := tapgarden.RandSeedlings(t, numSeedlings)

	// Pick a random seedling and give it a specific group.
	addRandGroupToBatch(t, assetStore, ctx, seedlings)
	mintingBatch.Seedlings = mergeMap(mintingBatch.Seedlings, seedlings)
	require.NoError(t,
		assetStore.AddSeedlingsToBatch(
			ctx, batchKey, maps.Values(seedlings)...,
		), "unable to write seedlings: %v", err,
	)

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
	// batch back if we query for the set of non final batches.
	mintingBatch = tapgarden.RandSeedlingMintingBatch(t, numSeedlings)
	err = assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err)
	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings)
}

func randKeyDesc(t *testing.T) (keychain.KeyDescriptor, *btcec.PrivateKey) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return keychain.KeyDescriptor{
		PubKey: priv.PubKey(),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	}, priv
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

		scriptKey, _ := randKeyDesc(t)

		var (
			groupPriv *btcec.PrivateKey
			groupKey  *asset.GroupKey
			groupInfo *asset.AssetGroup
			ok        bool
			err       error
		)

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

		if groupInfo != nil {
			groupKey, err = asset.DeriveGroupKey(
				asset.NewRawKeyGenesisSigner(groupPriv),
				groupInfo.GroupKey.RawKey,
				*groupInfo.Genesis, &assetGen,
			)
		}

		if seedling.EnableEmission {
			groupKeyRaw, newGroupPriv := randKeyDesc(t)
			groupKey, err = asset.DeriveGroupKey(
				asset.NewRawKeyGenesisSigner(newGroupPriv),
				groupKeyRaw, assetGen, nil,
			)
			newGroupPrivs[seedling.AssetName] = newGroupPriv
			newGroupInfo[seedling.AssetName] = &asset.AssetGroup{
				Genesis:  &assetGen,
				GroupKey: groupKey,
			}
		}

		require.NoError(t, err)

		var amount uint64
		switch seedling.AssetType {
		case asset.Normal:
			amount = seedling.Amount
		case asset.Collectible:
			amount = 1
		}

		newAsset, err := asset.New(
			assetGen, amount, 0, 0,
			asset.NewScriptKeyBip86(scriptKey), groupKey,
		)
		require.NoError(t, err)

		// Finally make a new asset commitment (the inner SMT tree) for
		// this newly created asset.
		assetRoot, err := commitment.NewAssetCommitment(
			newAsset,
		)
		require.NoError(t, err)

		assetRoots = append(assetRoots, assetRoot)
	}

	tapCommitment, err := commitment.NewTapCommitment(assetRoots...)
	require.NoError(t, err)

	return tapCommitment
}

func randGenesisPacket(t *testing.T) *tapgarden.FundedPsbt {
	tx := wire.NewMsgTx(2)

	var hash chainhash.Hash
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  hash,
			Index: 1,
		},
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    5,
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    10,
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    15,
	})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	return &tapgarden.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: 1,
		ChainFees:         100,
	}
}

func assertPsbtEqual(t *testing.T, a, b *tapgarden.FundedPsbt) {
	require.Equal(t, a.ChangeOutputIndex, b.ChangeOutputIndex)
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
	mintingBatch := tapgarden.RandSeedlingMintingBatch(t, numSeedlings)
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
	genesisPacket := randGenesisPacket(t)
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, seedlingGroups,
	)
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
	assertPsbtEqual(t, genesisPacket, mintingBatches[0].GenesisPacket)
	assertAssetsEqual(t, assetRoot, mintingBatches[0].RootAssetCommitment)

	// We also expect that for each of the assets we created above, we're
	// able to obtain the asset meta for them all.
	require.Len(t, mintingBatches[0].AssetMetas, numSeedlings)
}

func addRandAssets(t *testing.T, ctx context.Context,
	assetStore *AssetMintingStore,
	numAssets int) (*btcec.PublicKey, *btcec.PublicKey, uint64,
	*tapgarden.FundedPsbt, []byte, *commitment.TapCommitment) {

	mintingBatch := tapgarden.RandSeedlingMintingBatch(t, numAssets)
	genAmt, seedlingGroups, group := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)
	batchKey := mintingBatch.BatchKey.PubKey
	require.NoError(t, assetStore.CommitMintingBatch(ctx, mintingBatch))

	genesisPacket := randGenesisPacket(t)

	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, seedlingGroups,
	)
	require.NoError(t, assetStore.AddSproutsToBatch(
		ctx, batchKey, genesisPacket, assetRoot,
	))

	scriptRoot := assetRoot.TapscriptRoot(nil)
	return batchKey, &group.GroupKey.GroupPubKey, genAmt,
		genesisPacket, scriptRoot[:], assetRoot
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
	batchKey, groupKey, groupGenAmt, genesisPkt, scriptRoot, assetRoot :=
		addRandAssets(t, ctx, assetStore, numSeedlings)

	// The packet needs to be finalized, so we'll insert a fake
	// FinalScriptSig. The FinalScriptSig doesn't need to be well formed,
	// so we get by w/ this.
	//
	// TODO(roasbeef): move the tx extraction up one layer?
	genesisPkt.Pkt.Inputs[0].FinalScriptSig = []byte{}

	// With our assets inserted, we'll now commit the signed genesis packet
	// to disk, along with the Taproot Asset script root that's stored
	// alongside any managed UTXOs.
	require.NoError(t, assetStore.CommitSignedGenesisTx(
		ctx, batchKey, genesisPkt, 2, scriptRoot,
	))

	// The batch updated above should be found, with the batch state
	// updated, and also the genesis transaction updated to match what we
	// "signed" above.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertBatchState(
		t, mintingBatches[0], tapgarden.BatchStateBroadcast,
	)
	assertPsbtEqual(t, genesisPkt, mintingBatches[0].GenesisPacket)

	var rawTxBytes bytes.Buffer
	rawGenTx, err := psbt.Extract(genesisPkt.Pkt)
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
	require.Equal(t, genesisPkt.ChainFees, dbGenTx.ChainFees)

	// Now that we have the primary key for the chain transaction inserted
	// above, we'll use that to confirm that the managed UTXO has been
	// updated accordingly.
	managedUTXO, err := db.FetchManagedUTXO(ctx, sqlc.FetchManagedUTXOParams{
		TxnID: sqlInt32(dbGenTx.TxnID),
	})
	require.NoError(t, err)
	require.Equal(t, scriptRoot, managedUTXO.MerkleRoot)

	// Next, we'll confirm that all the assets inserted previously now are
	// able to be queried according to the anchor UTXO primary key.
	anchoredAssets, err := db.FetchAssetsByAnchorTx(
		ctx, sqlInt32(managedUTXO.UtxoID),
	)
	require.NoError(t, err)
	require.Equal(t, numSeedlings, len(anchoredAssets))

	// Finally, we'll verify that the genesis point also points to the
	// inserted chain transaction.
	_, err = db.FetchGenesisPointByAnchorTx(ctx, sqlInt32(dbGenTx.TxnID))
	require.NoError(t, err)

	// For each asset created above, we'll make a fake proof file for it.
	assetProofs := make(proof.AssetBlobs)
	for _, a := range assetRoot.CommittedAssets() {
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
		ctx, batchKey, &fakeBlockHash, blockHeight, txIndex,
		assetProofs,
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

	// If we query for the set of all active assets, then we should get
	// back the same number of seedlings.
	//
	// TODO(roasbeef): move into isolated test
	assets, err := confAssets.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)
	require.Equal(t, numSeedlings, len(assets))

	// All the assets returned should have the genesis prev ID set up.
	for _, dbAsset := range assets {
		require.True(t, dbAsset.HasGenesisWitness())
	}

	// Now that the batch has been committed on disk, we should be able to
	// obtain all the proofs we just committed.
	diskProofs, err := confAssets.FetchAssetProofs(ctx)
	require.NoError(t, err)
	require.Equal(t, assetProofs, diskProofs)

	// If we look up all the proofs by their specific script key, we should
	// get the same set of proofs.
	scriptKeys := fMapKeys(
		assetProofs, func(k asset.SerializedKey) *btcec.PublicKey {
			parsed, err := btcec.ParsePubKey(k.CopyBytes())
			require.NoError(t, err)

			return parsed
		},
	)
	diskProofs, err = confAssets.FetchAssetProofs(ctx, scriptKeys...)
	require.NoError(t, err)
	require.Equal(t, assetProofs, diskProofs)

	mintedAssets := assetRoot.CommittedAssets()

	// We'll now query for the set of balances to ensure they all line up
	// with the assets we just created, including the group genesis asset.
	assetBalances, err := confAssets.QueryBalancesByAsset(ctx, nil)
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
		ctx, nil,
	)
	require.NoError(t, err)
	require.Equal(t, numKeyGroups, len(assetBalancesByGroup))
	existingGroupKey := asset.ToSerialized(groupKey)

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
			assetBalance.Balance -= groupGenAmt
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
	keyDesc, _ := randKeyDesc(t)
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
	privDesc1, groupPriv1 := randKeyDesc(t)
	gen1 := asset.RandGenesis(t, asset.Normal)
	_, _, group1 := storeGroupGenesis(
		t, ctx, gen1, nil, assetStore, privDesc1, groupPriv1,
	)
	privDesc2, groupPriv2 := randKeyDesc(t)
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
			expectedID := int32(i + 1)
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
			genID := int32(i + 1)
			dbGroup, err := fetchGroupByGenesis(ctx, q, genID)
			require.NoError(t, err)
			assertGroupEqual(t, groupInfo, dbGroup)
		}

		// The returned group for the group anchor asset and reissued
		// asset should be the same.
		anchorGenID := int32(1)
		reissueGenID := int32(3)
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
	invalidGenID := int32(len(mintGroups) + 1)
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

	// First, we'll write a new minting batch to disk, including an
	// internal key and a set of seedlings. One random seedling will
	// be a reissuance into a specific group. Two other seedlings will form
	// a multi-asset group.
	mintingBatch := tapgarden.RandSeedlingMintingBatch(t, numSeedlings)
	_, seedlingGroups, _ := addRandGroupToBatch(
		t, assetStore, ctx, mintingBatch.Seedlings,
	)
	addMultiAssetGroupToBatch(t, mintingBatch.Seedlings)
	err := assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err, "unable to write batch: %v", err)

	batchKey := mintingBatch.BatchKey.PubKey

	// With the batch written, we should be able to read out the batch, and
	// have it be exactly the same as what we wrote.
	mintingBatchKeyed, err := assetStore.FetchMintingBatch(ctx, batchKey)
	require.NoError(t, err)
	assertBatchEqual(t, mintingBatch, mintingBatchKeyed)

	// Now we'll add an additional set of seedlings with
	// another multi-asset group.
	seedlings := tapgarden.RandSeedlings(t, numSeedlings)
	secondAnchor, secondGrouped := addMultiAssetGroupToBatch(
		t, seedlings,
	)

	// We add seedlings one at a time, in order, as the planter does.
	mintingBatch.Seedlings = mergeMap(mintingBatch.Seedlings, seedlings)
	orderedSeedlings := tapgarden.SortSeedlings(maps.Values(seedlings))
	for _, seedlingName := range orderedSeedlings {
		seedling := seedlings[seedlingName]
		require.NoError(t,
			assetStore.AddSeedlingsToBatch(
				ctx, batchKey, seedling,
			), "unable to write seedlings: %v", err,
		)
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
	require.ErrorContains(t,
		assetStore.AddSeedlingsToBatch(
			ctx, batchKey, badGrouped,
		), "no rows in result set",
	)
	seedlings[secondGrouped].GroupAnchor = &secondAnchor

	// Now we'll map these seedlings to an asset commitment and insert them
	// into the DB as sprouts.
	genesisPacket := randGenesisPacket(t)
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings, seedlingGroups,
	)
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
	assertPsbtEqual(t, genesisPacket, mintingBatches[0].GenesisPacket)
	assertAssetsEqual(t, assetRoot, mintingBatches[0].RootAssetCommitment)
}

func init() {
	rand.Seed(time.Now().Unix())

	logWriter := build.NewRotatingLogWriter()
	logger := logWriter.GenSubLogger(Subsystem, func() {})
	logWriter.RegisterSubLogger(Subsystem, logger)
	UseLogger(logger)
}
