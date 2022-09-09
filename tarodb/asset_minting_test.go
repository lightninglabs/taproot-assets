package tarodb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// newAssetStore makes a new instance of the AssetMintingStore backed by sqlite
// by default.
func newAssetStore(t *testing.T) (*AssetMintingStore, *AssetStore,
	*SqliteStore) {

	// First, Make a new test database.
	db := NewTestSqliteDB(t)

	// TODO(roasbeef): can use another layer of type params since
	// duplicated?
	txCreator := func(tx Tx) PendingAssetStore {
		// TODO(roasbeef): can get rid of this by emulating the
		// sqlite.DBTX interface
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	}
	activeTxCreator := func(tx Tx) ActiveAssetsStore {
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	}

	assetMintingDB := NewTransactionExecutor[PendingAssetStore, TxOptions](
		db, txCreator,
	)
	assetsDB := NewTransactionExecutor[ActiveAssetsStore, TxOptions](
		db, activeTxCreator,
	)
	return NewAssetMintingStore(assetMintingDB), NewAssetStore(assetsDB),
		db
}

// randBool rolls a random boolean.
func randBool() bool {
	return rand.Int()%2 == 0
}

// randSeedlings creates a new set of random seedlings.
func randSeedlings(t *testing.T, numSeedlings int) map[string]*tarogarden.Seedling {
	seedlings := make(map[string]*tarogarden.Seedling)
	for i := 0; i < numSeedlings; i++ {
		var n [32]byte
		if _, err := rand.Read(n[:]); err != nil {
			t.Fatalf("unable to read str: %v", err)
		}
		assetName := hex.EncodeToString(n[:])
		seedlings[assetName] = &tarogarden.Seedling{
			AssetType:      asset.Type(rand.Int31n(2)),
			AssetName:      assetName,
			Metadata:       n[:],
			Amount:         uint64(rand.Int63()),
			EnableEmission: randBool(),
		}
	}

	return seedlings
}

// randSeedlingMintingBatch creates a new minting batch with only random
// seedlings populated.
func randSeedlingMintingBatch(t *testing.T,
	numSeedlings int) *tarogarden.MintingBatch {

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return &tarogarden.MintingBatch{
		BatchKey: keychain.KeyDescriptor{
			PubKey: priv.PubKey(),
			KeyLocator: keychain.KeyLocator{
				Index:  uint32(rand.Int31()),
				Family: keychain.KeyFamily(rand.Int31()),
			},
		},
		Seedlings:    randSeedlings(t, numSeedlings),
		CreationTime: time.Now(),
	}
}

func assertBatchState(t *testing.T, batch *tarogarden.MintingBatch,
	state tarogarden.BatchState) {

	require.Equal(t, state, batch.BatchState)
}

func assertBatchEqual(t *testing.T, a, b *tarogarden.MintingBatch) {
	require.True(t, a.CreationTime.Equal(b.CreationTime))
	require.Equal(t, a.BatchState, b.BatchState)
	require.Equal(t, a.BatchKey, b.BatchKey)
	require.Equal(t, a.Seedlings, b.Seedlings)
	require.Equal(t, a.GenesisPacket, b.GenesisPacket)
	require.Equal(t, a.RootAssetCommitment, b.RootAssetCommitment)
}

func assertSeedlingBatchLen(t *testing.T, batches []*tarogarden.MintingBatch,
	numBatches, numSeedlings int) {

	require.Len(t, batches, numBatches)
	if numBatches == 0 {
		return
	}
	require.Len(t, batches[0].Seedlings, numSeedlings)
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
	// internal key and a set of seedlings.
	mintingBatch := randSeedlingMintingBatch(t, numSeedlings)
	err := assetStore.CommitMintingBatch(ctx, mintingBatch)
	require.NoError(t, err, "unable to write batch: %v", err)

	batchKey := mintingBatch.BatchKey.PubKey

	// With the batch written, we should be able to read out the batch, and
	// have it be exactly the same as what we wrote.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	require.NoError(t, err)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings)
	assertBatchEqual(t, mintingBatch, mintingBatches[0])

	// The batch should also still be in the pending state.
	assertBatchState(t, mintingBatches[0], tarogarden.BatchStatePending)

	// Now we'll add an additional set of seedlings.
	seedlings := randSeedlings(t, numSeedlings)
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
		ctx, batchKey, tarogarden.BatchStateFrozen,
	))

	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 1, numSeedlings*2)
	assertBatchState(t, mintingBatches[0], tarogarden.BatchStateFrozen)

	// If we finalize the batch, then the next query to
	// FetchNonFinalBatches should return zero batches.
	require.NoError(t, assetStore.UpdateBatchState(
		ctx, batchKey, tarogarden.BatchStateFinalized,
	))
	mintingBatches = noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertSeedlingBatchLen(t, mintingBatches, 0, 0)

	// Insert another normal batch into the database. We should get this
	// batch back if we query for the set of non final batches.
	mintingBatch = randSeedlingMintingBatch(t, numSeedlings)
	require.NoError(t, err, assetStore.CommitMintingBatch(ctx, mintingBatch))
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
// TODO(roasbeef): same func in tarogarden can just re-use?
func seedlingsToAssetRoot(t *testing.T, genesisPoint wire.OutPoint,
	seedlings map[string]*tarogarden.Seedling) *commitment.TaroCommitment {

	assetRoots := make([]*commitment.AssetCommitment, 0, len(seedlings))
	for _, seedling := range seedlings {
		assetGen := asset.Genesis{
			FirstPrevOut: genesisPoint,
			Tag:          seedling.AssetName,
			Metadata:     seedling.Metadata,
			OutputIndex:  0,
			Type:         seedling.AssetType,
		}

		scriptKey, _ := randKeyDesc(t)

		var familyKey *asset.FamilyKey
		if seedling.EnableEmission {
			famKeyRaw, famPriv := randKeyDesc(t)
			famKey, err := asset.DeriveFamilyKey(
				asset.NewRawKeyGenesisSigner(famPriv),
				famKeyRaw, assetGen,
			)
			require.NoError(t, err)

			familyKey = famKey
		}

		var amount uint64
		switch seedling.AssetType {
		case asset.Normal:
			amount = seedling.Amount
		case asset.Collectible:
			amount = 1
		}

		newAsset, err := asset.New(
			assetGen, amount, 0, 0, scriptKey, familyKey,
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

	taroCommitment, err := commitment.NewTaroCommitment(assetRoots...)
	require.NoError(t, err)

	return taroCommitment
}

func randGenesisPacket(t *testing.T) *tarogarden.FundedPsbt {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
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

	psbt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	return &tarogarden.FundedPsbt{
		Pkt:               psbt,
		ChangeOutputIndex: 1,
	}
}

func assertPsbtEqual(t *testing.T, a, b *tarogarden.FundedPsbt) {
	require.Equal(t, a.ChangeOutputIndex, b.ChangeOutputIndex)
	require.Equal(t, a.LockedUTXOs, b.LockedUTXOs)

	var aBuf, bBuf bytes.Buffer

	err := a.Pkt.Serialize(&aBuf)
	require.NoError(t, err)

	err = b.Pkt.Serialize(&bBuf)
	require.NoError(t, err)

	require.Equal(t, aBuf.Bytes(), bBuf.Bytes())
}

func assertAssetsEqual(t *testing.T, a, b *commitment.TaroCommitment) {
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
	mintingBatch := randSeedlingMintingBatch(t, numSeedlings)
	require.NoError(t, assetStore.CommitMintingBatch(ctx, mintingBatch))

	batchKey := mintingBatch.BatchKey.PubKey

	// Now that the batch is on disk, we'll map those seedlings to an
	// actual asset commitment, then insert them into the DB as sprouts.
	genesisPacket := randGenesisPacket(t)
	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings,
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
	assertBatchState(t, mintingBatches[0], tarogarden.BatchStateCommitted)
	assertPsbtEqual(t, genesisPacket, mintingBatches[0].GenesisPacket)
	assertAssetsEqual(t, assetRoot, mintingBatches[0].RootAssetCommitment)
}

func addRandAssets(t *testing.T, ctx context.Context,
	assetStore *AssetMintingStore,
	numAssets int) (*btcec.PublicKey, *tarogarden.FundedPsbt, []byte,
	*commitment.TaroCommitment) {

	mintingBatch := randSeedlingMintingBatch(t, numAssets)
	batchKey := mintingBatch.BatchKey.PubKey
	require.NoError(t, assetStore.CommitMintingBatch(ctx, mintingBatch))

	genesisPacket := randGenesisPacket(t)

	assetRoot := seedlingsToAssetRoot(
		t, genesisPacket.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
		mintingBatch.Seedlings,
	)
	require.NoError(t, assetStore.AddSproutsToBatch(
		ctx, batchKey, genesisPacket, assetRoot,
	))

	scriptRoot := assetRoot.TapscriptRoot(nil)
	return batchKey, genesisPacket, scriptRoot[:], assetRoot
}

// TestCommitBatchChainActions tests that we're able to properly write a signed
// genesis transaction to disk, update all dependent tables along the way, and
// also transition the batch to the BatchStateBroadcast state. Finally we test
// that if we mark the batch as confirmed on chain, then the confirmed
// transaction is updated accordingly.
func TestCommitBatchChainActions(t *testing.T) {
	ctx := context.Background()
	const numSeedlings = 5
	assetStore, confAssets, db := newAssetStore(t)

	// First, we'll create a new batch, then add some sample seedlings, and
	// then those seedlings as assets.
	batchKey, genesisPkt, scriptRoot, assetRoot := addRandAssets(
		t, ctx, assetStore, numSeedlings,
	)

	// The packet needs to be finalized, so we'll insert a fake
	// FinalScriptSig. The FinalScriptSig doesn't need to be well formed,
	// so we get by w/ this.
	//
	// TODO(roasbeef): move the tx extraction up one layer?
	genesisPkt.Pkt.Inputs[0].FinalScriptSig = []byte{}

	// With our assets inserted, we'll now commit the signed genesis packet
	// to disk, along with the taro script root that's stored along side
	// any managed UTXOs.
	require.NoError(t, assetStore.CommitSignedGenesisTx(
		ctx, batchKey, genesisPkt, 2, scriptRoot,
	))

	// The batch updated above should be found, with the batch state
	// updated, and also the genesis transaction updated to match what we
	// "signed" above.
	mintingBatches := noError1(t, assetStore.FetchNonFinalBatches, ctx)
	assertBatchState(
		t, mintingBatches[0], tarogarden.BatchStateBroadcast,
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

	// Now that we have the primary key for the chain transaction inserted
	// above, we'll use that to confirm that the managed UTXO has been
	// updated accordingly.
	managedUTXO, err := db.FetchManagedUTXO(ctx, dbGenTx.TxnID)
	require.NoError(t, err)
	require.Equal(t, scriptRoot, managedUTXO.TaroRoot)

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
	for _, asset := range assetRoot.CommittedAssets() {
		blob := make([]byte, 100)
		_, err := rand.Read(blob[:])
		require.NoError(t, err)

		assetProofs[*asset.ScriptKey.PubKey] = blob
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
	assets, err := confAssets.FetchAllAssets(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, numSeedlings, len(assets))

	// Now that the batch has been committed on disk, we should be able to
	// obtain all the proofs we just committed.
	diskProofs, err := confAssets.FetchAssetProofs(ctx)
	require.NoError(t, err)
	require.Equal(t, assetProofs, diskProofs)

	// If we look up all the proofs by their specific script key, we should
	// get the same set of proofs.
	scriptKeys := mapKeysPtr(assetProofs)
	diskProofs, err = confAssets.FetchAssetProofs(ctx, scriptKeys...)
	require.NoError(t, err)
	require.Equal(t, assetProofs, diskProofs)
}

// TestDuplicateFamilyKey tests that if we attempt to insert a family key with
// the exact same tweaked key blob, then the noop UPSERT logic triggers, and we
// get the ID of that same key.
func TestDuplicateFamilyKey(t *testing.T) {
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

	// Before we can insert the family key, we also need to insert a valid
	// genesis point as well. We'll just use the key again as uniqueness is
	// what matters.
	genesisPointID, err := db.UpsertGenesisPoint(ctx, rawKey)
	require.NoError(t, err)

	// We'll just use the same family key here as it doesn't really matter
	// what it is. What matters is that it's unique.
	assetKey := AssetFamilyKey{
		TweakedFamKey:  rawKey,
		InternalKeyID:  keyID,
		GenesisPointID: genesisPointID,
	}
	famID, err := db.UpsertAssetFamilyKey(ctx, assetKey)
	require.NoError(t, err)

	// Now we'll try to insert that same key family again. We should get no
	// error, and the same famID back.
	famID2, err := db.UpsertAssetFamilyKey(ctx, assetKey)
	require.NoError(t, err)
	require.Equal(t, famID, famID2)
}

func init() {
	rand.Seed(time.Now().Unix())
}
