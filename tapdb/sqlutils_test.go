package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
)

// DbHandler is a helper struct that contains all the database stores.
type DbHandler struct {
	// UniverseFederationStore is a handle to the universe federation store.
	UniverseFederationStore *UniverseFederationDB

	// MultiverseStore is a handle to the multiverse store.
	MultiverseStore *MultiverseStore

	// AssetMintingStore is a handle to the pending (minting) assets store.
	AssetMintingStore *AssetMintingStore

	// AssetStore is a handle to the active assets store.
	AssetStore *AssetStore

	// DirectQuery is a handle to the underlying database that can be used
	// to query the database directly.
	DirectQuery sqlc.Querier
}

// AddRandomAssetProof generates a random asset and corresponding proof and
// inserts them into the given test database.
func (d *DbHandler) AddRandomAssetProof(t *testing.T) (*asset.Asset,
	*proof.AnnotatedProof) {

	var (
		ctx = context.Background()

		assetStore = d.AssetStore
		db         = d.DirectQuery
	)

	// Next, we'll make a new random asset that also has a few inputs with
	// dummy witness information.
	testAsset := randAsset(t)
	testAltLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))

	assetRoot, err := commitment.NewAssetCommitment(testAsset)
	require.NoError(t, err)

	commitVersion := test.RandFlip(nil, fn.Ptr(commitment.TapCommitmentV2))
	taprootAssetRoot, err := commitment.NewTapCommitment(
		commitVersion, assetRoot,
	)
	require.NoError(t, err)

	err = taprootAssetRoot.MergeAltLeaves(testAltLeaves)
	require.NoError(t, err)

	// With our asset created, we can now create the AnnotatedProof we use
	// to import assets into the database.
	var blockHash chainhash.Hash
	_, err = rand.Read(blockHash[:])
	require.NoError(t, err)

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    10,
	})

	assetID := testAsset.ID()
	anchorPoint := wire.OutPoint{
		Hash:  anchorTx.TxHash(),
		Index: 0,
	}

	// Generate a random proof and encode it into a proof blob.
	testProof := randProof(t, testAsset)
	testProof.AltLeaves = testAltLeaves

	proofBlob, err := testProof.Bytes()
	require.NoError(t, err)

	scriptKey := testAsset.ScriptKey

	annotatedProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *scriptKey.PubKey,
		},
		Blob: proofBlob,
		AssetSnapshot: &proof.AssetSnapshot{
			Asset:             testAsset,
			OutPoint:          anchorPoint,
			AnchorBlockHash:   blockHash,
			AnchorBlockHeight: uint32(test.RandIntn(1000) + 1),
			AnchorTxIndex:     test.RandInt[uint32](),
			AnchorTx:          anchorTx,
			OutputIndex:       0,
			InternalKey:       test.RandPubKey(t),
			ScriptRoot:        taprootAssetRoot,
		},
	}
	if testAsset.GroupKey != nil {
		annotatedProof.GroupKey = &testAsset.GroupKey.GroupPubKey
	}

	// We'll now insert the internal key information as well as the script
	// key ahead of time to reflect the address creation that happens
	// elsewhere.
	_, err = db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    annotatedProof.InternalKey.SerializeCompressed(),
		KeyFamily: test.RandInt[int32](),
		KeyIndex:  test.RandInt[int32](),
	})
	require.NoError(t, err)
	rawScriptKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    scriptKey.RawKey.PubKey.SerializeCompressed(),
		KeyFamily: int32(testAsset.ScriptKey.RawKey.Family),
		KeyIndex:  int32(testAsset.ScriptKey.RawKey.Index),
	})
	require.NoError(t, err)
	_, err = db.UpsertScriptKey(ctx, NewScriptKey{
		InternalKeyID:    rawScriptKeyID,
		TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
		Tweak:            nil,
	})
	require.NoError(t, err)

	// We'll add the chain transaction of the proof now to simulate a
	// batched transfer on a higher layer.
	var anchorTxBuf bytes.Buffer
	err = annotatedProof.AnchorTx.Serialize(&anchorTxBuf)
	require.NoError(t, err)
	anchorTXID := annotatedProof.AnchorTx.TxHash()
	_, err = db.UpsertChainTx(ctx, ChainTxParams{
		Txid:        anchorTXID[:],
		RawTx:       anchorTxBuf.Bytes(),
		BlockHeight: sqlInt32(annotatedProof.AnchorBlockHeight),
		BlockHash:   annotatedProof.AnchorBlockHash[:],
		TxIndex:     sqlInt32(annotatedProof.AnchorTxIndex),
	})
	require.NoError(t, err, "unable to insert chain tx: %w", err)

	// Before we insert the proof, we expect our backend to report it as not
	// found.
	proofLocator := proof.Locator{
		ScriptKey: *testAsset.ScriptKey.PubKey,
	}
	found, err := assetStore.HasProof(ctx, proofLocator)
	require.NoError(t, err)
	require.False(t, found)

	// With all our test data constructed, we'll now attempt to import the
	// asset into the database.
	require.NoError(t, assetStore.ImportProofs(
		ctx, proof.MockVerifierCtx, false, annotatedProof,
	))

	// Now the HasProof should return true.
	found, err = assetStore.HasProof(ctx, proofLocator)
	require.NoError(t, err)
	require.True(t, found)

	return testAsset, annotatedProof
}

// AddUniProofLeaf generates a universe proof leaf and inserts it into the test
// database.
func (d *DbHandler) AddUniProofLeaf(t *testing.T, testAsset *asset.Asset,
	annotatedProof *proof.AnnotatedProof) *universe.Proof {

	ctx := context.Background()

	// Insert proof into the multiverse/universe store. This step will
	// populate the universe root and universe leaves tables.
	uniId := universe.NewUniIDFromAsset(*testAsset)

	leafKey := universe.BaseLeafKey{
		OutPoint:  annotatedProof.AssetSnapshot.OutPoint,
		ScriptKey: &testAsset.ScriptKey,
	}

	leaf := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  testAsset.Genesis,
			GroupKey: testAsset.GroupKey,
		},
		RawProof: annotatedProof.Blob,
		Asset:    testAsset,
		Amt:      testAsset.Amount,
	}

	uniProof, err := d.MultiverseStore.UpsertProofLeaf(
		ctx, uniId, leafKey, &leaf, nil,
	)
	require.NoError(t, err)

	return uniProof
}

// AddRandomServerAddrs is a helper function that will create server addresses
// and add them to the database.
func (d *DbHandler) AddRandomServerAddrs(t *testing.T,
	numServers int) []universe.ServerAddr {

	var (
		ctx   = context.Background()
		fedDB = d.UniverseFederationStore
	)

	addrs := make([]universe.ServerAddr, 0, numServers)
	for i := 0; i < numServers; i++ {
		portOffset := i + 10_000
		hostStr := fmt.Sprintf("localhost:%v", portOffset)

		addr := universe.NewServerAddr(int64(i+1), hostStr)
		addrs = append(addrs, addr)
	}

	// With the set of addrs created, we'll now insert them all into the
	// database.
	err := fedDB.AddServers(ctx, addrs...)
	require.NoError(t, err)

	return addrs
}

// newDbHandleFromDb creates a new database store handle given a database store.
func newDbHandleFromDb(db *BaseDB) *DbHandler {
	testClock := clock.NewTestClock(time.Now())

	// Gain a handle to the pending (minting) universe federation store.
	universeServerTxCreator := NewTransactionExecutor(
		db, func(tx *sql.Tx) UniverseServerStore {
			return db.WithTx(tx)
		},
	)
	fedStore := NewUniverseFederationDB(universeServerTxCreator, testClock)

	// Gain a handle to the multiverse store.
	multiverseTxCreator := NewTransactionExecutor(db,
		func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverseStore := NewMultiverseStore(
		multiverseTxCreator, DefaultMultiverseStoreConfig(),
	)

	// Gain a handle to the pending (minting) assets store.
	assetMintingDB := NewTransactionExecutor(
		db, func(tx *sql.Tx) PendingAssetStore {
			return db.WithTx(tx)
		},
	)
	assetMintingStore := NewAssetMintingStore(assetMintingDB)

	// Gain a handle to the active assets store.
	assetsDB := NewTransactionExecutor(
		db, func(tx *sql.Tx) ActiveAssetsStore {
			return db.WithTx(tx)
		},
	)

	// Gain a handle to the meta store.
	metaDB := NewTransactionExecutor(
		db, func(tx *sql.Tx) MetaStore {
			return db.WithTx(tx)
		},
	)

	activeAssetsStore := NewAssetStore(
		assetsDB, metaDB, testClock, db.Backend(),
	)

	return &DbHandler{
		UniverseFederationStore: fedStore,
		MultiverseStore:         multiverseStore,
		AssetMintingStore:       assetMintingStore,
		AssetStore:              activeAssetsStore,
		DirectQuery:             db,
	}
}

// NewDbHandleFromPath creates a new database store handle given a database file
// path.
func NewDbHandleFromPath(t *testing.T, dbPath string) *DbHandler {
	db := NewTestDbHandleFromPath(t, dbPath)
	return newDbHandleFromDb(db.BaseDB)
}

// NewDbHandle creates a new database store handle.
func NewDbHandle(t *testing.T) *DbHandler {
	// Create a new test database with the default database file path.
	db := NewTestDB(t)
	return newDbHandleFromDb(db.BaseDB)
}
