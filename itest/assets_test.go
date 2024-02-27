package itest

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/net/http2"
)

var (
	simpleAssets = []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "itestbuxx",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount:       5000,
				AssetVersion: taprpc.AssetVersion_ASSET_VERSION_V0,
			},
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_COLLECTIBLE,
				Name:      "itestbuxx-collectible",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount:       1,
				AssetVersion: taprpc.AssetVersion_ASSET_VERSION_V1,
			},
		},
	}
	issuableAssets = []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "itestbuxx-money-printer-brrr",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount:          5000,
				AssetVersion:    taprpc.AssetVersion_ASSET_VERSION_V1,
				NewGroupedAsset: true,
			},
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_COLLECTIBLE,
				Name:      "itestbuxx-collectible-brrr",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount:          1,
				AssetVersion:    taprpc.AssetVersion_ASSET_VERSION_V0,
				NewGroupedAsset: true,
			},
		},
	}

	transport = &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client = http.Client{
		Transport: transport,
		Timeout:   1 * time.Second,
	}
)

// testMintAssets tests that we're able to mint assets, retrieve their proofs
// and that we're able to import the proofs into a new node.
func testMintAssets(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	rpcSimpleAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd, simpleAssets,
	)
	rpcIssuableAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd, issuableAssets,
	)

	// Now that all our assets have been issued, we'll use the balance
	// calls to ensure that we're able to retrieve the proper balance for
	// them all.
	AssertAssetBalances(t.t, t.tapd, rpcSimpleAssets, rpcIssuableAssets)

	// Check that we can retrieve the group keys for the issuable assets.
	assertGroups(t.t, t.tapd, issuableAssets)

	// Make sure that the minting proofs reflect the correct state.
	AssertMintingProofs(t.t, t.tapd, simpleAssets, rpcSimpleAssets)
	AssertMintingProofs(t.t, t.tapd, issuableAssets, rpcIssuableAssets)

	// Make sure we can't mint assets with too much meta data.
	invalidRequest := CopyRequest(simpleAssets[0])
	invalidRequest.Asset.AssetMeta.Data = make(
		[]byte, proof.MetaDataMaxSizeBytes+1,
	)
	_, err := t.tapd.MintAsset(ctxt, invalidRequest)
	require.ErrorContains(t.t, err, proof.ErrMetaDataTooLarge.Error())

	// Make sure the proof files for the freshly minted assets can be
	// retrieved and are fully valid.
	var allAssets []*taprpc.Asset
	allAssets = append(allAssets, rpcSimpleAssets...)
	allAssets = append(allAssets, rpcIssuableAssets...)
	chainClient := t.tapd.cfg.LndNode.RPC.ChainKit
	for _, mintedAsset := range allAssets {
		AssertAssetProofs(t.t, t.tapd, chainClient, mintedAsset)
	}

	// Let's now create a new node and import all assets into that new node.
	charlie := t.lndHarness.NewNode("charlie", lndDefaultArgs)
	secondTapd := setupTapdHarness(
		t.t, t, charlie, t.universeServer,
	)
	defer shutdownAndAssert(t, charlie, secondTapd)

	// We import the assets into a node that doesn't have the keys to spend
	// them, so we don't expect them to show up with script_key_is_local set
	// to true in the list of assets.
	transferAssetProofs(t, t.tapd, secondTapd, allAssets, false)
}

// transferAssetProofs locates and exports the proof files for all given assets
// from the source node and imports them into the destination node.
func transferAssetProofs(t *harnessTest, src, dst *tapdHarness,
	assets []*taprpc.Asset, shouldShowUpAsLocal bool) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// TODO(roasbeef): modify import call, can't work as is
	//  * proof file only contains the tweaked script key
	//  * from that we don't know the internal key
	//  * we can import the proof but it's useless as is, but lets this
	//  itest work

	chainClient := src.cfg.LndNode.RPC.ChainKit
	for _, existingAsset := range assets {
		gen := existingAsset.AssetGenesis

		proofFile := AssertAssetProofs(
			t.t, src, chainClient, existingAsset,
		)
		_, err := dst.ImportProof(ctxt, &tapdevrpc.ImportProofRequest{
			ProofFile:    proofFile,
			GenesisPoint: gen.GenesisPoint,
		})
		require.NoError(t.t, err)
	}

	listResp, err := dst.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	importedAssets := GroupAssetsByName(listResp.Assets)
	for _, existingAsset := range assets {
		gen := existingAsset.AssetGenesis
		out, err := wire.NewOutPointFromString(
			existingAsset.ChainAnchor.AnchorOutpoint,
		)
		require.NoError(t.t, err)

		anchorTxHash := out.Hash

		anchorBlockHash, err := chainhash.NewHashFromStr(
			existingAsset.ChainAnchor.AnchorBlockHash,
		)
		require.NoError(t.t, err)

		AssertAssetState(
			t.t, importedAssets, gen.Name, gen.MetaHash,
			AssetAmountCheck(existingAsset.Amount),
			AssetTypeCheck(existingAsset.AssetGenesis.AssetType),
			AssetAnchorCheck(anchorTxHash, *anchorBlockHash),
			AssetScriptKeyIsLocalCheck(shouldShowUpAsLocal),
		)
	}
}

// testMintAssetNameCollisionError tests that no error is produced when
// attempting to mint an asset whose name collides with an existing minted asset
// or an asset from a cancelled minting batch. An error should be produced
// when asset names collide within the same minting batch.
func testMintAssetNameCollisionError(t *harnessTest) {
	// Asset name which will be common between minted asset and colliding
	// asset.
	commonAssetName := "test-asset-name"

	// Define and mint a single asset.
	assetMint := mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      commonAssetName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("metadata-1"),
			},
			Amount: 5000,
		},
	}
	rpcSimpleAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{&assetMint},
	)

	// Ensure minted asset with requested name was successfully minted.
	mintedAssetName := rpcSimpleAssets[0].AssetGenesis.Name
	require.Equal(t.t, commonAssetName, mintedAssetName)

	// Attempt to mint another asset whose name should collide with the
	// existing minted asset. No other fields should collide.
	assetCollide := mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_COLLECTIBLE,
			Name:      commonAssetName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("metadata-2"),
			},
			Amount: 1,
		},
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	equalityCheck := func(a *mintrpc.MintAsset, b *mintrpc.PendingAsset) {
		require.Equal(t.t, a.AssetType, b.AssetType)
		require.Equal(t.t, a.Name, b.Name)
		require.Equal(t.t, a.AssetMeta.Data, b.AssetMeta.Data)
		require.Equal(t.t, a.Amount, b.Amount)
		require.Equal(t.t, a.GroupKey, b.GroupKey)
		require.Equal(t.t, a.GroupAnchor, b.GroupAnchor)
	}

	equalityCheckSeedlings := func(a, b *mintrpc.PendingAsset) {
		require.Equal(t.t, a.AssetType, b.AssetType)
		require.Equal(t.t, a.Name, b.Name)
		require.Equal(t.t, a.AssetMeta.Data, b.AssetMeta.Data)
		require.Equal(t.t, a.Amount, b.Amount)
		require.Equal(t.t, a.NewGroupedAsset, b.NewGroupedAsset)
		require.Equal(t.t, a.GroupKey, b.GroupKey)
		require.Equal(t.t, a.GroupAnchor, b.GroupAnchor)
	}
	// If we attempt to add both assets to the same batch, the second mint
	// call should fail.
	collideResp, err := t.tapd.MintAsset(ctxt, &assetCollide)
	require.NoError(t.t, err)
	require.NotNil(t.t, collideResp.PendingBatch)
	require.NotNil(t.t, collideResp.PendingBatch.BatchKey)
	require.Len(t.t, collideResp.PendingBatch.Assets, 1)

	_, batchNameErr := t.tapd.MintAsset(ctxt, &assetMint)
	require.ErrorContains(t.t, batchNameErr, "already in batch")

	// If we cancel the batch, we should still be able to fetch it from the
	// daemon, and be able to refer to it by the batch key.
	rpcBatches, err := t.tapd.ListBatches(
		ctxt, &mintrpc.ListBatchRequest{},
	)
	require.NoError(t.t, err)

	allBatches := rpcBatches.Batches
	require.Len(t.t, allBatches, 2)

	isCollidingBatch := func(batch *mintrpc.MintingBatch) bool {
		if len(batch.Assets) == 0 {
			return false
		}

		return batch.Assets[0].AssetType == taprpc.AssetType_COLLECTIBLE
	}
	batchCollide, err := fn.First(allBatches, isCollidingBatch)
	require.NoError(t.t, err)

	require.Len(t.t, batchCollide.Assets, 1)
	equalityCheck(assetCollide.Asset, batchCollide.Assets[0])

	cancelBatchKey, err := t.tapd.CancelBatch(
		ctxt, &mintrpc.CancelBatchRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, cancelBatchKey.BatchKey, collideResp.PendingBatch.BatchKey,
	)

	// The only change in the returned batch after cancellation should be
	// the batch state.
	cancelBatch, err := t.tapd.ListBatches(
		ctxt, &mintrpc.ListBatchRequest{
			Filter: &mintrpc.ListBatchRequest_BatchKey{
				BatchKey: collideResp.PendingBatch.BatchKey,
			},
		})
	require.NoError(t.t, err)

	require.Len(t.t, cancelBatch.Batches, 1)
	cancelBatchCollide := cancelBatch.Batches[0]
	require.Len(t.t, cancelBatchCollide.Assets, 1)
	equalityCheckSeedlings(
		batchCollide.Assets[0], cancelBatchCollide.Assets[0],
	)
	cancelBatchState := cancelBatchCollide.State
	require.Equal(
		t.t, cancelBatchState,
		mintrpc.BatchState_BATCH_STATE_SEEDLING_CANCELLED,
	)

	// Minting the asset with the name collision should work, even though
	// it is also part of a cancelled batch.
	rpcCollideAsset := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{&assetCollide},
	)

	collideAssetName := rpcCollideAsset[0].AssetGenesis.Name
	require.Equal(t.t, commonAssetName, collideAssetName)
}

// testMintAssetsWithTapscriptSibling tests that a batch of assets can be minted
// with a tapscript sibling, and that the genesis output from that mint can be
// spend via the script path.
func testMintAssetsWithTapscriptSibling(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Build the tapscript tree.
	sigLockPrivKey := test.RandPrivKey(t.t)
	hashLockPreimage := []byte("foobar")
	hashLockLeaf := test.ScriptHashLock(t.t, hashLockPreimage)
	sigLeaf := test.ScriptSchnorrSig(t.t, sigLockPrivKey.PubKey())
	siblingTree := txscript.AssembleTaprootScriptTree(hashLockLeaf, sigLeaf)

	siblingBranch := txscript.NewTapBranch(
		siblingTree.RootNode.Left(), siblingTree.RootNode.Right(),
	)
	siblingPreimage := commitment.NewPreimageFromBranch(siblingBranch)
	typedBranch := asset.TapTreeNodesFromBranch(siblingBranch)
	rawBranch := fn.MapOptionZ(asset.GetBranch(typedBranch), asset.ToBranch)
	require.Len(t.t, rawBranch, 2)
	siblingReq := mintrpc.FinalizeBatchRequest_Branch{
		Branch: &taprpc.TapBranch{
			LeftTaphash:  rawBranch[0],
			RightTaphash: rawBranch[1],
		},
	}

	rpcSimpleAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd, simpleAssets,
		WithSiblingBranch(siblingReq),
	)
	rpcIssuableAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd, issuableAssets,
	)

	AssertAssetBalances(t.t, t.tapd, rpcSimpleAssets, rpcIssuableAssets)

	// Filter the managed UTXOs to select the genesis UTXO with the
	// tapscript sibling.
	utxos, err := t.tapd.ListUtxos(ctxt, &taprpc.ListUtxosRequest{})
	require.NoError(t.t, err)

	utxoWithTapSibling := func(utxo *taprpc.ManagedUtxo) bool {
		return !bytes.Equal(utxo.TaprootAssetRoot, utxo.MerkleRoot)
	}
	mintingOutputWithSibling := fn.Filter(
		maps.Values(utxos.ManagedUtxos), utxoWithTapSibling,
	)
	require.Len(t.t, mintingOutputWithSibling, 1)
	genesisWithSibling := mintingOutputWithSibling[0]

	// Verify that all assets anchored in the output with the tapscript
	// sibling have the correct sibling preimage. Also verify that the final
	// tweak used for the genesis output is derived from the tapscript
	// sibling created above and the batch Taproot Asset commitment.
	AssertGenesisOutput(t.t, genesisWithSibling, siblingPreimage)

	// Extract the fields needed to construct a script path spend, which
	// includes the Taproot Asset commitment root, the final tap tweak, and
	// the internal key.
	mintTapTweak := genesisWithSibling.MerkleRoot
	mintTapTreeRoot := genesisWithSibling.TaprootAssetRoot
	mintInternalKey, err := btcec.ParsePubKey(
		genesisWithSibling.InternalKey,
	)
	require.NoError(t.t, err)

	mintOutputKey := txscript.ComputeTaprootOutputKey(
		mintInternalKey, mintTapTweak,
	)
	mintOutputKeyIsOdd := mintOutputKey.SerializeCompressed()[0] == 0x03
	siblingScriptHash := sigLeaf.TapHash()

	// Build the control block and witness.
	inclusionProof := bytes.Join(
		[][]byte{siblingScriptHash[:], mintTapTreeRoot}, nil,
	)
	hashLockControlBlock := txscript.ControlBlock{
		InternalKey:     mintInternalKey,
		OutputKeyYIsOdd: mintOutputKeyIsOdd,
		LeafVersion:     txscript.BaseLeafVersion,
		InclusionProof:  inclusionProof,
	}
	hashLockControlBlockBytes, err := hashLockControlBlock.ToBytes()
	require.NoError(t.t, err)

	hashLockWitness := wire.TxWitness{
		hashLockPreimage, hashLockLeaf.Script, hashLockControlBlockBytes,
	}

	// Make a non-tap output from Bob to use in a TX spending Alice's
	// genesis UTXO.
	burnOutput := MakeOutput(
		t, t.lndHarness.Bob, lnrpc.AddressType_TAPROOT_PUBKEY, 500,
	)

	// Construct and publish the TX.
	genesisOutpoint, err := wire.NewOutPointFromString(
		genesisWithSibling.OutPoint,
	)
	require.NoError(t.t, err)

	burnTx := wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: *genesisOutpoint,
			Witness:          hashLockWitness,
		}},
		TxOut: []*wire.TxOut{burnOutput},
	}

	var burnTxBuf bytes.Buffer
	require.NoError(t.t, burnTx.Serialize(&burnTxBuf))
	t.lndHarness.Bob.RPC.PublishTransaction(&walletrpc.Transaction{
		TxHex: burnTxBuf.Bytes(),
	})

	// Bob should detect the TX, and the resulting confirmed UTXO once
	// a new block is mined.
	t.lndHarness.Miner.AssertNumTxsInMempool(1)
	t.lndHarness.AssertNumUTXOsUnconfirmed(t.lndHarness.Bob, 1)
	t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)
	t.lndHarness.AssertNumUTXOsWithConf(t.lndHarness.Bob, 1, 1, 1)
}
