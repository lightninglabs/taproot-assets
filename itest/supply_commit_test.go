package itest

import (
	"bytes"
	"context"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// assertAnchorTxPreCommitOut checks that the anchor transaction for the
// minted asset includes a pre-commitment output for the supply commitment.
// If an expected delegation key is provided, it verifies that it matches
// the one used in the pre-commitment output. The function returns the
// delegation key found in the asset metadata.
func assertAnchorTxPreCommitOut(
	t *harnessTest, tapd *tapdHarness, rpcAsset *taprpc.Asset,
	expectedDelegationKey fn.Option[btcec.PublicKey]) btcec.PublicKey {

	// Fetch metadata for the minted asset.
	ctxb := context.Background()

	metaResp, err := tapd.FetchAssetMeta(
		ctxb, &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetId{
				AssetId: rpcAsset.AssetGenesis.AssetId,
			},
		},
	)
	require.NoError(t.t, err)

	delegationKey, err := btcec.ParsePubKey(metaResp.DelegationKey)
	require.NoError(t.t, err)

	// If a specific delegation key is expected, verify it matches the one
	// retrieved from the asset metadata.
	expectedDelegationKey.WhenSome(func(expectedKey btcec.PublicKey) {
		require.True(t.t, expectedKey.IsEqual(delegationKey))
	})

	// Parse anchor tx and confirm that one output is a supply commitment
	// pre-commitment output.
	var msgTx wire.MsgTx
	err = msgTx.Deserialize(
		bytes.NewReader(rpcAsset.ChainAnchor.AnchorTx),
	)
	require.NoError(t.t, err)

	expectedTxOut, err := tapgarden.PreCommitTxOut(*delegationKey)
	require.NoError(t.t, err)

	// The pre-commitment output should be present in the anchor tx exactly
	// once.
	foundOnce := false
	for idx := range msgTx.TxOut {
		txOut := msgTx.TxOut[idx]
		if txOut.Value != expectedTxOut.Value {
			continue
		}
		if !bytes.Equal(txOut.PkScript, expectedTxOut.PkScript) {
			continue
		}

		// We found a pre-commitment output, but it should only be
		// present once.
		if foundOnce {
			t.t.Fatalf("found pre-commitment output more than once")
		}

		foundOnce = true
	}
	require.True(t.t, foundOnce)

	return *delegationKey
}

// testPreCommitOutput tests that the pre-commitment output is correctly
// included in the anchor transaction when minting an asset group with
// universe/supply commitments enabled.
func testPreCommitOutput(t *harnessTest) {
	mintReq := CopyRequest(issuableAssets[0])
	mintReq.Asset.EnableSupplyCommitments = true
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)
	require.Len(t.t, rpcAssets, 1, "expected one minted asset")

	rpcFirstTrancheAsset := rpcAssets[0]
	delegationKey := assertAnchorTxPreCommitOut(
		t, t.tapd, rpcFirstTrancheAsset, fn.None[btcec.PublicKey](),
	)

	// Mint another tranche into the same asset group to ensure that
	// the pre-commitment output is still included in the anchor tx when a
	// pre-existing asset group key is used.
	tweakedGroupKey := rpcFirstTrancheAsset.AssetGroup.TweakedGroupKey

	mintReq = &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "itestbuxx-money-printer-brrr-tranche-2",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("some metadata"),
			},
			Amount:          6000,
			AssetVersion:    taprpc.AssetVersion_ASSET_VERSION_V1,
			NewGroupedAsset: false,
			GroupedAsset:    true,
			GroupKey:        tweakedGroupKey,

			EnableSupplyCommitments: true,
		},
	}
	rpcAssets = MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)

	rpcSecondTrancheAsset := rpcAssets[0]

	assertAnchorTxPreCommitOut(
		t, t.tapd, rpcSecondTrancheAsset, fn.Some(delegationKey),
	)

	secondAssetGroupKey := rpcSecondTrancheAsset.AssetGroup.TweakedGroupKey
	// Ensure that the second tranche asset is part of the same group.
	require.EqualValues(t.t, tweakedGroupKey, secondAssetGroupKey)
}

// testSupplyCommitIgnoreAsset verifies that universe supply commitments
// correctly account for ignored asset outpoints. It:
//
//  1. Mints an asset group with universe supply commitments enabled.
//  2. Transfers a portion of the asset to a secondary node.
//  3. Instructs the primary node to ignore the outpoint now owned by the
//     secondary node.
//  4. Updates the asset group’s supply commitment, which should now include
//     the ignored outpoint in the “ignore” subtree.
//  5. Mines the commitment transaction.
//  6. Retrieves the updated supply commitment transaction and asserts that the
//     ignored subtree contains the expected outpoint.
func testSupplyCommitIgnoreAsset(t *harnessTest) {
	ctxb := context.Background()

	t.Log("Minting asset group with a single normal asset and " +
		"universe/supply commitments enabled")
	mintReq := CopyRequest(issuableAssets[0])
	mintReq.Asset.EnableSupplyCommitments = true
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)
	require.Len(t.t, rpcAssets, 1, "expected one minted asset")
	rpcAsset := rpcAssets[0]

	// Send some of the asset to a secondary node. We will then use the
	// primary node to ignore the asset outpoint owned by the secondary
	// node.
	t.Log("Setting up secondary node as recipient of asset")
	secondLnd := t.lndHarness.NewNodeWithCoins("SecondLnd", nil)
	secondTapd := setupTapdHarness(t.t, t, secondLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	t.Log("Sending asset to secondary node")
	sendAssetAmount := uint64(10)
	sendChangeAmount := rpcAsset.Amount - sendAssetAmount

	sendResp := sendAssetAndAssert(
		ctxb, t, t.tapd, secondTapd, sendAssetAmount, sendChangeAmount,
		rpcAsset.AssetGenesis, rpcAsset, 0, 1, 1,
	)
	require.Len(t.t, sendResp.RpcResp.Transfer.Outputs, 2)
	t.Log("Asset transfer completed successfully")

	// Parse the group key from the minted asset.
	groupKeyBytes := rpcAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)

	// Ignore the asset outpoint owned by the secondary node.
	t.Log("Registering supply commitment asset ignore for asset outpoint " +
		"owned by secondary node")

	// Determine the transfer output owned by the secondary node.
	// This is the output that we will ignore.
	transferOutput := sendResp.RpcResp.Transfer.Outputs[0]
	changeOutput := sendResp.RpcResp.Transfer.Outputs[1]
	if sendResp.RpcResp.Transfer.Outputs[1].Amount == sendAssetAmount {
		transferOutput = sendResp.RpcResp.Transfer.Outputs[1]
		changeOutput = sendResp.RpcResp.Transfer.Outputs[0]
	}

	// Get block height at the time of the ignore request.
	_, newIgnoreBlockHeight := t.lndHarness.Miner().GetBestBlock()

	// Ignore the asset outpoint owned by the secondary node.
	ignoreAmt := sendAssetAmount
	ignoreReq := &unirpc.IgnoreAssetOutPointRequest{
		AssetOutPoint: &taprpc.AssetOutPoint{
			AnchorOutPoint: transferOutput.Anchor.Outpoint,
			AssetId:        rpcAsset.AssetGenesis.AssetId,
			ScriptKey:      transferOutput.ScriptKey,
		},
		Amount: ignoreAmt,
	}
	respIgnore, err := t.tapd.IgnoreAssetOutPoint(ctxb, ignoreReq)
	require.NoError(t.t, err)
	require.NotNil(t.t, respIgnore)
	require.EqualValues(t.t, ignoreAmt, respIgnore.Leaf.RootSum)

	// We also ignore our change output, so we can later verify that the
	// proof verifier correctly denies spending the change output.
	ignoreReq2 := &unirpc.IgnoreAssetOutPointRequest{
		AssetOutPoint: &taprpc.AssetOutPoint{
			AnchorOutPoint: changeOutput.Anchor.Outpoint,
			AssetId:        rpcAsset.AssetGenesis.AssetId,
			ScriptKey:      changeOutput.ScriptKey,
		},
		Amount: sendChangeAmount,
	}
	respIgnore2, err := t.tapd.IgnoreAssetOutPoint(ctxb, ignoreReq2)
	require.NoError(t.t, err)
	require.NotNil(t.t, respIgnore2)
	require.EqualValues(t.t, sendChangeAmount, respIgnore2.Leaf.RootSum)

	// Assert that the mempool is empty.
	mempool := t.lndHarness.Miner().GetRawMempool()
	require.Empty(t.t, mempool)

	// At this point, the supply commitment should not yet exist, as we
	// haven't created it after ignoring the asset outpoint.
	//
	// nolint: lll
	fetchRespNil, err := t.tapd.FetchSupplyCommit(
		ctxb, &unirpc.FetchSupplyCommitRequest{
			GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
				GroupKeyBytes: groupKeyBytes,
			},
			Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
				VeryFirst: true,
			},
		},
	)
	require.Nil(t.t, fetchRespNil)
	require.ErrorContains(t.t, err, "commitment not found")

	t.Log("Update on-chain supply commitment for asset group")

	// nolint: lll
	respUpdate, err := t.tapd.UpdateSupplyCommit(
		ctxb, &unirpc.UpdateSupplyCommitRequest{
			GroupKey: &unirpc.UpdateSupplyCommitRequest_GroupKeyBytes{
				GroupKeyBytes: groupKeyBytes,
			},
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, respUpdate)

	t.Log("Mining supply commitment tx")
	minedBlocks := MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	t.Log("Fetch updated supply commitment")

	// Ensure that the supply commitment reflects the ignored asset
	// outpoint owned by the secondary node.
	var fetchResp *unirpc.FetchSupplyCommitResponse
	require.Eventually(t.t, func() bool {
		// nolint: lll
		fetchResp, err = t.tapd.FetchSupplyCommit(
			ctxb, &unirpc.FetchSupplyCommitRequest{
				GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
					GroupKeyBytes: groupKeyBytes,
				},
				Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
					VeryFirst: true,
				},
			},
		)
		require.NoError(t.t, err)

		// If the fetch response has no block height or hash,
		// it means that the supply commitment transaction has not
		// been mined yet, so we should retry.
		if fetchResp.ChainData.BlockHeight == 0 ||
			len(fetchResp.ChainData.BlockHash) == 0 {

			return false
		}

		// Once the ignore tree includes the ignored asset outpoint, we
		// know that the supply commitment has been updated.
		if fetchResp.IgnoreSubtreeRoot == nil {
			return false
		}

		return fetchResp.IgnoreSubtreeRoot.RootNode.RootSum ==
			int64(sendAssetAmount+sendChangeAmount)
	}, defaultWaitTimeout, time.Second)

	// Verify that the supply commitment tree commits to the ignore subtree.
	supplyCommitRootHash := fn.ToArray[[32]byte](
		fetchResp.ChainData.SupplyRootHash,
	)

	// Formulate the ignore leaf node as it should appear in the supply
	// tree.
	supplyTreeIgnoreLeafNode := mssmt.NewLeafNode(
		fetchResp.IgnoreSubtreeRoot.RootNode.RootHash,
		uint64(fetchResp.IgnoreSubtreeRoot.RootNode.RootSum),
	)

	ignoreRootLeafKey := fn.ToArray[[32]byte](
		fetchResp.IgnoreSubtreeRoot.SupplyTreeLeafKey,
	)

	AssertInclusionProof(
		t, supplyCommitRootHash,
		fetchResp.IgnoreSubtreeRoot.SupplyTreeInclusionProof,
		ignoreRootLeafKey, supplyTreeIgnoreLeafNode,
	)

	// Now fetch the inclusion proofs using FetchSupplyLeaves instead of
	// FetchSupplyCommit.
	t.Log("Fetch supply leaves with inclusion proofs")
	// nolint: lll
	fetchLeavesResp, err := t.tapd.FetchSupplyLeaves(
		ctxb, &unirpc.FetchSupplyLeavesRequest{
			GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
				GroupKeyBytes: groupKeyBytes,
			},
			IgnoreLeafKeys: [][]byte{
				respIgnore.LeafKey,
				respIgnore2.LeafKey,
			},
		},
	)
	require.NoError(t.t, err)

	// Unmarshal ignore tree leaf inclusion proof to verify that the
	// ignored asset outpoint is included in the ignore tree.
	require.Len(t.t, fetchLeavesResp.IgnoreLeafInclusionProofs, 2)
	inclusionProofBytes := fetchLeavesResp.IgnoreLeafInclusionProofs[0]

	// Verify that the ignore tree root can be computed from the ignore leaf
	// inclusion proof.
	expectedIgnoreSubtreeRootHash := fn.ToArray[[32]byte](
		fetchResp.IgnoreSubtreeRoot.RootNode.RootHash,
	)

	ignoreLeafKey := fn.ToArray[[32]byte](respIgnore.LeafKey)
	ignoreLeaf := unmarshalMerkleSumNode(respIgnore.Leaf)

	AssertInclusionProof(
		t, expectedIgnoreSubtreeRootHash, inclusionProofBytes,
		ignoreLeafKey, ignoreLeaf,
	)

	// Verify that the mined supply commitment transaction commits to the
	// supply commitment tree.
	require.Len(t.t, minedBlocks, 1)

	block := minedBlocks[0]
	expectedBlockHash := block.BlockHash()

	// Get block height for block.
	blockHash, blockHeight := t.lndHarness.Miner().GetBestBlock()
	require.True(t.t, blockHash.IsEqual(&expectedBlockHash))

	// Ensure that the block hash and height matches the values in the fetch
	// response.
	fetchBlockHash, err := chainhash.NewHash(fetchResp.ChainData.BlockHash)
	require.NoError(t.t, err)
	require.True(t.t, fetchBlockHash.IsEqual(blockHash))

	require.EqualValues(t.t, blockHeight, fetchResp.ChainData.BlockHeight)

	// We expect two transactions in the block:
	// 1. The supply commitment transaction.
	// 2. The coinbase transaction.
	require.Len(t.t, block.Transactions, 2)

	internalKey, err := btcec.ParsePubKey(fetchResp.ChainData.InternalKey)
	require.NoError(t.t, err)

	expectedTxOut, _, err := supplycommit.RootCommitTxOut(
		internalKey, nil, supplyCommitRootHash,
	)
	require.NoError(t.t, err)

	foundCommitTxOut := false
	actualBlockTxIndex := 0
	for idx := range block.Transactions {
		tx := block.Transactions[idx]

		for idxOut := range tx.TxOut {
			txOut := tx.TxOut[idxOut]

			pkScriptMatch := bytes.Equal(
				txOut.PkScript, expectedTxOut.PkScript,
			)
			if txOut.Value == expectedTxOut.Value && pkScriptMatch {
				// Ensure that the target tx out is only present
				// once.
				if foundCommitTxOut {
					t.Fatalf("found multiple supply " +
						"commitment tx outputs in " +
						"block")
				}

				foundCommitTxOut = true
				actualBlockTxIndex = idx
			}
		}
	}

	require.True(t.t, foundCommitTxOut)
	require.EqualValues(
		t.t, actualBlockTxIndex, fetchResp.ChainData.TxIndex,
	)

	// If we try to ignore the same asset outpoint using the secondary
	// node, it should fail because the secondary node does not have access
	// to the supply commitment delegation key for signing.
	_, err = secondTapd.IgnoreAssetOutPoint(ctxb, ignoreReq)
	require.ErrorContains(t.t, err, "delegation key locator not found")

	// Fetch the supply leaves to ensure that the ignored asset outpoint is
	// included in the supply leaves.
	//
	// nolint: lll
	respLeaves, err := t.tapd.FetchSupplyLeaves(
		ctxb, &unirpc.FetchSupplyLeavesRequest{
			GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
				GroupKeyBytes: groupKeyBytes,
			},
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, respLeaves)

	require.Len(t.t, respLeaves.IgnoreLeaves, 2)

	ignoreLeafEntry := respLeaves.IgnoreLeaves[0]
	require.EqualValues(
		t.t, sendAssetAmount, ignoreLeafEntry.LeafNode.RootSum,
	)
	require.EqualValues(
		t.t, newIgnoreBlockHeight, ignoreLeafEntry.BlockHeight,
	)
	require.True(
		t.t, bytes.Equal(
			rpcAsset.AssetGenesis.AssetId,
			ignoreLeafEntry.LeafKey.AssetId,
		),
		"asset ID mismatch in ignore leaf",
	)
	require.True(
		t.t, bytes.Equal(
			transferOutput.ScriptKey[1:],
			ignoreLeafEntry.LeafKey.ScriptKey,
		),
		"asset script key mismatch in ignore leaf",
	)

	ignoreLeafEntry2 := respLeaves.IgnoreLeaves[1]
	require.EqualValues(
		t.t, sendChangeAmount, ignoreLeafEntry2.LeafNode.RootSum,
	)

	transferOutPoint, err := wire.NewOutPointFromString(
		transferOutput.Anchor.Outpoint,
	)
	require.Equal(
		t.t, transferOutPoint.Hash.String(),
		ignoreLeafEntry.LeafKey.Outpoint.HashStr,
	)
	require.EqualValues(
		t.t, transferOutPoint.Index,
		ignoreLeafEntry.LeafKey.Outpoint.Index,
	)

	// We now add our change output to the ignore list as well, then try to
	// spend it.
	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: rpcAsset.AssetGenesis.AssetId,
		Amt:     sendChangeAmount / 2,
	})
	require.NoError(t.t, err)
	sendAsset(
		t, t.tapd, withReceiverAddresses(bobAddr),
		withError("is ignored"),
	)

	t.Log("Fetch first supply commitment from universe server")

	// Ensure that the supply commitment was pushed to the universe server
	// and that it is retrievable.
	var uniFetchResp *unirpc.FetchSupplyCommitResponse
	require.Eventually(t.t, func() bool {
		// nolint: lll
		uniFetchResp, err = t.universeServer.service.FetchSupplyCommit(
			ctxb, &unirpc.FetchSupplyCommitRequest{
				GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
					GroupKeyBytes: groupKeyBytes,
				},
				Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
					VeryFirst: true,
				},
			},
		)
		require.NoError(t.t, err)

		// If the fetch response does not include a block height, the
		// supply commitment transaction has not been mined yet, so we
		// should retry.
		if uniFetchResp.ChainData.BlockHeight == 0 {
			return false
		}

		return true
	}, defaultWaitTimeout, time.Second)

	// Assert universe supply commitment fetch response.
	require.Len(t.t, uniFetchResp.IssuanceLeaves, 1)
	require.Len(t.t, uniFetchResp.BurnLeaves, 0)
	require.Len(t.t, uniFetchResp.IgnoreLeaves, 2)

	// Assert issuance leaf properties.
	issuanceLeaf := uniFetchResp.IssuanceLeaves[0]
	require.EqualValues(
		t.t, rpcAsset.Amount, issuanceLeaf.LeafNode.RootSum,
	)

	// Assert ignored leaf properties.
	//
	// Determine which ignore leaf was the first one we added, so we
	// can assert its properties.
	firstIgnoreLeaf := uniFetchResp.IgnoreLeaves[0]
	secondIgnoreLeaf := uniFetchResp.IgnoreLeaves[1]
	if firstIgnoreLeaf.LeafNode.RootSum != int64(ignoreAmt) {
		firstIgnoreLeaf, secondIgnoreLeaf = secondIgnoreLeaf,
			firstIgnoreLeaf
	}

	require.EqualValues(t.t, ignoreAmt, firstIgnoreLeaf.LeafNode.RootSum)
	require.EqualValues(
		t.t, rpcAsset.Amount-sendAssetAmount,
		uint32(secondIgnoreLeaf.LeafNode.RootSum),
	)

	// Assert supply subtree root properties.
	require.NotNil(t.t, uniFetchResp.IssuanceSubtreeRoot)
	require.NotNil(t.t, uniFetchResp.BurnSubtreeRoot)
	require.NotNil(t.t, uniFetchResp.IgnoreSubtreeRoot)

	// Assert that the issuance subtree root sum matches the total
	// amount of issued assets.
	require.EqualValues(
		t.t, rpcAsset.Amount,
		uniFetchResp.IssuanceSubtreeRoot.RootNode.RootSum,
	)

	// Assert that the burn subtree root sum is zero, as no assets have
	// been burned.
	require.EqualValues(
		t.t, 0,
		uniFetchResp.BurnSubtreeRoot.RootNode.RootSum,
	)

	// Assert that the ignore subtree root sum equals the total issued
	// amount, since the entire issuance has been recorded as ignored.
	require.EqualValues(
		t.t, rpcAsset.Amount,
		uniFetchResp.IgnoreSubtreeRoot.RootNode.RootSum,
	)
}

// AssertInclusionProof checks that the inclusion proof for a given leaf key
// and leaf node matches the expected root hash.
func AssertInclusionProof(t *harnessTest, expectedRootHash [32]byte,
	inclusionProofBytes []byte, leafKey [32]byte, leafNode mssmt.Node) {

	t.t.Helper()

	// Decode the inclusion proof bytes into a compressed proof.
	var compressedProof mssmt.CompressedProof
	err := compressedProof.Decode(bytes.NewReader(inclusionProofBytes))
	require.NoError(t.t, err)

	// Decompress the inclusion proof to get the full proof structure.
	inclusionProof, err := compressedProof.Decompress()
	require.NoError(t.t, err)

	// Derive the root from the inclusion proof and the leaf node.
	derivedRoot := inclusionProof.Root(leafKey, leafNode)
	derivedRootHash := fn.ByteSlice(derivedRoot.NodeHash())

	// Verify that the derived root hash matches the expected root hash.
	if !bytes.Equal(expectedRootHash[:], derivedRootHash) {
		t.t.Fatalf("expected root hash %x, got %x",
			expectedRootHash[:], derivedRootHash)
	}
}

// AssertSubtreeInclusionProof verifies that a subtree is properly included in
// the supply commitment tree by checking the inclusion proof.
func AssertSubtreeInclusionProof(t *harnessTest,
	supplyRootHash []byte, subtreeRoot *unirpc.SupplyCommitSubtreeRoot) {

	require.NotNil(t.t, subtreeRoot)

	// Convert to fixed-size arrays for verification.
	rootHash := fn.ToArray[[32]byte](supplyRootHash)
	leafKey := fn.ToArray[[32]byte](subtreeRoot.SupplyTreeLeafKey)

	// Create the leaf node for the subtree.
	leafNode := mssmt.NewLeafNode(
		subtreeRoot.RootNode.RootHash,
		uint64(subtreeRoot.RootNode.RootSum),
	)

	// Verify the inclusion proof.
	AssertInclusionProof(
		t, rootHash,
		subtreeRoot.SupplyTreeInclusionProof,
		leafKey, leafNode,
	)
}

// MintAssetWithSupplyCommit mints an asset with supply commitments enabled
// and verifies the pre-commitment output.
func MintAssetWithSupplyCommit(t *harnessTest,
	mintReq *mintrpc.MintAssetRequest,
	expectedDelegationKey fn.Option[btcec.PublicKey],
) (*taprpc.Asset, btcec.PublicKey) {

	// Ensure supply commitments are enabled.
	mintReq.Asset.EnableSupplyCommitments = true

	// Mint the asset.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)
	require.Len(t.t, rpcAssets, 1, "expected one minted asset")
	rpcAsset := rpcAssets[0]

	// Verify the pre-commitment output.
	delegationKey := assertAnchorTxPreCommitOut(
		t, t.tapd, rpcAsset, expectedDelegationKey,
	)

	return rpcAsset, delegationKey
}
