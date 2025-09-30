package itest

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/itest/rpcassert"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
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
//  3. Instructs the primary node to ignore both the transfer output and change
//     output from the transfer.
//  4. Updates the asset group's supply commitment, which should now include
//     the ignored outpoints in the "ignore" subtree.
//  5. Mines the commitment transaction.
//  6. Retrieves the updated supply commitment transaction and asserts that the
//     ignored subtree contains the expected outpoints.
//  7. Verifies inclusion proofs for the ignored assets in the supply commitment
//     tree.
//  8. Verifies that the mined transaction correctly commits to the supply
//     commitment tree.
//  9. Attempts to ignore the same asset outpoint from the secondary node
//     (should fail due to lack of delegation key).
//  10. Attempts to spend the ignored change output (should fail).
//  11. Verifies that the supply commitment is retrievable from the universe
//     server.
//  12. Verifies that the supply commitment is retrievable from the secondary
//     node after it has synced the supply commitment.
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
	fetchPredicate := func(resp *unirpc.FetchSupplyCommitResponse) error {
		// If the fetch response has no block height or hash,
		// it means that the supply commitment transaction has not
		// been mined yet, so we should retry.
		if resp.ChainData.BlockHeight == 0 ||
			len(resp.ChainData.BlockHash) == 0 {

			return fmt.Errorf("supply commitment transaction not " +
				"mined yet")
		}

		// Once the ignore tree includes the ignored asset outpoint, we
		// know that the supply commitment has been updated.
		if resp.IgnoreSubtreeRoot == nil {
			return fmt.Errorf("IgnoreSubtreeRoot is nil")
		}

		expectedSum := int64(sendAssetAmount + sendChangeAmount)
		actualSum := resp.IgnoreSubtreeRoot.RootNode.RootSum
		if actualSum != expectedSum {
			return fmt.Errorf("expected RootSum %d, got %d",
				expectedSum, actualSum)
		}

		return nil
	}
	req := unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
			VeryFirst: true,
		},
	}
	fetchResp = rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, t.tapd, fetchPredicate, &req,
	)

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
	require.NoError(t.t, err)
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
	uniFetchPred := func(resp *unirpc.FetchSupplyCommitResponse) error {
		// If the fetch response does not include a block height, the
		// supply commitment transaction has not been mined yet, so we
		// should retry.
		if resp.ChainData.BlockHeight == 0 {
			return fmt.Errorf("supply commitment transaction not " +
				"mined yet")
		}

		return nil
	}
	req = unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
			VeryFirst: true,
		},
	}
	uniFetchResp := rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, t.universeServer.service, uniFetchPred, &req,
	)

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

	t.Log("Attempting to fetch supply commit from secondary node")

	var peerFetchResp *unirpc.FetchSupplyCommitResponse
	require.Eventually(t.t, func() bool {
		// nolint: lll
		peerFetchResp, err = secondTapd.FetchSupplyCommit(
			ctxb, &unirpc.FetchSupplyCommitRequest{
				GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
					GroupKeyBytes: groupKeyBytes,
				},
				Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
					VeryFirst: true,
				},
			},
		)
		if err != nil &&
			strings.Contains(err.Error(), "commitment not found") {

			return false
		}
		require.NoError(t.t, err)

		// If the fetch response has no block height or hash,
		// it means that the supply commitment transaction has not
		// been mined yet, so we should retry.
		if peerFetchResp.ChainData.BlockHeight == 0 ||
			len(peerFetchResp.ChainData.BlockHash) == 0 {

			return false
		}

		// Once the ignore tree includes the ignored asset outpoint, we
		// know that the supply commitment has been updated.
		if peerFetchResp.IgnoreSubtreeRoot == nil {
			return false
		}

		return true
	}, defaultWaitTimeout, time.Second)

	require.NotNil(t.t, peerFetchResp)
	require.Len(t.t, peerFetchResp.IssuanceLeaves, 1)
	require.Len(t.t, peerFetchResp.BurnLeaves, 0)
	require.Len(t.t, peerFetchResp.IgnoreLeaves, 2)

	require.EqualValues(
		t.t, rpcAsset.Amount,
		peerFetchResp.IssuanceLeaves[0].LeafNode.RootSum,
	)
	require.EqualValues(
		t.t, rpcAsset.Amount,
		peerFetchResp.IgnoreSubtreeRoot.RootNode.RootSum,
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

// assertFetchCommitResponse compares two FetchSupplyCommitResponse objects
// and asserts that their key fields match. This is a helper function to reduce
// repetitive assertions in tests.
func assertFetchCommitResponse(t *harnessTest, expected,
	actual *unirpc.FetchSupplyCommitResponse) {

	t.t.Helper()

	require.NotNil(t.t, expected)
	require.NotNil(t.t, actual)

	require.NotNil(t.t, expected.ChainData)
	require.NotNil(t.t, actual.ChainData)

	require.Equal(
		t.t, expected.ChainData.BlockHeight,
		actual.ChainData.BlockHeight,
		"block height mismatch",
	)
	require.True(
		t.t, bytes.Equal(
			expected.ChainData.BlockHash,
			actual.ChainData.BlockHash,
		),
		"block hash mismatch",
	)
	require.True(
		t.t, bytes.Equal(
			expected.ChainData.SupplyRootHash,
			actual.ChainData.SupplyRootHash,
		),
		"supply root hash mismatch",
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

// testSupplyCommitMintBurn tests that supply commitment trees are correctly
// updated when minting assets with group keys and burning outputs. It verifies:
//
//  1. Minting assets with EnableSupplyCommitments creates proper pre-commitment
//     outputs and updates the supply tree with mint leaves.
//  2. Re-issuing assets to the same group updates the supply tree correctly.
//  3. Burning assets creates burn leaves in the supply tree with negative
//     amounts.
//  4. All operations produce valid inclusion proofs that can be verified.
func testSupplyCommitMintBurn(t *harnessTest) {
	ctxb := context.Background()

	t.Log("Minting initial asset group with universe/supply " +
		"commitments enabled")

	// Create a mint request for a grouped asset with supply commitments.
	mintReq := CopyRequest(issuableAssets[0])
	mintReq.Asset.Amount = 5000

	t.Log("Minting asset with supply commitments and verifying " +
		"pre-commitment")

	rpcFirstAsset, delegationKey := MintAssetWithSupplyCommit(
		t, mintReq, fn.None[btcec.PublicKey](),
	)

	// Parse out the group key from the minted asset, we'll use this later.
	groupKeyBytes := rpcFirstAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)

	// Update the on-chain supply commitment for the asset group.
	//
	// TODO(roasbeef): still rely on the time based ticker here?
	t.Log("Create first supply commitment tx for asset group")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	// Fetch the latest supply commitment for the asset group.
	t.Log("Fetching first supply commitment to verify mint leaves")
	fetchResp, supplyOutpoint := WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.None[wire.OutPoint](),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.ChainData.BlockHeight > 0 &&
				len(resp.ChainData.BlockHash) > 0
		},
	)

	// Verify the issuance subtree root exists and has the correct amount.
	require.NotNil(t.t, fetchResp.IssuanceSubtreeRoot)
	require.Equal(
		t.t, int64(mintReq.Asset.Amount),
		fetchResp.IssuanceSubtreeRoot.RootNode.RootSum,
	)

	// Verify the issuance leaf inclusion in the supply tree.
	AssertSubtreeInclusionProof(
		t, fetchResp.ChainData.SupplyRootHash,
		fetchResp.IssuanceSubtreeRoot,
	)

	// Now we'll mint a second asset into the same group, this tests that
	// we're able to properly update the supply commitment with new mints.
	t.Log("Minting second tranche into the same asset group")

	secondMintReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "itestbuxx-supply-commit-tranche-2",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("second tranche metadata"),
			},
			Amount:                  3000,
			AssetVersion:            taprpc.AssetVersion_ASSET_VERSION_V1, //nolint:lll
			NewGroupedAsset:         false,
			GroupedAsset:            true,
			GroupKey:                groupKeyBytes,
			EnableSupplyCommitments: true,
		},
	}
	rpcSecondAsset, _ := MintAssetWithSupplyCommit(
		t, secondMintReq, fn.Some(delegationKey),
	)

	// Ensure both assets are in the same group.
	require.EqualValues(
		t.t, groupKeyBytes,
		rpcSecondAsset.AssetGroup.TweakedGroupKey,
	)

	t.Log("Updating supply commitment after second mint")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	t.Log("Verifying supply tree includes both mint operations")

	// Fetch and verify the updated supply includes both mints.
	expectedTotal := int64(
		mintReq.Asset.Amount + secondMintReq.Asset.Amount,
	)
	fetchResp, supplyOutpoint = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(supplyOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.IssuanceSubtreeRoot != nil &&
				resp.IssuanceSubtreeRoot.RootNode.RootSum == expectedTotal //nolint:lll
		},
	)

	// Finally, we'll test burning assets from the group, and ensure that
	// the supply tree is updated with this information.
	t.Log("Burning assets from the group")

	const (
		burnAmt  = 1000
		burnNote = "supply commit burn test"
	)

	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: rpcFirstAsset.AssetGenesis.AssetId,
		},
		AmountToBurn:     burnAmt,
		Note:             burnNote,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)
	require.NotNil(t.t, burnResp)

	t.Log("Confirming burn transaction")

	// Confirm the burn transaction, asserting that all the expected records
	// on disk are in place.
	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd, burnResp.BurnTransfer,
		[][]byte{rpcFirstAsset.AssetGenesis.AssetId},
		[]uint64{mintReq.Asset.Amount - burnAmt, burnAmt},
		0, 1, 2, true,
	)

	// Make sure that the burn is recognized in the burn records.
	burns := AssertNumBurns(t.t, t.tapd, 1, nil)
	burn := burns[0]
	require.Equal(t.t, uint64(burnAmt), burn.Amount)
	require.Equal(t.t, burnNote, burn.Note)

	t.Log("Updating supply commitment after burn")

	// Update and mine the supply commitment after burn.
	finalMinedBlocks := UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	t.Log("Verifying supply tree includes burn leaves")

	// Fetch and verify the supply tree now includes burn leaves.
	fetchResp, _ = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(supplyOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.BurnSubtreeRoot != nil &&
				resp.BurnSubtreeRoot.RootNode.RootSum == int64(burnAmt) //nolint:lll
		},
	)

	// Verify the burn subtree inclusion in the supply tree.
	AssertSubtreeInclusionProof(
		t, fetchResp.ChainData.SupplyRootHash,
		fetchResp.BurnSubtreeRoot,
	)

	t.Log("Fetching supply leaves for detailed verification")

	// Fetch supply leaves to verify individual entries have all been
	// properly committed.
	respLeaves, err := t.tapd.FetchSupplyLeaves(
		ctxb, &unirpc.FetchSupplyLeavesRequest{
			GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{ //nolint:lll
				GroupKeyBytes: groupKeyBytes,
			},
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, respLeaves)

	// Verify we have the expected issuance leaves (2 mints), and a single
	// burn leaf.
	require.Equal(
		t.t, len(respLeaves.IssuanceLeaves), 2,
		"expected at least 2 issuance leaves",
	)
	require.Equal(
		t.t, len(respLeaves.BurnLeaves), 1,
		"expected at least 1 burn leaf",
	)

	// Make sure that the burn leaf has the proper amount.
	foundBurn := false
	for _, burnLeaf := range respLeaves.BurnLeaves {
		if burnLeaf.LeafNode.RootSum == int64(burnAmt) {
			foundBurn = true

			require.True(t.t, bytes.Equal(
				rpcFirstAsset.AssetGenesis.AssetId,
				burnLeaf.LeafKey.AssetId,
			), "burn leaf asset ID mismatch")
			break
		}
	}
	require.True(t.t, foundBurn, "expected burn leaf not found")

	// Finally, we'll verify that the final supply commitment has the
	// pkScript that we expect.
	require.Len(t.t, finalMinedBlocks, 1, "expected one mined block")
	block := finalMinedBlocks[0]
	blockHash, _ := t.lndHarness.Miner().GetBestBlock()

	fetchBlockHash, err := chainhash.NewHash(fetchResp.ChainData.BlockHash)
	require.NoError(t.t, err)
	require.True(t.t, fetchBlockHash.IsEqual(blockHash))

	// Re-compute the supply commitment root hash from the latest fetch,
	// then use that to derive the expected commitment output.
	supplyCommitRootHash := fn.ToArray[[32]byte](
		fetchResp.ChainData.SupplyRootHash,
	)
	internalKey, err := btcec.ParsePubKey(fetchResp.ChainData.InternalKey)
	require.NoError(t.t, err)
	expectedTxOut, _, err := supplycommit.RootCommitTxOut(
		internalKey, nil, supplyCommitRootHash,
	)
	require.NoError(t.t, err)

	foundCommitTxOut := false
	for _, tx := range block.Transactions {
		for _, txOut := range tx.TxOut {
			pkScriptMatch := bytes.Equal(
				txOut.PkScript, expectedTxOut.PkScript,
			)
			if txOut.Value == expectedTxOut.Value && pkScriptMatch {
				foundCommitTxOut = true
				break
			}
		}
		if foundCommitTxOut {
			break
		}
	}
	require.True(
		t.t, foundCommitTxOut,
		"supply commitment tx output not found in block",
	)

	t.Log("Supply commit mint and burn test completed successfully")
}

// testFetchSupplyLeaves tests the FetchSupplyLeaves RPC endpoint by:
//
//  1. Minting an asset group with supply commitments enabled.
//  2. Calling FetchSupplyLeaves to verify initial mint leaves.
//  3. Burning some of the asset and updating the supply commit.
//  4. Calling FetchSupplyLeaves to verify burn leaves are included.
//  5. Minting another tranche into the same group.
//  6. Calling FetchSupplyLeaves to verify all leaves are present.
//  7. Testing inclusion proof generation for various leaf types.
func testFetchSupplyLeaves(t *harnessTest) {
	ctxb := context.Background()

	t.Log("Minting initial asset group with supply commitments enabled")
	mintReq := CopyRequest(issuableAssets[0])
	mintReq.Asset.Amount = 8000

	rpcFirstAsset, _ := MintAssetWithSupplyCommit(
		t, mintReq, fn.None[btcec.PublicKey](),
	)

	groupKeyBytes := rpcFirstAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)

	t.Log("Creating first supply commitment transaction")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	t.Log("Waiting for first supply commitment to be mined")
	_, supplyOutpoint := WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.None[wire.OutPoint](),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.ChainData.BlockHeight > 0 &&
				len(resp.ChainData.BlockHash) > 0
		},
	)

	t.Log("Fetching supply leaves after initial mint")
	req := unirpc.FetchSupplyLeavesRequest{
		GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
	}
	leavesResp1, err := t.tapd.FetchSupplyLeaves(ctxb, &req)
	require.NoError(t.t, err)
	require.NotNil(t.t, leavesResp1)

	// Verify we have one issuance leaf and no burn/ignore leaves.
	require.Len(
		t.t, leavesResp1.IssuanceLeaves, 1,
		"expected 1 issuance leaf after first mint",
	)
	require.Len(
		t.t, leavesResp1.BurnLeaves, 0,
		"expected 0 burn leaves after first mint",
	)
	require.Len(
		t.t, leavesResp1.IgnoreLeaves, 0,
		"expected 0 ignore leaves after first mint",
	)

	// Verify the issuance leaf amount.
	issuanceLeaf1 := leavesResp1.IssuanceLeaves[0]
	require.EqualValues(
		t.t, mintReq.Asset.Amount, issuanceLeaf1.LeafNode.RootSum,
		"issuance leaf amount mismatch",
	)

	t.Log("Burning portion of the asset")
	const (
		burnAmt  = 1500
		burnNote = "FetchSupplyLeaves burn test"
	)

	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: rpcFirstAsset.AssetGenesis.AssetId,
		},
		AmountToBurn:     burnAmt,
		Note:             burnNote,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)
	require.NotNil(t.t, burnResp)

	t.Log("Confirming burn transaction")
	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd, burnResp.BurnTransfer,
		[][]byte{rpcFirstAsset.AssetGenesis.AssetId},
		[]uint64{mintReq.Asset.Amount - burnAmt, burnAmt},
		0, 1, 2, true,
	)

	t.Log("Updating supply commitment after burn")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	// Wait for the supply commitment to include the burn.
	_, supplyOutpoint = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(supplyOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			if resp.BurnSubtreeRoot == nil {
				return false
			}

			actualBurnSum := resp.BurnSubtreeRoot.RootNode.RootSum
			return actualBurnSum == int64(burnAmt)
		},
	)

	t.Log("Fetching supply leaves after burn")
	req = unirpc.FetchSupplyLeavesRequest{
		GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
	}
	leavesResp2, err := t.tapd.FetchSupplyLeaves(ctxb, &req)
	require.NoError(t.t, err)
	require.NotNil(t.t, leavesResp2)

	// Verify we have one issuance leaf and one burn leaf.
	require.Len(
		t.t, leavesResp2.IssuanceLeaves, 1,
		"expected 1 issuance leaf after burn",
	)
	require.Len(
		t.t, leavesResp2.BurnLeaves, 1,
		"expected 1 burn leaf after burn",
	)
	require.Len(
		t.t, leavesResp2.IgnoreLeaves, 0,
		"expected 0 ignore leaves after burn",
	)

	burnLeaf := leavesResp2.BurnLeaves[0]
	require.EqualValues(t.t, burnAmt, burnLeaf.LeafNode.RootSum,
		"burn leaf amount mismatch")

	t.Log("Minting second tranche into the same asset group")
	secondMintReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "itestbuxx-fetchsupplyleaves-tranche-2",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("second tranche for " +
					"FetchSupplyLeaves test"),
			},
			Amount:          3500,
			AssetVersion:    taprpc.AssetVersion_ASSET_VERSION_V1,
			NewGroupedAsset: false,
			GroupedAsset:    true,
			GroupKey:        groupKeyBytes,

			EnableSupplyCommitments: true,
		},
	}

	rpcSecondAsset := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{secondMintReq},
	)
	require.Len(t.t, rpcSecondAsset, 1, "expected one minted asset")
	require.EqualValues(
		t.t, groupKeyBytes,
		rpcSecondAsset[0].AssetGroup.TweakedGroupKey,
	)

	t.Log("Updating supply commitment after second mint")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	// Wait for the supply commitment to include both mints.
	expectedIssuanceTotal := int64(
		mintReq.Asset.Amount + secondMintReq.Asset.Amount,
	)
	_, _ = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(supplyOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.IssuanceSubtreeRoot != nil &&
				resp.IssuanceSubtreeRoot.RootNode.RootSum ==
					expectedIssuanceTotal
		},
	)

	t.Log("Fetching supply leaves after second mint")
	req = unirpc.FetchSupplyLeavesRequest{
		GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
	}
	leavesResp3, err := t.tapd.FetchSupplyLeaves(ctxb, &req)
	require.NoError(t.t, err)
	require.NotNil(t.t, leavesResp3)

	// Verify we have two issuance leaves and one burn leaf.
	require.Len(
		t.t, leavesResp3.IssuanceLeaves, 2,
		"expected 2 issuance leaves after second mint",
	)
	require.Len(
		t.t, leavesResp3.BurnLeaves, 1,
		"expected 1 burn leaf after second mint",
	)
	require.Len(
		t.t, leavesResp3.IgnoreLeaves, 0,
		"expected 0 ignore leaves after second mint",
	)

	// Verify the total issuance amount across both leaves.
	totalIssuanceAmount := int64(0)
	for _, leaf := range leavesResp3.IssuanceLeaves {
		totalIssuanceAmount += leaf.LeafNode.RootSum
	}
	require.EqualValues(
		t.t, expectedIssuanceTotal, totalIssuanceAmount,
		"total issuance amount mismatch",
	)

	t.Log("Testing inclusion proof generation for supply leaves")

	// Collect leaf keys for inclusion proof request.
	var issuanceLeafKeys [][]byte
	var burnLeafKeys [][]byte
	for _, leaf := range leavesResp3.IssuanceLeaves {
		issuanceLeafKeys = append(
			issuanceLeafKeys,
			unmarshalRPCSupplyLeafKey(t.t, leaf.LeafKey),
		)
	}
	for _, leaf := range leavesResp3.BurnLeaves {
		burnLeafKeys = append(
			burnLeafKeys,
			unmarshalRPCSupplyLeafKey(t.t, leaf.LeafKey),
		)
	}

	// Request supply leaves with inclusion proofs.
	req = unirpc.FetchSupplyLeavesRequest{
		GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		IssuanceLeafKeys: issuanceLeafKeys,
		BurnLeafKeys:     burnLeafKeys,
	}
	leavesRespWithProofs, err := t.tapd.FetchSupplyLeaves(ctxb, &req)
	require.NoError(t.t, err)
	require.NotNil(t.t, leavesRespWithProofs)

	// Verify that inclusion proofs are provided.
	require.Len(
		t.t, leavesRespWithProofs.IssuanceLeafInclusionProofs,
		len(issuanceLeafKeys),
		"expected inclusion proofs for all issuance leaf keys",
	)
	require.Len(
		t.t, leavesRespWithProofs.BurnLeafInclusionProofs,
		len(burnLeafKeys),
		"expected inclusion proofs for all burn leaf keys",
	)

	t.Log("Verifying inclusion proof validity")

	// Fetch the current supply commitment to get the subtree roots.
	reqFetchCommit := unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_Latest{
			Latest: true,
		},
	}
	fetchResp, err := t.tapd.FetchSupplyCommit(ctxb, &reqFetchCommit)
	require.NoError(t.t, err)
	require.NotNil(t.t, fetchResp)

	// Verify issuance leaf inclusion proofs.
	inclusionProofs := leavesRespWithProofs.IssuanceLeafInclusionProofs
	for i, proofBytes := range inclusionProofs {
		leafKey := fn.ToArray[[32]byte](issuanceLeafKeys[i])
		leafNode := unmarshalMerkleSumNode(
			leavesRespWithProofs.IssuanceLeaves[i].LeafNode,
		)

		expectedSubtreeRootHash := fn.ToArray[[32]byte](
			fetchResp.IssuanceSubtreeRoot.RootNode.RootHash,
		)

		AssertInclusionProof(
			t, expectedSubtreeRootHash, proofBytes,
			leafKey, leafNode,
		)
	}

	// Verify burn leaf inclusion proofs.
	inclusionProofs = leavesRespWithProofs.BurnLeafInclusionProofs
	for i, proofBytes := range inclusionProofs {
		leafKey := fn.ToArray[[32]byte](burnLeafKeys[i])
		leafNode := unmarshalMerkleSumNode(
			leavesRespWithProofs.BurnLeaves[i].LeafNode,
		)

		expectedSubtreeRootHash := fn.ToArray[[32]byte](
			fetchResp.BurnSubtreeRoot.RootNode.RootHash,
		)

		AssertInclusionProof(
			t, expectedSubtreeRootHash, proofBytes,
			leafKey, leafNode,
		)
	}
}

// unmarshalRPCSupplyLeafKey converts a *unirpc.SupplyLeafKey to a byte slice
// using the same method as the universe key serialization.
func unmarshalRPCSupplyLeafKey(t *testing.T,
	leafKey *unirpc.SupplyLeafKey) []byte {

	t.Helper()

	hash, err := chainhash.NewHashFromStr(leafKey.Outpoint.HashStr)
	require.NoError(t, err)

	outpoint := wire.OutPoint{
		Hash:  *hash,
		Index: uint32(leafKey.Outpoint.Index),
	}

	scriptKeyPubKey, err := schnorr.ParsePubKey(leafKey.ScriptKey)
	require.NoError(t, err)

	scriptKey := asset.NewScriptKey(scriptKeyPubKey)

	assetID := fn.ToArray[[32]byte](leafKey.AssetId)
	assetLeafKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  outpoint,
			ScriptKey: &scriptKey,
		},
		AssetID: assetID,
	}

	universeKey := assetLeafKey.UniverseKey()
	return universeKey[:]
}

// testSupplyVerifyPeerNode verifies that a secondary node can sync and fetch
// multiple supply commitments published by the primary node. It:
//
//  1. Mints an asset group with universe supply commitments enabled.
//  2. Publishes the first supply commitment and mines it.
//  3. Sends some of the asset to a secondary node.
//  4. Verifies the secondary node can fetch the first supply commitment.
//  5. Ignores the asset outpoint sent to the secondary node.
//  6. Publishes the second supply commitment and mines it.
//  7. Verifies the secondary node can fetch the updated supply commitment.
//  8. Primary node mints another asset into the group and publishes the
//     third supply commitment.
//  9. Verifies the secondary node can fetch the third supply commitment.
func testSupplyVerifyPeerNode(t *harnessTest) {
	ctxb := context.Background()

	t.Log("Minting initial asset group with universe/supply " +
		"commitments enabled")

	// Create a mint request for a grouped asset with supply commitments.
	firstMintReq := CopyRequest(issuableAssets[0])
	firstMintReq.Asset.Amount = 5000

	rpcFirstAsset, _ := MintAssetWithSupplyCommit(
		t, firstMintReq, fn.None[btcec.PublicKey](),
	)

	// Parse out the group key from the minted asset.
	groupKeyBytes := rpcFirstAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)

	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	t.Log("Fetching first supply commitment to verify mint leaves")
	fetchResp, supplyOutpoint := WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.None[wire.OutPoint](),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.ChainData.BlockHeight > 0 &&
				len(resp.ChainData.BlockHash) > 0
		},
	)

	// Verify the issuance subtree root exists and has the correct amount.
	require.NotNil(t.t, fetchResp.IssuanceSubtreeRoot)
	require.Equal(
		t.t, int64(firstMintReq.Asset.Amount),
		fetchResp.IssuanceSubtreeRoot.RootNode.RootSum,
	)

	t.Log("Setting up secondary node as recipient of asset")
	secondLnd := t.lndHarness.NewNodeWithCoins("SecondLnd", nil)
	secondTapd := setupTapdHarness(t.t, t, secondLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	t.Log("Sending asset to secondary node")
	sendAssetAmount := uint64(1000)
	sendChangeAmount := rpcFirstAsset.Amount - sendAssetAmount

	sendResp := sendAssetAndAssert(
		ctxb, t, t.tapd, secondTapd, sendAssetAmount, sendChangeAmount,
		rpcFirstAsset.AssetGenesis, rpcFirstAsset, 0, 1, 1,
	)
	require.Len(t.t, sendResp.RpcResp.Transfer.Outputs, 2)
	t.Log("Asset transfer completed successfully")

	t.Log("Verifying secondary node can fetch first supply commitment")
	var peerFetchResp *unirpc.FetchSupplyCommitResponse
	peerFetchPred := func(resp *unirpc.FetchSupplyCommitResponse) error {
		// Check if the supply commitment has been mined.
		if resp.ChainData.BlockHeight == 0 ||
			len(resp.ChainData.BlockHash) == 0 {

			return fmt.Errorf("supply commitment transaction not " +
				"mined yet")
		}

		return nil
	}
	req := unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
			VeryFirst: true,
		},
	}
	peerFetchResp = rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, secondTapd, peerFetchPred, &req,
	)

	require.Equal(
		t.t, int64(firstMintReq.Asset.Amount),
		peerFetchResp.IssuanceSubtreeRoot.RootNode.RootSum,
	)

	t.Log("Ignoring asset outpoint sent to secondary node")

	// Determine the transfer output owned by the secondary node.
	// This is the output that we will ignore.
	transferOutput := sendResp.RpcResp.Transfer.Outputs[0]
	if sendResp.RpcResp.Transfer.Outputs[1].Amount == sendAssetAmount {
		transferOutput = sendResp.RpcResp.Transfer.Outputs[1]
	}

	// Ignore the asset outpoint owned by the secondary node.
	ignoreReq := &unirpc.IgnoreAssetOutPointRequest{
		AssetOutPoint: &taprpc.AssetOutPoint{
			AnchorOutPoint: transferOutput.Anchor.Outpoint,
			AssetId:        rpcFirstAsset.AssetGenesis.AssetId,
			ScriptKey:      transferOutput.ScriptKey,
		},
		Amount: sendAssetAmount,
	}
	respIgnore, err := t.tapd.IgnoreAssetOutPoint(ctxb, ignoreReq)
	require.NoError(t.t, err)
	require.NotNil(t.t, respIgnore)
	require.EqualValues(t.t, sendAssetAmount, respIgnore.Leaf.RootSum)

	t.Log("Updating supply commitment after ignoring asset outpoint")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	t.Log("Verifying retrieval of second supply commitment from primary " +
		"node")
	fetchResp, supplyOutpoint = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(supplyOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			ignoreRoot := resp.IgnoreSubtreeRoot
			if ignoreRoot == nil {
				return false
			}

			// Check if the supply commitment has been updated with
			// ignored assets.
			return ignoreRoot.RootNode.RootSum ==
				int64(sendAssetAmount)
		},
	)

	require.Equal(
		t.t, int64(sendAssetAmount),
		fetchResp.IgnoreSubtreeRoot.RootNode.RootSum,
	)

	t.Log("Verifying retrieval of second supply commitment from universe " +
		"server")
	var uniFetchResp *unirpc.FetchSupplyCommitResponse
	uniFetchPred2 := func(resp *unirpc.FetchSupplyCommitResponse) error {
		if resp.IgnoreSubtreeRoot == nil {
			return fmt.Errorf("IgnoreSubtreeRoot is nil")
		}

		// Check if the supply commitment has been updated with ignored
		// assets.
		expectedSum := int64(sendAssetAmount)
		actualSum := resp.IgnoreSubtreeRoot.RootNode.RootSum
		if actualSum != expectedSum {
			return fmt.Errorf("expected RootSum %d, got %d",
				expectedSum, actualSum)
		}

		return nil
	}
	req = unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_SpentCommitOutpoint{
			SpentCommitOutpoint: fetchResp.SpentCommitmentOutpoint,
		},
	}
	uniFetchResp = rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, t.universeServer.service, uniFetchPred2, &req,
	)

	require.Equal(
		t.t, int64(sendAssetAmount),
		uniFetchResp.IgnoreSubtreeRoot.RootNode.RootSum,
	)

	// Verify that the universe server's supply commitment matches the
	// primary's.
	assertFetchCommitResponse(t, fetchResp, uniFetchResp)

	// If we query for the latest supply commitment from the universe server
	// we should get the same result as well.
	req = unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_Latest{
			Latest: true,
		},
	}
	uniFetchRespLatest, err := t.universeServer.service.FetchSupplyCommit(
		ctxb, &req,
	)
	require.NoError(t.t, err)
	assertFetchCommitResponse(t, uniFetchResp, uniFetchRespLatest)

	t.Log("Verifying retrieval of second supply commitment from " +
		"secondary node")
	peerFetchPred2 := func(resp *unirpc.FetchSupplyCommitResponse) error {
		// Check if the supply commitment has been updated with ignored
		// assets.
		expectedSum := int64(sendAssetAmount)
		actualSum := resp.IgnoreSubtreeRoot.RootNode.RootSum
		if actualSum != expectedSum {
			return fmt.Errorf("expected RootSum %d, got %d",
				expectedSum, actualSum)
		}

		return nil
	}
	req = unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_SpentCommitOutpoint{
			SpentCommitOutpoint: fetchResp.SpentCommitmentOutpoint,
		},
	}
	peerFetchResp2 := rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, secondTapd, peerFetchPred2, &req,
	)

	// Verify that the secondary node's supply commitment matches the
	// primary's.
	assertFetchCommitResponse(t, fetchResp, peerFetchResp2)

	// Step 8: Primary node mints another asset into the group and publishes
	// the third supply commitment.
	t.Log("Minting second asset into the same asset group")

	secondMintReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "itestbuxx-supply-commit-tranche-2",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("second tranche metadata"),
			},
			Amount:          2000,
			AssetVersion:    taprpc.AssetVersion_ASSET_VERSION_V1,
			NewGroupedAsset: false,
			GroupedAsset:    true,
			GroupKey:        groupKeyBytes,

			EnableSupplyCommitments: true,
		},
	}

	MintAssetWithSupplyCommit(
		t, secondMintReq, fn.None[btcec.PublicKey](),
	)

	t.Log("Updating supply commitment after second mint (creating third " +
		"supply commitment)")
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, t.lndHarness.Miner().Client,
		groupKeyBytes, 1,
	)

	// Wait for the third supply commitment to be available.
	expectedTotalAfterSecondMint := int64(
		firstMintReq.Asset.Amount + secondMintReq.Asset.Amount,
	)
	var thirdSupplyCommitResp *unirpc.FetchSupplyCommitResponse
	thirdSupplyCommitResp, _ = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(supplyOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			actualRootSum :=
				resp.IssuanceSubtreeRoot.RootNode.RootSum

			return resp.IssuanceSubtreeRoot != nil &&
				actualRootSum == expectedTotalAfterSecondMint
		},
	)

	// Step 9: Verify the secondary node can fetch the third supply
	// commitment.
	t.Log("Verifying secondary node can fetch third supply commitment")

	// Verify the secondary node can fetch the third supply commitment.
	peerFetchPred3 := func(resp *unirpc.FetchSupplyCommitResponse) error {
		if resp.IssuanceSubtreeRoot == nil {
			return fmt.Errorf("expected issuance subtree root")
		}

		// Check if the supply commitment includes the second mint.
		if resp.IssuanceSubtreeRoot.RootNode.RootSum !=
			expectedTotalAfterSecondMint {

			return fmt.Errorf("expected RootSum %d, got %d",
				expectedTotalAfterSecondMint,
				resp.IssuanceSubtreeRoot.RootNode.RootSum)
		}

		return nil
	}

	// nolint: lll
	req = unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_SpentCommitOutpoint{
			SpentCommitOutpoint: thirdSupplyCommitResp.SpentCommitmentOutpoint,
		},
	}

	peerFetchResp3 := rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, secondTapd, peerFetchPred3, &req,
	)

	// Verify that the secondary node's third supply commitment matches the
	// primary's.
	assertFetchCommitResponse(t, thirdSupplyCommitResp, peerFetchResp3)
}
