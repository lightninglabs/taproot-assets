package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

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
