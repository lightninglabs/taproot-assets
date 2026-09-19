package itest

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/itest/rpcassert"
	"github.com/lightninglabs/taproot-assets/rpcserver"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/stretchr/testify/require"
)

// actGateSettle is how long the negative half of an act-gating
// assertion watches for an emission that must not arrive. The gated
// emissions ride the watcher's outbox, whose regtest scan interval is
// one second, so a few seconds of quiet is evidence the gate is
// holding rather than that the dispatcher is slow.
const actGateSettle = 5 * time.Second

// testActGatedMintPublication asserts the act gate end to end, in both
// directions, at a burial depth the suite does not otherwise exercise.
//
// The itest harness runs every other case at --reorgsafedepth=1. At
// that depth witnessing and burial coincide: the watcher skips the act
// subscription entirely and marks the first confirmation act-certified,
// so the whole suite satisfies act gating vacuously. A test that only
// ever observes the emission arriving cannot tell a working gate from
// an absent one.
//
// This case runs at depth 6 and pins both halves. After one
// confirmation the mint is locally complete — the batch finalizes, the
// assets are listed — but the universe publication, which is
// irreversible once remote federation members hold it, must not have
// happened. It must then appear once, and only once, the genesis
// transaction is buried.
func testActGatedMintPublication(t *harnessTest) {
	lndMiner := t.lndHarness.Miner()

	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0],
	}

	// Mint and confirm with a single block. The batch reaches its
	// finalized state on this confirmation, but the node is running
	// at depth 6, so the genesis transaction is five blocks short of
	// burial.
	mintedAssets := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, mintRequests, WithNoUniverseLeafWait(),
	)
	require.Len(t.t, mintedAssets, 1)

	// The negative half: nothing may reach the universe yet.
	t.Logf("Asserting issuance leaves are withheld below the act " +
		"threshold")
	AssertNoMintUniverseLeaves(
		t.t, t.tapd, mintedAssets, actGateSettle,
	)

	// Mine to the act threshold. The genesis transaction now has six
	// confirmations, so the watcher certifies burial and the outbox
	// releases the publication.
	t.lndHarness.MineBlocks(5)

	t.Logf("Asserting issuance leaves are published after burial")
	WaitForMintUniverseLeaves(t.t, t.tapd, mintedAssets)
}

// testActGatedSupplyEmissions asserts the act gate for the two other
// gated emission classes: a burn's supply-commit event, and a supply
// commitment's finalization and push to the remote universes. Like
// the mint case it runs at depth 6, where witnessing and burial are
// five blocks apart.
//
// Both are observed through supply commitments, since the pending
// event log has no RPC surface of its own. A commitment cycle binds
// the events pending when it starts, so a cycle started after the
// burn's first confirmation must not carry the burn, and the next
// one, started after the burn is buried, must. The first commitment
// pins the push gate as well: it is finalized locally and pushed to
// the universe server only on its own burial.
func testActGatedSupplyEmissions(t *harnessTest) {
	ctxb := context.Background()
	lndMiner := t.lndHarness.Miner()

	// Mint a grouped asset with supply commitments enabled, confirm
	// it with a single block and bury it. The issuance leaf and the
	// mint's supply-update event are released together on burial,
	// and the first commitment below needs that event pending.
	mintReq := CopyRequest(issuableAssets[0])
	mintReq.Asset.Amount = 5000
	mintReq.Asset.EnableSupplyCommitments = true

	mintedAssets := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, []*mintrpc.MintAssetRequest{mintReq},
		WithNoUniverseLeafWait(),
	)
	require.Len(t.t, mintedAssets, 1)
	rpcAsset := mintedAssets[0]
	assetID := rpcAsset.AssetGenesis.AssetId
	groupKeyBytes := rpcAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)

	fetchGroupKey := &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
		GroupKeyBytes: groupKeyBytes,
	}

	t.lndHarness.MineBlocks(5)
	WaitForMintUniverseLeaves(t.t, t.tapd, mintedAssets)

	// Burn part of the asset and confirm the burn with a single
	// block. The burn record is local state and lands on this
	// confirmation; its supply-commit event is act-gated.
	const burnAmt = 1000
	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: &taprpc.AssetSpecifier_AssetId{
				AssetId: assetID,
			},
		},
		AmountToBurn:     burnAmt,
		ConfirmationText: rpcserver.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, lndMiner, t.tapd, burnResp.BurnTransfer,
		[][]byte{assetID},
		[]uint64{mintReq.Asset.Amount - burnAmt, burnAmt},
		0, 1, 2, true,
	)
	AssertNumBurns(t.t, t.tapd, 1, nil)

	// The negative half for the burn. After a settle period, start a
	// commitment cycle: it binds the events pending now, which must
	// be the mint's alone.
	t.Logf("Starting a supply commitment below the burn's act " +
		"threshold")
	time.Sleep(actGateSettle)
	UpdateAndMineSupplyCommit(
		t.t, ctxb, t.tapd, lndMiner, groupKeyBytes, 1,
	)

	// The negative half for the commitment: one confirmation, five
	// short of burial, so it is neither finalized locally nor
	// pushed to the universe server.
	t.Logf("Asserting the supply commitment is withheld below the " +
		"act threshold")
	AssertNoSupplyCommit(t.t, t.tapd, groupKeyBytes, actGateSettle)
	AssertNoSupplyCommit(
		t.t, t.universeServer.service, groupKeyBytes, actGateSettle,
	)

	// Mine to the act threshold. The commitment transaction now has
	// six confirmations, so the watcher finalizes it and the outbox
	// releases the push; the burn, one block older, is buried too.
	t.lndHarness.MineBlocks(5)

	t.Logf("Asserting the supply commitment is finalized and pushed " +
		"after burial")
	fetchResp, firstOutpoint := WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.None[wire.OutPoint](),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.ChainData.BlockHeight > 0
		},
	)
	require.NotNil(t.t, fetchResp.IssuanceSubtreeRoot)
	require.EqualValues(
		t.t, mintReq.Asset.Amount,
		fetchResp.IssuanceSubtreeRoot.RootNode.RootSum,
	)

	// The cycle started below the burn's act threshold, so this
	// commitment carries no burn leaf.
	assertNoBurnLeaves(t, fetchResp)

	uniFetchResp := rpcassert.FetchSupplyCommitRPC(
		t.t, ctxb, t.universeServer.service,
		func(resp *unirpc.FetchSupplyCommitResponse) error {
			if resp.ChainData.BlockHeight == 0 {
				return fmt.Errorf("commitment not mined")
			}

			return nil
		},
		&unirpc.FetchSupplyCommitRequest{
			GroupKey: fetchGroupKey,
			Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
				VeryFirst: true,
			},
		},
	)
	assertFetchCommitResponse(t, fetchResp, uniFetchResp)
	assertNoBurnLeaves(t, uniFetchResp)

	// The positive half for the burn: its burial released the
	// supply-commit event, which rides the next cycle. The event is
	// recorded asynchronously, so tick until a commitment
	// transaction is broadcast; a tick with nothing pending is a
	// no-op, and one arriving mid-cycle is absorbed.
	t.Logf("Asserting the burn is committed after burial")
	updateReq := &unirpc.UpdateSupplyCommitRequest{
		GroupKey: &unirpc.UpdateSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
	}
	deadline := time.Now().Add(defaultWaitTimeout)
	for len(lndMiner.GetRawMempool()) == 0 {
		require.True(
			t.t, time.Now().Before(deadline),
			"no commitment broadcast after the burn's burial",
		)

		_, err = t.tapd.UpdateSupplyCommit(ctxb, updateReq)
		require.NoError(t.t, err)

		time.Sleep(2 * time.Second)
	}
	MineBlocks(t.t, lndMiner, 1, 1)
	t.lndHarness.MineBlocks(5)

	fetchResp, _ = WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.Some(firstOutpoint),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.BurnSubtreeRoot != nil &&
				resp.BurnSubtreeRoot.RootNode.RootSum == burnAmt
		},
	)

	leavesReq := &unirpc.FetchSupplyLeavesRequest{
		GroupKey: &unirpc.FetchSupplyLeavesRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
	}
	respLeaves, err := t.tapd.FetchSupplyLeaves(ctxb, leavesReq)
	require.NoError(t.t, err)
	require.Len(t.t, respLeaves.BurnLeaves, 1)
	burnLeaf := respLeaves.BurnLeaves[0]
	require.Equal(t.t, assetID, burnLeaf.LeafKey.AssetId)
	require.EqualValues(t.t, burnAmt, burnLeaf.LeafNode.RootSum)
}

// assertNoBurnLeaves asserts that a supply commitment commits to no
// burns.
func assertNoBurnLeaves(t *harnessTest,
	resp *unirpc.FetchSupplyCommitResponse) {

	t.t.Helper()

	require.Empty(t.t, resp.BurnLeaves)
	if resp.BurnSubtreeRoot != nil {
		require.Zero(t.t, resp.BurnSubtreeRoot.RootNode.RootSum)
	}
}
