//go:build itest

package itest

import (
	"context"

	"github.com/lightninglabs/taproot-assets/itest/rpcassert"
	"github.com/lightninglabs/taproot-assets/taprpc"
	mintrpc "github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

func testZeroValueAnchorSweep(t *harnessTest) {
	t.t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	miner := t.lndHarness.Miner().Client

	firstMint := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, []*mintrpc.MintAssetRequest{CopyRequest(simpleAssets[0])},
	)

	bobLnd := t.lndHarness.NewNodeWithCoins("bob-zero-anchor", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
		bobLnd.Cleanup(nil)
	}()

	recvAddr := rpcassert.NewAddrRPC(t.t, ctxt, bobTapd, nil, &taprpc.NewAddrRequest{
		AssetId:      firstMint[0].AssetGenesis.AssetId,
		Amt:          firstMint[0].Amount,
		AssetVersion: firstMint[0].Version,
	})

	sendResp1, sendEvents1 := sendAsset(
		t, t.tapd, withReceiverAddresses(recvAddr), withSkipProofCourierPingCheck(),
	)
	defer sendEvents1.Cancel()

	var tombstoneOutpoint string
	for _, out := range sendResp1.Transfer.Outputs {
		// We don't require ScriptKeyIsLocal on tombstones (NUMS key is not
		// controlled by us). We only check for zero-amount, split-root type.
		if out.Amount == 0 {
			tombstoneOutpoint = out.Anchor.Outpoint
			break
		}
	}
	require.NotEmpty(t.t, tombstoneOutpoint, "expected tombstone output not found")

	MineBlocks(t.t, miner, 1, 1)

	secondMint := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, []*mintrpc.MintAssetRequest{CopyRequest(simpleAssets[0])},
	)

	// The second mint should sweep the previous tombstone outpoint as a BTC
	// input of its anchor transaction.
	// Re-query managed transactions and assert usage indirectly by checking
	// that a new mint happened (already ensured) and later the following send
	// can select the same anchor input if needed.

	recvAddr2 := rpcassert.NewAddrRPC(t.t, ctxt, bobTapd, nil, &taprpc.NewAddrRequest{
		AssetId:      secondMint[0].AssetGenesis.AssetId,
		Amt:          secondMint[0].Amount,
		AssetVersion: secondMint[0].Version,
	})

	sendResp2, sendEvents2 := sendAsset(
		t, t.tapd, withReceiverAddresses(recvAddr2), withSkipProofCourierPingCheck(),
	)
	defer sendEvents2.Cancel()

	found := false
	for _, in := range sendResp2.Transfer.Inputs {
		if in.AnchorPoint == tombstoneOutpoint {
			found = true
			break
		}
	}
	require.Truef(t.t, found, "zero value anchor %v not swept", tombstoneOutpoint)
}
