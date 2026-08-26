package itest

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// countRootProofTypes counts how many of the given universe roots are of the
// issuance and transfer proof types respectively.
func countRootProofTypes(resp *unirpc.AssetRootResponse) (int, int) {
	var issuance, transfer int
	for _, root := range resp.UniverseRoots {
		switch root.Id.ProofType {
		case unirpc.ProofType_PROOF_TYPE_ISSUANCE:
			issuance++
		case unirpc.ProofType_PROOF_TYPE_TRANSFER:
			transfer++

		// Any other proof type is not counted.
		default:
		}
	}

	return issuance, transfer
}

// testUniverseRootsProofTypeFilter tests that the AssetRoots RPC only returns
// roots of the requested proof type when a proof type filter is set, and all
// roots when it is left unspecified.
func testUniverseRootsProofTypeFilter(t *harnessTest) {
	ctx := context.Background()
	miner := t.lndHarness.Miner()

	// Mint an issuable asset so that the sending node has an issuance
	// universe root.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)
	require.Len(t.t, rpcAssets, 1)
	mintedAsset := rpcAssets[0]

	// Set up a second node to receive a send. Sending an asset creates a
	// transfer universe root on the sending node, so afterwards our main
	// node holds both an issuance and a transfer root.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	addr, events := NewAddrWithEventStream(
		t.t, bob, &taprpc.NewAddrRequest{
			AssetId: mintedAsset.AssetGenesis.AssetId,
			Amt:     mintedAsset.Amount - 1,
		},
	)
	AssertAddrCreated(t.t, bob, mintedAsset, addr)

	_, sendEvents := sendAssetsToAddr(t, t.tapd, addr)
	AssertAddrEvent(t.t, bob, addr, 1, statusDetected)
	MineBlocks(t.t, miner, 1, 1)
	AssertAddrEvent(t.t, bob, addr, 1, statusConfirmed)
	AssertNonInteractiveRecvComplete(t.t, bob, 1)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)
	AssertReceiveEvents(t.t, addr, events)

	// The universe server receives the issuance root via federation from
	// the minting node and the transfer root via the proof courier, so it
	// holds both proof types. We run all root queries against it.
	uniServer := t.universeServer.service

	// Wait until the universe server holds both an issuance and a transfer
	// root.
	var issuanceRoots, transferRoots int
	err := wait.NoError(func() error {
		roots, err := uniServer.AssetRoots(
			ctx, &unirpc.AssetRootRequest{},
		)
		require.NoError(t.t, err)

		issuanceRoots, transferRoots = countRootProofTypes(roots)
		if issuanceRoots == 0 || transferRoots == 0 {
			return fmt.Errorf("expected both proof types, got "+
				"issuance=%d transfer=%d", issuanceRoots,
				transferRoots)
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, err)

	// Filtering by issuance must return only the issuance roots.
	issuanceOnly, err := uniServer.AssetRoots(ctx, &unirpc.AssetRootRequest{
		ProofType: unirpc.ProofType_PROOF_TYPE_ISSUANCE,
	})
	require.NoError(t.t, err)

	gotIssuance, gotTransfer := countRootProofTypes(issuanceOnly)
	require.Equal(t.t, issuanceRoots, gotIssuance)
	require.Zero(t.t, gotTransfer)

	// Filtering by transfer must return only the transfer roots.
	transferOnly, err := uniServer.AssetRoots(ctx, &unirpc.AssetRootRequest{
		ProofType: unirpc.ProofType_PROOF_TYPE_TRANSFER,
	})
	require.NoError(t.t, err)

	gotIssuance, gotTransfer = countRootProofTypes(transferOnly)
	require.Zero(t.t, gotIssuance)
	require.Equal(t.t, transferRoots, gotTransfer)
}
