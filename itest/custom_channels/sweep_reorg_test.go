//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsForceCloseSweepReorg exercises the sweeper-shaped
// replacement re-org: Dave's force-close sweep is fee-bumped into a
// second form while unconfirmed, the first form confirms and is then
// re-orged out, and the replacement form wins the fork. The porter
// registered one anchoring per broadcast form; the test asserts the
// full phase ladder on both — the winning form buries while the
// original drives through conflicted to abandoned and compensates —
// and that the swept assets remain spendable afterwards.
func testCustomChannelsForceCloseSweepReorg(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Zane serves as the proof courier and Universe server.
	zane := net.NewNode("Zane", lndArgs, tapdArgs)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	charlie := net.NewNode("Charlie", lndArgs, tapdArgs)

	// Dave's anchorings are the subjects under test: a burial depth
	// deeper than the fork keeps them at the potency tier through the
	// re-org window instead of absorbing at first confirmation.
	daveTapdArgs := append(
		slices.Clone(tapdArgs), "--reorgsafedepth=6",
	)
	dave := net.NewNode("Dave", lndArgs, daveTapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint the asset Charlie funds the channel with.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{{Asset: ccItestAsset}},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	syncUniverses(t.t, charlie, dave)

	t.Logf("Opening asset channel...")
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	mineBlocks(t, net, 6, 1)

	fundingTxid, err := chainhash.NewHashFromStr(assetFundResp.Txid)
	require.NoError(t.t, err)
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// Dave syncs the funding proof from the Universe server.
	_, err = asTapd(dave).SyncUniverse(ctx, &unirpc.SyncRequest{
		UniverseHost: zane.RPCAddr(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_FULL,
	})
	require.NoError(t.t, err)

	// Push value to Dave so his commitment output is worth sweeping.
	const (
		numPayments   = 5
		keySendAmount = 100
		btcAmt        = int64(5_000)
	)
	for i := 0; i < numPayments; i++ {
		sendAssetKeySendPayment(
			t.t, charlie, dave, keySendAmount, assetID,
			fn.Some(btcAmt),
		)
	}
	logBalance(t.t, nodes, assetID, "after keysend")

	// Force close from Charlie and confirm the close transaction. The
	// fork point of the coming re-org lies after this block, so the
	// close itself stays final throughout.
	t.Logf("Force closing channel...")
	charlieChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}
	_, closeTxid, err := net.CloseChannel(charlie, charlieChanPoint, true)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	findForceCloseTransfer(t.t, charlie, dave, closeTxid)

	// Dave's porter site already carries anchorings from before the
	// sweep (the channel funding among them); snapshot them so the
	// sweep forms below are identified by exclusion.
	preSweep := listPorterAnchoringIDs(t.t, dave)

	// Dave sweeps his non-delay commitment output: the first sweep
	// form. Capture the raw transaction while it sits in the mempool;
	// the re-org choreography below mines both forms explicitly.
	_, err = waitForNTxsInMempool(net.Miner, 1, ccShortTimeout)
	require.NoError(t.t, err)
	sweepFormA := net.Miner.GetNumTxsFromMempool(1)[0]
	sweepTxidA := sweepFormA.TxHash()

	t.Logf("Dave sweep form A: %v", sweepTxidA)

	// The porter staked the broadcast sweep as an anchoring the
	// moment it was handed the parcel: one fresh anchoring, not yet
	// witnessed.
	anchoringA := findPorterAnchoring(t.t, dave, preSweep)
	assertAnchoringPhase(t.t, dave, anchoringA, "unwitnessed")

	// Fee-bump the sweep while it is unconfirmed: lnd's sweeper
	// replaces it with a second form spending the same commitment
	// output, and the porter registers a second anchoring beside the
	// first.
	bumpSweepInput(t.t, net, dave, sweepFormA, closeTxid)

	var sweepFormB *wire.MsgTx
	err = wait.NoError(func() error {
		mem := net.Miner.GetRawMempool()
		if len(mem) != 1 {
			return fmt.Errorf("want 1 tx in mempool, got %d",
				len(mem))
		}
		if mem[0] == sweepTxidA {
			return fmt.Errorf("sweep not yet replaced")
		}
		sweepFormB = net.Miner.GetRawTransaction(mem[0]).MsgTx()

		return nil
	}, ccShortTimeout)
	require.NoError(t.t, err)
	sweepTxidB := sweepFormB.TxHash()

	t.Logf("Dave sweep form B: %v", sweepTxidB)

	anchoringB := findPorterAnchoring(
		t.t, dave, append(slices.Clone(preSweep), anchoringA),
	)
	assertAnchoringPhase(t.t, dave, anchoringB, "unwitnessed")

	// Fork point: both forms exist, neither is confirmed.
	tempMiner := spawnTempMiner(net)

	// Form A confirms first. Mining it directly evicts form B from
	// the mempool as a double spend.
	net.Miner.MineBlockWithTx(sweepFormA)

	locateAssetTransfers(t.t, dave, sweepTxidA)
	assertAnchoringPhase(t.t, dave, anchoringA, "witnessed")

	// Re-org form A out: on the fork neither form is confirmed, so
	// its anchoring returns to unwitnessed. Form A itself re-enters
	// the mempool, still valid on the fork.
	generateReOrg(t, net, tempMiner, 3, 2)

	_, tempHeight := tempMiner.GetBestBlock()
	waitForNodeHeight(t.t, dave, uint32(tempHeight))
	waitForNodeHeight(t.t, charlie, uint32(tempHeight))

	assertAnchoringPhase(t.t, dave, anchoringA, "unwitnessed")

	// Now the replacement form wins the fork; connecting its block
	// evicts form A from the mempool as a double spend. Form B's
	// anchoring witnesses, and for form A's anchoring the replacement
	// is a foreign spend of its trigger inputs: conflicted.
	net.Miner.MineBlockWithTx(sweepFormB)

	locateAssetTransfers(t.t, dave, sweepTxidB)
	assertAnchoringPhase(t.t, dave, anchoringB, "witnessed")
	assertAnchoringPhase(t.t, dave, anchoringA, "conflicted")

	// Bury the winning form at the safe depth. Charlie's CSV-delayed
	// sweep matures somewhere along the way — its exact broadcast
	// height shifted with the re-org — and confirms in whichever of
	// these blocks it reaches the mempool for. Should it reach the
	// mempool only after the last of them, confirm it explicitly, so
	// the balance assertion below never runs ahead of it.
	burying := mineBlocks(t, net, 7, 0)
	charlieSwept := false
	for _, block := range burying {
		if len(block.Transactions) > 1 {
			charlieSwept = true
		}
	}
	if !charlieSwept {
		_, err = waitForNTxsInMempool(net.Miner, 1, ccShortTimeout)
		require.NoError(t.t, err)
		mineBlocks(t, net, 1, 1)
	}

	// The winner buries; the original abandons and compensates
	// (transfer superseded, swept UTXOs restored to the winning
	// form's rows only).
	assertAnchoringPhase(t.t, dave, anchoringB, "buried")
	assertAnchoringPhase(t.t, dave, anchoringA, "abandoned")

	// Both sides land on their expected balances, each on the
	// winning sweep outputs.
	daveBalance := uint64(numPayments * keySendAmount)
	charlieBalance := ccItestAsset.Amount - daveBalance
	assertBalance(
		t.t, dave, daveBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
	)
	assertBalance(
		t.t, charlie, charlieBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
	)

	// Finally, Dave spends the swept output: the compensation left
	// exactly the winning form's rows live, so the transfer must
	// build and confirm cleanly.
	assetSendAmount := daveBalance - 1
	zaneAddr, err := asTapd(zane).NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     assetSendAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	t.Logf("Sending %v asset units from Dave to Zane...",
		assetSendAmount)

	itest.AssertAddrCreated(t.t, asTapd(zane), cents, zaneAddr)
	sendResp, err := dave.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{zaneAddr.Encoded},
	})
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, net.Miner, asTapd(dave), sendResp, assetID,
		[]uint64{1, assetSendAmount}, 3, 4,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(zane), 1)
}

// spawnTempMiner spawns a temporary miner off the network's miner.
// Every temporary miner in the suite saves logs from — and then
// removes — the same shared directory when it stops, so the first
// stop breaks the ones after it. The stops are cleanups on the
// miner's T and run in LIFO order: registering this after the spawn
// re-creates the directory just before this miner's own stop reads
// it, as the main itest suite's helper of the same name does.
func spawnTempMiner(net *itest.IntegratedNetworkHarness) *miner.HarnessMiner {
	tempMiner := net.Miner.SpawnTempMiner()

	net.Miner.Cleanup(func() {
		_ = os.MkdirAll("regtest/.logs/.tempminerlogs/regtest", 0755)
	})

	return tempMiner
}

// generateReOrg re-orgs the chain onto a longer fork mined by the
// given temporary miner, mirroring the main itest suite's helper of
// the same name: extend the fork, detach the chain backend from the
// miner, sync the miners so the longer fork wins, then reconnect.
func generateReOrg(t *ccHarnessTest, net *itest.IntegratedNetworkHarness,
	tempMiner *miner.HarnessMiner, depth uint32, expectedDelta int32) {

	tempMiner.MineEmptyBlocks(int(depth))
	net.Miner.AssertMinerBlockHeightDelta(tempMiner, expectedDelta)

	require.NoError(t.t, net.DisconnectMiner())
	net.Miner.ConnectMiner(tempMiner)
	net.Miner.AssertMinerBlockHeightDelta(tempMiner, 0)
	net.Miner.DisconnectMiner(tempMiner)
	require.NoError(t.t, net.ConnectMiner())
}

// waitForNodeHeight waits until the node's lnd reports the given best
// block height.
func waitForNodeHeight(t *testing.T, node *itest.IntegratedNode,
	height uint32) {

	t.Helper()

	ctxb := context.Background()
	err := wait.NoError(func() error {
		info, err := node.LightningClient.GetInfo(
			ctxb, &lnrpc.GetInfoRequest{},
		)
		if err != nil {
			return err
		}
		if info.BlockHeight != height {
			return fmt.Errorf("node at height %d, want %d",
				info.BlockHeight, height)
		}

		return nil
	}, ccShortTimeout)
	require.NoError(t, err)
}

// listPorterAnchoringIDs returns the IDs of the node's current
// porter-site anchorings.
func listPorterAnchoringIDs(t *testing.T,
	node *itest.IntegratedNode) []int64 {

	t.Helper()

	ctxb := context.Background()
	resp, err := asTapd(node).ListAnchorings(
		ctxb, &taprpc.ListAnchoringsRequest{
			Site: "tapfreighter.porter",
		},
	)
	require.NoError(t, err)

	ids := make([]int64, 0, len(resp.Anchorings))
	for _, a := range resp.Anchorings {
		ids = append(ids, a.Id)
	}

	return ids
}

// findPorterAnchoring returns the ID of the node's single porter-site
// anchoring not in the exclude list. The porter registers sweep
// broadcasts as anchorings, so each sweep form shows up here.
func findPorterAnchoring(t *testing.T, node *itest.IntegratedNode,
	exclude []int64) int64 {

	t.Helper()

	ctxb := context.Background()
	var id int64
	err := wait.NoError(func() error {
		resp, err := asTapd(node).ListAnchorings(
			ctxb, &taprpc.ListAnchoringsRequest{
				Site: "tapfreighter.porter",
			},
		)
		if err != nil {
			return err
		}

		var fresh []int64
		for _, a := range resp.Anchorings {
			if !slices.Contains(exclude, a.Id) {
				fresh = append(fresh, a.Id)
			}
		}
		if len(fresh) != 1 {
			return fmt.Errorf("want 1 fresh porter anchoring, "+
				"got %d", len(fresh))
		}
		id = fresh[0]

		return nil
	}, ccShortTimeout)
	require.NoError(t, err)

	return id
}

// assertAnchoringPhase waits until the anchoring with the given ID
// reports the given phase, both sensed and delivered. Phase strings on
// the RPC surface are decorated with their evidence, so matching is by
// prefix.
func assertAnchoringPhase(t *testing.T, node *itest.IntegratedNode,
	id int64, phase string) {

	t.Helper()

	ctxb := context.Background()
	err := wait.NoError(func() error {
		resp, err := asTapd(node).ListAnchorings(
			ctxb, &taprpc.ListAnchoringsRequest{},
		)
		if err != nil {
			return err
		}

		for _, a := range resp.Anchorings {
			if a.Id != id {
				continue
			}
			if !strings.HasPrefix(a.Phase, phase) ||
				!strings.HasPrefix(a.DeliveredPhase, phase) {

				return fmt.Errorf("anchoring %d: phase %v "+
					"(delivered %v), want %v", id,
					a.Phase, a.DeliveredPhase, phase)
			}

			return nil
		}

		return fmt.Errorf("anchoring %d not found", id)
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// bumpSweepInput fee-bumps the sweep's commitment-output input through
// lnd's BumpFee RPC, forcing the sweeper to publish a replacement form
// of the sweep. The bumped input is the highest-value output of the
// close transaction that the sweep claims — the asset commitment
// output.
func bumpSweepInput(t *testing.T, net *itest.IntegratedNetworkHarness,
	node *itest.IntegratedNode, sweepTx *wire.MsgTx,
	closeTxid *chainhash.Hash) {

	t.Helper()

	closeTx := net.Miner.GetRawTransaction(*closeTxid).MsgTx()

	var (
		bumpOutpoint *wire.OutPoint
		bumpValue    int64
	)
	for _, txIn := range sweepTx.TxIn {
		op := txIn.PreviousOutPoint
		if op.Hash != *closeTxid {
			continue
		}

		value := closeTx.TxOut[op.Index].Value
		if bumpOutpoint == nil || value > bumpValue {
			op := op
			bumpOutpoint = &op
			bumpValue = value
		}
	}
	require.NotNil(t, bumpOutpoint, "sweep does not spend the close tx")

	ctxb := context.Background()
	_, err := node.BumpFee(ctxb, &walletrpc.BumpFeeRequest{
		Outpoint: &lnrpc.OutPoint{
			TxidBytes:   bumpOutpoint.Hash[:],
			OutputIndex: bumpOutpoint.Index,
		},
		Immediate: true,
		Budget:    20_000,
	})
	require.NoError(t, err)
}
