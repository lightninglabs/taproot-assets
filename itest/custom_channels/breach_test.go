//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsBreach tests the breach/justice scenario for custom
// channels with in-flight HTLCs. Dave backs up his DB state (which has active
// hodl invoice HTLCs), the HTLCs are settled to advance the state, then Dave
// restores the old state and force-closes (broadcasting a revoked commitment
// with HTLC outputs). Charlie is suspended during the breach so Dave can
// advance HTLCs to second level. Charlie is then resumed, detects the breach,
// and sweeps all outputs including second-level HTLC outputs.
func testCustomChannelsBreach(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// Bump the fee rate so the justice transaction has enough fee to
	// pass btcd's minimum relay fee check. The default FeePerKwFloor
	// is borderline for the larger justice transaction.
	net.FeeService.SetFeeRate(chainfee.SatPerKWeight(1000), 1)

	lndArgs := slices.Clone(lndArgsTemplate)
	lndArgs = append(lndArgs, "--bitcoin.defaultremotedelay=144")
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Use Zane as a dedicated universe node that stays online as proof
	// courier, so that Dave can still import proofs and advance HTLCs
	// to second level even when Charlie is suspended.
	//
	// We allocate a port for Zane's RPC upfront and add it as an extra
	// --rpclisten so the proof courier address is known before Zane
	// starts (same pattern as core_test.go).
	zanePort := port.NextAvailablePort()
	zaneLndArgs := append(slices.Clone(lndArgs), fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", zanePort,
	))
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, zanePort),
	))
	zane := net.NewNode("Zane", zaneLndArgs, tapdArgs)

	// Charlie will be the breached party. We set --nolisten to ensure
	// Dave won't be able to connect to him and trigger the channel
	// protection logic automatically. We also can't have Charlie
	// automatically reconnect too early, otherwise DLP would be
	// initiated instead of the breach we want to provoke.
	charlieLndArgs := append(
		slices.Clone(lndArgs), "--nolisten", "--minbackoff=1h",
	)

	// For this simple test, we'll just have Charlie -> Dave as an assets
	// channel.
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	// Next we'll connect all the nodes and also fund them with some
	// coins.
	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Connect Zane to Dave directly, and have Charlie connect outbound
	// to Zane (since Charlie has --nolisten and can't accept inbound).
	net.EnsureConnected(t.t, zane, dave)
	net.EnsureConnected(t.t, charlie, zane)

	// Now we'll make an asset for Charlie that we'll use in the test to
	// open a channel.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, zane, dave)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// Next we can open an asset channel from Charlie -> Dave, then kick
	// off the main scenario.
	t.Logf("Opening asset channels...")
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", assetFundResp)

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	// A transfer for the funding transaction should be found in
	// Charlie's DB.
	fundingTxid, err := chainhash.NewHashFromStr(assetFundResp.Txid)
	require.NoError(t.t, err)
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	// Charlie's balance should reflect that the funding asset is now
	// excluded from balance reporting by tapd.
	assertBalance(
		t.t, charlie, ccItestAsset.Amount-fundingAmount,
		itest.WithAssetID(assetID), itest.WithNumUtxos(1),
	)

	// Make sure that Charlie properly uploaded funding proof to the
	// Universe server (Zane is the proof courier).
	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptTreeBytes := fundingScriptKey.SerializeCompressed()
	assertUniverseProofExists(
		t.t, zane, assetID, nil, fundingScriptTreeBytes,
		fmt.Sprintf(
			"%v:%v", assetFundResp.Txid,
			assetFundResp.OutputIndex,
		),
	)

	// Make sure the channel shows the correct asset information.
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	// Before we start sending out payments, let's make sure each node
	// can see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// Next, we'll make keysend payments from Charlie to Dave. We use
	// 10k sats per keysend so Dave has enough BTC to cover multiple
	// in-flight HTLCs (at 6x dust each) plus channel reserve.
	const (
		numPayments   = 5
		keySendAmount = 200
		btcAmt        = int64(10_000)
	)
	for i := 0; i < numPayments; i++ {
		sendAssetKeySendPayment(
			t.t, charlie, dave, keySendAmount, assetID,
			fn.Some(btcAmt),
		)
	}

	logBalance(t.t, nodes, assetID, "after keysend -- balanced state")

	// Now create hodl invoices on both sides to ensure HTLCs exist on
	// the commitment we're about to backup. This tests the revoked HTLC
	// sweep paths (TaprootHtlcOfferedRevoke, TaprootHtlcAcceptedRevoke).
	const (
		numHodlInvoices = 2
		htlcAmount      = 200
	)

	var (
		daveHodlInvoices    []assetHodlInvoice
		charlieHodlInvoices []assetHodlInvoice
	)

	t.Logf("Creating %d hodl invoices per peer...", numHodlInvoices)

	// Create Dave's hodl invoices (Charlie pays = outgoing HTLCs).
	for i := 0; i < numHodlInvoices; i++ {
		daveHodlInvoices = append(
			daveHodlInvoices, createAssetHodlInvoice(
				t.t, charlie, dave, htlcAmount, assetID,
			),
		)
	}

	// Create Charlie's hodl invoices (Dave pays = incoming HTLCs).
	for i := 0; i < numHodlInvoices; i++ {
		charlieHodlInvoices = append(
			charlieHodlInvoices, createAssetHodlInvoice(
				t.t, dave, charlie, htlcAmount, assetID,
			),
		)
	}

	// Pay all invoices but don't settle (HTLCs stay in flight).
	payOpt := withFailure(
		lnrpc.Payment_IN_FLIGHT,
		lnrpc.PaymentFailureReason_FAILURE_REASON_NONE,
	)

	t.Logf("Paying hodl invoices to create HTLCs on commitment...")

	for _, daveInv := range daveHodlInvoices {
		payInvoiceWithAssets(
			t.t, charlie, dave, daveInv.payReq, assetID, payOpt,
		)
	}

	for _, charlieInv := range charlieHodlInvoices {
		payInvoiceWithAssets(
			t.t, dave, charlie, charlieInv.payReq, assetID, payOpt,
		)
	}

	// Verify HTLCs are active on both sides.
	expectedHtlcs := numHodlInvoices * 2
	assertNumHtlcs(t.t, charlie, expectedHtlcs)
	assertNumHtlcs(t.t, dave, expectedHtlcs)

	logBalance(t.t, nodes, assetID, "after hodl invoices -- breach state")

	// Now we'll create an on disk snapshot that we'll use to restore
	// back to as our breached state. This state has active HTLCs!
	require.NoError(t.t, net.StopAndBackupDB(dave))
	connectAllNodes(t.t, net, nodes)

	// Settle all the hodl invoices to revoke the state with HTLCs.
	// This will cause the backed-up state to become revoked, which
	// will trigger the breach detection when Dave broadcasts it.
	t.Logf("Settling hodl invoices to revoke breach state...")

	for _, daveInv := range daveHodlInvoices {
		_, err := dave.InvoicesClient.SettleInvoice(
			ctx, &invoicesrpc.SettleInvoiceMsg{
				Preimage: daveInv.preimage[:],
			},
		)
		require.NoError(t.t, err)
	}

	for _, charlieInv := range charlieHodlInvoices {
		_, err := charlie.InvoicesClient.SettleInvoice(
			ctx, &invoicesrpc.SettleInvoiceMsg{
				Preimage: charlieInv.preimage[:],
			},
		)
		require.NoError(t.t, err)
	}

	// Send one more keysend to ensure the state with settled HTLCs is
	// committed and the previous state (with active HTLCs) is revoked.
	sendAssetKeySendPayment(
		t.t, charlie, dave, keySendAmount, assetID, fn.Some(btcAmt),
	)

	// Wait for all HTLCs to clear.
	assertNumHtlcs(t.t, charlie, 0)
	assertNumHtlcs(t.t, dave, 0)

	logBalance(t.t, nodes, assetID, "after settling HTLCs -- final state")

	// With the final state achieved, we'll now restore Dave (who will
	// be force closing) to that old state, the breach state.
	require.NoError(t.t, net.StopAndRestoreDB(dave))

	// With Dave restored, we'll now execute the force close.
	t.Logf("Force close by Dave to breach...")
	daveChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	// Suspend Charlie BEFORE the breach so Dave can advance HTLCs to
	// second level without Charlie's justice tx interfering.
	t.Logf("Suspending Charlie before breach...")
	restartCharlie, err := net.SuspendNode(charlie)
	require.NoError(t.t, err)

	_, breachTxid, err := net.CloseChannel(dave, daveChanPoint, true)
	require.NoError(t.t, err)

	t.Logf("Channel closed! Mining blocks, close_txid=%v", breachTxid)

	// Mine a block to confirm the breach transaction.
	mineBlocks(t, net, 1, 1)

	// Mine blocks to let Dave's HTLC timeout resolvers advance HTLCs to
	// second level. CLTV delta is 80, so we need ~100 blocks. We must
	// NOT mine enough for the CSV delay (144) on second-level outputs
	// to expire, or Dave will sweep them before Charlie can.
	//
	// We mine in small batches and check the mempool between batches to
	// give Dave's sweeper time to broadcast second-level HTLC txs.
	t.Logf("Mining blocks to let Dave advance HTLCs to 2nd level...")
	var secondLevelTxns []*wire.MsgTx
	breachHash := breachTxid
	const (
		totalBlocks = 100
		batchSize   = 10
	)
	var allBlocks []*wire.MsgBlock
	for mined := uint32(0); mined < totalBlocks; {
		// Check mempool before mining the next batch.
		mempool, mempoolErr := net.Miner.Client.GetRawMempool()
		require.NoError(t.t, mempoolErr)
		if len(mempool) > 0 {
			t.Logf("Mempool has %d txns at height offset %d",
				len(mempool), mined)
			for _, txid := range mempool {
				rawTx, txErr := net.Miner.Client.
					GetRawTransaction(txid)
				if txErr != nil {
					continue
				}
				tx := rawTx.MsgTx()
				for _, txIn := range tx.TxIn {
					if txIn.PreviousOutPoint.Hash ==
						*breachHash {

						t.Logf("Found 2nd-level tx "+
							"%v in mempool "+
							"spending breach "+
							"output %d",
							tx.TxHash(),
							txIn.PreviousOutPoint.Index)
					}
				}
			}
		}

		// Mine a batch, including any mempool txs in first block.
		n := batchSize
		if mined+uint32(n) > totalBlocks {
			n = int(totalBlocks - mined)
		}
		blocks := mineBlocks(t, net, uint32(n), len(mempool))
		allBlocks = append(allBlocks, blocks...)
		mined += uint32(n)

		t.Logf("Mined %d/%d blocks", mined, totalBlocks)
	}

	// Scan all mined blocks for second-level txns (txs spending from
	// the breach transaction).
	for _, block := range allBlocks {
		for _, tx := range block.Transactions {
			for _, txIn := range tx.TxIn {
				if txIn.PreviousOutPoint.Hash == *breachHash {
					t.Logf("Found 2nd-level tx %v "+
						"spending breach output %d",
						tx.TxHash(),
						txIn.PreviousOutPoint.Index)

					secondLevelTxns = append(
						secondLevelTxns, tx,
					)
				}
			}
		}
	}
	t.Logf("Found %d second-level txns total", len(secondLevelTxns))

	// Log the breach tx outputs for reference.
	breachTx, err := net.Miner.Client.GetRawTransaction(breachTxid)
	require.NoError(t.t, err)
	for i, out := range breachTx.MsgTx().TxOut {
		t.Logf("Breach output %d: value=%d pkscript=%x",
			i, out.Value, out.PkScript)
	}

	// Log second-level tx details.
	for i, tx := range secondLevelTxns {
		for j, out := range tx.TxOut {
			t.Logf("2nd-level tx %d output %d: value=%d "+
				"pkscript=%x", i, j, out.Value, out.PkScript)
		}
	}

	// Now resume Charlie. She should detect the breach and attempt
	// justice, including sweeping any second-level HTLC outputs.
	t.Logf("Resuming Charlie...")
	restartCharlie()

	// Wait for Charlie's justice tx(s) in the mempool. There may be
	// multiple: one for the commitment/HTLC outputs and potentially
	// another for second-level HTLC outputs.
	t.Logf("Waiting for Charlie's justice txns in mempool...")
	charlieJusticeTxids, err := waitForNTxsInMempool(
		net.Miner.Client, 2, wait.MinerMempoolTimeout,
	)
	if err != nil {
		// If we don't find 2, try with 1.
		charlieJusticeTxids, err = waitForNTxsInMempool(
			net.Miner.Client, 1, wait.MinerMempoolTimeout,
		)
	}
	require.NoError(t.t, err,
		"expected Charlie's justice tx(s) in mempool")

	t.Logf("Charlie justice txids: %v", charlieJusticeTxids)

	// Log justice tx details. The BRAR may replace txs between our
	// mempool query and the GetRawTransaction call, so tolerate errors.
	for _, txid := range charlieJusticeTxids {
		justiceTx, jErr := net.Miner.Client.GetRawTransaction(txid)
		if jErr != nil {
			t.Logf("Justice tx %v no longer in mempool "+
				"(likely replaced): %v", txid, jErr)

			continue
		}
		t.Logf("Justice tx %v has %d inputs:",
			txid, len(justiceTx.MsgTx().TxIn))
		for _, txIn := range justiceTx.MsgTx().TxIn {
			t.Logf("  input: %v (witness len=%d)",
				txIn.PreviousOutPoint, len(txIn.Witness))
		}
		for i, out := range justiceTx.MsgTx().TxOut {
			t.Logf("  output %d: value=%d", i, out.Value)
		}
	}

	// Mine the justice transaction(s). We only require 1 tx in the
	// mempool because the breach arbiter may consolidate multiple
	// partial justice txs into a single spendAll variant at any time.
	// The mined block will include all mempool txns regardless.
	mineBlocks(t, net, 1, 1)
	t.Logf("Justice tx confirmed")

	// After the first justice tx confirms, the breach arbiter may detect
	// that some outputs were spent to second level and create follow-up
	// justice txs. Give it a few blocks to react.
	t.Logf("Mining blocks to let breach arbiter react to " +
		"second-level...")
	for i := 0; i < 10; i++ {
		mempool, mErr := net.Miner.Client.GetRawMempool()
		require.NoError(t.t, mErr)

		if len(mempool) > 0 {
			t.Logf("Found %d txns in mempool after %d blocks:",
				len(mempool), i)
			for _, txid := range mempool {
				raw, rErr := net.Miner.Client.
					GetRawTransaction(txid)
				require.NoError(t.t, rErr)
				tx := raw.MsgTx()
				t.Logf("  tx %v: %d inputs, %d outputs",
					txid, len(tx.TxIn), len(tx.TxOut))
				for _, in := range tx.TxIn {
					t.Logf("    input: %v "+
						"(witness len=%d)",
						in.PreviousOutPoint,
						len(in.Witness))
				}
				for j, out := range tx.TxOut {
					t.Logf("    output %d: value=%d",
						j, out.Value)
				}
			}

			mineBlocks(t, net, 1, len(mempool))
			t.Logf("Mined second-level justice tx")
		} else {
			mineBlocks(t, net, 1, 0)
		}
	}

	// After sweeping, Charlie should have all the asset balance back.
	assertBalance(
		t.t, charlie, ccItestAsset.Amount,
		itest.WithAssetID(assetID),
	)

	t.Logf("Charlie balance restored after breach")
}
