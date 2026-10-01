//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

const (
	// spenderUpgradeVersion is the last release whose asset channel
	// commitments carry no spender leaves.
	spenderUpgradeVersion = "v0.8.4"

	// spenderActivationDelay is the number of blocks from the upgrade of
	// the channel peers to the proof activation height. It leaves room for
	// the commitment update that brings the channel to spender leaves.
	spenderActivationDelay = 10
)

// TestSpenderLeafUpgrade tests that an asset channel opened before spender
// leaves can be brought to them before the proof activation height. Both peers
// open the channel on the last release without spender leaves, then upgrade,
// reconnect and update the channel once, after which both report that their
// commitments carry spender leaves. A force close past the activation height
// must then yield proofs that carry spender proofs, which only a commitment
// with spender leaves can provide.
func TestSpenderLeafUpgrade(t *testing.T) {
	oldBinary := buildCompatBinary(t, spenderUpgradeVersion)
	t.Logf("Using compat binary for %s: %s", spenderUpgradeVersion,
		oldBinary)

	runWithCompatHarness(t, func(ctx context.Context,
		net *itest.IntegratedNetworkHarness, ht *ccHarnessTest) {

		runSpenderLeafUpgrade(ctx, net, ht, oldBinary)
	})
}

// runSpenderLeafUpgrade runs the upgrade of TestSpenderLeafUpgrade: open a
// channel on the old release, upgrade both peers with an activation height a
// few blocks ahead, reconnect, update the channel, force close past the
// activation height, and verify the proofs of the swept outputs.
func runSpenderLeafUpgrade(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest,
	oldBinary string) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Zane runs the current build throughout, as the proof courier of
	// Charlie and Dave.
	zane := net.NewNode("Zane", lndArgs, tapdArgs)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	// Charlie and Dave start on the old release.
	charlie := net.NewNodeWithBinary(
		"Charlie", oldBinary, lndArgs, tapdArgs,
	)
	dave := net.NewNodeWithBinary("Dave", oldBinary, lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	oldVersion := strings.TrimPrefix(spenderUpgradeVersion, "v")
	for _, node := range nodes {
		info, err := asTapd(node).GetInfo(ctx, &taprpc.GetInfoRequest{})
		require.NoError(t.t, err)
		require.Contains(t.t, info.Version, oldVersion)
	}

	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{Asset: ccItestAsset},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId
	syncUniverses(t.t, charlie, dave)

	t.Logf("Opening asset channel Charlie -> Dave on %s...",
		spenderUpgradeVersion)
	fundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 6, 1)

	fundingTxid, err := chainhash.NewHashFromStr(fundResp.Txid)
	require.NoError(t.t, err)
	fundingOutpoint := &wire.OutPoint{
		Hash:  *fundingTxid,
		Index: uint32(fundResp.OutputIndex),
	}
	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundResp.Txid,
		},
	}

	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	// Each payment carries enough sats to keep Dave's commitment output
	// above dust, so it is swept after the force close.
	const (
		keySendAmount = 100
		keySendSats   = int64(5_000)
		numPayments   = 3
	)
	pay := func() {
		sendAssetKeySendPayment(
			t.t, charlie, dave, keySendAmount, assetID,
			fn.Some(keySendSats),
		)
	}

	// Payments on the old release leave the channel with commitments
	// that carry no spender leaves.
	for range numPayments {
		pay()
	}

	// Upgrade both peers, and Zane, with an activation height a few
	// blocks ahead, then reconnect the peers.
	_, height := net.Miner.GetBestBlock()
	activationHeight := uint32(height) + spenderActivationDelay
	activationArg := fmt.Sprintf(
		"--proofactivationheight=%d", activationHeight,
	)
	t.Logf("Upgrading Charlie and Dave, activation height %d...",
		activationHeight)
	for _, node := range []*itest.IntegratedNode{zane, charlie, dave} {
		net.UpgradeNode(node, activationArg)
	}
	net.EnsureConnected(t.t, charlie, dave)
	require.NoError(t.t, net.AssertChannelExists(charlie, fundingOutpoint))
	require.NoError(t.t, net.AssertChannelExists(dave, fundingOutpoint))

	zaneInfo, err := asTapd(zane).GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t.t, err)
	for _, node := range nodes {
		info, err := asTapd(node).GetInfo(ctx, &taprpc.GetInfoRequest{})
		require.NoError(t.t, err)
		require.Equal(t.t, zaneInfo.Version, info.Version)
	}

	// The channel's commitments still carry no spender leaves.
	assertSpenderLeaves(t.t, charlie, dave, false)
	assertSpenderLeaves(t.t, dave, charlie, false)

	// With both peers upgraded, one payment updates the channel to
	// commitments that carry spender leaves. It must complete before the
	// activation height.
	pay()
	assertSpenderLeaves(t.t, charlie, dave, true)
	assertSpenderLeaves(t.t, dave, charlie, true)
	_, height = net.Miner.GetBestBlock()
	require.Less(t.t, uint32(height), activationHeight)

	// Mine up to the activation height, then force close: the commitment
	// transaction confirms past it.
	mineBlocks(t, net, activationHeight-uint32(height), 0)

	t.Logf("Force closing Charlie -> Dave channel past activation...")
	_, closeTxid, err := net.CloseChannel(charlie, chanPoint, true)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	// Both peers import the proofs of the commitment outputs, which they
	// can only verify if those proofs carry spender proofs.
	findForceCloseTransfer(t.t, charlie, dave, closeTxid)

	// Dave sweeps his commitment output first; Charlie's is CSV delayed.
	_, err = waitForNTxsInMempool(net.Miner, 1, ccShortTimeout)
	require.NoError(t.t, err)
	daveSweepBlocks := mineBlocks(t, net, 1, 1)
	daveSweepTxid := daveSweepBlocks[0].Transactions[1].TxHash()
	daveSweep := locateAssetTransfers(t.t, dave, daveSweepTxid)

	mineBlocks(t, net, 4, 0)
	charlieSweepTxids, err := waitForNTxsInMempool(
		net.Miner, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)
	charlieSweep := locateAssetTransfers(
		t.t, charlie, *charlieSweepTxids[0],
	)

	daveBalance := uint64((numPayments + 1) * keySendAmount)
	assertBalance(t.t, dave, daveBalance, itest.WithAssetID(assetID))
	assertBalance(
		t.t, charlie, ccItestAsset.Amount-daveBalance,
		itest.WithAssetID(assetID),
	)

	assertSweptProofs(
		ctx, t, charlie, assetID, charlieSweep, activationHeight,
	)
	assertSweptProofs(ctx, t, dave, assetID, daveSweep, activationHeight)
}

// assertSpenderLeaves asserts that the custom data of the asset channel from
// src to dst reports whether its local commitment carries spender leaves.
func assertSpenderLeaves(t *testing.T, src, dst *itest.IntegratedNode,
	want bool) {

	t.Helper()

	err := wait.NoError(func() error {
		chanData, err := getChannelCustomData(src, dst)
		if err != nil {
			return err
		}

		if chanData.SpenderLeaves != want {
			return fmt.Errorf("%s reports spender leaves %v, "+
				"want %v", src.Cfg.Name,
				chanData.SpenderLeaves, want)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// assertSweptProofs exports the proof file of the asset a sweep transfer
// leaves to the given node, and asserts that it mixes proofs from before the
// activation height, made on the old release without spender proofs, with
// proofs from the activation height on, which carry them. The node, which
// applies the activation height, must verify the file.
func assertSweptProofs(ctx context.Context, t *ccHarnessTest,
	node *itest.IntegratedNode, assetID []byte,
	sweep *taprpc.AssetTransfer, activationHeight uint32) {

	t.t.Helper()

	isOurs := func(o *taprpc.TransferOutput) bool {
		return o.ScriptKeyIsLocal && o.Amount > 0
	}
	idx := slices.IndexFunc(sweep.Outputs, isOurs)
	require.GreaterOrEqual(t.t, idx, 0)
	out := sweep.Outputs[idx]

	op, err := wire.NewOutPointFromString(out.Anchor.Outpoint)
	require.NoError(t.t, err)

	resp, err := asTapd(node).ExportProof(ctx, &taprpc.ExportProofRequest{
		AssetId:   assetID,
		ScriptKey: out.ScriptKey,
		Outpoint: &taprpc.OutPoint{
			Txid:        op.Hash[:],
			OutputIndex: op.Index,
		},
	})
	require.NoError(t.t, err)

	file, err := proof.DecodeFile(resp.RawProofFile)
	require.NoError(t.t, err)

	var before, after int
	for i := range file.NumProofs() {
		p, err := file.ProofAt(uint32(i))
		require.NoError(t.t, err)

		if p.Asset.IsGenesisAsset() {
			continue
		}

		rootProof := &p.InclusionProof
		if p.Asset.HasSplitCommitmentWitness() {
			rootProof = p.SplitRootProof
		}
		require.NotNil(t.t, rootProof)
		require.NotNil(t.t, rootProof.CommitmentProof)
		spenderProofs := rootProof.CommitmentProof.SpenderProofs

		if p.BlockHeight < activationHeight {
			require.Empty(t.t, spenderProofs)
			before++

			continue
		}

		require.NotEmpty(t.t, spenderProofs)
		after++
	}

	// The funding transfer precedes the activation height; the force
	// close and the sweep follow it.
	require.Positive(t.t, before)
	require.GreaterOrEqual(t.t, after, 2)

	verifyResp, err := asTapd(node).VerifyProof(ctx, &taprpc.ProofFile{
		RawProofFile: resp.RawProofFile,
	})
	require.NoError(t.t, err)
	require.True(t.t, verifyResp.Valid)
}
