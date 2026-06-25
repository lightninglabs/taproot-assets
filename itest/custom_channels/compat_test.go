//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// compatVersions lists the historical release versions to test backward
// compatibility against. Update this list before each release to include
// the latest 2 minor versions. v0.8.0 is the earliest tagged release that
// includes the cmd/tapd-integrated binary, so it is our initial baseline.
var compatVersions = []string{
	"v0.8.0",
}

// buildCompatBinary builds or retrieves a cached tapd-integrated binary for
// the given version tag. It returns the path to the binary.
func buildCompatBinary(t *testing.T, version string) string {
	t.Helper()

	// Locate the build script relative to the repo root.
	repoRoot, err := exec.Command(
		"git", "rev-parse", "--show-toplevel",
	).Output()
	require.NoError(t, err, "unable to find repo root")

	script := filepath.Join(
		strings.TrimSpace(string(repoRoot)),
		"scripts", "build-compat-binary.sh",
	)

	// Run the build script. It prints the binary path on stdout.
	//nolint:gosec
	cmd := exec.Command(script, version)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	require.NoError(t, err, "unable to build compat binary for %s",
		version)

	binaryPath := strings.TrimSpace(string(out))
	require.FileExists(t, binaryPath)

	return binaryPath
}

// TestBackwardsCompatChannels runs a single, lean custom channel scenario with one
// node (Charlie) running an older release binary and the other (Dave) running
// the current build, for each historical version in compatVersions. It is gated
// behind the `itest` build tag and intended to run only on release branches or
// via manual dispatch, so we deliberately keep it to one scenario to avoid
// inflating CI runtime with version-multiplied test cases.
func TestBackwardsCompatChannels(t *testing.T) {
	if len(compatVersions) == 0 {
		t.Skip("no compat versions configured")
	}

	for _, version := range compatVersions {
		version := version
		t.Run(version, func(t *testing.T) {
			runCompatScenario(t, version)
		})
	}
}

// runCompatScenario stands up the shared test infrastructure (miner, chain
// backend, fee service and network harness) for a single historical version and
// then runs the cooperative-close compat scenario against it.
func runCompatScenario(t *testing.T, version string) {
	t.Helper()

	// Build or retrieve the old binary that Charlie will run.
	oldBinary := buildCompatBinary(t, version)
	t.Logf("Using compat binary for %s: %s", version, oldBinary)

	lntest.MaxBlocksMinedPerTest = 250

	logDir := node.GetLogDir()
	netName := miner.HarnessNetParams.Name
	for _, dir := range []string{".minerlogs", ".backendlogs"} {
		path := fmt.Sprintf("%s/%s/%s", logDir, dir, netName)
		require.NoError(t, os.MkdirAll(path, 0750))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := miner.NewMiner(ctx, t)
	require.NoError(t, m.Start(true, 50))
	require.NoError(t, m.NotifyNewTransactions(false))
	t.Cleanup(func() { m.Stop() })

	numBlocks := miner.HarnessNetParams.MinerConfirmationWindow * 2
	m.GenerateBlocks(numBlocks)

	chainBackend, cleanup, err := lntest.NewBackend(
		m.P2PAddress(), miner.HarnessNetParams,
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, cleanup())
	}()
	require.NoError(t, chainBackend.ConnectMiner())

	feeService := lntest.NewFeeService(t)
	feeService.SetFeeRate(chainfee.FeePerKwFloor, 1)
	require.NoError(t, feeService.Start())
	t.Cleanup(func() {
		require.NoError(t, feeService.Stop())
	})

	net := itest.NewIntegratedNetworkHarness(
		t, "../tapd-integrated-itest", chainBackend,
		miner.HarnessNetParams,
	)
	net.Miner = m
	net.FeeServiceURL = feeService.URL()
	net.FeeService = feeService
	defer net.TearDown()

	ht := &ccHarnessTest{
		t:          t,
		lndHarness: net,
	}

	ctxt, cancelScenario := context.WithTimeout(ctx, 15*time.Minute)
	defer cancelScenario()

	runBackwardsCompatLifecycle(ctxt, net, ht, oldBinary, version)
}

// runBackwardsCompatLifecycle exercises the core lifecycle of an asset channel
// between a node running a pinned historical binary (Charlie) and a node
// running the current build (Dave). To cover both on-chain close paths
// cross-version, it runs two cycles on the same node pair: the first funds a
// channel, sends asset payments in both directions and cooperatively closes;
// the second funds a fresh channel, sends payments and force closes, then
// drives the resulting sweeps. Its purpose is to detect cross-version
// regressions in the channel protocol, so it is deliberately a single lean
// scenario rather than a re-run of the full custom channel test matrix.
func runBackwardsCompatLifecycle(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest,
	oldBinary, version string) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Charlie (the old node) doubles as the proof courier for both nodes,
	// so we pin his RPC port up front (minimum viable proof distribution).
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))
	charlieLndArgs := append(slices.Clone(lndArgs), fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))

	// Charlie runs the pinned historical binary; Dave runs the current
	// build provided by the harness.
	charlie := net.NewNodeWithBinary(
		"Charlie", oldBinary, charlieLndArgs, tapdArgs,
	)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Sanity check: Charlie really is running the pinned historical version,
	// and Dave is running a different (current) build.
	charlieInfo, err := asTapd(charlie).GetInfo(
		ctx, &taprpc.GetInfoRequest{},
	)
	require.NoError(t.t, err)
	daveInfo, err := asTapd(dave).GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t.t, err)
	require.Contains(
		t.t, charlieInfo.Version, strings.TrimPrefix(version, "v"),
		"Charlie should report the pinned %s version", version,
	)
	require.NotEqual(t.t, charlieInfo.Version, daveInfo.Version)
	t.Logf("Charlie (old) version=%s, Dave (current) version=%s",
		charlieInfo.Version, daveInfo.Version)

	// Charlie mints the channel asset and Dave syncs to him as universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{Asset: ccItestAsset},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave)

	// ----------------------------------------------------------------
	// Cycle 1: fund -> bidirectional payments -> cooperative close.
	// ----------------------------------------------------------------

	// Charlie opens an asset channel to Dave, pushing a few sats so Dave
	// has an initial balance on his side of the channel.
	t.Logf("Opening asset channel Charlie -> Dave (coop close cycle)...")
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            DefaultPushSat,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel: %v", assetFundResp)

	mineBlocks(t, net, 6, 1)

	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	logBalance(t.t, nodes, assetID, "after funding")

	// Send two asset payments from Charlie to Dave.
	const forwardAmount = 10_000
	for range 2 {
		sendAssetKeySendPayment(
			t.t, charlie, dave, forwardAmount, assetID,
			fn.None[int64](),
		)
	}
	logBalance(t.t, nodes, assetID, "after forward payments")

	// Replenish Dave's channel sat balance with a BTC-only keysend so he
	// can fund the HTLCs for the return asset payments.
	sendKeySendPayment(t.t, charlie, dave, 10_000)

	// Send two asset payments back from Dave to Charlie. We use a smaller
	// amount so Dave retains an asset balance for the close assertions.
	const backAmount = 5_000
	for range 2 {
		sendAssetKeySendPayment(
			t.t, dave, charlie, backAmount, assetID,
			fn.None[int64](),
		)
	}
	logBalance(t.t, nodes, assetID, "after return payments")

	// Expected channel asset balances after the four payments:
	//   Charlie: fundingAmount - 2*forwardAmount + 2*backAmount = 40_000
	//   Dave:                    2*forwardAmount - 2*backAmount = 10_000
	const (
		coopCharlieChan = fundingAmount - 2*forwardAmount + 2*backAmount
		coopDaveChan    = 2*forwardAmount - 2*backAmount
	)

	// Cooperatively close the channel from Charlie. Dave holds both a sat
	// and an asset balance, so the close tx carries outputs for both.
	t.Logf("Cooperatively closing Charlie -> Dave channel...")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPoint, [][]byte{assetID}, nil,
		charlie, assertDefaultCoOpCloseBalance(true, true),
	)

	// With the channel closed, the assets are back on-chain. Charlie keeps
	// his minted remainder plus his channel share, and Dave keeps his
	// channel share.
	assertBalance(
		t.t, charlie, ccItestAsset.Amount-fundingAmount+coopCharlieChan,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, dave, coopDaveChan, itest.WithAssetID(assetID),
	)

	// ----------------------------------------------------------------
	// Cycle 2: fund -> payments -> force close -> sweeps.
	// ----------------------------------------------------------------
	net.EnsureConnected(t.t, charlie, dave)

	t.Logf("Opening asset channel Charlie -> Dave (force close cycle)...")
	forceFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel: %v", forceFundResp)

	mineBlocks(t, net, 6, 1)

	// Dave already synced the asset genesis from Charlie in cycle 1, and the
	// new channel's funding proof is delivered via the proof courier during
	// funding, so no additional universe sync is needed here.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	// Push a handful of asset keysends to Dave, carrying enough sats each
	// time that Dave's commitment output stays above dust and is therefore
	// worth sweeping after the force close.
	const (
		forceNumPayments = 5
		forceKeySend     = 100
		forceBtcAmt      = int64(5_000)
	)
	for range forceNumPayments {
		sendAssetKeySendPayment(
			t.t, charlie, dave, forceKeySend, assetID,
			fn.Some(forceBtcAmt),
		)
	}
	logBalance(t.t, nodes, assetID, "after force-close-cycle payments")

	// Force close from Charlie and confirm the commitment transaction.
	t.Logf("Force closing Charlie -> Dave channel...")
	forceChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(forceFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: forceFundResp.Txid,
		},
	}
	_, forceCloseTxid, err := net.CloseChannel(
		charlie, forceChanPoint, true,
	)
	require.NoError(t.t, err)

	mineBlocks(t, net, 1, 1)

	// Both nodes should record the force close transfer.
	findForceCloseTransfer(t.t, charlie, dave, forceCloseTxid)

	// Dave sweeps his (non-delayed) commitment output first.
	_, err = waitForNTxsInMempool(net.Miner, 1, ccShortTimeout)
	require.NoError(t.t, err)
	daveSweepBlocks := mineBlocks(t, net, 1, 1)
	daveSweepTxHash := daveSweepBlocks[0].Transactions[1].TxHash()
	locateAssetTransfers(t.t, dave, daveSweepTxHash)

	// Charlie's to-local output is CSV-delayed; mine the delay, then confirm
	// his sweep.
	mineBlocks(t, net, 4, 0)
	_, err = waitForNTxsInMempool(net.Miner, 1, ccShortTimeout)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 0)

	// Final on-chain asset balances across both cycles. Dave keeps his coop
	// cycle share plus everything Charlie pushed to him this cycle; Charlie
	// holds the rest of the minted supply.
	const forceDaveGain = forceNumPayments * forceKeySend
	daveFinal := uint64(coopDaveChan + forceDaveGain)
	assertBalance(t.t, dave, daveFinal, itest.WithAssetID(assetID))
	assertBalance(
		t.t, charlie, ccItestAsset.Amount-daveFinal,
		itest.WithAssetID(assetID),
	)
}
