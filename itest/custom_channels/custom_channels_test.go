//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testCases is the list of custom channel integration tests.
var testCases = []*ccTestCase{
	{
		name: "core",
		test: testCustomChannels,
	},
	{
		name: "large",
		test: testCustomChannelsLarge,
	},
	{
		name: "grouped asset",
		test: testCustomChannelsGroupedAsset,
	},
	{
		name: "force close",
		test: testCustomChannelsForceClose,
	},
	{
		name: "group tranches force close",
		test: testCustomChannelsGroupTranchesForceClose,
	},
	{
		name: "group tranches htlc force close",
		test: testCustomChannelsGroupTranchesHtlcForceClose,
	},
	{
		name: "htlc force close",
		test: testCustomChannelsHtlcForceClose,
	},
	{
		name: "htlc force close mpp",
		test: testCustomChannelsHtlcForceCloseMpp,
	},
	{
		name: "liquidity edge cases",
		test: testCustomChannelsLiquidityEdgeCases,
	},
	{
		name: "liquidity edge cases group",
		test: testCustomChannelsLiquidityEdgeCasesGroup,
	},
	{
		name: "balance consistency",
		test: testCustomChannelsBalanceConsistency,
	},
	{
		name: "single asset multi input",
		test: testCustomChannelsSingleAssetMultiInput,
	},
	{
		name: "forward bandwidth",
		test: testCustomChannelsForwardBandwidth,
	},
	{
		name: "multi channel pathfinding",
		test: testCustomChannelsMultiChannelPathfinding,
	},
	{
		name: "strict forwarding",
		test: testCustomChannelsStrictForwarding,
	},
	{
		name: "decode asset invoice",
		test: testCustomChannelsDecodeAssetInvoice,
	},
	{
		name: "self payment",
		test: testCustomChannelsSelfPayment,
	},
	{
		name: "multi rfq",
		test: testCustomChannelsMultiRFQ,
	},
	{
		name: "oracle pricing",
		test: testCustomChannelsOraclePricing,
	},
}

// TestCustomChannels is the main entry point for running custom channel
// integration tests against the tapd-integrated binary. It creates a miner,
// chain backend, and network harness, then runs each test case sequentially.
func TestCustomChannels(t *testing.T) {
	if len(testCases) == 0 {
		t.Skip("no test cases registered")
	}

	// Allow more blocks to be mined during these tests.
	lntest.MaxBlocksMinedPerTest = 250

	// Create the log directories that the miner and chain backend
	// cleanup routines expect to exist.
	logDir := node.GetLogDir()
	netName := miner.HarnessNetParams.Name
	for _, dir := range []string{".minerlogs", ".backendlogs"} {
		path := fmt.Sprintf("%s/%s/%s", logDir, dir, netName)
		require.NoError(t, os.MkdirAll(path, 0750))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Step 1: Create and start a btcd miner.
	m := miner.NewMiner(ctx, t)
	require.NoError(t, m.SetUp(true, 50))
	require.NoError(t, m.Client.NotifyNewTransactions(false))
	t.Cleanup(func() { m.Stop() })

	// Generate enough blocks so we're past the coinbase maturity window.
	numBlocks := miner.HarnessNetParams.MinerConfirmationWindow * 2
	m.GenerateBlocks(numBlocks)

	// Step 2: Create a chain backend (btcd) connected to the miner.
	chainBackend, cleanup, err := lntest.NewBackend(
		m.P2PAddress(), miner.HarnessNetParams,
	)
	require.NoError(t, err, "unable to create chain backend")
	defer func() {
		require.NoError(t, cleanup(), "cleanup chain backend")
	}()
	require.NoError(t, chainBackend.ConnectMiner(),
		"unable to connect miner")

	// Step 3: Create fee service for predictable fee estimation.
	// Without this, btcd's fee estimator returns unpredictable rates
	// in regtest, causing tests with hard-coded commit fee values
	// (like oracle pricing) to fail. We set the fee rate to the floor
	// value to prevent the sweeper's budget-derived max fee rate from
	// being lower than the estimated fee rate, which would make fee
	// bumping impossible.
	feeService := lntest.NewFeeService(t)
	feeService.SetFeeRate(chainfee.FeePerKwFloor, 1)
	require.NoError(t, feeService.Start())
	t.Cleanup(func() {
		require.NoError(t, feeService.Stop())
	})

	// Step 4: Create integrated network harness.
	net := itest.NewIntegratedNetworkHarness(
		t, "../tapd-integrated-itest", chainBackend,
		miner.HarnessNetParams,
	)
	net.Miner = m
	net.FeeServiceURL = feeService.URL()
	defer net.TearDown()

	// Step 5: Filter tests by tranche if running in parallel CI mode.
	tests := testCases
	if *splitTranches > 1 {
		tests = filterByTranche(
			tests, *runTranche, *splitTranches,
		)
		t.Logf("Running tranche %d of %d (%d tests)",
			*runTranche, *splitTranches, len(tests))
	}

	if len(tests) == 0 {
		t.Skip("no tests in this tranche")
	}

	// Step 6: Run test cases.
	for _, tc := range tests {
		tc := tc
		success := t.Run(tc.name, func(t1 *testing.T) {
			ht := &ccHarnessTest{
				t:          t1,
				testCase:   tc,
				lndHarness: net,
			}
			ctxt, cancel := context.WithTimeout(
				ctx, 10*time.Minute,
			)
			defer cancel()

			tc.test(ctxt, net, ht)
		})

		// Stop all nodes from this test case before the next one.
		net.TearDown()

		if !success {
			t.Logf("Failure time: %v", time.Now().Format(
				"2006-01-02 15:04:05.000",
			))

			return
		}
	}
}
