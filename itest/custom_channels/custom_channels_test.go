//go:build itest

package custom_channels

import (
	"context"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/stretchr/testify/require"
)

// customChannelTestCases is the list of custom channel integration tests.
// Each test function lives in its own file (e.g.
// custom_channels_large_test.go).
var customChannelTestCases = []*ccTestCase{
	{
		name: "custom channels large",
		test: testCustomChannelsLarge,
	},
}

// TestCustomChannels is the main entry point for running custom channel
// integration tests against the tapd-integrated binary. It creates a miner,
// chain backend, and network harness, then runs each test case sequentially.
func TestCustomChannels(t *testing.T) {
	if len(customChannelTestCases) == 0 {
		t.Skip("no custom channel test cases registered")
	}

	// Allow more blocks to be mined during these tests.
	lntest.MaxBlocksMinedPerTest = 250

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

	// Step 3: Create integrated network harness.
	net := itest.NewIntegratedNetworkHarness(
		t, "../tapd-integrated-itest", chainBackend,
		miner.HarnessNetParams,
	)
	net.Miner = m
	defer net.TearDown()

	// Step 4: Filter tests by tranche if running in parallel CI mode.
	tests := customChannelTestCases
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

	// Step 5: Run test cases.
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
		if !success {
			t.Logf("Failure time: %v", time.Now().Format(
				"2006-01-02 15:04:05.000",
			))

			return
		}
	}
}
