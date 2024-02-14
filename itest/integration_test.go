//go:build itest

package itest

import (
	"context"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/stretchr/testify/require"
)

var optionalTests = flag.Bool("optional", false, "if true, the optional test"+
	"list will be used")

// TestTaprootAssetsDaemon performs a series of integration tests amongst a
// programmatically driven set of participants, namely a Taproot Assets daemon
// and a universe server.
func TestTaprootAssetsDaemon(t *testing.T) {
	// Switch to the list of optional test cases with the '-optional' flag.
	testList := testCases
	if *optionalTests {
		testList = optionalTestCases
	}

	// If no tests are registered, then we can exit early.
	if len(testList) == 0 {
		t.Skip("integration tests not selected with flag 'itest'")
	}

	ht := &harnessTest{t: t}
	ht.setupLogging()

	// Now we can set up our test harness (LND instance), with the chain
	// backend we just created.
	feeService := lntest.NewFeeService(t)
	lndHarness := lntest.SetupHarness(t, "./lnd-itest", "bbolt", feeService)
	defer func() {
		// There is a timing issue in here somewhere. If we shut down
		// lnd immediately after stopping the tapd server, sometimes
		// we get a race in the TX notifier chan closes. The wait seems
		// to fix it for now...
		time.Sleep(100 * time.Millisecond)
		lndHarness.Stop()
	}()

	lndHarness.SetupStandbyNodes()

	// Create a new LND node for use with the universe server.
	t.Log("Starting universe server LND node")
	uniServerLndHarness := lndHarness.NewNode("uni-server-lnd", nil)

	// Wait for the new LND node to be fully synced to the blockchain.
	lndHarness.WaitForBlockchainSync(uniServerLndHarness)

	t.Logf("Running %v integration tests", len(testList))
	for _, testCase := range testList {
		logLine := fmt.Sprintf("STARTING ============ %v ============\n",
			testCase.name)

		success := t.Run(testCase.name, func(t1 *testing.T) {
			// The universe server and tapd client are both freshly
			// created and later discarded for each test run to
			// assure no state is taken over between runs.
			tapdHarness, uniHarness, proofCourier := setupHarnesses(
				t1, ht, lndHarness, uniServerLndHarness,
				testCase.proofCourierType,
			)
			lndHarness.EnsureConnected(
				lndHarness.Alice, lndHarness.Bob,
			)
			lndHarness.EnsureConnected(
				lndHarness.Alice, uniServerLndHarness,
			)
			lndHarness.EnsureConnected(
				lndHarness.Bob, uniServerLndHarness,
			)

			lndHarness.Alice.AddToLogf(logLine)
			lndHarness.Bob.AddToLogf(logLine)

			ht := ht.newHarnessTest(
				t1, lndHarness, uniHarness, tapdHarness,
				proofCourier,
			)

			// Now we have everything to run the test case.
			ht.RunTestCase(testCase)

			// Shut down both client and server to remove all state.
			err := ht.shutdown(t1)
			require.NoError(t1, err)
		})

		// Stop at the first failure. Mimic behavior of original test
		// framework.
		if !success {
			return
		}
	}
}

// testGetInfo tests the GetInfo RPC call.
func testGetInfo(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := t.tapd.GetInfo(ctxt, &taprpc.GetInfoRequest{})
	require.NoError(t.t, err)

	// Ensure network field is set correctly.
	expectedNetwork := t.tapd.cfg.NetParams.Name
	require.Equal(t.t, expectedNetwork, resp.Network)
}
