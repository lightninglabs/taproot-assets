//go:build itest
// +build itest

package itest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/stretchr/testify/require"
)

// TestTaprootAssetsDaemon performs a series of integration tests amongst a
// programmatically driven set of participants, namely a Taproot Assets daemon
// and a universe server.
func TestTaprootAssetsDaemon(t *testing.T) {
	// If no tests are registered, then we can exit early.
	if len(testCases) == 0 {
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

	t.Logf("Running %v integration tests", len(testCases))
	for _, testCase := range testCases {
		logLine := fmt.Sprintf("STARTING ============ %v ============\n",
			testCase.name)

		success := t.Run(testCase.name, func(t1 *testing.T) {
			// Create a subtest harness for each test case.
			subTestLnd := lndHarness.Subtest(t1)

			// The universe server and tapd client are both freshly
			// created and later discarded for each test run to
			// assure no state is taken over between runs.
			tapdHarness, universeServer, proofCourier :=
				setupHarnesses(
					t1, ht, subTestLnd,
					testCase.proofCourierType,
				)
			subTestLnd.EnsureConnected(
				subTestLnd.Alice, subTestLnd.Bob,
			)

			subTestLnd.Alice.AddToLogf(logLine)
			subTestLnd.Bob.AddToLogf(logLine)

			ht := ht.newHarnessTest(
				t1, subTestLnd, universeServer,
				tapdHarness, proofCourier,
			)

			// Now we have everything to run the test case.
			ht.RunTestCase(testCase)

			// Shut down both client and server to remove all state.
			err := ht.shutdown(t)
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
