//go:build itest
// +build itest

package itest

import (
	"fmt"
	"testing"
	"time"

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

	// Start aperture service and attach to test harness.
	//
	// TODO(ffranr): Each test case should have access to its own
	// 		 independent aperture service. Remove this global
	//   	         instance.
	apertureHarness := setupApertureHarness(ht.t)
	ht.apertureHarness = &apertureHarness

	t.Logf("Running %v integration tests", len(testCases))
	for _, testCase := range testCases {
		logLine := fmt.Sprintf("STARTING ============ %v ============\n",
			testCase.name)

		success := t.Run(testCase.name, func(t1 *testing.T) {
			// The universe server and tapd client are both freshly
			// created and later discarded for each test run to
			// assure no state is taken over between runs.
			tapdHarness, universeServer := setupHarnesses(
				t1, ht, lndHarness, testCase.enableHashMail,
			)
			lndHarness.EnsureConnected(
				lndHarness.Alice, lndHarness.Bob,
			)

			lndHarness.Alice.AddToLogf(logLine)
			lndHarness.Bob.AddToLogf(logLine)

			ht := ht.newHarnessTest(
				t1, lndHarness, universeServer, tapdHarness,
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
