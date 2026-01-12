//go:build itest

package itest

import (
	"context"
	"flag"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
)

const (
	// defaultSplitTranches is the default number of tranches we split the
	// test cases into.
	defaultSplitTranches uint = 1

	// defaultRunTranche is the default index of the test cases tranche that
	// we run.
	defaultRunTranche uint = 0
)

var (
	optionalTests = flag.Bool(
		"optional", false, "if true, the optional test list will be "+
			"used",
	)

	// testCasesSplitParts is the number of tranches the test cases should
	// be split into. By default this is set to 1, so no splitting happens.
	// If this value is increased, then the -runtranche flag must be
	// specified as well to indicate which part should be run in the current
	// invocation.
	testCasesSplitTranches = flag.Uint(
		"splittranches", defaultSplitTranches, "split the test cases "+
			"in this many tranches and run the tranche at "+
			"0-based index specified by the -runtranche flag",
	)

	// shuffleSeedFlag is the source of randomness used to shuffle the test
	// cases. If not specified, the test cases won't be shuffled.
	shuffleSeedFlag = flag.Uint64(
		"shuffleseed", 0, "if set, shuffles the test cases using this "+
			"as the source of randomness",
	)

	// testCasesRunTranche is the 0-based index of the split test cases
	// tranche to run in the current invocation.
	testCasesRunTranche = flag.Uint(
		"runtranche", defaultRunTranche, "run the tranche of the "+
			"split test cases with the given (0-based) index",
	)
)

// TestTaprootAssetsDaemon performs a series of integration tests amongst a
// programmatically driven set of participants, namely a Taproot Assets daemon
// and a universe server.
func TestTaprootAssetsDaemon(t *testing.T) {
	// Get the test cases to be run in this tranche.
	testCases, trancheIndex, trancheOffset := getTestCaseSplitTranche()

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
	lndHarness := lntest.SetupHarness(
		t, "./lnd-itest", "bbolt", true, feeService,
	)
	t.Cleanup(func() {
		lndHarness.CleanShutDown()
	})

	// Get the current block height.
	height := lndHarness.CurrentHeight()

	t.Logf("Running %v integration tests", len(testList))
	for idx, testCase := range testList {
		name := fmt.Sprintf("tranche%02d/%02d-of-%d/%s",
			trancheIndex, trancheOffset+uint(idx)+1,
			len(allTestCases), testCase.name)

		success := t.Run(name, func(t1 *testing.T) {
			// Create a new LND node for use with the universe
			// server.
			t.Log("Starting universe server LND node")
			uniServerLndHarness := lndHarness.NewNode(
				"uni-server-lnd", nil,
			)

			// We need to shut down any lnd nodes that were created
			// for this test case.
			t1.Cleanup(func() {
				lndHarness.CleanShutDown()
			})

			// Wait for the new LND node to be fully synced to the
			// blockchain.
			lndHarness.WaitForBlockchainSync(uniServerLndHarness)

			// The universe server and tapd client are both freshly
			// created and later discarded for each test run to
			// assure no state is taken over between runs.
			tapdHarness, uniHarness, proofCourier := setupHarnesses(
				t1, ht, lndHarness, uniServerLndHarness,
				testCase.proofCourierType,
			)

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

	//nolint:forbidigo
	fmt.Printf("=========> tranche %v finished, tested %d cases, mined "+
		"blocks: %d\n", trancheIndex, len(testCases),
		lndHarness.CurrentHeight()-height)
}

// testGetInfo tests the GetInfo RPC call.
func testGetInfo(t *harnessTest) {
	ctx := context.Background()

	resp, err := t.tapd.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t.t, err)

	// Ensure network field is set correctly.
	expectedNetwork := t.tapd.cfg.NetParams.Name
	require.Equal(t.t, expectedNetwork, resp.Network)

	// Attempt to get the info using the CLI.
	respGeneric, err := ExecTapCLI(ctx, t.tapd, "getinfo")
	require.NoError(t.t, err)

	// Type assert the response to the expected type.
	respCli := respGeneric.(*taprpc.GetInfoResponse)

	// Ensure the response matches the expected response.
	require.Equal(t.t, resp, respCli)
}

// maybeShuffleTestCases shuffles the test cases if the flag `shuffleseed` is
// set and not 0. In parallel tests we want to shuffle the test cases so they
// are executed in a random order. This is done to even out the blocks mined in
// each test tranche so they can run faster.
//
// NOTE: Because the parallel tests are initialized with the same seed (job
// ID), they will always have the same order.
func maybeShuffleTestCases() {
	// Exit if not set.
	if shuffleSeedFlag == nil {
		return
	}

	// Exit if set to 0.
	if *shuffleSeedFlag == 0 {
		return
	}

	// Init the seed and shuffle the test cases.
	rand.Seed(*shuffleSeedFlag)
	rand.Shuffle(len(allTestCases), func(i, j int) {
		allTestCases[i], allTestCases[j] =
			allTestCases[j], allTestCases[i]
	})
}

// createIndices divides the number of test cases into pairs of indices that
// specify the start and end of a tranche.
func createIndices(numCases, numTranches uint) [][2]uint {
	// Calculate base value and remainder.
	base := numCases / numTranches
	remainder := numCases % numTranches

	// Generate indices.
	indices := make([][2]uint, numTranches)
	start := uint(0)

	for i := uint(0); i < numTranches; i++ {
		end := start + base
		if i < remainder {
			// Add one for the remainder.
			end++
		}
		indices[i] = [2]uint{start, end}
		start = end
	}

	return indices
}

// getTestCaseSplitTranche returns the sub slice of the test cases that should
// be run as the current split tranche as well as the index and slice offset of
// the tranche.
func getTestCaseSplitTranche() ([]*testCase, uint, uint) {
	numTranches := defaultSplitTranches
	if testCasesSplitTranches != nil {
		numTranches = *testCasesSplitTranches
	}
	runTranche := defaultRunTranche
	if testCasesRunTranche != nil {
		runTranche = *testCasesRunTranche
	}

	// There's a special flake-hunt mode where we run the same test multiple
	// times in parallel. In that case the tranche index is equal to the
	// thread ID, but we need to actually run all tests for the regex
	// selection to work.
	threadID := runTranche
	if numTranches == 1 {
		runTranche = 0
	}

	// Shuffle the test cases if the `shuffleseed` flag is set.
	maybeShuffleTestCases()

	numCases := uint(len(allTestCases))
	indices := createIndices(numCases, numTranches)
	index := indices[runTranche]
	trancheOffset, trancheEnd := index[0], index[1]

	return allTestCases[trancheOffset:trancheEnd], threadID,
		trancheOffset
}
