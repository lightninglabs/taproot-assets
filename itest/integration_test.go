//go:build itest
// +build itest

package itest

import (
	"fmt"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// TestTaroDaemon performs a series of integration tests amongst a
// programmatically driven set of participants, namely a Taro daemon and a
// universe server.
func TestTaroDaemon(t *testing.T) {
	// If no tests are registered, then we can exit early.
	if len(testCases) == 0 {
		t.Skip("integration tests not selected with flag 'itest'")
	}

	ht := &harnessTest{t: t}
	ht.setupLogging()

	// Create an instance of the btcd's rpctest.Harness that will act as
	// the miner for all tests. This will be used to fund the wallets of
	// the nodes within the test network and to drive blockchain related
	// events within the network. Revert the default setting of accepting
	// non-standard transactions on simnet to reject them. Transactions on
	// the lightning network should always be standard to get better
	// guarantees of getting included in to blocks.
	//
	// We will also connect it to our chain backend.
	miner, err := lntest.NewMiner()
	require.NoError(ht.t, err)
	defer func() {
		require.NoError(t, miner.Stop())
	}()

	// Start a chain backend.
	chainBackend, cleanUp, err := lntest.NewBackend(
		miner.P2PAddress(), harnessNetParams,
	)
	require.NoError(ht.t, err)
	defer cleanUp()

	// As we mine blocks below to trigger segwit and CSV activation, we
	// don't need to mine a test chain here.
	require.NoError(ht.t, miner.SetUp(false, 0))
	require.NoError(ht.t, miner.Client.NotifyNewTransactions(false))
	require.NoError(ht.t, chainBackend.ConnectMiner())

	// Now we can set up our test harness (LND instance), with the chain
	// backend we just created.
	lndHarness, err := lntest.NewNetworkHarness(
		miner, chainBackend, "./lnd-itest", lntest.BackendBbolt,
	)
	require.NoError(ht.t, err)

	defer func() {
		// There is a timing issue in here somewhere. If we shut down
		// lnd immediately after stopping the tarod server, sometimes
		// we get a race in the TX notifier chan closes. The wait seems
		// to fix it for now...
		time.Sleep(100 * time.Millisecond)
		_ = lndHarness.TearDown()
		lndHarness.Stop()
	}()

	// Spawn a new goroutine to watch for any fatal errors that any of the
	// running lnd processes encounter. If an error occurs, then the test
	// case should naturally as a result and we log the server error here to
	// help debug.
	go func() {
		for {
			select {
			case err, more := <-lndHarness.ProcessErrors():
				if !more {
					return
				}
				ht.Logf("lnd finished with error (stderr):\n%v",
					err)
			}
		}
	}()

	// Next mine enough blocks in order for segwit and the CSV package
	// soft-fork to activate on SimNet.
	numBlocks := harnessNetParams.MinerConfirmationWindow * 4
	_, err = miner.Client.Generate(numBlocks)
	require.NoError(ht.t, err)

	// With the btcd harness created, we can now complete the
	// initialization of the network.
	err = lndHarness.SetUp(ht.t, "taro-itest", lndDefaultArgs)
	require.NoError(ht.t, err)

	// Before we continue on below, we'll wait here until the specified
	// number of blocks has been mined, to ensure we have complete control
	// over the extension of the chain. 10 extra block are mined as the
	// SetUp method above mines 10 blocks to confirm the coins it sends to
	// the first nodes in the harness.
	targetHeight := int32(numBlocks) + 10
	err = wait.NoError(func() error {
		_, blockHeight, err := miner.Client.GetBestBlock()
		if err != nil {
			return fmt.Errorf("unable to get best block: %v", err)
		}

		if blockHeight < targetHeight {
			return fmt.Errorf("want height %v, got %v",
				blockHeight, targetHeight)
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t, err)

	t.Logf("Running %v integration tests", len(testCases))
	for _, testCase := range testCases {
		logLine := fmt.Sprintf("STARTING ============ %v ============\n",
			testCase.name)

		success := t.Run(testCase.name, func(t1 *testing.T) {
			// The universe server and tarod client are both freshly
			// created and later discarded for each test run to
			// assure no state is taken over between runs.
			tarodHarness, universeServer := setupHarnesses(
				t1, ht, lndHarness,
			)
			lndHarness.EnsureConnected(
				t1, lndHarness.Alice, lndHarness.Bob,
			)

			lndHarness.Alice.AddToLogf(logLine)
			lndHarness.Bob.AddToLogf(logLine)

			ht := ht.newHarnessTest(
				t1, lndHarness, universeServer, tarodHarness,
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
