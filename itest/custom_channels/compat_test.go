//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// compatVersions lists the historical release versions to test backward
// compatibility against. Update this list before each release to include
// the latest 2 minor versions.
var compatVersions = []string{
	// TODO: Uncomment once v0.8.0 is released and the integrated binary
	// can be built from that tag.
	// "v0.8.0",
}

// compatTestCases is the subset of test cases that exercise critical
// backward compatibility surfaces: channel open/close, routing, force
// close, and upgrade.
var compatTestCases = []*ccTestCase{
	{
		name: "core",
		test: testCustomChannels,
	},
	{
		name: "force close",
		test: testCustomChannelsForceClose,
	},
	{
		name: "v1 upgrade",
		test: testCustomChannelsV1Upgrade,
	},
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
		string(repoRoot[:len(repoRoot)-1]),
		"scripts", "build-compat-binary.sh",
	)

	// Run the build script. It prints the binary path on stdout.
	//nolint:gosec
	cmd := exec.Command(script, version)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	require.NoError(t, err, "unable to build compat binary for %s",
		version)

	binaryPath := string(out[:len(out)-1]) // trim trailing newline
	require.FileExists(t, binaryPath)

	return binaryPath
}

// TestCustomChannelsCompat runs a subset of custom channel tests with one
// node running an older binary version for each historical version in
// compatVersions. This test is gated behind the `compat` build tag and
// intended to run only on release branches or via manual dispatch.
//
// The test creates a fresh network harness for each version, builds or
// retrieves the old binary, and runs each compat test case. In each test,
// one node (typically the "old" peer) is started with the historical binary
// via NewNodeWithBinary, while the other nodes use the current build.
func TestCustomChannelsCompat(t *testing.T) {
	if len(compatVersions) == 0 {
		t.Skip("no compat versions configured")
	}

	for _, version := range compatVersions {
		version := version
		t.Run(version, func(t *testing.T) {
			runCompatSuite(t, version)
		})
	}
}

// runCompatSuite runs all compat test cases for a single historical version.
func runCompatSuite(t *testing.T, version string) {
	t.Helper()

	// Build or retrieve the old binary.
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
	require.NoError(t, m.SetUp(true, 50))
	require.NoError(t, m.Client.NotifyNewTransactions(false))
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

	// Store the old binary path in the harness so test cases can
	// retrieve it. We use an environment variable as a simple
	// side channel.
	t.Setenv("COMPAT_OLD_BINARY", oldBinary)

	for _, tc := range compatTestCases {
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

		net.TearDown()

		if !success {
			t.Logf("Failure time: %v", time.Now().Format(
				"2006-01-02 15:04:05.000",
			))
			return
		}
	}
}
