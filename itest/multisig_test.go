package itest

import (
	"context"

	"github.com/stretchr/testify/require"
)

// testMultiSignature tests that we can use multi signature on all levels of the
// Taproot Assets Protocol. This includes the BTC level, the asset level and the
// group key level.
func testMultiSignature(t *harnessTest) {
	var (
		aliceTapd = t.tapd
		aliceLnd  = t.lndHarness.Alice
		bobLnd    = t.lndHarness.Bob
	)

	// We create a second tapd node that will be used to simulate a second
	// party in the test. This tapd node is connected to lnd "Bob".
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	MultiSigTest(
		t.t, context.Background(), aliceTapd, bobTapd,
		aliceTapd.rpcHost(), t.lndHarness.Miner().Client, aliceLnd.RPC,
		bobLnd.RPC, regtestParams, defaultTimeout,
	)
}
