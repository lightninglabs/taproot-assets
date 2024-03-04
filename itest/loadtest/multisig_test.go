package loadtest

import (
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/stretchr/testify/require"
)

// multisigTest tests that we can use multi signature on all levels of the
// Taproot Assets Protocol. This includes the BTC level, the asset level and the
// group key level.
func multisigTest(t *testing.T, ctx context.Context, cfg *Config) {
	// Start by initializing all our client connections.
	aliceTapd, bobTapd, bitcoinClient := initClients(t, ctx, cfg)

	params, err := networkParams(cfg.Network)
	require.NoError(t, err)

	var (
		aliceLnd = aliceTapd.lnd
		bobLnd   = bobTapd.lnd
	)

	aliceHost := fmt.Sprintf(
		"%s:%d", aliceTapd.cfg.Host, aliceTapd.cfg.Port,
	)

	itest.MultiSigTest(
		t, ctx, aliceTapd, bobTapd, aliceHost, bitcoinClient, aliceLnd,
		bobLnd, params, cfg.TestTimeout,
	)
}
