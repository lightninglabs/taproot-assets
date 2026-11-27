//go:build itest

package custom_channels

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/itest"
)

// deterministicHtlcsUpgradeVersion is a release whose asset channels know
// nothing of deterministic second-level HTLCs.
const deterministicHtlcsUpgradeVersion = "v0.8.4"

// TestDeterministicHtlcsUpgrade tests that an asset channel opened before
// deterministic second-level HTLCs existed moves over to them once both
// peers run a build that negotiates the feature. Both peers open the channel
// and exchange payments on the old release, then upgrade and reconnect. The
// commitments that exist at that point were built with the legacy HTLC
// sighash and must keep being treated as such, while every commitment
// created afterwards uses the deterministic form. Payments in both
// directions take the channel across that switch.
//
// The channel is then force closed with HTLCs in flight in both directions,
// and the full HTLC force close scenario must play out exactly as it does
// for a channel that was deterministic from the start: pre-signed
// second-level HTLC transactions with a CPFP anchor, their imports and all
// sweeps. This only works if lnd and tapd agreed on the sighash of every
// commitment throughout the switch.
func TestDeterministicHtlcsUpgrade(t *testing.T) {
	oldBinary := buildCompatBinary(t, deterministicHtlcsUpgradeVersion)
	t.Logf("Using compat binary for %s: %s",
		deterministicHtlcsUpgradeVersion, oldBinary)

	runWithCompatHarness(t, func(ctx context.Context,
		net *itest.IntegratedNetworkHarness, ht *ccHarnessTest) {

		runCustomChannelsHtlcForceClose(ctx, ht, net, false, oldBinary)
	})
}
