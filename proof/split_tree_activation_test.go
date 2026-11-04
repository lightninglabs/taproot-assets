package proof

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taproot-assets/mssmt"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// TestNetworkSplitTreeActivationHeight tests the split tree activation
// heights of the networks.
func TestNetworkSplitTreeActivationHeight(t *testing.T) {
	t.Parallel()

	require.Equal(
		t, lfn.Some(MainNetSplitTreeActivationHeight),
		NetworkSplitTreeActivationHeight(chaincfg.MainNetParams.Name),
	)
	require.Equal(
		t, lfn.Some(SigNetSplitTreeActivationHeight),
		NetworkSplitTreeActivationHeight(chaincfg.SigNetParams.Name),
	)
	require.Equal(
		t, lfn.Some(TestNet3SplitTreeActivationHeight),
		NetworkSplitTreeActivationHeight(chaincfg.TestNet3Params.Name),
	)
	require.Equal(
		t, lfn.Some(TestNet4SplitTreeActivationHeight),
		NetworkSplitTreeActivationHeight(chaincfg.TestNet4Params.Name),
	)

	for _, params := range []chaincfg.Params{
		chaincfg.RegressionNetParams, chaincfg.SimNetParams,
	} {
		height := NetworkSplitTreeActivationHeight(params.Name)
		require.True(t, height.IsNone())
	}
}

// TestDefaultSplitTreeActivationHeight tests that a verifier context without a
// split tree activation height of its own applies the default, and that the
// branch versions allowed at a height follow the default. The test changes
// the default, so it must not run in parallel with other tests.
func TestDefaultSplitTreeActivationHeight(t *testing.T) {
	defer SetDefaultSplitTreeActivationHeight(
		DefaultSplitTreeActivationHeight(),
	)

	both := []mssmt.BranchVersion{mssmt.BranchV0, mssmt.BranchV1}
	v1 := []mssmt.BranchVersion{mssmt.BranchV1}

	SetDefaultSplitTreeActivationHeight(lfn.None[uint32]())
	require.True(t, MockVerifierCtx.splitTreeActivationHeight().IsNone())
	require.Equal(t, both, SplitTreeVersionsAt(1_000_000))

	SetDefaultSplitTreeActivationHeight(lfn.Some(uint32(100)))
	require.Equal(
		t, lfn.Some(uint32(100)),
		MockVerifierCtx.splitTreeActivationHeight(),
	)
	require.Equal(t, both, SplitTreeVersionsAt(99))
	require.Equal(t, v1, SplitTreeVersionsAt(100))

	vCtx := MockVerifierCtx
	vCtx.SplitTreeActivationHeight = lfn.Some(uint32(200))
	require.Equal(
		t, lfn.Some(uint32(200)), vCtx.splitTreeActivationHeight(),
	)
}
