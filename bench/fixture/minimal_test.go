package fixture

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
)

// TestMinimalFixture verifies the Minimal fixture spins up and can serve
// the simplest possible handler: GetInfo. This guards against regressions
// in the fixture wiring without requiring any per-RPC benchmark to exist
// yet.
func TestMinimalFixture(t *testing.T) {
	t.Parallel()

	f := NewMinimal(t)

	// DebugLevel(Show:true) only reads cfg.LogMgr, which the Minimal
	// fixture populates. It is a cheap proof that Start wired the cfg in
	// without panicking and that handlers can read it.
	resp, err := f.Server.DebugLevel(
		context.Background(),
		&taprpc.DebugLevelRequest{Show: true},
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
}
