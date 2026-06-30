package fixture

import (
	"testing"
)

// TestMintDriverEndToEnd verifies the mint driver can take the planter
// from empty through to a confirmed batch. Failure here means the pump
// is missing a signal channel or the conf payload is malformed.
//
// FinalizeBatch internally waits for the batch to reach Confirmed, so
// the test just checks the call returns without error.
func TestMintDriverEndToEnd(t *testing.T) {
	t.Parallel()

	d := NewMintDriver(t)

	d.EnqueueSeedlings(t, 1)
	d.FinalizeBatch(t)
}
