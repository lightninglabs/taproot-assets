package supplycommit

import (
	"testing"

	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// TestHydrateInitialState checks that a restarted UpdatesPendingState
// picks up the transition's pending updates, and that a broadcast state
// is left alone.
func TestHydrateInitialState(t *testing.T) {
	t.Parallel()

	event := &NewMintEvent{}
	pending := &UpdatesPendingState{}
	hydrateInitialState(pending, lfn.Some(SupplyStateTransition{
		PendingUpdates: []SupplyUpdateEvent{event},
	}))
	require.Equal(t, []SupplyUpdateEvent{event}, pending.pendingUpdates)

	kept := &NewMintEvent{}
	already := &UpdatesPendingState{
		pendingUpdates: []SupplyUpdateEvent{kept},
	}
	hydrateInitialState(already, lfn.Some(SupplyStateTransition{
		PendingUpdates: []SupplyUpdateEvent{event},
	}))
	require.Equal(t, []SupplyUpdateEvent{kept}, already.pendingUpdates)

	broadcast := &CommitBroadcastState{}
	hydrateInitialState(broadcast, lfn.Some(SupplyStateTransition{
		PendingUpdates: []SupplyUpdateEvent{event},
	}))
}
