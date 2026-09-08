package tapdb

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

func TestFederationPendingProofSyncFIFO(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbHandle := NewDbHandle(t)
	fedStore := dbHandle.UniverseFederationStore

	testAsset, annotatedProof := dbHandle.AddRandomAssetProof(t)
	uniProof := dbHandle.AddUniProofLeaf(t, testAsset, annotatedProof)
	uniID := universe.NewUniIDFromAsset(*testAsset)
	servers := dbHandle.AddRandomServerAddrs(t, 3)

	insertOrder := []universe.ServerAddr{
		servers[2], servers[0], servers[1],
	}
	for _, server := range insertOrder {
		_, err := fedStore.UpsertFederationProofSyncLog(
			ctx, uniID, uniProof.LeafKey, server,
			universe.SyncDirectionPush,
			universe.ProofSyncStatusPending, false,
		)
		require.NoError(t, err)
	}

	// A retry updates the existing row but must not move it behind work
	// that was queued later.
	_, err := fedStore.UpsertFederationProofSyncLog(
		ctx, uniID, uniProof.LeafKey, insertOrder[0],
		universe.SyncDirectionPush, universe.ProofSyncStatusPending,
		true,
	)
	require.NoError(t, err)

	direction := universe.SyncDirectionPush
	pending, err := fedStore.FetchPendingProofsSyncLogFIFO(
		ctx, &direction,
	)
	require.NoError(t, err)
	require.Len(t, pending, len(insertOrder))

	for idx := range pending {
		require.Equal(t, insertOrder[idx], pending[idx].ServerAddr)
	}
}
