package authmailbox

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// TestCleanupSpentOutpoints verifies that cleanupSpentOutpoints deletes
// outpoints that the checker reports as spent and keeps unspent ones.
func TestCleanupSpentOutpoints(t *testing.T) {
	t.Parallel()

	store := NewMockStore()
	ctx := context.Background()

	// Create test messages with known outpoints.
	spentOP := wire.OutPoint{
		Hash:  test.RandHash(),
		Index: 0,
	}
	unspentOP := wire.OutPoint{
		Hash:  test.RandHash(),
		Index: 1,
	}
	errorOP := wire.OutPoint{
		Hash:  test.RandHash(),
		Index: 2,
	}

	receiverKey := test.RandPubKey(t)

	// Store 3 messages with distinct outpoints.
	for _, op := range []wire.OutPoint{spentOP, unspentOP, errorOP} {
		txProof := proof.MockTxProof(t)
		txProof.ClaimedOutPoint = op

		_, err := store.StoreMessage(ctx, *txProof, &Message{
			ReceiverKey:      *receiverKey,
			EncryptedPayload: []byte("payload"),
			ArrivalTimestamp: time.Now(),
		})
		require.NoError(t, err)
	}

	require.EqualValues(t, 3, store.NumMessages(ctx))

	// Track which outpoints were checked.
	var checkedMu sync.Mutex
	checkedOutpoints := make(map[wire.OutPoint]bool)

	// Create a checker that marks spentOP as spent, unspentOP as unspent,
	// and returns a context error for errorOP (simulating timeout).
	checker := func(ctx context.Context, op wire.OutPoint,
		_ []byte, _ uint32) (bool, error) {

		checkedMu.Lock()
		checkedOutpoints[op] = true
		checkedMu.Unlock()

		switch op {
		case spentOP:
			return true, nil
		case errorOP:
			return false, context.DeadlineExceeded
		default:
			return false, nil
		}
	}

	srv := &Server{
		cfg: &ServerConfig{
			MsgStore:            store,
			OutpointChecker:     checker,
			CleanupCheckTimeout: time.Second,
		},
		ContextGuard: lfn.NewContextGuard(),
	}

	// Run cleanup.
	srv.cleanupSpentOutpoints()

	// Verify the spent outpoint was deleted.
	_, err := store.FetchMessageByOutPoint(ctx, spentOP)
	require.ErrorIs(t, err, ErrMessageNotFound)

	// The unspent outpoint should still exist.
	msg, err := store.FetchMessageByOutPoint(ctx, unspentOP)
	require.NoError(t, err)
	require.NotNil(t, msg)

	// The error outpoint should still exist (we don't delete on error).
	msg, err = store.FetchMessageByOutPoint(ctx, errorOP)
	require.NoError(t, err)
	require.NotNil(t, msg)

	// Total count should be 2 (only the spent one was removed).
	require.EqualValues(t, 2, store.NumMessages(ctx))

	// All 3 outpoints should have been checked.
	checkedMu.Lock()
	require.Len(t, checkedOutpoints, 3)
	checkedMu.Unlock()
}
