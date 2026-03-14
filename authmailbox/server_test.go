package authmailbox

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
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

// newRemoveTestServer creates a Server with a MockMsgStore pre-populated with
// messages for two different receivers, and a MockSigner with a 64-byte
// signature that passes Schnorr size validation.
func newRemoveTestServer(t *testing.T) (*Server, *MockMsgStore,
	[]uint64, []uint64) {

	t.Helper()

	store := NewMockStore()
	ctx := context.Background()

	signer := test.NewMockSigner()
	signer.Signature = test.RandBytes(schnorr.SignatureSize)

	receiverA := test.RandPubKey(t)
	receiverB := test.RandPubKey(t)

	// Store 3 messages for receiverA.
	var idsA []uint64
	for i := 0; i < 3; i++ {
		txProof := proof.MockTxProof(t)
		id, err := store.StoreMessage(ctx, *txProof, &Message{
			ReceiverKey:      *receiverA,
			EncryptedPayload: []byte("payload-a"),
			ArrivalTimestamp: time.Now(),
		})
		require.NoError(t, err)
		idsA = append(idsA, id)
	}

	// Store 2 messages for receiverB.
	var idsB []uint64
	for i := 0; i < 2; i++ {
		txProof := proof.MockTxProof(t)
		id, err := store.StoreMessage(ctx, *txProof, &Message{
			ReceiverKey:      *receiverB,
			EncryptedPayload: []byte("payload-b"),
			ArrivalTimestamp: time.Now(),
		})
		require.NoError(t, err)
		idsB = append(idsB, id)
	}

	srv := &Server{
		cfg: &ServerConfig{
			MsgStore: store,
			Signer:   signer,
		},
		ContextGuard: lfn.NewContextGuard(),
	}

	return srv, store, idsA, idsB
}

// TestRemoveMessageValid verifies that RemoveMessage successfully deletes
// messages belonging to the authenticated receiver.
func TestRemoveMessageValid(t *testing.T) {
	t.Parallel()

	srv, store, idsA, _ := newRemoveTestServer(t)
	ctx := context.Background()

	// The mock signer's VerifyMessage returns true when the signature
	// equals signer.Signature. Grab it for our request.
	sig := srv.cfg.Signer.(*test.MockSigner).Signature
	receiverA, _ := store.FetchMessage(ctx, idsA[0])
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	// Remove the first two messages for receiverA.
	resp, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: idsA[:2],
		Signature:  sig,
	})
	require.NoError(t, err)
	require.EqualValues(t, 2, resp.NumRemoved)

	// Those messages should be gone.
	for _, id := range idsA[:2] {
		_, err := store.FetchMessage(ctx, id)
		require.Error(t, err)
	}

	// The third message for receiverA should still exist.
	msg, err := store.FetchMessage(ctx, idsA[2])
	require.NoError(t, err)
	require.NotNil(t, msg)

	// Total: started with 5, removed 2, expect 3.
	require.EqualValues(t, 3, store.NumMessages(ctx))
}

// TestRemoveMessageWrongReceiver verifies that RemoveMessage does not delete
// messages belonging to a different receiver, even with a valid signature.
func TestRemoveMessageWrongReceiver(t *testing.T) {
	t.Parallel()

	srv, store, _, idsB := newRemoveTestServer(t)
	ctx := context.Background()

	sig := srv.cfg.Signer.(*test.MockSigner).Signature

	// Try to remove receiverB's messages using receiverA's identity.
	receiverA, _ := store.FetchMessage(ctx, 1) // idsA[0] == 1
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	resp, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: idsB,
		Signature:  sig,
	})
	require.NoError(t, err)

	// Nothing should be removed because those messages belong to
	// receiverB.
	require.EqualValues(t, 0, resp.NumRemoved)

	// ReceiverB's messages should still exist.
	for _, id := range idsB {
		msg, err := store.FetchMessage(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, msg)
	}
}

// TestRemoveMessageNonExistent verifies that RemoveMessage gracefully handles
// message IDs that don't exist.
func TestRemoveMessageNonExistent(t *testing.T) {
	t.Parallel()

	srv, store, idsA, _ := newRemoveTestServer(t)
	ctx := context.Background()

	sig := srv.cfg.Signer.(*test.MockSigner).Signature
	receiverA, _ := store.FetchMessage(ctx, idsA[0])
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	// Include one valid ID and two non-existent ones.
	resp, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: []uint64{idsA[0], 99999, 88888},
		Signature:  sig,
	})
	require.NoError(t, err)

	// Only the one valid message should be removed.
	require.EqualValues(t, 1, resp.NumRemoved)

	// 5 - 1 = 4 messages remaining.
	require.EqualValues(t, 4, store.NumMessages(ctx))
}

// TestRemoveMessageEmptyIDs verifies that RemoveMessage with no message IDs
// returns immediately with zero removed.
func TestRemoveMessageEmptyIDs(t *testing.T) {
	t.Parallel()

	srv, store, idsA, _ := newRemoveTestServer(t)
	ctx := context.Background()

	receiverA, _ := store.FetchMessage(ctx, idsA[0])
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	resp, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: nil,
		// No signature needed for empty request.
	})
	require.NoError(t, err)
	require.EqualValues(t, 0, resp.NumRemoved)
	require.EqualValues(t, 5, store.NumMessages(ctx))
}

// TestRemoveMessageInvalidSignature verifies that RemoveMessage rejects
// requests with an invalid signature.
func TestRemoveMessageInvalidSignature(t *testing.T) {
	t.Parallel()

	srv, store, idsA, _ := newRemoveTestServer(t)
	ctx := context.Background()

	receiverA, _ := store.FetchMessage(ctx, idsA[0])
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	// Use a wrong signature (different from signer.Signature).
	wrongSig := make([]byte, schnorr.SignatureSize)
	copy(wrongSig, []byte("wrong-sig-padding-to-64-bytes"+
		"-00000000000000000000000000000000000"))

	_, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: idsA[:1],
		Signature:  wrongSig,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "signature not valid")

	// Nothing should have been deleted.
	require.EqualValues(t, 5, store.NumMessages(ctx))
}

// TestRemoveMessageBadSignatureLength verifies that a signature with the wrong
// length is rejected before any verification takes place.
func TestRemoveMessageBadSignatureLength(t *testing.T) {
	t.Parallel()

	srv, store, idsA, _ := newRemoveTestServer(t)
	ctx := context.Background()

	receiverA, _ := store.FetchMessage(ctx, idsA[0])
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	_, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: idsA[:1],
		Signature:  []byte("too-short"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature length")
	require.EqualValues(t, 5, store.NumMessages(ctx))
}

// TestRemoveMessageIdempotent verifies that removing the same message twice
// succeeds without error (second call finds nothing to delete).
func TestRemoveMessageIdempotent(t *testing.T) {
	t.Parallel()

	srv, store, idsA, _ := newRemoveTestServer(t)
	ctx := context.Background()

	sig := srv.cfg.Signer.(*test.MockSigner).Signature
	receiverA, _ := store.FetchMessage(ctx, idsA[0])
	receiverABytes := receiverA.ReceiverKey.SerializeCompressed()

	// First removal should succeed.
	resp, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: idsA[:1],
		Signature:  sig,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, resp.NumRemoved)

	// Second removal of the same ID should succeed but remove nothing.
	resp, err = srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiverABytes,
		MessageIds: idsA[:1],
		Signature:  sig,
	})
	require.NoError(t, err)
	require.EqualValues(t, 0, resp.NumRemoved)

	// Total: 5 - 1 = 4 (only the first removal counted).
	require.EqualValues(t, 4, store.NumMessages(ctx))
}

// TestRemoveMessageChallengeConsistency verifies that the challenge hash is
// deterministic and order-dependent.
func TestRemoveMessageChallengeConsistency(t *testing.T) {
	t.Parallel()

	receiverID := test.RandBytes(33)
	ids := []uint64{1, 2, 3}

	// Same inputs produce same hash.
	h1 := RemoveMessageChallenge(receiverID, ids)
	h2 := RemoveMessageChallenge(receiverID, ids)
	require.Equal(t, h1, h2)

	// Different order produces different hash.
	h3 := RemoveMessageChallenge(receiverID, []uint64{3, 2, 1})
	require.NotEqual(t, h1, h3)

	// Different receiver produces different hash.
	otherReceiver := test.RandBytes(33)
	h4 := RemoveMessageChallenge(otherReceiver, ids)
	require.NotEqual(t, h1, h4)

	// Different IDs produce different hash.
	h5 := RemoveMessageChallenge(receiverID, []uint64{1, 2, 4})
	require.NotEqual(t, h1, h5)

	// Empty IDs produces a valid hash (just SHA256 of receiver_id).
	h6 := RemoveMessageChallenge(receiverID, nil)
	require.NotEqual(t, h1, h6)
	require.NotEqual(t, h6, [32]byte{})
}
