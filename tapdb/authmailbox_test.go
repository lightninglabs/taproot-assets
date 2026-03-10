package tapdb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/authmailbox"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
)

// newMailboxStore creates a new instance of MailboxStore for testing.
func newMailboxStore(t *testing.T) (*MailboxStore, sqlc.Querier) {
	db := NewTestDB(t)

	txCreator := func(tx *sql.Tx) AuthMailboxStore {
		return db.WithTx(tx)
	}

	mailboxTx := NewTransactionExecutor(db, txCreator)
	return NewMailboxStore(mailboxTx), db
}

// TestStoreAndFetchMessage tests storing and fetching a message in the mailbox.
func TestStoreAndFetchMessage(t *testing.T) {
	t.Parallel()

	receiverKey := test.RandPubKey(t)
	mailboxStore, _ := newMailboxStore(t)
	ctx := context.Background()

	txProof := proof.MockTxProof(t)
	msg := &authmailbox.Message{
		ReceiverKey:      *receiverKey,
		EncryptedPayload: []byte("payload"),
		ArrivalTimestamp: time.Now(),
	}

	msgID, err := mailboxStore.StoreMessage(ctx, *txProof, msg)
	require.NoError(t, err)

	// Verify the message was stored correctly.
	dbMsg, err := mailboxStore.FetchMessage(ctx, msgID)
	require.NoError(t, err)
	require.Equal(t, msg.ReceiverKey, dbMsg.ReceiverKey)
	require.Equal(t, msg.EncryptedPayload, dbMsg.EncryptedPayload)
	require.Equal(
		t, msg.ArrivalTimestamp.Unix(), dbMsg.ArrivalTimestamp.Unix(),
	)

	// We should also be able to fetch the message by its outpoint.
	dbMsgByOutPoint, err := mailboxStore.FetchMessageByOutPoint(
		ctx, txProof.ClaimedOutPoint,
	)
	require.NoError(t, err)

	require.Equal(t, dbMsg, dbMsgByOutPoint)
}

// TestQueryMessages tests querying messages with filters.
func TestQueryMessages(t *testing.T) {
	t.Parallel()

	receiverKey := test.RandPubKey(t)
	mailboxStore, _ := newMailboxStore(t)
	ctx := context.Background()

	// Use a fixed base timestamp to avoid flaky tests.
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	const numMessages = 5
	for i := 0; i < numMessages; i++ {
		txProof := proof.MockTxProof(t)
		msg := &authmailbox.Message{
			ReceiverKey:      *receiverKey,
			EncryptedPayload: []byte("payload"),
			ArrivalTimestamp: baseTime.Add(
				time.Duration(i) * time.Hour,
			),
		}

		_, err := mailboxStore.StoreMessage(ctx, *txProof, msg)
		require.NoError(t, err)
	}

	// Query messages created after the second message (after 1 hour from
	// base time).
	filter := authmailbox.MessageFilter{
		ReceiverKey: *receiverKey,
		After:       baseTime.Add(time.Hour),
	}
	messages, err := mailboxStore.QueryMessages(ctx, filter)
	require.NoError(t, err)
	require.Len(t, messages, numMessages-2)

	// Query messages with a specific ID offset.
	filter.AfterID = 3
	messages, err = mailboxStore.QueryMessages(ctx, filter)
	require.NoError(t, err)
	require.Len(t, messages, numMessages-3)
}

// TestNumMessages tests counting the number of messages in the mailbox.
func TestNumMessages(t *testing.T) {
	t.Parallel()

	receiverKey := test.RandPubKey(t)
	mailboxStore, _ := newMailboxStore(t)
	ctx := context.Background()

	const numMessages = 5
	for i := 0; i < numMessages; i++ {
		txProof := proof.MockTxProof(t)
		msg := &authmailbox.Message{
			ReceiverKey:      *receiverKey,
			EncryptedPayload: []byte("payload"),
			ArrivalTimestamp: time.Now(),
		}

		_, err := mailboxStore.StoreMessage(ctx, *txProof, msg)
		require.NoError(t, err)
	}

	count := mailboxStore.NumMessages(ctx)
	require.EqualValues(t, numMessages, count)
}

// TestListOutpointsAndDelete tests listing claimed outpoints and deleting them
// with cascading message deletion.
func TestListOutpointsAndDelete(t *testing.T) {
	t.Parallel()

	receiverKey := test.RandPubKey(t)
	mailboxStore, _ := newMailboxStore(t)
	ctx := context.Background()

	// Store several messages with distinct outpoints.
	const numMessages = 5
	var storedOutpoints []proof.TxProof
	for i := 0; i < numMessages; i++ {
		txProof := proof.MockTxProof(t)
		msg := &authmailbox.Message{
			ReceiverKey:      *receiverKey,
			EncryptedPayload: []byte("payload"),
			ArrivalTimestamp: time.Now(),
		}

		_, err := mailboxStore.StoreMessage(ctx, *txProof, msg)
		require.NoError(t, err)
		storedOutpoints = append(storedOutpoints, *txProof)
	}

	// List all outpoints.
	outpoints, err := mailboxStore.ListOutpoints(ctx, 100, 0)
	require.NoError(t, err)
	require.Len(t, outpoints, numMessages)

	// Each outpoint should have a non-empty PkScript and BlockHeight.
	for _, op := range outpoints {
		require.NotEmpty(t, op.PkScript)
	}

	// Test pagination: list with limit 2.
	page1, err := mailboxStore.ListOutpoints(ctx, 2, 0)
	require.NoError(t, err)
	require.Len(t, page1, 2)

	page2, err := mailboxStore.ListOutpoints(ctx, 2, 2)
	require.NoError(t, err)
	require.Len(t, page2, 2)

	page3, err := mailboxStore.ListOutpoints(ctx, 2, 4)
	require.NoError(t, err)
	require.Len(t, page3, 1)

	// Delete one outpoint and verify cascading deletion.
	targetOp := storedOutpoints[0].ClaimedOutPoint
	err = mailboxStore.DeleteByOutpoint(ctx, targetOp)
	require.NoError(t, err)

	// The message should be gone.
	_, err = mailboxStore.FetchMessageByOutPoint(ctx, targetOp)
	require.ErrorIs(t, err, authmailbox.ErrMessageNotFound)

	// Total count should be reduced.
	count := mailboxStore.NumMessages(ctx)
	require.EqualValues(t, numMessages-1, count)

	// List should return one fewer.
	outpoints, err = mailboxStore.ListOutpoints(ctx, 100, 0)
	require.NoError(t, err)
	require.Len(t, outpoints, numMessages-1)
}

// TestDeleteByMessageID tests deleting messages by ID with receiver
// verification at the database level.
func TestDeleteByMessageID(t *testing.T) {
	t.Parallel()

	receiverA := test.RandPubKey(t)
	receiverB := test.RandPubKey(t)
	mailboxStore, _ := newMailboxStore(t)
	ctx := context.Background()

	// Store a message for receiverA.
	txProofA := proof.MockTxProof(t)
	msgA := &authmailbox.Message{
		ReceiverKey:      *receiverA,
		EncryptedPayload: []byte("payload-a"),
		ArrivalTimestamp: time.Now(),
	}
	idA, err := mailboxStore.StoreMessage(ctx, *txProofA, msgA)
	require.NoError(t, err)

	// Store a message for receiverB.
	txProofB := proof.MockTxProof(t)
	msgB := &authmailbox.Message{
		ReceiverKey:      *receiverB,
		EncryptedPayload: []byte("payload-b"),
		ArrivalTimestamp: time.Now(),
	}
	idB, err := mailboxStore.StoreMessage(ctx, *txProofB, msgB)
	require.NoError(t, err)

	require.EqualValues(t, 2, mailboxStore.NumMessages(ctx))

	// Try to delete receiverA's message using receiverB's key — should
	// not delete anything.
	deleted, err := mailboxStore.DeleteByMessageID(
		ctx, idA, receiverB.SerializeCompressed(),
	)
	require.NoError(t, err)
	require.False(t, deleted)

	// Message should still exist.
	_, err = mailboxStore.FetchMessage(ctx, idA)
	require.NoError(t, err)

	// Delete receiverA's message with the correct key.
	deleted, err = mailboxStore.DeleteByMessageID(
		ctx, idA, receiverA.SerializeCompressed(),
	)
	require.NoError(t, err)
	require.True(t, deleted)

	// Message and its outpoint should be gone.
	_, err = mailboxStore.FetchMessageByOutPoint(
		ctx, txProofA.ClaimedOutPoint,
	)
	require.ErrorIs(t, err, authmailbox.ErrMessageNotFound)
	require.EqualValues(t, 1, mailboxStore.NumMessages(ctx))

	// ReceiverB's message should still exist.
	fetchedB, err := mailboxStore.FetchMessage(ctx, idB)
	require.NoError(t, err)
	require.Equal(t, receiverB.SerializeCompressed(),
		fetchedB.ReceiverKey.SerializeCompressed())

	// Deleting a non-existent ID should return false, no error.
	deleted, err = mailboxStore.DeleteByMessageID(
		ctx, 99999, receiverA.SerializeCompressed(),
	)
	require.NoError(t, err)
	require.False(t, deleted)

	// Deleting the same ID again (already deleted) should also return
	// false.
	deleted, err = mailboxStore.DeleteByMessageID(
		ctx, idA, receiverA.SerializeCompressed(),
	)
	require.NoError(t, err)
	require.False(t, deleted)
}

// TestStoreProof tests storing a transaction proof.
func TestStoreProof(t *testing.T) {
	t.Parallel()

	receiverKey := test.RandPubKey(t)
	mailboxStore, _ := newMailboxStore(t)
	ctx := context.Background()

	txProof := proof.MockTxProof(t)
	msg := &authmailbox.Message{
		ReceiverKey:      *receiverKey,
		EncryptedPayload: []byte("payload"),
		ArrivalTimestamp: time.Now(),
	}

	_, err := mailboxStore.StoreMessage(ctx, *txProof, msg)
	require.NoError(t, err)

	// Verify the proof exists.
	existingMsg, err := mailboxStore.FetchMessageByOutPoint(
		ctx, txProof.ClaimedOutPoint,
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, existingMsg.ID, uint64(1))

	// If we try to store another proof with the same outpoint, it should
	// return an error.
	otherProof := *proof.MockTxProof(t)
	otherProof.ClaimedOutPoint = txProof.ClaimedOutPoint
	_, err = mailboxStore.StoreMessage(ctx, otherProof, msg)
	require.ErrorIs(t, err, proof.ErrTxMerkleProofExists)
}
