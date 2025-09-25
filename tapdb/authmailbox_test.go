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
