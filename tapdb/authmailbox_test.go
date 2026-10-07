package tapdb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/authmailbox"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
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

	// A message without a payload can't be stored.
	_, err = mailboxStore.StoreMessage(
		ctx, *proof.MockTxProof(t), &authmailbox.Message{
			ReceiverKey:      *receiverKey,
			ArrivalTimestamp: time.Now(),
		},
	)
	require.ErrorIs(t, err, authmailbox.ErrEmptyPayload)
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

	// The message should be gone from the mailbox.
	_, err = mailboxStore.FetchMessage(ctx, idA)
	require.Error(t, err)
	msgsA, err := mailboxStore.QueryMessages(ctx, authmailbox.MessageFilter{
		ReceiverKey: *receiverA,
	})
	require.NoError(t, err)
	require.Empty(t, msgsA)
	require.EqualValues(t, 1, mailboxStore.NumMessages(ctx))

	// Its record should remain under its claimed outpoint, without the
	// payload.
	removedA, err := mailboxStore.FetchMessageByOutPoint(
		ctx, txProofA.ClaimedOutPoint,
	)
	require.NoError(t, err)
	require.Equal(t, idA, removedA.ID)
	require.True(t, receiverA.IsEqual(&removedA.ReceiverKey))
	require.Empty(t, removedA.EncryptedPayload)

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

	// The record goes once its claimed outpoint is deleted.
	err = mailboxStore.DeleteByOutpoint(ctx, txProofA.ClaimedOutPoint)
	require.NoError(t, err)
	_, err = mailboxStore.FetchMessageByOutPoint(
		ctx, txProofA.ClaimedOutPoint,
	)
	require.ErrorIs(t, err, authmailbox.ErrMessageNotFound)
}

// TestSendMessageAfterDelete makes sure that a sender re-sending a message
// after its receiver deleted it gets back the original message ID, while the
// same outpoint still can't be used for a different receiver.
func TestSendMessageAfterDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mailboxStore, _ := newMailboxStore(t)

	signer := test.NewMockSigner()
	signer.Signature = test.RandBytes(schnorr.SignatureSize)

	srv := authmailbox.NewServer()
	require.NoError(t, srv.Start(&authmailbox.ServerConfig{
		Signer:         signer,
		HeaderVerifier: proof.MockHeaderVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		MsgStore:       mailboxStore,
	}))
	t.Cleanup(func() {
		require.NoError(t, srv.Stop())
	})

	txProof := proof.MockTxProof(t)
	txProof.BlockHeight = 100
	rpcProof, err := proof.MarshalTxProof(*txProof)
	require.NoError(t, err)

	send := func(receiver *btcec.PublicKey) (uint64, error) {
		resp, err := srv.SendMessage(ctx, &mboxrpc.SendMessageRequest{
			ReceiverId:       receiver.SerializeCompressed(),
			EncryptedPayload: test.RandBytes(32),
			Proof: &mboxrpc.SendMessageRequest_TxProof{
				TxProof: rpcProof,
			},
		})
		if err != nil {
			return 0, err
		}

		return resp.MessageId, nil
	}

	receiver := test.RandPubKey(t)
	msgID, err := send(receiver)
	require.NoError(t, err)

	// The receiver deletes the message once it has processed it.
	resp, err := srv.RemoveMessage(ctx, &mboxrpc.RemoveMessageRequest{
		ReceiverId: receiver.SerializeCompressed(),
		MessageIds: []uint64{msgID},
		Signature:  signer.Signature,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, resp.NumRemoved)
	require.Zero(t, mailboxStore.NumMessages(ctx))

	// A sender retrying its delivery gets the original message ID back,
	// and nothing is stored again.
	resendID, err := send(receiver)
	require.NoError(t, err)
	require.Equal(t, msgID, resendID)
	require.Zero(t, mailboxStore.NumMessages(ctx))

	// The outpoint can't be used for a different receiver.
	_, err = send(test.RandPubKey(t))
	require.ErrorIs(t, err, proof.ErrTxMerkleProofExists)
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
