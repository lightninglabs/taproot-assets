package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/authmailbox"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

type (
	// NewTxProof is used to insert a new transaction proof into the
	// database.
	NewTxProof = sqlc.InsertTxProofParams

	// NewMailboxMessage is used to insert a new mailbox message
	// into the database.
	NewMailboxMessage = sqlc.InsertAuthMailboxMessageParams

	// MailboxMessage is a row in the auth mailbox messages table.
	MailboxMessage = sqlc.FetchAuthMailboxMessageRow

	// MailboxMessageByOutpoint is a row in the auth mailbox messages table.
	MailboxMessageByOutpoint = sqlc.FetchAuthMailboxMessageByOutpointRow

	// QueryMailboxMessages is used to query mailbox messages from the
	// database. It contains the parameters for the query.
	QueryMailboxMessages = sqlc.QueryAuthMailboxMessagesParams

	// MailboxMessageRow is a row in the auth mailbox messages table
	// returned by the query.
	MailboxMessageRow = sqlc.QueryAuthMailboxMessagesRow
)

// AuthMailboxStore defines the interface for interacting with the authmailbox
// database.
type AuthMailboxStore interface {
	// CountAuthMailboxMessages returns the number of messages in the
	// authmailbox database.
	CountAuthMailboxMessages(ctx context.Context) (int64, error)

	// FetchAuthMailboxMessage retrieves a mailbox message by its ID.
	FetchAuthMailboxMessage(ctx context.Context,
		id int64) (MailboxMessage, error)

	// FetchAuthMailboxMessageByOutpoint retrieves a mailbox message by its
	// claimed outpoint.
	FetchAuthMailboxMessageByOutpoint(ctx context.Context,
		claimedOutpoint []byte) (MailboxMessageByOutpoint, error)

	// InsertAuthMailboxMessage inserts a new mailbox message into the
	// database. It returns an error if the insertion fails.
	InsertAuthMailboxMessage(ctx context.Context,
		arg NewMailboxMessage) (int64, error)

	// InsertTxProof inserts a new transaction proof into the database.
	InsertTxProof(ctx context.Context, arg NewTxProof) error

	// QueryAuthMailboxMessages queries mailbox messages from the database
	// based on the provided parameters. It returns a slice of
	// MailboxMessageRow and an error if the query fails.
	QueryAuthMailboxMessages(ctx context.Context,
		arg QueryMailboxMessages) ([]MailboxMessageRow, error)
}

// BatchedMailboxStore is a version of the AuthMailboxStore that's capable of
// batched database operations.
type BatchedMailboxStore interface {
	AuthMailboxStore

	BatchedTx[AuthMailboxStore]
}

// MailboxStore represents a storage backend for all the authenticated mailbox
// operations. It implements the authmailbox.MsgStore and proof.TxProofStore
// interfaces and is used to interact with the database for storing and
// retrieving mailbox messages, transaction proofs, and other related
// operations.
type MailboxStore struct {
	db BatchedMailboxStore
}

// NewMailboxStore creates a new MailboxStore instance with the provided
// BatchedMailboxStore.
func NewMailboxStore(db BatchedMailboxStore) *MailboxStore {
	return &MailboxStore{
		db: db,
	}
}

// Two compile-time assertions to ensure that MailboxStore implements the
// authmailbox.MsgStore and proof.TxProofStore interfaces.
var _ authmailbox.MsgStore = (*MailboxStore)(nil)

// StoreMessage stores a message in the mailbox, referencing the claimed
// outpoint of the transaction that was used to prove the message's
// authenticity. If a message with the same outpoint already exists,
// it returns proof.ErrTxMerkleProofExists.
func (m MailboxStore) StoreMessage(ctx context.Context, txProof proof.TxProof,
	msg *authmailbox.Message) (uint64, error) {

	serializedOp, err := encodeOutpoint(txProof.ClaimedOutPoint)
	if err != nil {
		return 0, fmt.Errorf("error encoding outpoint: %w", err)
	}

	var (
		txOpt = WriteTxOption()
		msgID int64
	)
	dbErr := m.db.ExecTx(ctx, txOpt, func(q AuthMailboxStore) error {
		err := q.InsertTxProof(ctx, NewTxProof{
			Outpoint: serializedOp,
			BlockHash: fn.ByteSlice(
				txProof.BlockHeader.BlockHash(),
			),
			BlockHeight: int32(txProof.BlockHeight),
			InternalKey: txProof.InternalKey.SerializeCompressed(),
			MerkleRoot:  txProof.MerkleRoot,
		})
		if err != nil {
			return fmt.Errorf("error inserting proof: %w", err)
		}

		receiverKey := msg.ReceiverKey.SerializeCompressed()
		msgID, err = q.InsertAuthMailboxMessage(ctx, NewMailboxMessage{
			ClaimedOutpoint:  serializedOp,
			ReceiverKey:      receiverKey,
			EncryptedPayload: msg.EncryptedPayload,
			ArrivalTimestamp: msg.ArrivalTimestamp.Unix(),
		})
		if err != nil {
			return fmt.Errorf("error inserting message: %w", err)
		}

		return nil
	})
	if dbErr != nil {
		// Add context to unique constraint errors.
		var uniqueConstraintErr *ErrSqlUniqueConstraintViolation
		if errors.As(dbErr, &uniqueConstraintErr) {
			return 0, proof.ErrTxMerkleProofExists
		}

		return 0, fmt.Errorf("error storing message for outpoint "+
			"%s: %w", txProof.ClaimedOutPoint, dbErr)
	}

	return uint64(msgID), nil
}

// FetchMessage retrieves a message from the mailbox by its ID.
func (m MailboxStore) FetchMessage(ctx context.Context,
	id uint64) (*authmailbox.Message, error) {

	var (
		txOpt = ReadTxOption()
		msg   *authmailbox.Message
	)
	dbErr := m.db.ExecTx(ctx, txOpt, func(q AuthMailboxStore) error {
		dbMsg, err := q.FetchAuthMailboxMessage(ctx, int64(id))
		if err != nil {
			return fmt.Errorf("error fetching message %d: %w", id,
				err)
		}

		receiverKey, err := btcec.ParsePubKey(dbMsg.ReceiverKey)
		if err != nil {
			return fmt.Errorf("error parsing receiver key: %w", err)
		}

		msg = &authmailbox.Message{
			ID:               uint64(dbMsg.ID),
			ReceiverKey:      *receiverKey,
			EncryptedPayload: dbMsg.EncryptedPayload,
			ArrivalTimestamp: time.Unix(dbMsg.ArrivalTimestamp, 0),
			ProofBlockHeight: uint32(dbMsg.BlockHeight),
		}

		return nil
	})
	if dbErr != nil {
		return nil, fmt.Errorf("error fetching message %d: %w", id,
			dbErr)
	}

	return msg, nil
}

// FetchMessageByOutPoint retrieves a message from the mailbox by its
// claimed outpoint of the TX proof that was used to send it.
func (m MailboxStore) FetchMessageByOutPoint(ctx context.Context,
	claimedOp wire.OutPoint) (*authmailbox.Message, error) {

	serializedOp, err := encodeOutpoint(claimedOp)
	if err != nil {
		return nil, fmt.Errorf("error encoding outpoint: %w", err)
	}

	var (
		txOpt = ReadTxOption()
		msg   *authmailbox.Message
	)
	dbErr := m.db.ExecTx(ctx, txOpt, func(q AuthMailboxStore) error {
		dbMsg, err := q.FetchAuthMailboxMessageByOutpoint(
			ctx, serializedOp,
		)
		if err != nil {
			return fmt.Errorf("error fetching message by "+
				"outpoint %v: %w", serializedOp, err)
		}

		receiverKey, err := btcec.ParsePubKey(dbMsg.ReceiverKey)
		if err != nil {
			return fmt.Errorf("error parsing receiver key: %w", err)
		}

		msg = &authmailbox.Message{
			ID:               uint64(dbMsg.ID),
			ReceiverKey:      *receiverKey,
			EncryptedPayload: dbMsg.EncryptedPayload,
			ArrivalTimestamp: time.Unix(dbMsg.ArrivalTimestamp, 0),
			ProofBlockHeight: uint32(dbMsg.BlockHeight),
		}

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, authmailbox.ErrMessageNotFound
	case dbErr != nil:
		return nil, fmt.Errorf("error fetching message by outpoint "+
			"%v: %w", serializedOp, dbErr)
	}

	return msg, nil
}

// QueryMessages retrieves messages based on a query.
func (m MailboxStore) QueryMessages(ctx context.Context,
	filter authmailbox.MessageFilter) ([]*authmailbox.Message, error) {

	var (
		txOpt    = ReadTxOption()
		messages []*authmailbox.Message
	)
	dbErr := m.db.ExecTx(ctx, txOpt, func(q AuthMailboxStore) error {
		queryParams := QueryMailboxMessages{
			ReceiverKey: filter.ReceiverKey.SerializeCompressed(),
		}
		if filter.AfterID != 0 {
			queryParams.AfterID = sqlInt64(filter.AfterID)
		}
		if !filter.After.IsZero() {
			queryParams.AfterTime = sqlInt64(filter.After.Unix())
		}
		if filter.StartBlock != 0 {
			queryParams.StartBlock = sqlInt32(filter.StartBlock)
		}

		dbMessages, err := q.QueryAuthMailboxMessages(ctx, queryParams)
		if err != nil {
			return fmt.Errorf("error querying messages: %w", err)
		}

		messages = make([]*authmailbox.Message, 0, len(dbMessages))
		for _, dbMsg := range dbMessages {
			receiverKey, err := btcec.ParsePubKey(dbMsg.ReceiverKey)
			if err != nil {
				return fmt.Errorf("error parsing receiver "+
					"key: %w", err)
			}

			msg := &authmailbox.Message{
				ID:               uint64(dbMsg.ID),
				ReceiverKey:      *receiverKey,
				EncryptedPayload: dbMsg.EncryptedPayload,
				ArrivalTimestamp: time.Unix(
					dbMsg.ArrivalTimestamp, 0,
				),
				ProofBlockHeight: uint32(dbMsg.BlockHeight),
			}
			messages = append(messages, msg)
		}

		return nil
	})
	if dbErr != nil {
		return nil, fmt.Errorf("error querying messages: %w", dbErr)
	}

	return messages, nil
}

// NumMessages returns the number of messages currently in the mailbox.
// Implementations should make sure that this can be calculated quickly and
// efficiently (e.g., by caching the result), as it might be queried often.
func (m MailboxStore) NumMessages(ctx context.Context) uint64 {
	var (
		txOpt = ReadTxOption()
		err   error
		count int64
	)
	dbErr := m.db.ExecTx(ctx, txOpt, func(q AuthMailboxStore) error {
		count, err = q.CountAuthMailboxMessages(ctx)
		if err != nil {
			return fmt.Errorf("error counting messages: %w", err)
		}

		return nil
	})
	if dbErr != nil {
		// If we fail to count the messages, we return 0. This is a
		// conservative approach, as it means we won't report more
		// messages than actually exist.
		return 0
	}

	return uint64(count)
}
