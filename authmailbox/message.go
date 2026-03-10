package authmailbox

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
)

const (
	// MsgMaxSize is the maximum size of a message in bytes.
	MsgMaxSize = 65536
)

// OutpointChecker checks whether a given outpoint has been spent on chain.
// Returns true if the outpoint has been spent, false if it is still unspent.
// pkScript is the output's script, heightHint is the block height where the
// outpoint was confirmed (used to optimize the chain backend lookup).
type OutpointChecker func(ctx context.Context, op wire.OutPoint,
	pkScript []byte, heightHint uint32) (bool, error)

// ClaimedOutpoint holds an outpoint and metadata needed for spent checks.
type ClaimedOutpoint struct {
	// OutPoint is the claimed outpoint from the transaction proof.
	OutPoint wire.OutPoint

	// PkScript is the output's pkScript, reconstructed from the internal
	// key and merkle root stored in the database.
	PkScript []byte

	// BlockHeight is the block height at which the outpoint was confirmed.
	BlockHeight uint32
}

var (
	// ErrMessageTooLong is returned when a message exceeds the maximum
	// allowed length.
	ErrMessageTooLong = fmt.Errorf("message too long, max %d bytes",
		MsgMaxSize)

	// ErrMessageNotFound is returned when a message with the given ID or
	// outpoint cannot be found in the mailbox.
	ErrMessageNotFound = fmt.Errorf("message not found")
)

// Message represents a message in the mailbox.
type Message struct {
	// ID is the unique identifier for this message, assigned by the
	// mailbox server.
	ID uint64

	// ReceiverKey is the intended recipient of the message. This is the
	// public key of the receiver.
	ReceiverKey btcec.PublicKey

	// EncryptedPayload is the encrypted message payload. This is the actual
	// content of the message, encrypted with EICS.
	EncryptedPayload []byte

	// ArrivalTimestamp is the time when the message was received and
	// validated by the mailbox server.
	ArrivalTimestamp time.Time

	// ProofBlockHeight is the block height of the block that was used as
	// the tx proof for this message.
	ProofBlockHeight uint32
}

// Timestamp returns the time when the message was received.
//
// This is part of the fn.Event interface.
func (m *Message) Timestamp() time.Time {
	return m.ArrivalTimestamp
}

// MessageFilter is used to filter messages based on certain criteria.
type MessageFilter struct {
	// ReceiverKey is the message receiver's public key.
	ReceiverKey btcec.PublicKey

	// After is the time after which the message was received. If set, the
	// filter will cause only messages that arrived after this time to be
	// returned (exclusive).
	After time.Time

	// AfterID is the ID of the message after which the message was
	// received. If set, the filter will cause only messages that arrived
	// after this ID to be returned (exclusive).
	AfterID uint64

	// StartBlock is the block height after which the message was received.
	// If set, the filter will cause only messages that arrived at this
	// block or later to be returned (inclusive).
	StartBlock uint32
}

// DeliverExisting returns true if the filter is set to deliver existing
// messages. This is the case if any of the fields other than the receiver key
// are set.
func (f *MessageFilter) DeliverExisting() bool {
	return !f.After.IsZero() || f.StartBlock != 0 || f.AfterID != 0
}

// MsgStore is an interface for storing and retrieving messages in the mailbox.
type MsgStore interface {
	// StoreMessage stores a message in the mailbox, referencing the claimed
	// outpoint of the transaction that was used to prove the message's
	// authenticity. If a message with the same outpoint already exists,
	// it returns proof.ErrTxMerkleProofExists.
	StoreMessage(ctx context.Context, proof proof.TxProof,
		msg *Message) (uint64, error)

	// FetchMessage retrieves a message from the mailbox by its ID.
	FetchMessage(ctx context.Context, id uint64) (*Message, error)

	// FetchMessageByOutPoint retrieves a message from the mailbox by its
	// claimed outpoint of the TX proof that was used to send it. If no
	// message with the given outpoint exists, it returns
	// ErrMessageNotFound.
	FetchMessageByOutPoint(ctx context.Context,
		claimedOp wire.OutPoint) (*Message, error)

	// QueryMessages retrieves messages based on a query.
	QueryMessages(ctx context.Context, filter MessageFilter) ([]*Message,
		error)

	// NumMessages returns the number of messages currently in the mailbox.
	// Implementations should make sure that this can be calculated quickly
	// and efficiently (e.g., by caching the result), as it might be queried
	// often.
	NumMessages(ctx context.Context) uint64

	// ListOutpoints returns a paginated list of claimed outpoints with
	// their pkScripts and block heights, for use by the cleanup process.
	ListOutpoints(ctx context.Context, limit,
		offset int32) ([]ClaimedOutpoint, error)

	// DeleteByOutpoint deletes the outpoint record and its associated
	// message (via CASCADE).
	DeleteByOutpoint(ctx context.Context, op wire.OutPoint) error
}
