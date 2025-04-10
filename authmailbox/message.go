package authmailbox

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	// MsgMaxSize is the maximum size of a message in bytes.
	MsgMaxSize = 65536
)

var (
	// ErrMessageTooLong is returned when a message exceeds the maximum
	// allowed length.
	ErrMessageTooLong = fmt.Errorf("message too long, max %d bytes",
		MsgMaxSize)
)

type Message struct {
	ID uint64

	ReceiverKey btcec.PublicKey

	EncryptedPayload []byte

	SenderEphemeralKey btcec.PublicKey

	ArrivalTimestamp time.Time

	ArrivalBlockHeight uint32

	ExpiryBlockHeight uint32
}

// Timestamp returns the time when the message was received.
//
// This is part of the fn.Event interface.
func (m *Message) Timestamp() time.Time {
	return m.ArrivalTimestamp
}

// MessageFilter is used to filter messages based on certain criteria.
type MessageFilter struct {
	// ReceiverKey is the public key of the receiver of the message.
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

func (f *MessageFilter) DeliverExisting() bool {
	return !f.After.IsZero() || f.StartBlock != 0
}

type Store interface {
	// StoreMessage stores a message in the mailbox.
	StoreMessage(msg *Message) error

	// FetchMessage retrieves a message from the mailbox by its ID.
	FetchMessage(id uint64) (*Message, error)

	// FetchMessages retrieves all messages in the mailbox.
	FetchMessages() ([]*Message, error)

	// QueryMessages retrieves messages based on a query.
	QueryMessages(filter MessageFilter) ([]*Message, error)
}

type InMemoryStore struct {
	messages      map[uint64]*Message
	nextMessageID atomic.Uint64
	mu            sync.RWMutex
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		messages: make(map[uint64]*Message),
	}
}

func (s *InMemoryStore) StoreMessage(msg *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg.ID = s.nextMessageID.Add(1)

	s.messages[msg.ID] = msg
	return nil
}

func (s *InMemoryStore) FetchMessage(id uint64) (*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	msg, exists := s.messages[id]
	if !exists {
		return nil, fmt.Errorf("message with ID %d not found", id)
	}

	return msg, nil
}

func (s *InMemoryStore) FetchMessages() ([]*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return slices.Collect(maps.Values(s.messages)), nil
}

func (s *InMemoryStore) QueryMessages(
	filter MessageFilter) ([]*Message, error) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Message
	for _, msg := range s.messages {
		if !msg.ReceiverKey.IsEqual(&filter.ReceiverKey) {
			continue
		}

		if !filter.After.IsZero() &&
			msg.ArrivalTimestamp.Before(filter.After) {

			continue
		}

		if filter.StartBlock != 0 &&
			msg.ArrivalBlockHeight < filter.StartBlock {

			continue
		}

		result = append(result, msg)
	}

	return result, nil
}
