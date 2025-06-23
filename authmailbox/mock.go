package authmailbox

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/wire"
)

type MockMsgStore struct {
	messages      map[uint64]*Message
	nextMessageID atomic.Uint64
	mu            sync.RWMutex
}

var _ MsgStore = (*MockMsgStore)(nil)

func NewMockStore() *MockMsgStore {
	return &MockMsgStore{
		messages: make(map[uint64]*Message),
	}
}

func (s *MockMsgStore) StoreMessage(_ context.Context, _ wire.OutPoint,
	msg *Message) (uint64, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextMessageID.Add(1)
	s.messages[id] = msg

	return id, nil
}

func (s *MockMsgStore) FetchMessage(_ context.Context,
	id uint64) (*Message, error) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	msg, exists := s.messages[id]
	if !exists {
		return nil, fmt.Errorf("message with ID %d not found", id)
	}

	return msg, nil
}

func (s *MockMsgStore) QueryMessages(_ context.Context,
	filter MessageFilter) ([]*Message, error) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Message
	for _, msg := range s.messages {
		if !msg.ReceiverKey.IsEqual(&filter.ReceiverKey) {
			continue
		}

		if filter.AfterID != 0 &&
			msg.ID <= filter.AfterID {

			continue
		}

		if !filter.After.IsZero() &&
			(msg.ArrivalTimestamp.Before(filter.After) ||
				msg.ArrivalTimestamp.Equal(filter.After)) {

			continue
		}

		if filter.StartBlock != 0 &&
			msg.ProofBlockHeight < filter.StartBlock {

			continue
		}

		result = append(result, msg)
	}

	return result, nil
}

func (s *MockMsgStore) NumMessages(context.Context) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return uint64(len(s.messages))
}
