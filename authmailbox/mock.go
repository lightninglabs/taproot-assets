package authmailbox

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
)

type MockMsgStore struct {
	messages      map[uint64]*Message
	nextMessageID atomic.Uint64
	mu            sync.RWMutex
}

func NewMockStore() *MockMsgStore {
	return &MockMsgStore{
		messages: make(map[uint64]*Message),
	}
}

func (s *MockMsgStore) StoreMessage(msg *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg.ID = s.nextMessageID.Add(1)

	s.messages[msg.ID] = msg
	return nil
}

func (s *MockMsgStore) FetchMessage(id uint64) (*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	msg, exists := s.messages[id]
	if !exists {
		return nil, fmt.Errorf("message with ID %d not found", id)
	}

	return msg, nil
}

func (s *MockMsgStore) FetchMessages() ([]*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return slices.Collect(maps.Values(s.messages)), nil
}

func (s *MockMsgStore) QueryMessages(
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
