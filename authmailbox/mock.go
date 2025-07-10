package authmailbox

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
)

type MockMsgStore struct {
	messages          map[uint64]*Message
	outpointToMessage map[wire.OutPoint]uint64
	nextMessageID     atomic.Uint64
	proofs            map[wire.OutPoint]struct{}
	mu                sync.RWMutex
}

var _ MsgStore = (*MockMsgStore)(nil)

func NewMockStore() *MockMsgStore {
	return &MockMsgStore{
		messages:          make(map[uint64]*Message),
		outpointToMessage: make(map[wire.OutPoint]uint64),
		proofs:            make(map[wire.OutPoint]struct{}),
	}
}

func (s *MockMsgStore) StoreMessage(_ context.Context, txProof proof.TxProof,
	msg *Message) (uint64, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.proofs[txProof.ClaimedOutPoint]; exists {
		return 0, proof.ErrTxMerkleProofExists
	}

	s.proofs[txProof.ClaimedOutPoint] = struct{}{}

	id := s.nextMessageID.Add(1)
	s.messages[id] = msg
	s.outpointToMessage[txProof.ClaimedOutPoint] = id

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

func (s *MockMsgStore) FetchMessageByOutPoint(ctx context.Context,
	claimedOp wire.OutPoint) (*Message, error) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	msgID, exists := s.outpointToMessage[claimedOp]
	if !exists {
		return nil, ErrMessageNotFound
	}

	return s.FetchMessage(ctx, msgID)
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
