package proof

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/lightninglabs/lightning-node-connect/hashmailrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"pgregory.net/rapid"
)

type mailboxOperation uint8

const (
	mailboxInit mailboxOperation = iota
	mailboxWriteProof
	mailboxReadProof
	mailboxWriteAck
	mailboxReadAck
	mailboxCleanup
)

type mailboxInput struct {
	op       mailboxOperation
	streamID byte
	value    byte
}

type mailboxOutput struct {
	value  byte
	failed bool
}

type mailboxSlot struct {
	message byte
	isAck   bool
	full    bool
}

type mailboxModelState map[byte]mailboxSlot

var proofMailboxModel = porcupine.Model{
	Init: func() interface{} {
		return mailboxModelState{}
	},
	Step: func(state, input, output interface{}) (bool, interface{}) {
		current := state.(mailboxModelState)
		in := input.(mailboxInput)
		out := output.(mailboxOutput)
		next := maps.Clone(current)
		slot, initialized := current[in.streamID]

		switch in.op {
		case mailboxInit:
			if out.failed {
				return false, current
			}
			if !initialized {
				next[in.streamID] = mailboxSlot{}
			}

		case mailboxWriteProof, mailboxWriteAck:
			shouldFail := !initialized || slot.full
			if out.failed != shouldFail {
				return false, current
			}
			if !shouldFail {
				message := in.value
				if in.op == mailboxWriteAck {
					message = ackMsg[0]
				}
				next[in.streamID] = mailboxSlot{
					message: message,
					isAck:   in.op == mailboxWriteAck,
					full:    true,
				}
			}

		case mailboxReadProof:
			shouldFail := !initialized || !slot.full
			if out.failed != shouldFail {
				return false, current
			}
			if !shouldFail {
				if out.value != slot.message {
					return false, current
				}
				next[in.streamID] = mailboxSlot{}
			}

		case mailboxReadAck:
			missing := !initialized || !slot.full
			if missing {
				return out.failed, current
			}
			if out.failed == slot.isAck {
				return false, current
			}
			next[in.streamID] = mailboxSlot{}

		case mailboxCleanup:
			if out.failed {
				return false, current
			}
			delete(next, in.streamID)

		default:
			return false, current
		}

		return true, next
	},
	Equal: func(state1, state2 interface{}) bool {
		return maps.Equal(
			state1.(mailboxModelState), state2.(mailboxModelState),
		)
	},
	DescribeOperation: func(input, output interface{}) string {
		in := input.(mailboxInput)
		out := output.(mailboxOutput)
		return fmt.Sprintf(
			"op=%d, stream=%d, value=%d -> value=%d, failed=%v",
			in.op, in.streamID, in.value, out.value, out.failed,
		)
	},
}

// porcupineHashMailClient is a synchronized, single-message implementation of
// the hashmail RPC boundary. The production HashMailBox translates each public
// operation into calls against this boundary.
type porcupineHashMailClient struct {
	mu    sync.Mutex
	boxes map[string]mailboxSlot
}

func newPorcupineHashMailBox() *HashMailBox {
	return &HashMailBox{client: &porcupineHashMailClient{
		boxes: make(map[string]mailboxSlot),
	}}
}

func (p *porcupineHashMailClient) NewCipherBox(_ context.Context,
	in *hashmailrpc.CipherBoxAuth, _ ...grpc.CallOption) (
	*hashmailrpc.CipherInitResp, error) {

	p.mu.Lock()
	defer p.mu.Unlock()

	key := string(in.Desc.StreamId)
	if _, ok := p.boxes[key]; ok {
		return nil, status.Error(codes.AlreadyExists, "mailbox exists")
	}
	p.boxes[key] = mailboxSlot{}

	return &hashmailrpc.CipherInitResp{}, nil
}

func (p *porcupineHashMailClient) DelCipherBox(_ context.Context,
	in *hashmailrpc.CipherBoxAuth, _ ...grpc.CallOption) (
	*hashmailrpc.DelCipherBoxResp, error) {

	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.boxes, string(in.Desc.StreamId))

	return &hashmailrpc.DelCipherBoxResp{}, nil
}

func (p *porcupineHashMailClient) SendStream(_ context.Context,
	_ ...grpc.CallOption) (hashmailrpc.HashMail_SendStreamClient, error) {

	return &porcupineHashMailSendStream{client: p}, nil
}

func (p *porcupineHashMailClient) RecvStream(_ context.Context,
	in *hashmailrpc.CipherBoxDesc, _ ...grpc.CallOption) (
	hashmailrpc.HashMail_RecvStreamClient, error) {

	return &porcupineHashMailRecvStream{
		client: p, streamID: append([]byte(nil), in.StreamId...),
	}, nil
}

type porcupineHashMailSendStream struct {
	grpc.ClientStream
	client *porcupineHashMailClient
	box    *hashmailrpc.CipherBox
}

func (p *porcupineHashMailSendStream) Send(box *hashmailrpc.CipherBox) error {
	p.box = &hashmailrpc.CipherBox{
		Desc: &hashmailrpc.CipherBoxDesc{
			StreamId: append([]byte(nil), box.Desc.StreamId...),
		},
		Msg: append([]byte(nil), box.Msg...),
	}

	return nil
}

func (p *porcupineHashMailSendStream) CloseSend() error {
	if p.box == nil {
		return status.Error(codes.InvalidArgument, "message missing")
	}

	p.client.mu.Lock()
	defer p.client.mu.Unlock()

	key := string(p.box.Desc.StreamId)
	slot, ok := p.client.boxes[key]
	if !ok {
		return status.Error(codes.NotFound, "mailbox missing")
	}
	if slot.full {
		return status.Error(codes.ResourceExhausted, "mailbox full")
	}

	isAck := string(p.box.Msg) == string(ackMsg)
	value := byte(0)
	if !isAck && len(p.box.Msg) > 0 {
		value = p.box.Msg[0]
	}
	p.client.boxes[key] = mailboxSlot{
		message: value, isAck: isAck, full: true,
	}

	return nil
}

func (p *porcupineHashMailSendStream) CloseAndRecv() (
	*hashmailrpc.CipherBoxDesc, error) {

	if err := p.CloseSend(); err != nil {
		return nil, err
	}

	return p.box.Desc, nil
}

type porcupineHashMailRecvStream struct {
	grpc.ClientStream
	client   *porcupineHashMailClient
	streamID []byte
}

func (p *porcupineHashMailRecvStream) Recv() (*hashmailrpc.CipherBox, error) {
	p.client.mu.Lock()
	defer p.client.mu.Unlock()

	key := string(p.streamID)
	slot, ok := p.client.boxes[key]
	if !ok || !slot.full {
		return nil, status.Error(codes.NotFound, "message missing")
	}
	p.client.boxes[key] = mailboxSlot{}

	message := []byte{slot.message}
	if slot.isAck {
		message = append([]byte(nil), ackMsg...)
	}

	return &hashmailrpc.CipherBox{
		Desc: &hashmailrpc.CipherBoxDesc{
			StreamId: append([]byte(nil), p.streamID...),
		},
		Msg: message,
	}, nil
}

func porcupineStreamID(id byte) streamID {
	var sid streamID
	sid[0] = id
	return sid
}

func executeMailboxOperation(mailbox *HashMailBox,
	in mailboxInput) mailboxOutput {

	ctx := context.Background()
	sid := porcupineStreamID(in.streamID)
	switch in.op {
	case mailboxInit:
		return mailboxOutput{failed: mailbox.Init(ctx, sid) != nil}

	case mailboxWriteProof:
		err := mailbox.WriteProof(ctx, sid, Blob{in.value})
		return mailboxOutput{failed: err != nil}

	case mailboxReadProof:
		blob, err := mailbox.ReadProof(ctx, sid)
		out := mailboxOutput{failed: err != nil}
		if err == nil && len(blob) > 0 {
			out.value = blob[0]
		}
		return out

	case mailboxWriteAck:
		return mailboxOutput{failed: mailbox.AckProof(ctx, sid) != nil}

	case mailboxReadAck:
		return mailboxOutput{failed: mailbox.RecvAck(ctx, sid) != nil}

	case mailboxCleanup:
		return mailboxOutput{failed: mailbox.CleanUp(ctx, sid) != nil}

	default:
		return mailboxOutput{failed: true}
	}
}

func executeMailboxHistory(mailbox *HashMailBox,
	clients [][]mailboxInput) []porcupine.Operation {

	var operationCount int
	for _, operations := range clients {
		operationCount += len(operations)
	}

	var (
		clock   atomic.Int64
		wg      sync.WaitGroup
		start   = make(chan struct{})
		history = make(chan porcupine.Operation, operationCount)
	)
	for clientID, operations := range clients {
		clientID := clientID
		operations := operations
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for _, input := range operations {
				call := clock.Add(1)
				output := executeMailboxOperation(
					mailbox, input,
				)
				ret := clock.Add(1)
				history <- porcupine.Operation{
					ClientId: clientID,
					Input:    input,
					Call:     call,
					Output:   output,
					Return:   ret,
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(history)

	result := make([]porcupine.Operation, 0, operationCount)
	for operation := range history {
		result = append(result, operation)
	}

	return result
}

func checkProofMailboxLinearizability(rt *rapid.T) {
	numClients := rapid.IntRange(2, 5).Draw(rt, "num_clients")
	clients := make([][]mailboxInput, numClients)
	for clientID := range clients {
		numOperations := rapid.IntRange(1, 4).Draw(
			rt, fmt.Sprintf("client_%d_operations", clientID),
		)
		clients[clientID] = make([]mailboxInput, numOperations)
		for operationID := range clients[clientID] {
			label := fmt.Sprintf(
				"client_%d_operation_%d", clientID, operationID,
			)
			clients[clientID][operationID] = mailboxInput{
				op: mailboxOperation(rapid.IntRange(0, 5).Draw(
					rt, label+"_op",
				)),
				streamID: byte(rapid.IntRange(
					0, 2,
				).Draw(rt, label+"_stream")),
				value: byte(rapid.IntRange(
					1, 8,
				).Draw(rt, label+"_value")),
			}
		}
	}

	history := executeMailboxHistory(newPorcupineHashMailBox(), clients)
	result := porcupine.CheckOperationsTimeout(
		proofMailboxModel, history, 5*time.Second,
	)
	if result != porcupine.Ok {
		rt.Fatalf(
			"proof mailbox history is not linearizable: %v", result,
		)
	}
}

// TestProofMailboxLinearizability checks stream initialization, proof and ACK
// delivery, reads, cleanup, and isolation through the production adapter.
func TestProofMailboxLinearizability(t *testing.T) {
	t.Parallel()

	const rapidBatches = 10
	for batch := range rapidBatches {
		t.Run(fmt.Sprintf("batch_%02d", batch), func(t *testing.T) {
			rapid.Check(t, checkProofMailboxLinearizability)
		})
	}
}

// TestProofMailboxModelRejectsCrossStreamRead proves that a proof written to
// one stream cannot be observed from another stream.
func TestProofMailboxModelRejectsCrossStreamRead(t *testing.T) {
	t.Parallel()

	history := []porcupine.Operation{{
		ClientId: 0, Input: mailboxInput{op: mailboxInit, streamID: 0},
		Call: 1, Output: mailboxOutput{}, Return: 2,
	}, {
		ClientId: 0,
		Input: mailboxInput{
			op: mailboxWriteProof, streamID: 0, value: 7,
		},
		Call: 3, Output: mailboxOutput{}, Return: 4,
	}, {
		ClientId: 1,
		Input: mailboxInput{
			op: mailboxReadProof, streamID: 1,
		},
		Call: 5, Output: mailboxOutput{value: 7}, Return: 6,
	}}

	result := porcupine.CheckOperationsTimeout(
		proofMailboxModel, history, time.Second,
	)
	require.Equal(t, porcupine.Illegal, result)
}
