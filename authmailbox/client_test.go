package authmailbox

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type clientHarness struct {
	cfg          *ClientConfig
	key          keychain.KeyDescriptor
	filter       MessageFilter
	client       *Client
	msgChan      chan *ReceivedMessages
	subscription ReceiveSubscription
}

func newClientHarness(t *testing.T, cfg *ClientConfig,
	key keychain.KeyDescriptor, filter MessageFilter,
	subscribe bool) *clientHarness {

	t.Helper()

	client := NewClient(cfg)
	require.NoError(t, client.Start())

	h := &clientHarness{
		cfg:     cfg,
		key:     key,
		filter:  filter,
		msgChan: make(chan *ReceivedMessages, 1),
		client:  client,
	}

	if subscribe {
		h.subscribe(t)
		h.assertConnected(t)
	}

	return h
}

func (h *clientHarness) subscribe(t *testing.T) {
	t.Helper()

	var (
		ctx = context.Background()
		err error
	)
	h.subscription, err = h.client.StartAccountSubscription(
		ctx, h.msgChan, h.key, h.filter,
	)
	require.NoError(t, err)
}

func (h *clientHarness) assertConnected(t *testing.T) {
	t.Helper()

	require.Eventually(
		t, h.subscription.IsSubscribed, testTimeout, testMinBackoff,
	)
}

func (h *clientHarness) assertDisconnected(t *testing.T) {
	t.Helper()

	require.Eventually(t, func() bool {
		return !h.subscription.IsSubscribed()
	}, testTimeout, testMinBackoff)
}

func (h *clientHarness) readMessages(t *testing.T, targetID ...uint64) {
	t.Helper()

	select {
	case inboundMsgs := <-h.msgChan:

		receivedIDs := fn.Map(
			inboundMsgs.Messages,
			func(msg *mboxrpc.MailboxMessage) uint64 {
				return msg.MessageId
			},
		)

		for _, target := range targetID {
			require.Contains(t, receivedIDs, target)
		}

	case <-time.After(testTimeout):
		t.Fatalf("timeout waiting for message with ID %d", targetID)
	}
}

func (h *clientHarness) expectNoMessage(t *testing.T) {
	t.Helper()

	select {
	case msg := <-h.msgChan:
		t.Fatalf("Received message when didn't expect one: %v", msg)

	case <-time.After(testTimeout):
	}
}

func (h *clientHarness) stop(t *testing.T) {
	t.Helper()

	t.Logf("Stopping client %x", h.key.PubKey.SerializeCompressed())
	if h.subscription != nil {
		err := h.subscription.Stop()
		require.NoError(t, err)
	}

	err := h.client.Stop()
	require.NoError(t, err)
}

func randProof(t *testing.T) proof.TxProof {
	t.Helper()

	randOp := test.RandOp(t)
	return proof.TxProof{
		ClaimedOutPoint: randOp,
	}
}

// TestServerClientAuthAndRestart tests the server and client authentication
// process, and that the client can re-connect to the server after it has
// restarted. It also tests that the client can receive messages from the
// server's backlog.
func TestServerClientAuthAndRestart(t *testing.T) {
	ctx := context.Background()
	harness := NewMockServer(t)
	clientCfg := harness.clientCfg

	clientKey1, _ := test.RandKeyDesc(t)
	clientKey2, _ := test.RandKeyDesc(t)
	filter := MessageFilter{}
	client1 := newClientHarness(t, clientCfg, clientKey1, filter, true)
	client2 := newClientHarness(t, clientCfg, clientKey1, filter, true)
	t.Cleanup(func() {
		client1.stop(t)
		client2.stop(t)
	})

	// We also add a multi-subscription to the same two keys, so we can make
	// sure we can receive messages from multiple clients at once.
	multiSub := NewMultiSubscription(*clientCfg)
	err := multiSub.Subscribe(
		ctx, url.URL{Host: clientCfg.ServerAddress}, clientKey1, filter,
	)
	require.NoError(t, err)
	err = multiSub.Subscribe(
		ctx, url.URL{Host: clientCfg.ServerAddress}, clientKey2, filter,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, multiSub.Stop())
	})
	msgChan := multiSub.MessageChan()
	readMultiSub := func(targetID ...uint64) {
		t.Helper()
		select {
		case inboundMsgs := <-msgChan:
			receivedIDs := fn.Map(
				inboundMsgs.Messages,
				func(msg *mboxrpc.MailboxMessage) uint64 {
					return msg.MessageId
				},
			)
			for _, target := range targetID {
				require.Contains(t, receivedIDs, target)
			}
		case <-time.After(testTimeout):
			t.Fatalf("timeout waiting for message with ID %v",
				targetID)
		}
	}

	// Send a message to all clients.
	msg1 := &Message{
		ID:               1000,
		ReceiverKey:      *clientKey1.PubKey,
		ArrivalTimestamp: time.Now(),
	}

	// We also store the message in the store, so we can retrieve it later.
	_, err = harness.mockMsgStore.StoreMessage(ctx, randProof(t), msg1)
	require.NoError(t, err)

	harness.srv.publishMessage(msg1)

	// We should be able to receive that message.
	client1.readMessages(t, msg1.ID)
	client2.readMessages(t, msg1.ID)
	readMultiSub(msg1.ID)

	// We now stop the server and assert that the subscription is no longer
	// active.
	harness.Stop(t)
	client1.assertDisconnected(t)
	client2.assertDisconnected(t)

	// We wait a bit to simulate the server taking a while to start.
	time.Sleep(testMinBackoff * 2)

	// Let's start the server again and make sure the clients eventually
	// re-connect.
	harness.Start(t)
	client1.assertConnected(t)
	client2.assertConnected(t)

	// Let's send another message to all clients.
	msg2 := &Message{
		ID:               1001,
		ReceiverKey:      *clientKey1.PubKey,
		ArrivalTimestamp: time.Now(),
	}
	_, err = harness.mockMsgStore.StoreMessage(ctx, randProof(t), msg2)
	require.NoError(t, err)

	harness.srv.publishMessage(msg2)

	// We should be able to receive that message.
	client1.readMessages(t, msg2.ID)
	client2.readMessages(t, msg2.ID)
	readMultiSub(msg2.ID)

	// If we now start a third client, we should be able to receive all
	// three messages, given we are using the same key and specify the
	// filter.
	client3 := newClientHarness(t, clientCfg, clientKey1, MessageFilter{
		After: time.Now().Add(-time.Hour),
	}, true)
	client3.readMessages(t, msg1.ID, msg2.ID)

	// Make sure a client can disconnect and then re-connect again.
	t.Logf("Disconnecting and re-connecting client")
	require.NoError(t, client3.subscription.Stop())
	client3.assertDisconnected(t)
	client3.subscribe(t)
	t.Cleanup(func() {
		client3.stop(t)
	})
	client3.assertConnected(t)

	client3.readMessages(t, msg1.ID, msg2.ID)

	// We now make sure that messages are only delivered to the clients
	// with the correct key.
	client4 := newClientHarness(t, clientCfg, clientKey2, filter, true)
	msg3 := &Message{
		ID:               1000,
		ReceiverKey:      *clientKey1.PubKey,
		ArrivalTimestamp: time.Now(),
	}
	harness.srv.publishMessage(msg3)
	client4.expectNoMessage(t)
	client1.readMessages(t, msg3.ID)
	client2.readMessages(t, msg3.ID)
	client3.readMessages(t, msg3.ID)
	readMultiSub(msg3.ID)

	// Let's make sure that a message sent to the second key is only
	// received by the fourth client and the multi-subscription.
	msg4 := &Message{
		ID:               1001,
		ReceiverKey:      *clientKey2.PubKey,
		ArrivalTimestamp: time.Now(),
	}
	harness.srv.publishMessage(msg4)
	client1.expectNoMessage(t)
	client2.expectNoMessage(t)
	client3.expectNoMessage(t)
	client4.readMessages(t, msg4.ID)
	readMultiSub(msg4.ID)
}

// TestSendMessage tests the SendMessage RPC of the server and its ability to
// rate limit messages by validating the transaction proofs.
func TestSendMessage(t *testing.T) {
	txProof1 := proof.MockTxProof(t)
	txProof2 := proof.MockTxProof(t)
	txProof3 := proof.MockTxProof(t)

	clientKey1, _ := test.RandKeyDesc(t)
	clientKey2, _ := test.RandKeyDesc(t)
	clientKey3, _ := test.RandKeyDesc(t)

	proofWithHeight := func(p proof.TxProof, h uint32) proof.TxProof {
		p.BlockHeight = h
		return p
	}

	// To be able to have these test cases be fully independent of each
	// other, we allow each test case to send multiple messages, using
	// different proofs and expecting different errors.
	testCases := []struct {
		name         string
		txProofs     []proof.TxProof
		recvKeys     []keychain.KeyDescriptor
		sendKey      keychain.KeyDescriptor
		msgs         [][]byte
		expiryHeight uint32
		expectedErrs []string
	}{
		{
			name:         "empty payload",
			txProofs:     []proof.TxProof{*txProof1},
			recvKeys:     []keychain.KeyDescriptor{clientKey2},
			sendKey:      clientKey1,
			msgs:         [][]byte{nil},
			expectedErrs: []string{"empty payload"},
		},
		{
			name:     "long payload",
			txProofs: []proof.TxProof{*txProof1},
			recvKeys: []keychain.KeyDescriptor{clientKey2},
			sendKey:  clientKey1,
			msgs: [][]byte{
				bytes.Repeat([]byte("foo"), MsgMaxSize),
			},
			expectedErrs: []string{ErrMessageTooLong.Error()},
		},
		{
			name: "expiry delta not set",
			txProofs: []proof.TxProof{
				proofWithHeight(*txProof1, 100002),
			},
			recvKeys: []keychain.KeyDescriptor{clientKey2},
			sendKey:  clientKey1,
			msgs:     [][]byte{[]byte("yoooo")},
			expectedErrs: []string{
				"missing expiry block delta",
			},
		},
		{
			name: "success",
			txProofs: []proof.TxProof{
				proofWithHeight(*txProof1, 100002),
			},
			recvKeys:     []keychain.KeyDescriptor{clientKey2},
			sendKey:      clientKey1,
			msgs:         [][]byte{[]byte("yoooo")},
			expiryHeight: 100002 + 123,
		},
		{
			name: "duplicate proof",
			txProofs: []proof.TxProof{
				proofWithHeight(*txProof1, 100002),
				proofWithHeight(*txProof1, 100002),
			},
			recvKeys: []keychain.KeyDescriptor{
				clientKey2,
				clientKey3,
			},
			sendKey: clientKey1,
			msgs: [][]byte{
				[]byte("yoooo"),
				[]byte("imma try again"),
			},
			expiryHeight: 100002 + 123,
			expectedErrs: []string{
				"",
				proof.ErrTxMerkleProofExists.Error(),
			},
		},
		{
			name: "multiple successful proofs",
			txProofs: []proof.TxProof{
				proofWithHeight(*txProof1, 100002),
				proofWithHeight(*txProof2, 100002),
				proofWithHeight(*txProof3, 100002),
			},
			recvKeys: []keychain.KeyDescriptor{
				clientKey2,
				clientKey2,
				clientKey2,
			},
			sendKey: clientKey1,
			msgs: [][]byte{
				[]byte("yoooo"),
				[]byte("imma try again"),
				[]byte("and again"),
			},
			expiryHeight: 100002 + 123,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			harness := NewMockServer(t)
			clientCfg := harness.clientCfg

			filter := MessageFilter{
				After: time.Now().Add(-time.Hour),
			}
			client1 := newClientHarness(
				t, clientCfg, clientKey1, filter, false,
			)
			client2 := newClientHarness(
				t, clientCfg, clientKey2, filter, true,
			)
			t.Cleanup(func() {
				client1.stop(t)
				client2.stop(t)
			})

			for idx := range tc.msgs {
				msg := tc.msgs[idx]
				txProof := tc.txProofs[idx]
				recvKey := tc.recvKeys[idx]

				msgID, err := client1.client.SendMessage(
					ctx, *recvKey.PubKey, msg, txProof,
					tc.expiryHeight,
				)

				if len(tc.expectedErrs) > 0 &&
					tc.expectedErrs[idx] != "" {

					require.ErrorContains(
						t, err, tc.expectedErrs[idx],
					)

					return
				}

				require.NoError(t, err)

				// We should be able to read the message if
				// there was no error sending it.
				client2.readMessages(t, msgID)

				// Sending the same message again should result
				// in the same message ID, but should not cause
				// another message to be sent to any recipients.
				msgIDReSend, err := client1.client.SendMessage(
					ctx, *recvKey.PubKey, msg, txProof,
					tc.expiryHeight,
				)
				require.NoError(t, err)

				require.Equal(t, msgID, msgIDReSend)
				client2.expectNoMessage(t)
			}
		})
	}
}

type msgOpt func(*Message)

func withTimestamp(ts time.Time) msgOpt {
	return func(msg *Message) {
		msg.ArrivalTimestamp = ts
	}
}

func withArrivalBlockHeight(height uint32) msgOpt {
	return func(msg *Message) {
		msg.ProofBlockHeight = height
	}
}

func makeMessage(c clock.Clock, id uint64, key keychain.KeyDescriptor,
	opts ...msgOpt) *Message {

	msg := &Message{
		ID:               id,
		ReceiverKey:      *key.PubKey,
		ArrivalTimestamp: c.Now(),
	}

	for _, opt := range opts {
		opt(msg)
	}

	return msg
}

// TestReceiveBacklog tests that the client can receive messages from the
// server's backlog, using custom filters.
func TestReceiveBacklog(t *testing.T) {
	harness := NewMockServer(t)

	ctx := context.Background()
	receiver1, _ := test.RandKeyDesc(t)
	receiver2, _ := test.RandKeyDesc(t)
	receiver3, _ := test.RandKeyDesc(t)

	// We create and store a bunch of messages with different properties.
	// Timestamps are converted to Unix timestamps, so we lose sub-second
	// precision.
	c := clock.NewTestClock(time.Now().Truncate(time.Second))
	yesterday := c.Now().Add(-24 * time.Hour).Truncate(time.Second)
	lastHour := c.Now().Add(-time.Hour).Truncate(time.Second)
	lastHalfHour := c.Now().Add(-time.Hour / 2).Truncate(time.Second)
	messages := []*Message{
		// For receiver 1.
		makeMessage(c, 1, receiver1),
		makeMessage(c, 2, receiver1, withTimestamp(lastHour)),
		makeMessage(c, 3, receiver1, withArrivalBlockHeight(123)),
		makeMessage(
			c, 4, receiver1, withTimestamp(lastHour),
			withArrivalBlockHeight(345),
		),

		// For receiver 2.
		makeMessage(c, 5, receiver2),
		makeMessage(c, 6, receiver2, withTimestamp(lastHour)),
		makeMessage(c, 7, receiver2, withArrivalBlockHeight(123)),
		makeMessage(
			c, 8, receiver2, withTimestamp(lastHour),
			withArrivalBlockHeight(345),
		),

		// For receiver 3.
		makeMessage(c, 9, receiver3),
		makeMessage(c, 10, receiver3, withTimestamp(lastHour)),
		makeMessage(c, 11, receiver3, withArrivalBlockHeight(123)),
		makeMessage(
			c, 12, receiver3, withTimestamp(lastHour),
			withArrivalBlockHeight(345),
		),
	}

	for _, msg := range messages {
		_, err := harness.mockMsgStore.StoreMessage(
			ctx, randProof(t), msg,
		)
		require.NoError(t, err)
	}

	testCases := []struct {
		name             string
		receiver         keychain.KeyDescriptor
		filter           MessageFilter
		expected         []uint64
		expectNoMessages bool
	}{
		{
			name:     "timestamp is exclusive",
			receiver: receiver1,
			filter: MessageFilter{
				After: lastHour,
			},
			expected: []uint64{1, 3},
		},
		{
			name:     "block height is inclusive",
			receiver: receiver1,
			filter: MessageFilter{
				StartBlock: 123,
			},
			expected: []uint64{3},
		},
		{
			name:     "id is exclusive",
			receiver: receiver1,
			filter: MessageFilter{
				AfterID: 1,
			},
			expected: []uint64{2, 3, 4},
		},
		{
			name: "receiver 2, no filter means no " +
				"backlog",
			receiver:         receiver2,
			filter:           MessageFilter{},
			expectNoMessages: true,
		},
		{
			name:     "receiver 2, all",
			receiver: receiver2,
			filter: MessageFilter{
				After: yesterday,
			},
			expected: []uint64{5, 6, 7, 8},
		},
		{
			name:     "receiver 3, all values set",
			receiver: receiver3,
			filter: MessageFilter{
				AfterID:    9,
				After:      lastHalfHour,
				StartBlock: 123,
			},
			expected: []uint64{11},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientCfg := harness.clientCfg
			client := newClientHarness(
				t, clientCfg, tc.receiver, tc.filter, true,
			)
			defer client.stop(t)

			if tc.expectNoMessages {
				client.expectNoMessage(t)

				return
			}

			client.readMessages(t, tc.expected...)
		})
	}
}

func init() {
	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	UseLogger(logger.SubSystem(Subsystem))
}
