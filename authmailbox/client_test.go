package authmailbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	// oddTxBlockHexFileName is the file name for a testdata file that
	// contains the hex encoded block 100002 with 9 transactions on bitcoin
	// mainnet.
	oddTxBlockHexFileName = filepath.Join(testDataFileName, "odd-block.hex")

	testTimeout    = time.Second
	testMinBackoff = time.Millisecond * 20
	testMaxBackoff = time.Millisecond * 100
)

type serverHarness struct {
	cfg          *ServerConfig
	clientCfg    *ClientConfig
	mockSigner   *test.MockSigner
	mockMsgStore *MockMsgStore
	mockTxStore  proof.TxProofStore
	srv          *Server
	grpcServer   *grpc.Server
	cleanup      func()
	listenAddr   string
}

func newServerHarness(t *testing.T) *serverHarness {
	signer := test.NewMockSigner()
	signer.Signature = test.RandBytes(64)

	inMemMsgStore := NewMockStore()
	inMemTxStore := proof.NewMockTxProofStore()

	nextPort := port.NextAvailablePort()
	listenAddr := fmt.Sprintf(test.ListenAddrTemplate, nextPort)

	serverCfg := &ServerConfig{
		AuthTimeout:    testTimeout,
		Signer:         signer,
		HeaderVerifier: proof.MockHeaderVerifier,
		MsgStore:       inMemMsgStore,
		TxProofStore:   inMemTxStore,
	}
	h := &serverHarness{
		listenAddr: listenAddr,
		cfg:        serverCfg,
		clientCfg: &ClientConfig{
			ServerAddress: listenAddr,
			Insecure:      true,
			Signer:        signer,
			MinBackoff:    testMinBackoff,
			MaxBackoff:    testMaxBackoff,
		},
		mockSigner:   signer,
		mockMsgStore: inMemMsgStore,
		mockTxStore:  inMemTxStore,
	}
	h.start(t)

	return h
}

func (h *serverHarness) start(t *testing.T) {
	t.Helper()

	t.Logf("Starting server %s", h.listenAddr)
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	h.grpcServer = grpc.NewServer(serverOpts...)

	h.srv = NewServer(h.cfg)
	mboxrpc.RegisterMailboxServer(h.grpcServer, h.srv)

	cleanup, err := test.StartMockGRPCServerWithAddr(
		t, h.grpcServer, false, h.listenAddr,
	)
	require.NoError(t, err)

	h.cleanup = cleanup
}

func (h *serverHarness) stop(t *testing.T) {
	t.Helper()

	t.Logf("Stopping server %s", h.listenAddr)
	err := h.srv.Stop()
	require.NoError(t, err)

	h.grpcServer.GracefulStop()
	h.cleanup()
}

type clientHarness struct {
	cfg          *ClientConfig
	key          keychain.KeyDescriptor
	filter       MessageFilter
	client       *Client
	subscription ReceiveSubscription
}

func newClientHarness(t *testing.T, cfg *ClientConfig,
	key keychain.KeyDescriptor, filter MessageFilter,
	subscribe bool) *clientHarness {

	t.Helper()

	client := NewClient(cfg)
	require.NoError(t, client.Start())

	h := &clientHarness{
		cfg:    cfg,
		key:    key,
		filter: filter,
		client: client,
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
		ctx, h.key, h.filter,
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

func (h *clientHarness) readMessage(t *testing.T, targetID uint64) {
	t.Helper()

	select {
	case inboundMsg := <-h.subscription.Messages():
		require.IsType(t, &respTypeMessage{}, inboundMsg.ResponseType)
		rpcMsg := inboundMsg.ResponseType.(*respTypeMessage)

		require.Equal(t, targetID, rpcMsg.Message.MessageId)

	case <-time.After(testTimeout):
		t.Fatalf("timeout waiting for message with ID %d", targetID)
	}
}

func (h *clientHarness) expectNoMessage(t *testing.T) {
	t.Helper()

	select {
	case msg := <-h.subscription.Messages():
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

// TestServerClientAuthAndRestart tests the server and client authentication
// process, and that the client can re-connect to the server after it has
// restarted. It also tests that the client can receive messages from the
// server's backlog.
func TestServerClientAuthAndRestart(t *testing.T) {
	harness := newServerHarness(t)
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

	// Send a message to all clients.
	msg1 := &Message{
		ID:               1000,
		ReceiverKey:      *clientKey1.PubKey,
		ArrivalTimestamp: time.Now(),
	}
	harness.srv.publishMessage(msg1)

	// We also store the message in the store, so we can retrieve it later.
	require.NoError(t, harness.mockMsgStore.StoreMessage(msg1))

	// We should be able to receive that message.
	client1.readMessage(t, msg1.ID)
	client2.readMessage(t, msg1.ID)

	// We now stop the server and assert that the subscription is no longer
	// active.
	harness.stop(t)
	client1.assertDisconnected(t)
	client2.assertDisconnected(t)

	// We wait a bit to simulate the server taking a while to start.
	time.Sleep(testMinBackoff * 2)

	// Let's start the server again and make sure the clients eventually
	// re-connect.
	harness.start(t)
	client1.assertConnected(t)
	client2.assertConnected(t)

	// Let's send another message to all clients.
	msg2 := &Message{
		ID:               1001,
		ReceiverKey:      *clientKey1.PubKey,
		ArrivalTimestamp: time.Now(),
	}
	harness.srv.publishMessage(msg2)
	require.NoError(t, harness.mockMsgStore.StoreMessage(msg2))

	// We should be able to receive that message.
	client1.readMessage(t, msg2.ID)
	client2.readMessage(t, msg2.ID)

	// If we now start a third client, we should be able to receive all
	// three messages, given we are using the same key and specify the
	// filter.
	client3 := newClientHarness(t, clientCfg, clientKey1, MessageFilter{
		After: time.Now().Add(-time.Hour),
	}, true)
	client3.readMessage(t, msg1.ID)
	client3.readMessage(t, msg2.ID)

	// Make sure a client can disconnect and then re-connect again.
	t.Logf("Disconnecting and re-connecting client")
	require.NoError(t, client3.subscription.Stop())
	client3.assertDisconnected(t)
	client3.subscribe(t)
	defer client3.stop(t)
	client3.assertConnected(t)

	client3.readMessage(t, msg1.ID)
	client3.readMessage(t, msg2.ID)

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
	client1.readMessage(t, msg3.ID)
}

// TestSendMessage tests the SendMessage RPC of the server and its ability to
// rate limit messages by validating the transaction proofs.
func TestSendMessage(t *testing.T) {
	// There are 9 transactions in the oddTxBlockHexFileName block, with
	// the first one being the coinbase transaction. Because we don't know
	// how many outputs there are per transaction, we just grab the first
	// one of each transaction.
	txProof1 := proof.MockTxProof(t, oddTxBlockHexFileName, 1, 0)
	txProof2 := proof.MockTxProof(t, oddTxBlockHexFileName, 2, 0)
	txProof3 := proof.MockTxProof(t, oddTxBlockHexFileName, 3, 0)

	clientKey1, _ := test.RandKeyDesc(t)
	clientKey2, _ := test.RandKeyDesc(t)

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
		recvKey      keychain.KeyDescriptor
		sendKey      keychain.KeyDescriptor
		msgs         [][]byte
		expiryHeight uint32
		expectedErrs []string
	}{
		{
			name:         "empty payload",
			txProofs:     []proof.TxProof{*txProof1},
			recvKey:      clientKey2,
			sendKey:      clientKey1,
			msgs:         [][]byte{nil},
			expectedErrs: []string{"empty payload"},
		},
		{
			name:     "long payload",
			txProofs: []proof.TxProof{*txProof1},
			recvKey:  clientKey2,
			sendKey:  clientKey1,
			msgs: [][]byte{
				bytes.Repeat([]byte("foo"), MsgMaxSize),
			},
			expectedErrs: []string{ErrMessageTooLong.Error()},
		},
		{
			name:         "missing expiry height",
			txProofs:     []proof.TxProof{*txProof1},
			recvKey:      clientKey2,
			sendKey:      clientKey1,
			msgs:         [][]byte{[]byte("yoooo")},
			expectedErrs: []string{"missing expiry block height"},
		},
		{
			name: "expiry height too low",
			txProofs: []proof.TxProof{
				proofWithHeight(*txProof1, 100002),
			},
			recvKey:      clientKey2,
			sendKey:      clientKey1,
			msgs:         [][]byte{[]byte("yoooo")},
			expiryHeight: 123,
			expectedErrs: []string{
				"expiry block height 123 is before proof " +
					"block height 100002",
			},
		},
		{
			name: "success",
			txProofs: []proof.TxProof{
				proofWithHeight(*txProof1, 100002),
			},
			recvKey:      clientKey2,
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
			recvKey: clientKey2,
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
			recvKey: clientKey2,
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

			harness := newServerHarness(t)
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

				msgID, err := client1.client.SendMessage(
					ctx, *tc.recvKey.PubKey,
					*tc.sendKey.PubKey, msg, txProof,
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
				client2.readMessage(t, msgID)
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
	harness := newServerHarness(t)

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
		require.NoError(t, harness.mockMsgStore.StoreMessage(msg))
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

			for _, expectedID := range tc.expected {
				client.readMessage(t, expectedID)
			}
		})
	}
}

func init() {
	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	UseLogger(logger.SubSystem(Subsystem))
}
