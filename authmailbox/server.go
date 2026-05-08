package authmailbox

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/davecgh/go-spew/spew"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
)

const (
	// defaultCleanupInterval is the default interval at which the server
	// checks for spent outpoints and deletes stale messages.
	defaultCleanupInterval = 24 * time.Hour

	// defaultCleanupCheckTimeout is the default per-outpoint timeout when
	// checking if an outpoint has been spent on chain.
	defaultCleanupCheckTimeout = 30 * time.Second

	// cleanupBatchSize is the number of outpoints to fetch per page
	// during cleanup.
	cleanupBatchSize int32 = 1000

	// maxConcurrentChecks is the maximum number of outpoint spend checks
	// that can run concurrently during cleanup.
	maxConcurrentChecks = 50

	// maxRemoveMessageIDs is the maximum number of message IDs that can
	// be removed in a single RemoveMessage RPC call.
	maxRemoveMessageIDs = 1000

	// maxSubscriberOverflow is the maximum number of items
	// allowed to accumulate in a subscriber's overflow queue
	// before the subscriber is evicted. This is a memory-
	// safety bound, not a delivery guarantee: messages are
	// persisted in MsgStore before being published, so an
	// evicted subscriber recovers via replay on reconnect.
	maxSubscriberOverflow = 64
)

// ServerConfig is the configuration struct for the mailbox server. It contains
// all the dependencies needed to run the server.
type ServerConfig struct {
	// AuthTimeout is the maximum time the server will wait for the client
	// to authenticate before closing the connection.
	AuthTimeout time.Duration

	// Signer is the lndclient.SignerClient used to verify the
	// authentication signature.
	Signer lndclient.SignerClient

	// HeaderVerifier is the proof.HeaderVerifier used to verify the TX
	// proofs sent by clients to prove the rate limit of their messages.
	HeaderVerifier proof.HeaderVerifier

	// MerkleVerifier is the proof.MerkleVerifier used to verify the
	// TX proofs sent by clients to prove the rate limit of their messages.
	MerkleVerifier proof.MerkleVerifier

	// MsgStore is the message store used to store and retrieve messages
	// sent to the mailbox server.
	MsgStore MsgStore

	// OutpointChecker checks whether a given outpoint has been spent on
	// chain. If nil, no periodic cleanup is performed.
	OutpointChecker OutpointChecker

	// CleanupInterval is how often the server checks for spent outpoints
	// and deletes stale messages. Defaults to 24h if zero.
	CleanupInterval time.Duration

	// CleanupCheckTimeout is the per-outpoint timeout when checking if
	// an outpoint has been spent. Defaults to 30s if zero.
	CleanupCheckTimeout time.Duration
}

// Server is the mailbox server that handles incoming messages from clients and
// sends them to the appropriate subscribers. It also handles the
// authentication process for clients and manages the connected streams.
type Server struct {
	mboxrpc.UnimplementedMailboxServer

	startOnce sync.Once
	stopOnce  sync.Once

	cfg *ServerConfig

	nextStreamID atomic.Uint64

	// connectedStreams is a map of all connected mailbox client streams.
	connectedStreams map[uint64]*mailboxStream

	// connectedStreamsMtx guards the connected streams map.
	connectedStreamsMtx sync.Mutex

	// msgEventsSubs is a map of subscribers that want to be notified on
	// new message events, keyed by their stream ID.
	msgEventsSubs map[uint64]*fn.EventReceiver[[]*Message]

	// msgEventsSubsMtx guards the general message events subscribers map.
	msgEventsSubsMtx sync.Mutex

	*lfn.ContextGuard
}

// NewServer creates a new mailbox server with the given configuration.
func NewServer() *Server {
	return &Server{
		msgEventsSubs: make(
			map[uint64]*fn.EventReceiver[[]*Message],
		),
		connectedStreams: make(map[uint64]*mailboxStream),
		ContextGuard:     lfn.NewContextGuard(),
	}
}

// Start signals that the RPC server starts accepting requests.
func (s *Server) Start(cfg *ServerConfig) error {
	var startErr error
	s.startOnce.Do(func() {
		log.Infof("Starting authmailbox RPC Server")

		if cfg == nil {
			startErr = fmt.Errorf("authmailbox server config not " +
				"provided in Start")
			return
		}

		s.cfg = cfg

		if s.cfg.OutpointChecker != nil {
			s.WgAdd(1)
			go func() {
				defer s.WgDone()
				s.cleanupLoop()
			}()
		}
	})

	return startErr
}

// RegisterWithGrpcServer registers the rpcServer with the passed root gRPC
// server.
func (s *Server) RegisterWithGrpcServer(registrar grpc.ServiceRegistrar) error {
	mboxrpc.RegisterMailboxServer(registrar, s)

	return nil
}

// RegisterWithRestProxy registers the RPC server with the given rest proxy.
func (s *Server) RegisterWithRestProxy(restCtx context.Context,
	restMux *proxy.ServeMux, restDialOpts []grpc.DialOption,
	restProxyDest string) error {

	// With our custom REST proxy mux created, register our main RPC and
	// give all subservers a chance to register as well.
	err := mboxrpc.RegisterMailboxHandlerFromEndpoint(
		restCtx, restMux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return err
	}

	return nil
}

// Stop closes all connected streams and removes all subscribers. It also
// waits for all goroutines to finish before returning. Only the last error
// encountered while stopping the server is returned.
func (s *Server) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		log.Infof("Stopping authmailbox RPC Server")

		s.ContextGuard.Quit()

		s.WgWait()

		s.connectedStreamsMtx.Lock()
		defer s.connectedStreamsMtx.Unlock()

		for _, stream := range s.connectedStreams {
			stream.abort()
		}

		s.connectedStreams = make(map[uint64]*mailboxStream)

		s.msgEventsSubsMtx.Lock()
		subscribers := maps.Values(s.msgEventsSubs)
		s.msgEventsSubsMtx.Unlock()

		for _, sub := range subscribers {
			err := s.RemoveSubscriber(sub)
			if err != nil {
				log.Error("Unable to remove subscriber: %v",
					err)
				stopErr = err
			}
		}
	})

	return stopErr
}

// SendMessage sends a single message to a receiver's mailbox. Requires a valid,
// unused Bitcoin transaction outpoint as proof of work/stake.
func (s *Server) SendMessage(ctx context.Context,
	req *mboxrpc.SendMessageRequest) (*mboxrpc.SendMessageResponse, error) {

	receiverID, err := btcec.ParsePubKey(req.ReceiverId)
	if err != nil {
		return nil, fmt.Errorf("error parsing receiver ID: %w", err)
	}

	ctx = btclog.WithCtx(
		ctx, btclog.Hex("receiver_id", req.ReceiverId),
		"server", true,
	)
	log.DebugS(ctx, "Received SendMessage message")

	if len(req.EncryptedPayload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	if len(req.EncryptedPayload) > MsgMaxSize {
		return nil, ErrMessageTooLong
	}

	if req.Proof == nil {
		return nil, fmt.Errorf("missing proof")
	}

	msg := &Message{
		EncryptedPayload: req.EncryptedPayload,
		ReceiverKey:      *receiverID,
		ArrivalTimestamp: time.Now(),
	}

	var txProof *proof.TxProof
	switch p := req.Proof.(type) {
	case *mboxrpc.SendMessageRequest_TxProof:
		txProof, err = proof.UnmarshalTxProof(p.TxProof)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling proof: %w",
				err)
		}

		// We now validate the proof.
		err = txProof.Verify(s.cfg.HeaderVerifier, s.cfg.MerkleVerifier)
		if err != nil {
			return nil, fmt.Errorf("error validating proof: %w",
				err)
		}

		// If this proof has already been used, we reject the message.
		// This is the last step of the proof validation.
		existingMsg, err := s.cfg.MsgStore.FetchMessageByOutPoint(
			ctx, txProof.ClaimedOutPoint,
		)
		switch {
		case errors.Is(err, ErrMessageNotFound):
			// This is the expected case, we don't have a message
			// with this outpoint yet, so we can continue below.

		case err != nil:
			return nil, fmt.Errorf("error checking for proof: %w",
				err)

		default:
			// If we already have this proof, we check if it's for
			// the same recipient. If it is, we'll return the
			// message ID, making this call idempotent to simplify
			// the client re-try logic. Because the encryption
			// algorithm will produce a different ciphertext for the
			// same message each time, we cannot compare the actual
			// message itself. So we have to assume that using the
			// same outpoint in the proof for the same recipient
			// means it's also the same message.
			if !existingMsg.ReceiverKey.IsEqual(&msg.ReceiverKey) {
				// It's a different recipient, so someone is
				// attempting to re-use a proof for a different
				// recipient.
				return nil, fmt.Errorf("outpoint in proof "+
					"alread in use: %w",
					proof.ErrTxMerkleProofExists)
			}

			// We have a message with the same outpoint and
			// recipient, so we can return the message ID, so it
			// looks to the client as if we stored the message, even
			// though we have it already.
			return &mboxrpc.SendMessageResponse{
				MessageId: existingMsg.ID,
			}, nil
		}

		msg.ProofBlockHeight = txProof.BlockHeight

	default:
		return nil, fmt.Errorf("unsupported proof type: %T", p)
	}

	// We have verified everything we can, we'll allow the message to be
	// stored now.
	log.TraceS(ctx, "Sending message", "msg", spew.Sdump(msg))
	msgID, err := s.cfg.MsgStore.StoreMessage(ctx, *txProof, msg)
	if err != nil {
		return nil, fmt.Errorf("error storing message: %w", err)
	}

	// Publish the message to all subscribers, meaning it will be
	// distributed to all subscribed streams. Each stream will filter by
	// recipient ID by itself.
	msg.ID = msgID
	s.publishMessage(msg)

	return &mboxrpc.SendMessageResponse{
		MessageId: msgID,
	}, nil
}

// ReceiveMessages initiates a bidirectional stream to receive messages for a
// specific receiver. This stream implements the challenge-response handshake
// required for receiver authentication before messages are delivered.
// Expected flow:
//  1. Client -> Server: ReceiveMessagesRequest(init = InitReceive{...})
//  2. Server -> Client: ReceiveMessagesResponse(challenge = Challenge{...})
//  3. Client -> Server: ReceiveMessagesRequest(auth_sig = AuthSignature{...})
//  4. Server -> Client: [Stream of ReceiveMessagesResponse(
//     message = MailboxMessage{...}
//     )]
//  5. Server -> Client: ReceiveMessagesResponse(eos = EndOfStream{}) or
//     ReceiveMessagesResponse(error = ReceiveError{...})
func (s *Server) ReceiveMessages(grpcStream serverStream) error {
	id := s.nextStreamID.Load()
	_ = s.nextStreamID.Add(1)

	ctxl := btclog.WithCtx(grpcStream.Context(), "sid", id, "server", true)

	stream, err := newMailboxStream(id, s.Done())
	if err != nil {
		return fmt.Errorf("error creating mailbox stream: %w", err)
	}

	s.connectedStreamsMtx.Lock()
	s.connectedStreams[id] = stream
	s.connectedStreamsMtx.Unlock()

	log.DebugS(ctxl, "New ReceiveMessages stream created")

	return s.handleStream(ctxl, grpcStream, stream)
}

// MailboxInfo returns basic server information.
func (s *Server) MailboxInfo(ctx context.Context,
	_ *mboxrpc.MailboxInfoRequest) (*mboxrpc.MailboxInfoResponse, error) {

	log.TraceS(ctx, "Received Info message")

	return &mboxrpc.MailboxInfoResponse{
		ServerTime:   time.Now().Unix(),
		MessageCount: s.cfg.MsgStore.NumMessages(ctx),
	}, nil
}

// handleStream handles the incoming stream from the client. It starts the
// goroutine that reads incoming messages from the client and handles the
// authentication process. It also handles the sending of messages to the
// client and the disconnection of the client when the stream is closed or
// when an error occurs.
func (s *Server) handleStream(ctx context.Context,
	grpcStream serverStream, stream *mailboxStream) error {

	initialAuthTimeout := time.After(s.cfg.AuthTimeout)

	// Start the goroutine that just accepts incoming messages from the
	// client.
	s.WgAdd(1)
	go func() {
		defer s.WgDone()
		s.readIncomingStream(ctx, grpcStream, stream)
	}()

	// The client is now registered and the below loop will run for as long
	// as the connection is alive. Whatever happens to cause the loop to
	// exit, we need to remove the client from the active connection map,
	// as essentially they need to re-establish their connection, and we see
	// them as offline.
	defer func() {
		log.DebugS(ctx, "Removing client connection")

		if err := s.disconnectClient(stream); err != nil {
			log.ErrorS(ctx, "Unable to disconnect/unregister "+
				"client", err)
		}
	}()

	// Handle any client related events and messages in one loop.
	for {
		select {
		// Disconnect clients if they don't complete the auth step
		// before the timeout ends.
		case <-initialAuthTimeout:
			if !stream.isAuthenticated.Load() {
				return fmt.Errorf("no auth received before " +
					"timeout")
			}

		// Authentication was successful, we can now start sending
		// messages to the client.
		case <-stream.authSuccessChan:
			stream.isAuthenticated.Store(true)
			ctx = btclog.WithCtx(ctx, btclog.Hex(
				"receiver_id",
				stream.receiverID.SerializeCompressed(),
			))
			log.DebugS(ctx, "Client successfully authenticated")

			stream.RLock()
			err := s.RegisterSubscriber(
				stream.msgReceiver,
				stream.filter.DeliverExisting(),
				stream.filter,
			)
			stream.RUnlock()
			if err != nil {
				return fmt.Errorf("unable to register "+
					"subscriber: %w", err)
			}

			log.TraceS(ctx, "Client registered as subscriber")

			// Inform the client that auth is complete.
			// This is sent after RegisterSubscriber so
			// that the subscriber is in the map before
			// the client can observe IsSubscribed()=true.
			err = grpcStream.Send(&toClientMsg{
				ResponseType: &respTypeAuthSuccess{
					AuthSuccess: true,
				},
			})
			if err != nil {
				return fmt.Errorf("unable to send "+
					"auth success: %w", err)
			}

		// A new message was received by the server that needs to be
		// forwarded to the client.
		case msgs := <-stream.msgReceiver.NewItemCreated.ChanOut():
			// Ignore any messages that aren't for this stream's
			// receiver.
			msgs = fn.Filter(msgs, func(msg *Message) bool {
				return msg.ReceiverKey.IsEqual(
					&stream.receiverID,
				)
			})

			// If there are no messages for this client, we can skip
			// sending any message.
			if len(msgs) == 0 {
				continue
			}

			rpcMsgs := fn.Map(msgs, MarshalMessage)

			err := grpcStream.Send(&toClientMsg{
				ResponseType: &respTypeMessages{
					Messages: &mboxrpc.MailboxMessages{
						Messages: rpcMsgs,
					},
				},
			})
			if err != nil {
				return fmt.Errorf("unable to send message: %w",
					err)
			}

		// The client is signaling abort or is closing the connection.
		case <-stream.quitConn:
			log.DebugS(ctx, "Client is disconnecting")
			return nil

		// An error happened anywhere in the process, we need to abort
		// the connection.
		case err := <-stream.errChan:
			log.ErrorS(ctx, "Error in client stream: %v", err)

			stream.abort()
			return fmt.Errorf("error reading client=%d stream: %w",
				stream.streamID, err)

		// The server is shutting down.
		case <-s.Done():
			err := grpcStream.Send(&toClientMsg{
				ResponseType: &respTypeEndOfStream{
					Eos: &mboxrpc.EndOfStream{},
				},
			})
			if err != nil {
				log.ErrorS(ctx, "Unable to send shutdown msg: "+
					"%v", err)
			}

			stream.abort()

			return fmt.Errorf("server shutting down")
		}
	}
}

// disconnectClient removes a client from the list of connected clients and
// aborts the communication channel. This is called when the client
// disconnects or when the server is shutting down.
func (s *Server) disconnectClient(stream *mailboxStream) error {
	s.connectedStreamsMtx.Lock()
	defer s.connectedStreamsMtx.Unlock()

	_, ok := s.connectedStreams[stream.streamID]
	if !ok {
		// Already removed (e.g. by slow-subscriber eviction).
		return nil
	}

	delete(s.connectedStreams, stream.streamID)
	stream.abort()

	return s.RemoveSubscriber(stream.msgReceiver)
}

// readIncomingStream reads incoming messages on a bidirectional stream and
// forwards them to the correct channels. For now, only auth messages can be
// sent from the client to the server.
func (s *Server) readIncomingStream(ctx context.Context,
	grpcStream serverStream, stream *mailboxStream) {

	for {
		// We only end up here after each received message. But in case
		// we're shutting down, we don't need to block on reading
		// another one.
		select {
		case <-s.Done():
			return
		default:
		}

		// The client always has to respond in time to our challenge by
		// telling us which receiver ID they're interested in. We read
		// that auth message and validate it.
		msg, err := grpcStream.Recv()
		switch {
		// The default disconnect signal from the client, if the client
		// is shut down.
		case err == io.EOF || fn.IsCanceled(err):
			stream.abort()
			return

		// Any other error we receive is treated as critical and leads
		// to a termination of the stream.
		case err != nil:
			stream.sendErr(fmt.Errorf("error receiving "+
				"from stream: %w", err))
			return
		}

		// The client is only ever expected to send us messages that are
		// related to the authentication handshake. After
		// authentication, only the server sends messages to the
		// client.
		err = handleAuthMessage(
			ctx, s.cfg.Signer, msg, grpcStream, stream,
		)
		if err != nil {
			stream.sendErr(fmt.Errorf("auth error: %w", err))
		}
	}
}

// handleAuthMessage parses an incoming gRPC message and interprets it based
// on the three-way authentication handshake.
func handleAuthMessage(ctx context.Context, signer lndclient.SignerClient,
	rpcMsg *toServerMsg, grpcStream serverStream,
	stream *mailboxStream) error {

	log.DebugS(ctx, "Handling incoming message from client",
		"msg_type", fmt.Sprintf("%T", rpcMsg.RequestType))

	switch msg := rpcMsg.RequestType.(type) {
	// The init message is the first message the client is expected to send
	// to us, to authenticate themselves. This kicks off the three-way
	// authentication handshake.
	case *mboxrpc.ReceiveMessagesRequest_Init:
		init := msg.Init

		// Fail if we're already fully authenticated.
		if stream.isAuthenticated.Load() {
			return fmt.Errorf("already authenticated")
		}

		// Parse their public key to validate the signature.
		receiverID, err := btcec.ParsePubKey(init.ReceiverId)
		if err != nil {
			return fmt.Errorf("error parsing receiver ID: %w", err)
		}

		ctx = btclog.WithCtx(
			ctx, btclog.Hex("receiver_id", init.ReceiverId),
		)
		log.DebugS(ctx, "Received InitReceive message")

		stream.Lock()
		stream.receiverID = *receiverID
		stream.filter = MessageFilter{
			ReceiverKey: *receiverID,
			AfterID:     init.StartMessageIdExclusive,
			StartBlock:  init.StartBlockHeightInclusive,
		}
		if init.StartTimestampExclusive != 0 {
			stream.filter.After = time.Unix(
				init.StartTimestampExclusive, 0,
			)
		}
		stream.Unlock()

		// Send the step 2 message with the challenge to the client.
		challenge := concatAndHash(init.ReceiverId, stream.authNonce[:])
		err = grpcStream.Send(&toClientMsg{
			ResponseType: &respTypeChallenge{
				Challenge: &mboxrpc.Challenge{
					ChallengeHash: challenge[:],
				},
			},
		})
		if err != nil {
			return fmt.Errorf("error sending challenge: %w", err)
		}

	// After the client has received the challenge, they need to send us
	// their signature. This is the final step of the authentication
	// handshake.
	case *mboxrpc.ReceiveMessagesRequest_AuthSig:
		sig := msg.AuthSig
		log.DebugS(ctx, "Received AuthSig message")

		// Fail if we're already fully authenticated.
		if stream.isAuthenticated.Load() {
			return fmt.Errorf("already authenticated")
		}

		stream.RLock()
		var pubKey [33]byte
		copy(pubKey[:], stream.receiverID.SerializeCompressed())
		challenge := concatAndHash(pubKey[:], stream.authNonce[:])
		stream.RUnlock()

		if len(sig.Signature) != schnorr.SignatureSize {
			return fmt.Errorf("invalid signature length: %d",
				len(sig.Signature))
		}

		sigValid, err := signer.VerifyMessage(
			ctx, challenge[:], sig.Signature, pubKey,
			lndclient.VerifySchnorr(),
		)
		if err != nil {
			return fmt.Errorf("unable to verify auth signature: %w",
				err)
		}
		if !sigValid {
			return fmt.Errorf("signature not valid for public "+
				"key %x", pubKey[:])
		}

		// Signal handleStream to complete registration
		// and send AuthSuccess to the client.
		stream.authSuccessChan <- struct{}{}

	default:
		return fmt.Errorf("unknown client message: %v", msg)
	}

	return nil
}

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new status update events.
func (s *Server) RegisterSubscriber(receiver *fn.EventReceiver[[]*Message],
	deliverExisting bool, deliverFrom MessageFilter) error {

	s.msgEventsSubsMtx.Lock()
	defer s.msgEventsSubsMtx.Unlock()

	s.msgEventsSubs[receiver.ID()] = receiver

	ctx := context.Background()
	if deliverExisting {
		messages, err := s.cfg.MsgStore.QueryMessages(ctx, deliverFrom)
		if err != nil {
			return fmt.Errorf("error querying messages: %w", err)
		}

		// We sort the messages by their ID, so that the receiver can
		// process them in the order they were received.
		slices.SortFunc(messages, func(a, b *Message) int {
			return cmp.Compare(a.ID, b.ID)
		})

		select {
		case receiver.NewItemCreated.ChanIn() <- messages:
		case <-s.Done():
			return fmt.Errorf("unable to deliver " +
				"existing messages, server shutting " +
				"down")
		}
	}

	return nil
}

// publishMessage publishes an event to all status event
// subscribers (which in this case are all subscribed clients).
// After publishing, any subscriber whose overflow queue is at
// capacity is evicted to prevent unbounded memory growth.
func (s *Server) publishMessage(msg *Message) {
	s.msgEventsSubsMtx.Lock()

	var slowSubs []uint64
	msgSlice := []*Message{msg}
	for id, sub := range s.msgEventsSubs {
		select {
		case sub.NewItemCreated.ChanIn() <- msgSlice:
		case <-s.Done():
			s.msgEventsSubsMtx.Unlock()
			log.Errorf("Unable to publish status event, " +
				"server shutting down")
			return
		}

		if sub.NewItemCreated.OverflowLen() >=
			maxSubscriberOverflow {

			log.Warnf("Evicting slow subscriber %d: "+
				"overflow queue at capacity", id)
			slowSubs = append(slowSubs, id)
		}
	}

	for _, id := range slowSubs {
		sub, ok := s.msgEventsSubs[id]
		if !ok {
			continue
		}

		sub.Stop()
		delete(s.msgEventsSubs, id)
	}

	s.msgEventsSubsMtx.Unlock()

	// Abort the owning streams outside the subscriber lock
	// so that the handleStream defer (which calls
	// disconnectClient → RemoveSubscriber) can acquire
	// msgEventsSubsMtx without deadlocking.
	if len(slowSubs) > 0 {
		s.abortSlowStreams(slowSubs)
	}
}

// abortSlowStreams finds and disconnects any connected streams
// whose subscriber ID matches one of the evicted IDs. This
// closes quitConn, which unblocks the handleStream select and
// tears down the gRPC stream and its read goroutine.
func (s *Server) abortSlowStreams(subIDs []uint64) {
	s.connectedStreamsMtx.Lock()
	defer s.connectedStreamsMtx.Unlock()

	idSet := fn.NewSet(subIDs...)

	for streamID, stream := range s.connectedStreams {
		if idSet.Contains(stream.msgReceiver.ID()) {
			stream.abort()
			delete(s.connectedStreams, streamID)
		}
	}
}

// RemoveSubscriber removes a subscriber from the set of status event
// subscribers.
func (s *Server) RemoveSubscriber(
	subscriber *fn.EventReceiver[[]*Message]) error {

	s.msgEventsSubsMtx.Lock()
	defer s.msgEventsSubsMtx.Unlock()

	_, ok := s.msgEventsSubs[subscriber.ID()]
	if !ok {
		return fmt.Errorf("status event subscriber with ID %d not "+
			"found", subscriber.ID())
	}

	subscriber.Stop()
	delete(s.msgEventsSubs, subscriber.ID())

	return nil
}

// RemoveMessage removes one or more messages from the mailbox. The caller must
// prove ownership of the receiver key by providing a Schnorr signature over the
// challenge hash SHA256(receiver_id || msg_id_1 || msg_id_2 || ...).
func (s *Server) RemoveMessage(ctx context.Context,
	req *mboxrpc.RemoveMessageRequest) (*mboxrpc.RemoveMessageResponse,
	error) {

	receiverID, err := btcec.ParsePubKey(req.ReceiverId)
	if err != nil {
		return nil, fmt.Errorf("error parsing receiver ID: %w", err)
	}

	ctx = btclog.WithCtx(
		ctx, btclog.Hex("receiver_id", req.ReceiverId),
		"server", true,
	)
	log.DebugS(ctx, "Received RemoveMessage request",
		"num_ids", len(req.MessageIds))

	if len(req.MessageIds) == 0 {
		return &mboxrpc.RemoveMessageResponse{}, nil
	}

	if len(req.MessageIds) > maxRemoveMessageIDs {
		return nil, fmt.Errorf("too many message IDs: %d, max %d",
			len(req.MessageIds), maxRemoveMessageIDs)
	}

	if len(req.Signature) != schnorr.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: %d",
			len(req.Signature))
	}

	// Verify the Schnorr signature over the challenge hash.
	receiverKeyBytes := receiverID.SerializeCompressed()

	var pubKey [33]byte
	copy(pubKey[:], receiverKeyBytes)

	challenge := RemoveMessageChallenge(receiverKeyBytes, req.MessageIds)
	sigValid, err := s.cfg.Signer.VerifyMessage(
		ctx, challenge[:], req.Signature, pubKey,
		lndclient.VerifySchnorr(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to verify signature: %w", err)
	}
	if !sigValid {
		return nil, fmt.Errorf("signature not valid for public "+
			"key %x", receiverKeyBytes)
	}

	// Delete each message, verifying ownership.
	var numRemoved uint64
	for _, msgID := range req.MessageIds {
		deleted, err := s.cfg.MsgStore.DeleteByMessageID(
			ctx, msgID, receiverKeyBytes,
		)
		if err != nil {
			log.WarnS(ctx, "Error deleting message", err,
				"msg_id", msgID)
			continue
		}

		if deleted {
			numRemoved++
		}
	}

	log.DebugS(ctx, "RemoveMessage completed",
		"num_removed", numRemoved,
		"num_requested", len(req.MessageIds))

	return &mboxrpc.RemoveMessageResponse{
		NumRemoved: numRemoved,
	}, nil
}

// concatAndHash writes two byte slices to a sha256 hash and returns the sum.
// The result is SHA256(a || b).
func concatAndHash(a, b []byte) [32]byte {
	var result [32]byte

	// Hash both elements together. The Write function of a hash never
	// returns an error so we can safely ignore the return values.
	h := sha256.New()
	_, _ = h.Write(a)
	_, _ = h.Write(b)
	copy(result[:], h.Sum(nil))
	return result
}

// spentResult holds the result of a single outpoint spend check.
type spentResult struct {
	outpoint wire.OutPoint
	spent    bool
	err      error
}

// cleanupLoop runs periodically and removes outpoints (and their associated
// messages) that have been spent on chain.
func (s *Server) cleanupLoop() {
	interval := cmp.Or(
		s.cfg.CleanupInterval, defaultCleanupInterval,
	)

	cleanupTicker := time.NewTicker(interval)
	defer cleanupTicker.Stop()

	log.Infof("Authmailbox cleanup loop started, interval=%v", interval)

	for {
		select {
		case <-cleanupTicker.C:
			s.cleanupSpentOutpoints()

		case <-s.Done():
			log.Debugf("Authmailbox cleanup loop stopping")
			return
		}
	}
}

// cleanupSpentOutpoints iterates through all claimed outpoints, checks each
// one for on-chain spends concurrently in batches, and deletes spent ones.
func (s *Server) cleanupSpentOutpoints() {
	checkTimeout := cmp.Or(
		s.cfg.CleanupCheckTimeout, defaultCleanupCheckTimeout,
	)

	var (
		totalChecked int
		totalDeleted int
		offset       int32
	)

	for {
		listCtx, listCancel := s.Create(context.Background())
		outpoints, err := s.cfg.MsgStore.ListOutpoints(
			listCtx, cleanupBatchSize, offset,
		)
		listCancel()

		if err != nil {
			log.Errorf("Error listing outpoints for cleanup: %v",
				err)
			return
		}

		if len(outpoints) == 0 {
			break
		}

		// Check all outpoints in this batch concurrently, bounded
		// by a semaphore to avoid overwhelming the chain backend.
		sem := make(chan struct{}, maxConcurrentChecks)
		results := make(chan spentResult, len(outpoints))
		for _, op := range outpoints {
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()

				checkCtx, checkCancel :=
					s.Create(
						context.Background(),
						lfn.WithCustomTimeoutCG(
							checkTimeout,
						),
					)
				defer checkCancel()

				spent, checkErr := s.cfg.OutpointChecker(
					checkCtx, op.OutPoint,
					op.PkScript, op.BlockHeight,
				)
				results <- spentResult{
					outpoint: op.OutPoint,
					spent:    spent,
					err:      checkErr,
				}
			}()
		}

		// Collect results from all concurrent checks.
		batchDeleted := 0
		for range outpoints {
			res := <-results
			if res.err != nil {
				log.Warnf("Error checking outpoint %v: %v",
					res.outpoint, res.err)
				continue
			}

			if !res.spent {
				continue
			}

			delCtx, delCancel := s.Create(
				context.Background(),
				lfn.WithCustomTimeoutCG(checkTimeout),
			)
			err := s.cfg.MsgStore.DeleteByOutpoint(
				delCtx, res.outpoint,
			)
			delCancel()

			if err != nil {
				log.Errorf("Error deleting outpoint %v: %v",
					res.outpoint, err)
				continue
			}

			batchDeleted++
		}

		totalChecked += len(outpoints)
		totalDeleted += batchDeleted

		// When we delete rows, subsequent pages shift. Only advance
		// the offset by the number of rows that were NOT deleted, so
		// we don't skip any.
		offset += int32(len(outpoints)) - int32(batchDeleted)

		// If we got fewer rows than the batch size, we've reached
		// the end.
		if int32(len(outpoints)) < cleanupBatchSize {
			break
		}
	}

	if totalChecked > 0 {
		log.Infof("Authmailbox cleanup: checked %d outpoints, "+
			"deleted %d spent messages", totalChecked,
			totalDeleted)
	}
}
