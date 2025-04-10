package authmailbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverStream = mboxrpc.Mailbox_ReceiveMessagesServer

type Config struct {
	AuthTimeout time.Duration

	Signer lndclient.SignerClient

	HeaderVerifier proof.HeaderVerifier

	MsgStore Store

	TxProofStore proof.TxProofStore
}

type Server struct {
	mboxrpc.UnimplementedMailboxServer

	cfg *Config

	connectedStreamsMtx sync.Mutex

	nextStreamID atomic.Uint64

	connectedStreams map[uint64]*mailboxStream

	// msgEventsSubs is a map of subscribers that want to be notified on
	// new message events, keyed by their stream ID.
	msgEventsSubs map[uint64]*fn.EventReceiver[*Message]

	// msgEventsSubsMtx guards the general message events subscribers map.
	msgEventsSubsMtx sync.Mutex

	*lfn.ContextGuard
}

func NewServer(cfg *Config) *Server {
	return &Server{
		cfg:              cfg,
		connectedStreams: make(map[uint64]*mailboxStream),
		ContextGuard:     lfn.NewContextGuard(),
	}
}

func (s *Server) SendMessage(ctx context.Context,
	req *mboxrpc.SendMessageRequest) (*mboxrpc.SendMessageResponse, error) {

	receiverID, err := btcec.ParsePubKey(req.ReceiverId)
	if err != nil {
		return nil, fmt.Errorf("error parsing receiver ID: %w", err)
	}

	ctx = btclog.WithCtx(ctx, btclog.Hex("receiver_id", req.ReceiverId))
	log.DebugS(ctx, "Received SendMessage message")

	if len(req.EncryptedPayload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	if len(req.EncryptedPayload) > MsgMaxSize {
		return nil, ErrMessageTooLong
	}

	if req.ExpiryBlockHeight == 0 {
		return nil, fmt.Errorf("missing expiry block height")
	}

	if req.Proof == nil {
		return nil, fmt.Errorf("missing proof")
	}

	senderEphemeralKey, err := btcec.ParsePubKey(req.SenderEphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("error parsing sender ephemeral "+
			"public key: %w", err)
	}

	msg := &Message{
		EncryptedPayload:   req.EncryptedPayload,
		ReceiverKey:        *receiverID,
		SenderEphemeralKey: *senderEphemeralKey,
		ArrivalTimestamp:   time.Now(),
	}

	var arrivalBlockHeight uint32
	switch p := req.Proof.(type) {
	case *mboxrpc.SendMessageRequest_TxProof:
		txProof, err := UnmarshalTxProof(p.TxProof)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling proof: %w",
				err)
		}

		// We now validate the proof.
		err = txProof.Verify(
			s.cfg.HeaderVerifier, proof.DefaultMerkleVerifier,
		)
		if err != nil {
			return nil, fmt.Errorf("error validating proof: %w",
				err)
		}

		// If this proof has already been used, we reject the message.
		// This is the last step of the proof validation.
		haveProof, err := s.cfg.TxProofStore.HaveProof(
			txProof.ClaimedOutPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("error checking for proof: %w",
				err)
		}
		if haveProof {
			return nil, proof.ErrTxMerkleProofExists
		}

		// We didn't have the proof before, so we store it now. If at
		// the same time a different goroutine is trying to store the
		// same proof, we expect the database to handle the concurrency.
		err = s.cfg.TxProofStore.StoreProof(txProof.ClaimedOutPoint)
		if err != nil {
			return nil, fmt.Errorf("error storing proof: %w",
				err)
		}

		arrivalBlockHeight = txProof.BlockHeight
	}

	// Now that we know the arrival block height (either from the proof or
	// from our backend), we can validate the expiry block height.
	if req.ExpiryBlockHeight <= arrivalBlockHeight {
		return nil, fmt.Errorf("expiry block height %d is before "+
			"arrival block height %d", req.ExpiryBlockHeight,
			arrivalBlockHeight)
	}

	// We have verified everything we can, we'll allow the message to be
	// stored now.
	err = s.cfg.MsgStore.StoreMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("error storing message: %w", err)
	}

	// Publish the message to all subscribers, meaning it will be
	// distributed to all subscribed streams. Each stream will filter by
	// recipient ID by itself.
	s.publishMessage(msg)

	return &mboxrpc.SendMessageResponse{
		MessageId: msg.ID,
	}, nil
}

func (s *Server) ReceiveMessages(grpcStream serverStream) error {
	id := s.nextStreamID.Load()
	_ = s.nextStreamID.Add(1)

	ctxl := btclog.WithCtx(grpcStream.Context(), "sid", id)

	stream := &mailboxStream{
		streamID: id,
		comm: &commChannel{
			authSuccessful: make(chan struct{}),
			msgReceiver: fn.NewEventReceiver[*Message](
				fn.DefaultQueueSize,
			),
			quit:     s.Done(),
			quitConn: make(chan struct{}),
			err:      make(chan error),
		},
	}

	_, err := rand.Read(stream.authNonce[:])
	if err != nil {
		return fmt.Errorf("error creating nonce: %w", err)
	}

	s.connectedStreamsMtx.Lock()
	s.connectedStreams[id] = stream
	s.connectedStreamsMtx.Unlock()

	log.DebugS(ctxl, "New ReceiveMessages stream created")

	return s.handleStream(ctxl, grpcStream, stream)
}

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
				"client: %v", err)
		}
	}()

	// Handle any client related events and messages in one loop.
	for {
		select {
		// Disconnect clients if they don't complete the auth step
		// before the timeout ends.
		case <-initialAuthTimeout:
			if !stream.isAuthenticated.Load() {
				return fmt.Errorf("no auth received " +
					"before timeout")
			}

		// Authentication was successful, we can now start sending
		// messages to the client.
		case <-stream.comm.authSuccessful:
			ctx = btclog.WithCtx(ctx, btclog.Hex(
				"receiver_id",
				stream.receiverID.SerializeCompressed(),
			))
			log.DebugS(ctx, "Client successfully authenticated")

			stream.RLock()
			err := s.RegisterSubscriber(
				stream.comm.msgReceiver,
				stream.filter.DeliverExisting(), stream.filter,
			)
			stream.RUnlock()
			if err != nil {
				return fmt.Errorf("unable to register "+
					"subscriber: %w", err)
			}

		// A new message was received by the server that needs to be
		// forwarded to the client.
		case msg := <-stream.comm.msgReceiver.NewItemCreated.ChanOut():
			err := s.sendToClient(grpcStream, msg)
			if err != nil {
				return fmt.Errorf("unable to send message: %w",
					err)
			}

		// The client is signaling abort or is closing the connection.
		case <-stream.comm.quitConn:
			log.DebugS(ctx, "Client is disconnecting")
			return nil

		// An error happened anywhere in the process, we need to abort
		// the connection.
		case err := <-stream.comm.err:
			log.ErrorS(ctx, "Error in trader stream: %v", err)

			stream.comm.abort()
			return fmt.Errorf("error reading client=%d stream: %v",
				stream.streamID, err)

		// The server is shutting down.
		case <-s.Done():
			err := grpcStream.Send(&mboxrpc.ReceiveMessagesResponse{
				// nolint: lll
				ResponseType: &mboxrpc.ReceiveMessagesResponse_Eos{
					Eos: &mboxrpc.EndOfStream{},
				},
			})
			if err != nil {
				log.ErrorS(ctx, "Unable to send shutdown msg: "+
					"%v", err)
			}

			stream.comm.abort()

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
		return fmt.Errorf("stream %d not found", stream.streamID)
	}

	delete(s.connectedStreams, stream.streamID)
	stream.comm.abort()

	return s.RemoveSubscriber(stream.comm.msgReceiver)
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
		// The default disconnect signal from the client, if the trader
		// is shut down.
		case err == io.EOF || isCancel(err):
			stream.comm.abort()
			return

		// Any other error we receive is treated as critical and leads
		// to a termination of the stream.
		case err != nil:
			stream.comm.sendErr(fmt.Errorf("error receiving "+
				"from stream: %w", err))
			return
		}

		// Convert the gRPC message into an internal message.
		s.handleIncomingMessage(ctx, msg, grpcStream, stream)
	}
}

// handleIncomingMessage parses the incoming gRPC messages, turns them into
// native structs and forwards them to the correct channel.
func (s *Server) handleIncomingMessage(ctx context.Context,
	rpcMsg *mboxrpc.ReceiveMessagesRequest, grpcStream serverStream,
	stream *mailboxStream) {

	log.DebugS(ctx, "Handling incoming message from client",
		"msg_type", fmt.Sprintf("%T", rpcMsg.RequestType))

	comm := stream.comm
	switch msg := rpcMsg.RequestType.(type) {
	// The init message is the first message the client is expected to send
	// to us, in order to authenticate themselves. This kicks off the
	// three-way authentication handshake.
	case *mboxrpc.ReceiveMessagesRequest_Init:
		init := msg.Init

		// Fail if we're already fully authenticated.
		if stream.isAuthenticated.Load() {
			comm.sendErr(fmt.Errorf("already authenticated"))
			return
		}

		// Parse their public key to validate the signature.
		receiverID, err := btcec.ParsePubKey(init.ReceiverId)
		if err != nil {
			comm.sendErr(fmt.Errorf("error parsing receiver ID: %w",
				err))
			return
		}

		ctx = btclog.WithCtx(
			ctx, btclog.Hex("receiver_id", init.ReceiverId),
		)
		log.DebugS(ctx, "Received InitReceive message")

		stream.Lock()
		stream.receiverID = *receiverID
		stream.filter = MessageFilter{
			ReceiverKey: *receiverID,
			After:       time.Unix(init.StartTimestampExclusive, 0),
			AfterID:     init.StartMessageIdExclusive,
			StartBlock:  init.StartBlockHeightInclusive,
		}
		stream.Unlock()

		// Send the step 2 message with the challenge to the client.
		challenge := concatAndHash(init.ReceiverId, stream.authNonce[:])
		err = grpcStream.Send(&mboxrpc.ReceiveMessagesResponse{
			// nolint: lll
			ResponseType: &mboxrpc.ReceiveMessagesResponse_Challenge{
				Challenge: &mboxrpc.Challenge{
					ChallengeHash: challenge[:],
				},
			},
		})
		if err != nil {
			comm.sendErr(fmt.Errorf("error sending challenge: %w",
				err))
			return
		}

	case *mboxrpc.ReceiveMessagesRequest_AuthSig:
		sig := msg.AuthSig
		log.DebugS(ctx, "Received AuthSig message")

		// Fail if we're already fully authenticated.
		if stream.isAuthenticated.Load() {
			comm.sendErr(fmt.Errorf("already authenticated"))
			return
		}

		stream.RLock()
		var pubKey [33]byte
		copy(pubKey[:], stream.receiverID.SerializeCompressed())
		challenge := concatAndHash(pubKey[:], stream.authNonce[:])
		stream.RUnlock()

		if len(sig.Signature) != schnorr.SignatureSize {
			comm.sendErr(fmt.Errorf("invalid signature length: "+
				"%d", len(sig.Signature)))
			return
		}

		sigValid, err := s.cfg.Signer.VerifyMessage(
			ctx, challenge[:], sig.Signature, pubKey,
			lndclient.VerifySchnorr(),
		)
		if err != nil {
			comm.sendErr(fmt.Errorf("unable to verify auth "+
				"signature: %w", err))
			return
		}
		if !sigValid {
			comm.sendErr(fmt.Errorf("signature not valid for "+
				"public key %x", pubKey[:]))
			return
		}

		// The client is now successfully authenticated.
		comm.authSuccessful <- struct{}{}

	default:
		comm.sendErr(fmt.Errorf("unknown client message: %v", msg))
		return
	}
}

func (s *Server) sendToClient(grpcStream serverStream, msg *Message) error {
	senderKey := msg.SenderEphemeralKey.SerializeCompressed()
	rpcMsg := &mboxrpc.MailboxMessage{
		MessageId:             msg.ID,
		EncryptedPayload:      msg.EncryptedPayload,
		SenderEphemeralPubkey: senderKey,
		ArrivalTimestamp:      msg.ArrivalTimestamp.Unix(),
		ExpiryBlockHeight:     msg.ExpiryBlockHeight,
	}
	return grpcStream.Send(&mboxrpc.ReceiveMessagesResponse{
		ResponseType: &mboxrpc.ReceiveMessagesResponse_Message{
			Message: rpcMsg,
		},
	})
}

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new status update events.
func (s *Server) RegisterSubscriber(receiver *fn.EventReceiver[*Message],
	deliverExisting bool, deliverFrom MessageFilter) error {

	s.msgEventsSubsMtx.Lock()
	defer s.msgEventsSubsMtx.Unlock()

	s.msgEventsSubs[receiver.ID()] = receiver

	if deliverExisting {
		messages, err := s.cfg.MsgStore.QueryMessages(deliverFrom)
		if err != nil {
			return fmt.Errorf("error querying messages: %w", err)
		}

		for _, msg := range messages {
			select {
			case receiver.NewItemCreated.ChanIn() <- msg:
			case <-s.Done():
				return fmt.Errorf("unable to deliver existing " +
					"messages, server shutting down")
			}
		}
	}

	return nil
}

// publishMessage publishes an event to all status events
// subscribers.
func (s *Server) publishMessage(msg *Message) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	s.msgEventsSubsMtx.Lock()
	defer s.msgEventsSubsMtx.Unlock()

	for _, sub := range s.msgEventsSubs {
		select {
		case sub.NewItemCreated.ChanIn() <- msg:
		case <-s.Done():
			log.Errorf("Unable publish status event, server " +
				"shutting down")
		}
	}
}

// RemoveSubscriber removes a subscriber from the set of status event
// subscribers.
func (s *Server) RemoveSubscriber(
	subscriber *fn.EventReceiver[*Message]) error {

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

// isCancel returns true if the given error is either a context canceled error
// directly or its equivalent wrapped as a gRPC error.
func isCancel(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}

	statusErr, ok := status.FromError(err)
	if !ok {
		return false
	}

	return statusErr.Code() == codes.Canceled
}
