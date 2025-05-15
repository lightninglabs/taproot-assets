package authmailbox

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	// reconnectRetries is the number of times we try to reconnect to
	// the mailbox server after a shutdown.
	reconnectRetries = math.MaxInt16
)

// ReceiveSubscription is the interface returned from a client to the caller for
// receiving messages from the server that are intended for a specific receiver.
type ReceiveSubscription interface {
	// IsSubscribed returns true if the subscription is active and the
	// stream to the server is open. This might flip to false if the server
	// connection is lost. As long as the subscription isn't stopped, it
	// will try to reconnect to the server automatically and indefinitely.
	IsSubscribed() bool

	// Messages is the channel that receives messages from the server.
	Messages() <-chan *toClientMsg

	// Stop can be used to terminate the subscription. This will close the
	// stream to the server.
	Stop() error
}

// receiveSubscription holds the receiver subscribed to updates from the
// mailbox. It can also perform the 3-way authentication handshake needed to
// connectAndAuthenticate a client for a message receipt subscription.
type receiveSubscription struct {
	cfg           *ClientConfig
	receiverKey   keychain.KeyDescriptor
	receiveFilter MessageFilter

	client mboxrpc.MailboxClient

	serverStream clientStream
	streamMutex  sync.RWMutex
	streamCancel func()

	authOkChan chan struct{}
	msgChan    chan *toClientMsg
	errChan    chan error
	wg         sync.WaitGroup
	quit       chan struct{}
}

// A compile time assertion to ensure receiveSubscription meets the
// ReceiveSubscription interface.
var _ ReceiveSubscription = (*receiveSubscription)(nil)

// newReceiveSubscription creates a new receive subscription for the
// mailbox client. The subscription is not yet active and must be
// connected/authenticated first.
func newReceiveSubscription(cfg *ClientConfig,
	receiverKey keychain.KeyDescriptor, receiveFilter MessageFilter,
	client mboxrpc.MailboxClient) *receiveSubscription {

	return &receiveSubscription{
		cfg:           cfg,
		receiverKey:   receiverKey,
		receiveFilter: receiveFilter,
		client:        client,

		authOkChan: make(chan struct{}),
		msgChan:    make(chan *toClientMsg),
		errChan:    make(chan error, 1),
		quit:       make(chan struct{}),
	}
}

// connectAndAuthenticate performs the 3-way authentication handshake between
// the mailbox client and the server. This method blocks until the handshake is
// complete or fails which involves 1.5 round trips to the server.
func (s *receiveSubscription) connectAndAuthenticate(ctx context.Context,
	initialBackoff time.Duration) error {

	log.DebugS(ctx, "Establishing initial connection to server")

	err := s.connectServerStream(ctx, initialBackoff, reconnectRetries)
	if err != nil {
		return fmt.Errorf("connecting server stream failed: %w", err)
	}

	// An uninitialized time in Go doesn't mean a Unix timestamp of zero.
	var ts int64
	if !s.receiveFilter.After.IsZero() {
		ts = s.receiveFilter.After.Unix()
	}

	receiverKey := s.receiverKey.PubKey
	init := &mboxrpc.InitReceive{
		ReceiverId:                receiverKey.SerializeCompressed(),
		StartMessageIdExclusive:   s.receiveFilter.AfterID,
		StartBlockHeightInclusive: s.receiveFilter.StartBlock,
		StartTimestampExclusive:   ts,
	}

	// The client starts by sending over its receiver key and potential
	// message backlog parameters.
	err = s.SendToServer(&toServerMsg{
		RequestType: &reqTypeInit{
			Init: init,
		},
	})
	if err != nil {
		return err
	}

	// We can't sign anything if we haven't received the server's challenge
	// yet. So we'll wait for the message or an error to arrive.
	select {
	case <-s.authOkChan:
		log.DebugS(ctx, "Received auth success, subscription is active")

	case err := <-s.errChan:
		return fmt.Errorf("error during authentication, before "+
			"sending subscribe: %v", err)

	case <-ctx.Done():
		return fmt.Errorf("context canceled before challenge was " +
			"received")

	case <-s.quit:
		return ErrAuthCanceled
	}

	return nil
}

// SendToServer sends a mailbox message through the long-lived stream to the
// mailbox server. A message can only be sent as a response to a server message.
// Therefore, the stream must already be open.
func (s *receiveSubscription) SendToServer(msg *toServerMsg) error {
	s.streamMutex.RLock()
	defer s.streamMutex.RUnlock()

	if s.serverStream == nil {
		return fmt.Errorf("cannot send message, stream not open")
	}

	return s.serverStream.Send(msg)
}

// wait blocks for a given amount of time but returns immediately if the client
// is shutting down.
func (s *receiveSubscription) wait(backoff time.Duration) error {
	select {
	case <-time.After(backoff):
		return nil

	case <-s.quit:
		return ErrClientShutdown
	}
}

// Messages returns the channel that receives messages from the server. The
// channel is closed when the subscription is stopped or the server
func (s *receiveSubscription) Messages() <-chan *toClientMsg {
	return s.msgChan
}

// IsSubscribed returns true if at least one account is in an active state and
// the subscription stream to the server was established successfully.
func (s *receiveSubscription) IsSubscribed() bool {
	s.streamMutex.RLock()
	defer s.streamMutex.RUnlock()

	return s.serverStream != nil
}

// connectServerStream opens the initial connection to the server for the stream
// of account updates and handles reconnect trials with incremental backoff.
func (s *receiveSubscription) connectServerStream(ctx context.Context,
	initialBackoff time.Duration, numRetries int) error {

	var (
		backoff = initialBackoff
		err     error
	)
	for i := 0; i < numRetries; i++ {
		// Wait before connecting in case this is a re-connect trial.
		if backoff != 0 {
			err = s.wait(backoff)
			if err != nil {
				return err
			}
		}

		// Try connecting by querying a "cheap" RPC that the server can
		// answer from memory only.
		_, err = s.client.Ping(ctx, &mboxrpc.PingRequest{})
		if err == nil {
			log.DebugS(ctx, "Connected successfully to server",
				"num_tries", i+1)
			break
		}

		// Connect wasn't successful, cancel the context and increase
		// the time we'll wait until the next try.
		backoff *= 2
		if backoff == 0 {
			backoff = s.cfg.MinBackoff
		}
		if backoff > s.cfg.MaxBackoff {
			backoff = s.cfg.MaxBackoff
		}
		log.DebugS(ctx, "Connect failed with error, canceling and "+
			"backing off", "backoff", backoff, "err", err)

		if i < numRetries-1 {
			log.InfoS(ctx, "Connection to server failed, will try "+
				"again", "backoff", backoff)
		}
	}
	if err != nil {
		log.ErrorS(ctx, "Connection to server failed", err,
			"num_tries", numRetries)
		return err
	}

	ctxc, cancel := context.WithCancel(ctx)

	// We're now going to open the long-lived stream to the server.
	s.streamMutex.Lock()
	s.streamCancel = cancel
	s.serverStream, err = s.client.ReceiveMessages(ctxc)
	s.streamMutex.Unlock()

	if err != nil {
		log.ErrorS(ctx, "Subscribing to message receipt failed", err)
		return err
	}

	// Read incoming messages and send them to the channel where the caller
	// is listening to.
	log.InfoS(ctx, "Successfully connected to mailbox server")
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// We need to pass in the main/root context here, because we
		// need that to re-establish the connection. If we need access
		// to the per-stream (cancellable) context, we can use the
		// s.serverStream.Context() method.
		s.readIncomingStream(ctx)
	}()

	return nil
}

// readIncomingStream reads incoming messages on a server update stream.
// Messages read from the stream are placed in the FromServerChan channel.
//
// NOTE: This method must be called as a subroutine because it blocks as long as
// the stream is open.
func (s *receiveSubscription) readIncomingStream(ctx context.Context) {
	for {
		// Cancel the stream on client shutdown.
		select {
		case <-s.quit:
			return

		default:
		}

		s.streamMutex.RLock()
		ss := s.serverStream
		s.streamMutex.RUnlock()

		// This should never happen as we always close the quit channel
		// before we set the connection to nil (which _should_ cause us
		// to return in the first place), but just to be safe and avoid
		// a panic.
		if ss == nil {
			return
		}

		// Read next message from server.
		msg, err := ss.Recv()
		log.TraceS(ctx, "Received message from server",
			"msg", taprpc.PrintMsg(msg), "err", err)

		switch {
		// EOF is the "normal" close signal, meaning the server has
		// cut its side of the connection. We will only get this during
		// the proper shutdown of the server where we already have a
		// re-connect scheduled. On an improper shutdown, we'll get an
		// error, which usually is "transport is closing".
		case err == io.EOF:
			select {
			case s.errChan <- ErrServerShutdown:
			case <-s.quit:
			}
			return

		// Any other error is likely on a connection level and leaves
		// us no choice but to abort.
		case err != nil:
			// Context canceled is the error that signals we closed
			// the stream, most likely because the trader is
			// shutting down.
			if fn.IsCanceled(err) {
				return
			}

			log.ErrorS(ctx, "Server connection error", err)

			// For any other error type, we'll attempt to trigger
			// the re-connect logic so we'll always try to connect
			// to the server in the background.
			select {
			case s.errChan <- ErrServerErrored:
			case <-s.quit:
			}
			return
		}

		// We only handle three kinds of messages here, those related to
		// the initial challenge, to the account recovery and the
		// shutdown. Everything else is passed into the channel to be
		// handled by a manager.
		switch t := msg.ResponseType.(type) {
		// The server sends us the challenge that we need to complete
		// the 3-way handshake.
		case *respTypeChallenge:
			// Try to find the subscription this message is for so
			// we can send it over the correct chan.
			var challengeHash [32]byte
			copy(challengeHash[:], t.Challenge.ChallengeHash)

			// Next, sign the challenge to authenticate ourselves.
			sig, err := s.cfg.Signer.SignMessage(
				ctx, challengeHash[:], s.receiverKey.KeyLocator,
			)
			if err != nil {
				select {
				case s.errChan <- err:
				case <-s.quit:
				}
			}

			err = s.SendToServer(&toServerMsg{
				RequestType: &reqTypeAuthSig{
					AuthSig: &mboxrpc.AuthSignature{
						Signature: sig,
					},
				},
			})
			if err != nil {
				select {
				case s.errChan <- err:
				case <-s.quit:
				}
			}

		// The server confirms the account subscription. Nothing for us
		// to do here.
		case *respTypeAuthSuccess:
			// Inform the subscription about the arrived auth
			// confirmation.
			select {
			case s.authOkChan <- struct{}{}:
			case <-s.quit:
			}

		case *respTypeEndOfStream:
			err := s.HandleServerShutdown(ctx, nil)
			if err != nil {
				select {
				case s.errChan <- err:
				case <-s.quit:
				}
			}
			return

		// A valid message from the server. Forward it to the handler.
		default:
			// Inform the subscription about the arrived message.
			select {
			case s.msgChan <- msg:
			case <-s.quit:
			}
		}
	}
}

// HandleServerShutdown handles the signal from the server that it is going to
// shut down. In that case, we try to reconnect a number of times with an
// incremental backoff time we wait between trials. If the connection succeeds,
// all previous subscriptions are sent again.
func (s *receiveSubscription) HandleServerShutdown(ctx context.Context,
	err error) error {

	if err == nil {
		log.InfoS(ctx, "Server is shutting down, will reconnect",
			"backoff", s.cfg.MinBackoff)
	} else {
		log.ErrorS(ctx, "Error in stream, trying to reconnect", err)
	}

	err = s.closeStream(ctx)
	if err != nil {
		log.ErrorS(ctx, "Error closing stream connection", err)
	}

	return s.connectAndAuthenticate(ctx, s.cfg.MinBackoff)
}

// closeStream closes the long-lived stream connection to the server.
func (s *receiveSubscription) closeStream(ctx context.Context) error {
	s.streamMutex.Lock()
	defer s.streamMutex.Unlock()

	if s.serverStream == nil {
		return nil
	}

	log.DebugS(ctx, "Closing server stream")
	err := s.serverStream.CloseSend()
	s.streamCancel()
	s.serverStream = nil

	return err
}

// Stop shuts down the client stream and closes the quit and message channels.
func (s *receiveSubscription) Stop() error {
	ctxl := btclog.WithCtx(context.Background(), "stop", true)
	err := s.closeStream(ctxl)

	// Close this subscription's quit channel to signal to the goroutine
	// that it should stop.
	close(s.quit)
	close(s.msgChan)

	s.wg.Wait()

	return err
}
