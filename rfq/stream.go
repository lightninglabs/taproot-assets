package rfq

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
)

// StreamHandlerCfg is a struct that holds the configuration parameters for the
// RFQ peer message stream handler.
type StreamHandlerCfg struct {
	// PeerMessenger is the peer messenger. This component provides the RFQ
	// manager with the ability to send and receive raw peer messages.
	PeerMessenger PeerMessenger

	// IncomingMessages is a channel which is populated with incoming
	// (received) RFQ messages. These messages have been extracted from the
	// raw peer wire messages by the stream handler service.
	IncomingMessages chan<- rfqmsg.IncomingMsg
}

// StreamHandler is a struct that handles incoming and outgoing peer RFQ stream
// messages.
//
// This component subscribes to incoming raw peer messages (custom messages). It
// processes those messages with the aim of extracting relevant request for
// quotes (RFQs).
type StreamHandler struct {
	startOnce sync.Once
	stopOnce  sync.Once

	// cfg holds the configuration parameters for the RFQ peer message
	// stream handler.
	cfg StreamHandlerCfg

	// recvRawMessages is a channel that receives incoming raw peer
	// messages.
	recvRawMessages <-chan lndclient.CustomMessage

	// errRecvRawMessages is a channel that receives errors emanating from
	// the peer raw messages subscription.
	errRecvRawMessages <-chan error

	// outgoingRequests is a map of request IDs to outgoing requests.
	// This map is used to match incoming accept messages to outgoing
	// requests.
	//
	// TODO(ffranr): Periodically remove expired outgoing requests from
	//  this map.
	outgoingRequests lnutils.SyncMap[rfqmsg.ID, rfqmsg.OutgoingMsg]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewStreamHandler creates and starts a new RFQ stream handler.
//
// TODO(ffranr): Pass in a signer so that we can create a signature over output
// message fields.
func NewStreamHandler(ctx context.Context,
	cfg StreamHandlerCfg) (*StreamHandler, error) {

	pPorter := cfg.PeerMessenger
	msgChan, peerMsgErrChan, err := pPorter.SubscribeCustomMessages(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to wire "+
			"messages via peer message porter: %w", err)
	}

	return &StreamHandler{
		cfg: cfg,

		recvRawMessages:    msgChan,
		errRecvRawMessages: peerMsgErrChan,

		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}, nil
}

// handleIncomingWireMessage handles an incoming wire message.
func (h *StreamHandler) handleIncomingWireMessage(
	wireMsg rfqmsg.WireMessage) error {

	// Parse the wire message as an RFQ message. The session cache load
	// function is provided to associate incoming wire messages with their
	// corresponding outgoing requests during parsing.
	msg, err := rfqmsg.NewIncomingMsgFromWire(
		wireMsg, h.outgoingRequests.Load,
	)
	if err != nil {
		if errors.Is(err, rfqmsg.ErrUnknownMessageType) {
			// Silently disregard the message if we don't recognise
			// the message type.
			log.Tracef("Silently disregarding incoming message of "+
				"unknown type (msg_type=%d)", wireMsg.MsgType)
			return nil
		}

		return fmt.Errorf("unable to create incoming message from "+
			"wire message: %w", err)
	}

	log.Debugf("Stream handling incoming message: %s", msg)

	// If the incoming message is a response to an outgoing request, we
	// will remove the corresponding session from the store. We can safely
	// remove the session at this point because we have received the only
	// response we expect for this session.
	switch msg.(type) {
	case *rfqmsg.BuyAccept, *rfqmsg.SellAccept, *rfqmsg.Reject:
		h.outgoingRequests.Delete(msg.MsgID())
		log.Tracef("Deleted outgoing request with ID %s", msg.MsgID())
	}

	// Send the incoming message to the RFQ manager.
	sendSuccess := fn.SendOrQuit(h.cfg.IncomingMessages, msg, h.Quit)
	if !sendSuccess {
		return fmt.Errorf("RFQ stream handler shutting down")
	}

	return nil
}

// HandleOutgoingMessage handles an outgoing RFQ message.
func (h *StreamHandler) HandleOutgoingMessage(
	outgoingMsg rfqmsg.OutgoingMsg) error {

	log.Debugf("Stream handling outgoing message: %s", outgoingMsg)

	// Convert the outgoing message to a lndclient custom message.
	wireMsg, err := outgoingMsg.ToWire()
	if err != nil {
		return fmt.Errorf("unable to create lndclient custom "+
			"message: %w", err)
	}
	lndClientCustomMsg := lndclient.CustomMessage{
		Peer:    wireMsg.Peer,
		MsgType: uint32(wireMsg.MsgType),
		Data:    wireMsg.Data,
	}

	// Send the message to the peer.
	ctx, cancel := h.WithCtxQuitNoTimeout()
	defer cancel()

	// We store the outgoing request in the request map, so we can interpret
	// any response and map it to the original request. We do this before
	// sending the message, because otherwise we could potentially receive
	// the response while we're waiting for the atomic lock to be released,
	// which would lead to us not knowing about the request in the first
	// place, and we couldn't map the response.
	switch msg := outgoingMsg.(type) {
	case *rfqmsg.BuyRequest:
		h.outgoingRequests.Store(msg.ID, msg)
		log.Tracef("Stored outgoing request with ID %s",
			msg.ID.String())

	case *rfqmsg.SellRequest:
		h.outgoingRequests.Store(msg.ID, msg)
		log.Tracef("Stored outgoing request with ID %s",
			msg.ID.String())
	}

	err = h.cfg.PeerMessenger.SendCustomMessage(ctx, lndClientCustomMsg)
	if err != nil {
		return fmt.Errorf("unable to send message to peer: %w",
			err)
	}

	return nil
}

// mainEventLoop executes the main event handling loop.
func (h *StreamHandler) mainEventLoop() {
	log.Debug("Starting stream handler event loop")

	for {
		select {
		case rawMsg, ok := <-h.recvRawMessages:
			if !ok {
				log.Warnf("Raw peer messages channel closed " +
					"unexpectedly")
				return
			}

			// Convert custom message type to wire message type,
			// taking care not to overflow in the down conversion.
			if rawMsg.MsgType > uint32(rfqmsg.MaxMessageType) {
				log.Warnf("Received message with invalid "+
					"type: msg_type=%d", rawMsg.MsgType)
				continue
			}
			msgType := lnwire.MessageType(rawMsg.MsgType)

			// Convert the raw peer message into a wire message.
			// Wire message is a RFQ package type that is used by
			// interfaces throughout the package.
			wireMsg := rfqmsg.WireMessage{
				Peer:    rawMsg.Peer,
				MsgType: msgType,
				Data:    rawMsg.Data,
			}

			err := h.handleIncomingWireMessage(wireMsg)
			if err != nil {
				log.Warnf("Error handling incoming wire "+
					"message: %v", err)
			}

		case errSubCustomMessages := <-h.errRecvRawMessages:
			// Report any error that we receive from the peer
			// message subscription.
			log.Warnf("Error received from stream handler wire "+
				"message channel: %v", errSubCustomMessages)

		case <-h.Quit:
			log.Debug("Received quit signal. Stopping stream " +
				"handler event loop")
			return
		}
	}
}

// Start starts the service.
func (h *StreamHandler) Start() error {
	var startErr error
	h.startOnce.Do(func() {
		log.Info("Starting subsystem: peer message stream handler")

		// Start the main event loop in a separate goroutine.
		h.Wg.Add(1)
		go func() {
			defer h.Wg.Done()
			h.mainEventLoop()
		}()
	})
	return startErr
}

// Stop stops the handler.
func (h *StreamHandler) Stop() error {
	h.stopOnce.Do(func() {
		log.Info("Stopping subsystem: stream handler")

		// Stop the main event loop.
		close(h.Quit)
	})
	return nil
}

// PeerMessenger is an interface that abstracts the peer message transport
// layer.
type PeerMessenger interface {
	// SubscribeCustomMessages creates a subscription to raw messages
	// received from our peers.
	SubscribeCustomMessages(
		ctx context.Context) (<-chan lndclient.CustomMessage,
		<-chan error, error)

	// SendCustomMessage sends a raw message to a peer.
	SendCustomMessage(context.Context, lndclient.CustomMessage) error
}
