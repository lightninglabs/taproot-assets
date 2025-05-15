package authmailbox

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/fn"
)

// mailboxStream represents a single mailbox receiver stream. Each stream
// represents a single authenticated client connected to the mailbox server,
// subscribing to messages for a specific receiver ID.
type mailboxStream struct {
	// streamID is a unique identifier for this mailbox stream.
	streamID uint64

	// receiverID is the ID of the receiver that this stream is associated
	// with. Only messages intended for this receiver will be sent to this
	// stream.
	receiverID btcec.PublicKey

	// filter is the client-specified filter for messages. If any fields on
	// the filter are set, it means the client wishes to receive backlog
	// messages matching the filter. An empty filter means the client only
	// wishes to receive new messages.
	filter MessageFilter

	// isAuthenticated indicates whether the client has successfully
	// authenticated with the mailbox server.
	isAuthenticated atomic.Bool

	// authNonce is a nonce used during the authentication process.
	authNonce [32]byte

	// authSuccessChan is a channel that is closed when the client has
	// successfully authenticated. This is used to signal to the caller
	// that they can start sending messages to the client.
	authSuccessChan chan struct{}

	// msgReceiver is the channel through which messages are sent to the
	// client. This has an underlying concurrent queue that allows
	// multiple messages to be sent to the client without blocking.
	msgReceiver *fn.EventReceiver[*Message]

	// errChan is a channel used to send errors back to the caller. This
	// is used to signal any errors that occur during the operation of the
	// mailbox stream.
	errChan chan error

	// callerQuit is a channel that is closed when the caller wants to
	// terminate the stream. This is used to signal to the mailbox stream
	// that it should stop processing messages and close the connection.
	callerQuit <-chan struct{}

	// quitConn is a channel that is closed when the mailbox stream wants
	// to terminate the connection. This is used to signal to the caller
	// that the connection should be closed.
	quitConn chan struct{}

	// quitConnOnce is a sync.Once that ensures that the quitConn channel
	// is only closed once.
	quitConnOnce sync.Once

	// RWMutex guards all the fields (except for the isAuthenticated, as
	// that is atomic) in this struct.
	sync.RWMutex
}

// newMailboxStream creates a new mailbox stream with the given ID and
// initializes the necessary channels for communication.
func newMailboxStream(id uint64,
	callerQuit <-chan struct{}) (*mailboxStream, error) {

	stream := &mailboxStream{
		streamID:        id,
		authSuccessChan: make(chan struct{}),
		msgReceiver: fn.NewEventReceiver[*Message](
			fn.DefaultQueueSize,
		),
		callerQuit: callerQuit,
		quitConn:   make(chan struct{}),
		errChan:    make(chan error),
	}

	_, err := rand.Read(stream.authNonce[:])
	if err != nil {
		return nil, fmt.Errorf("error creating nonce: %w", err)
	}

	return stream, nil
}

// abort can be called to initiate a shutdown of the mailbox stream between the
// client and server.
func (s *mailboxStream) abort() {
	s.quitConnOnce.Do(func() {
		close(s.quitConn)
	})
}

// sendErr tries to send an error to the error channel but unblocks if the main
// quit channel is closed.
func (s *mailboxStream) sendErr(err error) {
	select {
	case s.errChan <- err:
	case <-s.quitConn:
	}
}
