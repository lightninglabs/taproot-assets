package authmailbox

import (
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/fn"
)

type mailboxStream struct {
	streamID uint64

	receiverID btcec.PublicKey

	isAuthenticated atomic.Bool

	authNonce [32]byte

	filter MessageFilter

	comm *commChannel

	// RWMutex guards all the fields (except for the isAuthenticated, as
	// that is atomic) in this struct.
	sync.RWMutex
}

type commChannel struct {
	authSuccessful chan struct{}
	msgReceiver    *fn.EventReceiver[*Message]

	quit <-chan struct{}

	abortOnce sync.Once
	quitConn  chan struct{}

	err chan error
}

// abort can be called to initiate a shutdown of the communication channel
// between the client and server.
func (c *commChannel) abort() {
	c.abortOnce.Do(func() {
		close(c.quitConn)
	})
}

// sendErr tries to send an error to the error channel but unblocks if the main
// quit channel is closed.
func (c *commChannel) sendErr(err error) {
	select {
	case c.err <- err:
	case <-c.quit:
	}
}
