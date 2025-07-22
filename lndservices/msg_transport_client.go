package lndservices

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// LndMsgTransportClient is an LND RPC message transport client.
type LndMsgTransportClient struct {
	lnd *lndclient.LndServices
}

// NewLndMsgTransportClient creates a new message transport RPC client for a
// given LND service.
func NewLndMsgTransportClient(
	lnd *lndclient.LndServices) *LndMsgTransportClient {

	return &LndMsgTransportClient{
		lnd: lnd,
	}
}

// SubscribeCustomMessages creates a subscription to custom messages received
// from our peers.
func (l *LndMsgTransportClient) SubscribeCustomMessages(
	ctx context.Context) (<-chan lndclient.CustomMessage,
	<-chan error, error) {

	return l.lnd.Client.SubscribeCustomMessages(ctx)
}

// SendCustomMessage sends a custom message to a peer.
func (l *LndMsgTransportClient) SendCustomMessage(ctx context.Context,
	msg lndclient.CustomMessage) error {

	return l.lnd.Client.SendCustomMessage(ctx, msg)
}

// SendMessage sends a message to a remote peer.
func (l *LndMsgTransportClient) SendMessage(ctx context.Context,
	peer btcec.PublicKey, msg lnwire.Message) error {

	var buf bytes.Buffer
	if err := msg.Encode(&buf, 0); err != nil {
		return fmt.Errorf("unable to encode message: %w", err)
	}

	return l.SendCustomMessage(ctx, lndclient.CustomMessage{
		Peer:    route.NewVertex(&peer),
		MsgType: uint32(msg.MsgType()),
		Data:    buf.Bytes(),
	})
}

// ReportError sends a custom message with the error type to a peer.
//
// NOTE: In order for this custom message to be sent over the lnd RPC interface,
// lnd needs to be configured with the `--custom-message=17` flag, which allows
// sending the non-custom error message type.
func (l *LndMsgTransportClient) ReportError(ctx context.Context,
	peer btcec.PublicKey, pid funding.PendingChanID, err error) {

	log.Errorf("Error in funding flow for pending chan ID %x: %v", pid[:],
		err)

	msg := &lnwire.Error{
		ChanID: pid,
		Data:   []byte(err.Error()),
	}

	sendErr := l.SendMessage(ctx, peer, msg)
	if sendErr != nil {
		log.Errorf("Error sending error message to peer %x: %v",
			peer.SerializeCompressed(), sendErr)
	}
}

// Ensure LndMsgTransportClient implements the rfq.PeerMessenger,
// tapchannel.PeerMessenger and tapchannel.ErrorReporter interfaces.
var _ rfq.PeerMessenger = (*LndMsgTransportClient)(nil)
var _ tapchannel.PeerMessenger = (*LndMsgTransportClient)(nil)
var _ tapchannel.ErrorReporter = (*LndMsgTransportClient)(nil)
