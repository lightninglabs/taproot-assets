package authmailbox

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/proof"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/tor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	// ErrServerShutdown is the error returned if the mailbox server signals
	// it's going to shut down.
	ErrServerShutdown = errors.New("server shutting down")

	// ErrServerInternal is the error returned if the mailbox server sends
	// back an error instead of a proper message.
	ErrServerInternal = errors.New("server sent unexpected error")

	// ErrClientShutdown is the error returned if the mailbox client itself
	// is shutting down.
	ErrClientShutdown = errors.New("client shutting down")

	// ErrAuthCanceled is returned if the authentication process of a single
	// mailbox subscription is aborted.
	ErrAuthCanceled = errors.New("authentication was canceled")
)

// ClientConfig holds the configuration options for the mailbox client.
type ClientConfig struct {
	// ServerAddress is the domain:port of the mailbox server.
	ServerAddress string

	// ProxyAddress is the SOCKS proxy that should be used to establish the
	// connection.
	ProxyAddress string

	// Insecure signals that no TLS should be used if set to true.
	Insecure bool

	// SkipTlsVerify signals that the TLS certificate of the mailbox server
	// should not be verified. This is only needed if the server uses a
	// self-signed certificate.
	SkipTlsVerify bool

	// TLSPathServer is the path to a local file that holds the mailbox
	// server's TLS certificate. This is only needed if the server is using
	// a self-signed cert.
	TLSPathServer string

	// DialOpts is a list of additional options that should be used when
	// dialing the gRPC connection.
	DialOpts []grpc.DialOption

	// Signer is the signing interface used to sign messages during the
	// authentication handshake with the mailbox server.
	Signer lndclient.SignerClient

	// MinBackoff is the minimum time waited before the next re-connect
	// attempt is made. After each try the backoff is doubled until
	// MaxBackoff is reached.
	MinBackoff time.Duration

	// MaxBackoff is the maximum time waited between connection attempts.
	MaxBackoff time.Duration
}

// Client performs the client side part of mailbox message exchange.
type Client struct {
	cfg *ClientConfig

	startOnce sync.Once
	stopped   atomic.Bool
	stopOnce  sync.Once

	serverConn *grpc.ClientConn
	client     mboxrpc.MailboxClient
}

// NewClient returns a new instance to initiate mailbox connections with.
func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		cfg: cfg,
	}
}

// Start starts the client, establishing the connection to the server.
func (c *Client) Start() error {
	var startErr error
	c.startOnce.Do(func() {
		dialOpts, err := getServerDialOpts(
			c.cfg.Insecure, c.cfg.SkipTlsVerify, c.cfg.ProxyAddress,
			c.cfg.TLSPathServer, c.cfg.DialOpts...,
		)
		if err != nil {
			startErr = err
			return
		}

		serverConn, err := grpc.NewClient(
			c.cfg.ServerAddress, dialOpts...,
		)
		if err != nil {
			startErr = fmt.Errorf("unable to connect to RPC "+
				"server: %w", err)
			return
		}

		c.serverConn = serverConn
		c.client = mboxrpc.NewMailboxClient(serverConn)
	})

	return startErr
}

// Stop shuts down the client connection to the mailbox server.
func (c *Client) Stop() error {
	var stopErr error
	c.stopOnce.Do(func() {
		c.stopped.Store(true)

		log.Infof("Shutting down mailbox client")

		stopErr = c.serverConn.Close()
	})

	return stopErr
}

// SendMessage sends a message to the mailbox server. The receiverKey is the
// public key of the receiver, senderEphemeralKey is the ephemeral key used
// to encrypt the message, encryptedPayload is the encrypted message payload
// and txProof is the proof of the transaction that contains the message.
func (c *Client) SendMessage(ctx context.Context, receiverKey btcec.PublicKey,
	encryptedPayload []byte, txProof proof.TxProof,
	expiryBlockHeight uint32) (uint64, error) {

	if c.stopped.Load() {
		return 0, ErrClientShutdown
	}

	rpcProof, err := proof.MarshalTxProof(txProof)
	if err != nil {
		return 0, fmt.Errorf("unable to marshal tx proof: %w", err)
	}

	resp, err := c.client.SendMessage(ctx, &mboxrpc.SendMessageRequest{
		ReceiverId:       receiverKey.SerializeCompressed(),
		EncryptedPayload: encryptedPayload,
		Proof: &mboxrpc.SendMessageRequest_TxProof{
			TxProof: rpcProof,
		},
		ExpiryBlockHeight: expiryBlockHeight,
	})
	if err != nil {
		return 0, fmt.Errorf("unable to send message: %w", err)
	}

	return resp.MessageId, nil
}

// StartAccountSubscription opens a stream to the server and subscribes to all
// updates that concern the given account, including all orders that spend from
// that account. Only a single stream is ever open to the server, so a second
// call to this method will send a second subscription over the same stream,
// multiplexing all messages into the same connection. A stream can be
// long-lived, so this can be called for every account as soon as it's confirmed
// open. This method will return as soon as the authentication was successful.
// Messages sent from the server can then be received on the FromServerChan
// channel.
func (c *Client) StartAccountSubscription(ctx context.Context,
	msgChan chan<- *ReceivedMessages, receiverKey keychain.KeyDescriptor,
	filter MessageFilter) (ReceiveSubscription, error) {

	if c.stopped.Load() {
		return nil, ErrClientShutdown
	}

	ctxl := btclog.WithCtx(
		ctx, lnutils.LogPubKey("receiver_key", receiverKey.PubKey),
		"server", false,
	)

	return c.connectAndAuthenticate(ctxl, msgChan, receiverKey, filter)
}

// connectAndAuthenticate opens a stream to the server and authenticates the
// account to receive updates.
func (c *Client) connectAndAuthenticate(ctx context.Context,
	msgChan chan<- *ReceivedMessages, acctKey keychain.KeyDescriptor,
	filter MessageFilter) (*receiveSubscription, error) {

	var receiverKey [33]byte
	copy(receiverKey[:], acctKey.PubKey.SerializeCompressed())

	// Before we can expect to receive any updates, we need to perform the
	// 3-way authentication handshake.
	sub := newReceiveSubscription(c.cfg, msgChan, acctKey, filter, c.client)
	err := sub.connectAndAuthenticate(ctx, 0)
	if err != nil {
		log.ErrorS(ctx, "Authentication failed", err)

		return nil, err
	}

	return sub, nil
}

// getServerDialOpts returns the dial options to connect to the mailbox server.
func getServerDialOpts(insecure, skipTlsVerify bool, proxyAddress,
	tlsPath string, dialOpts ...grpc.DialOption) ([]grpc.DialOption,
	error) {

	// Create a copy of the dial options array.
	opts := dialOpts

	// There are four options to connect to a mailbox server, either
	// completely skipping TLS verification, using an insecure (h2c)
	// transport, using a self-signed certificate or with a certificate
	// signed by a public CA.
	switch {
	case skipTlsVerify:
		opts = append(opts, grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true,
			}),
		))

	case insecure:
		opts = append(opts, grpc.WithInsecure())

	case tlsPath != "":
		// Load the specified TLS certificate and build
		// transport credentials
		creds, err := credentials.NewClientTLSFromFile(tlsPath, "")
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))

	default:
		creds := credentials.NewTLS(&tls.Config{})
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	// If a SOCKS proxy address was specified,
	// then we should dial through it.
	if proxyAddress != "" {
		log.Infof("Proxying connection to mailbox server over Tor "+
			"SOCKS proxy %v", proxyAddress)

		torDialer := func(_ context.Context, addr string) (net.Conn,
			error) {

			return tor.Dial(
				addr, proxyAddress, false, false,
				tor.DefaultConnTimeout,
			)
		}
		opts = append(opts, grpc.WithContextDialer(torDialer))
	}

	return opts, nil
}
