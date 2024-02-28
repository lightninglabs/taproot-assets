package proof

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lightning-node-connect/hashmailrpc"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// CourierType is an enum that represents the different proof courier services
// protocols that are supported.
type CourierType string

const (
	// DisabledCourier is the default courier type that is used when no
	// courier is specified.
	DisabledCourier CourierType = "disabled_courier"

	// HashmailCourierType is a courier that uses the hashmail protocol to
	// deliver proofs.
	HashmailCourierType = "hashmail"

	// UniverseRpcCourierType is a courier that uses the daemon universe RPC
	// endpoints to deliver proofs.
	UniverseRpcCourierType = "universerpc"
)

// CourierHarness interface is an integration testing harness for a proof
// courier service.
type CourierHarness interface {
	// Start starts the proof courier service.
	Start(chan error) error

	// Stop stops the proof courier service.
	Stop() error
}

// Courier abstracts away from the final proof retrieval/delivery process as
// part of the non-interactive send flow. A sender can use this given the
// abstracted Addr/source type to send a proof to the receiver. Conversely, a
// receiver can use this to fetch a proof from the sender.
type Courier interface {
	// DeliverProof attempts to delivery a proof to the receiver, using the
	// information in the Addr type.
	DeliverProof(context.Context, *AnnotatedProof) error

	// ReceiveProof attempts to obtain a proof as identified by the passed
	// locator from the source encapsulated within the specified address.
	ReceiveProof(context.Context, Locator) (*AnnotatedProof, error)

	// SetSubscribers sets the set of subscribers that will be notified
	// of proof courier related events.
	SetSubscribers(map[uint64]*fn.EventReceiver[fn.Event])

	// Close stops the courier instance.
	Close() error
}

// CourierCfg contains general config parameters applicable to all proof
// couriers.
type CourierCfg struct {
	// HashMailCfg contains hashmail protocol specific config parameters.
	HashMailCfg *HashMailCourierCfg

	// UniverseRpcCfg contains universe RPC protocol specific config
	// parameters.
	UniverseRpcCfg *UniverseRpcCourierCfg

	// TransferLog is a log for recording proof delivery and retrieval
	// attempts.
	TransferLog TransferLog

	// LocalArchive is an archive that can be used to fetch proofs from the
	// local archive.
	LocalArchive Archiver
}

// CourierDispatch is an interface that abstracts away the different proof
// courier services that are supported.
type CourierDispatch interface {
	// NewCourier instantiates a new courier service handle given a service
	// URL address.
	NewCourier(addr *url.URL, recipient Recipient) (Courier, error)
}

// URLDispatch is a proof courier dispatch that uses the courier address URL
// scheme to determine which courier service to use.
type URLDispatch struct {
	cfg *CourierCfg
}

// NewCourierDispatch creates a new proof courier dispatch.
func NewCourierDispatch(cfg *CourierCfg) *URLDispatch {
	return &URLDispatch{
		cfg: cfg,
	}
}

// NewCourier instantiates a new courier service handle given a service URL
// address.
func (u *URLDispatch) NewCourier(addr *url.URL,
	recipient Recipient) (Courier, error) {

	subscribers := make(map[uint64]*fn.EventReceiver[fn.Event])

	// Create new courier addr based on URL scheme.
	switch addr.Scheme {
	case HashmailCourierType:
		cfg := u.cfg.HashMailCfg
		backoffHandler := NewBackoffHandler(
			cfg.BackoffCfg, u.cfg.TransferLog,
		)

		hashMailBox, err := NewHashMailBox(addr)
		if err != nil {
			return nil, fmt.Errorf("unable to make mailbox: %w",
				err)
		}

		return &HashMailCourier{
			cfg:           u.cfg,
			backoffHandle: backoffHandler,
			recipient:     recipient,
			mailbox:       hashMailBox,
			subscribers:   subscribers,
		}, nil

	case UniverseRpcCourierType:
		cfg := u.cfg.UniverseRpcCfg
		backoffHandler := NewBackoffHandler(
			cfg.BackoffCfg, u.cfg.TransferLog,
		)

		// Connect to the universe RPC server.
		dialOpts, err := serverDialOpts()
		if err != nil {
			return nil, err
		}

		serverAddr := fmt.Sprintf("%s:%s", addr.Hostname(), addr.Port())
		conn, err := grpc.Dial(serverAddr, dialOpts...)
		if err != nil {
			return nil, err
		}

		client := unirpc.NewUniverseClient(conn)

		return &UniverseRpcCourier{
			recipient:     recipient,
			client:        client,
			backoffHandle: backoffHandler,
			cfg:           u.cfg,
			subscribers:   subscribers,
			rawConn:       conn,
		}, nil

	default:
		return nil, fmt.Errorf("unknown courier address protocol "+
			"(consider updating tapd): %v", addr.Scheme)
	}
}

// A compile-time assertion to ensure that the URLDispatch meets the
// CourierDispatch interface.
var _ CourierDispatch = (*URLDispatch)(nil)

// ParseCourierAddress attempts to parse the given string as a proof courier
// address, validates that all required fields are present and ensures the
// protocol is one of the supported protocols.
func ParseCourierAddress(addr string) (*url.URL, error) {
	urlAddr, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid proof courier URI address: %w",
			err)
	}

	if err := ValidateCourierAddress(urlAddr); err != nil {
		return nil, err
	}

	return urlAddr, nil
}

// ValidateCourierAddress validates that all required fields are present and
// ensures the protocol is one of the supported protocols.
func ValidateCourierAddress(addr *url.URL) error {
	// We expect the port number to be specified.
	if addr.Port() == "" {
		return fmt.Errorf("proof courier URI address port unspecified")
	}

	switch addr.Scheme {
	case HashmailCourierType, UniverseRpcCourierType:
		// Valid and known courier address protocol.
		return nil

	default:
		return fmt.Errorf("unknown courier address protocol "+
			"(consider updating tapd): %v", addr.Scheme)
	}
}

// ProofMailbox represents an abstract store-and-forward mailbox that can be
// used to send/receive proofs.
type ProofMailbox interface {
	// Init creates a mailbox given the specified stream ID.
	Init(ctx context.Context, sid streamID) error

	// WriteProof writes the proof to the mailbox specified by the sid.
	WriteProof(ctx context.Context, sid streamID, proof Blob) error

	// ReadProof reads a proof from the mailbox. This is a blocking method.
	ReadProof(ctx context.Context, sid streamID) (Blob, error)

	// AckProof sends an ACK from the receiver to the sender that a proof
	// has been received.
	AckProof(ctx context.Context, sid streamID) error

	// RecvAck waits for the sender to receive the ack from the receiver.
	RecvAck(ctx context.Context, sid streamID) error

	// CleanUp attempts to tear down the mailbox as specified by the passed
	// sid.
	CleanUp(ctx context.Context, sid streamID) error

	// Close closes the underlying connection to the hashmail server.
	Close() error
}

// HashMailBox is an implementation of the ProofMailbox interface backed by the
// hashmailrpc.HashMailClient.
type HashMailBox struct {
	rawConn *grpc.ClientConn

	client hashmailrpc.HashMailClient
}

// serverDialOpts returns the set of server options needed to connect to the
// server using a TLS connection.
func serverDialOpts() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	// Skip TLS certificate verification.
	tlsConfig := tls.Config{InsecureSkipVerify: true}
	transportCredentials := credentials.NewTLS(&tlsConfig)
	opts = append(opts, grpc.WithTransportCredentials(transportCredentials))

	return opts, nil
}

// NewHashMailBox makes a new mailbox by dialing to the server specified by the
// address above.
//
// NOTE: The TLS certificate path argument (tlsCertPath) is optional. If unset,
// then the system's TLS trust store is used.
func NewHashMailBox(courierAddr *url.URL) (*HashMailBox,
	error) {

	if courierAddr.Scheme != HashmailCourierType {
		return nil, fmt.Errorf("unsupported courier protocol: %v",
			courierAddr.Scheme)
	}

	dialOpts, err := serverDialOpts()
	if err != nil {
		return nil, err
	}

	serverAddr := fmt.Sprintf(
		"%s:%s", courierAddr.Hostname(), courierAddr.Port(),
	)
	conn, err := grpc.Dial(serverAddr, dialOpts...)
	if err != nil {
		return nil, err
	}

	client := hashmailrpc.NewHashMailClient(conn)

	return &HashMailBox{
		client:  client,
		rawConn: conn,
	}, nil
}

// isErrAlreadyExists returns true if the passed error is the "already exists"
// error within the error wrapped error which is returned by the hash mail
// server when a stream we're attempting to create already exists.
func isErrAlreadyExists(err error) bool {
	statusCode, ok := status.FromError(err)
	if !ok {
		return false
	}

	return statusCode.Code() == codes.AlreadyExists
}

// Init creates a mailbox given the specified stream ID.
func (h *HashMailBox) Init(ctx context.Context, sid streamID) error {
	streamInit := &hashmailrpc.CipherBoxAuth{
		Desc: &hashmailrpc.CipherBoxDesc{
			StreamId: sid[:],
		},
		Auth: &hashmailrpc.CipherBoxAuth_LndAuth{
			LndAuth: &hashmailrpc.LndAuth{},
		},
	}

	_, err := h.client.NewCipherBox(ctx, streamInit)
	if err != nil && !isErrAlreadyExists(err) {
		return err
	}

	return nil
}

// WriteProof writes the proof to the mailbox specified by the sid.
func (h *HashMailBox) WriteProof(ctx context.Context, sid streamID,
	proof Blob) error {

	writeStream, err := h.client.SendStream(ctx)
	if err != nil {
		return fmt.Errorf("unable to create send stream: %w", err)
	}

	err = writeStream.Send(&hashmailrpc.CipherBox{
		Desc: &hashmailrpc.CipherBoxDesc{
			StreamId: sid[:],
		},
		Msg: proof[:],
	})
	if err != nil {
		return err
	}

	return writeStream.CloseSend()
}

// ReadProof reads a proof from the mailbox. This is a blocking method.
func (h *HashMailBox) ReadProof(ctx context.Context,
	sid streamID) (Blob, error) {

	readStream, err := h.client.RecvStream(ctx, &hashmailrpc.CipherBoxDesc{
		StreamId: sid[:],
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create read stream: %w", err)
	}

	msg, err := readStream.Recv()
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): modify ACK based on size of ting?

	return Blob(msg.Msg), nil
}

// ackMsg is the string used to signal that the receiver has received the proof
// sent by the sender.
var ackMsg = []byte("ack")

// AckProof sends an ACK from the receiver to the sender that a proof has been
// received.
func (h *HashMailBox) AckProof(ctx context.Context, sid streamID) error {
	writeStream, err := h.client.SendStream(ctx)
	if err != nil {
		return fmt.Errorf("unable to create send stream: %w", err)
	}

	err = writeStream.Send(&hashmailrpc.CipherBox{
		Desc: &hashmailrpc.CipherBoxDesc{
			StreamId: sid[:],
		},
		Msg: ackMsg,
	})
	if err != nil {
		return err
	}

	return writeStream.CloseSend()
}

// RecvAck waits for the sender to receive the ack from the receiver.
func (h *HashMailBox) RecvAck(ctx context.Context, sid streamID) error {
	readStream, err := h.client.RecvStream(ctx, &hashmailrpc.CipherBoxDesc{
		StreamId: sid[:],
	})
	if err != nil {
		return fmt.Errorf("unable to create read stream: %w", err)
	}

	msg, err := readStream.Recv()
	if err != nil {
		return err
	}

	if bytes.Equal(msg.Msg, ackMsg) {
		return nil
	}

	return fmt.Errorf("expected ack, got %x", msg.Msg)
}

// CleanUp attempts to tear down the mailbox as specified by the passed sid.
func (h *HashMailBox) CleanUp(ctx context.Context, sid streamID) error {
	streamAuth := &hashmailrpc.CipherBoxAuth{
		Desc: &hashmailrpc.CipherBoxDesc{
			StreamId: sid[:],
		},
		Auth: &hashmailrpc.CipherBoxAuth_LndAuth{
			LndAuth: &hashmailrpc.LndAuth{},
		},
	}

	_, err := h.client.DelCipherBox(ctx, streamAuth)
	return err
}

// Close closes the underlying connection to the hashmail server.
func (h *HashMailBox) Close() error {
	return h.rawConn.Close()
}

// A compile-time assertion to ensure that the HashMailBox meets the
// ProofMailbox interface.
var _ ProofMailbox = (*HashMailBox)(nil)

// streamID wraps the 64-byte stream ID the mailbox scheme uses.
type streamID [64]byte

// deriveSenderStreamID derives the stream ID for the sender in the asset
// transfer.
func deriveSenderStreamID(recipient Recipient) streamID {
	sid := sha512.Sum512(recipient.ScriptKey.SerializeCompressed())

	return sid
}

// deriveReceiverStreamID derives the stream ID for the receiver in the asset
// transfer.
func deriveReceiverStreamID(recipient Recipient) streamID {
	sid := deriveSenderStreamID(recipient)
	sid[63] ^= 0x01

	return sid
}

// Recipient describes the recipient of a proof. The script key is enough to
// identify a transferred asset in the context of the proof courier. This is
// because a proof only needs to be delivered via courier if the recipient used
// an address to receive (non-interactive). And each address requires the user
// to derive a fresh and unique script key. The other fields are used for
// logging purposes only.
type Recipient struct {
	// ScriptKey is the main identifier of the recipient. It is used to
	// derive the stream IDs for the mailbox.
	ScriptKey *btcec.PublicKey

	// AssetID is the ID of the asset that is being transferred. This is
	// used for logging purposes only.
	AssetID asset.ID

	// Amount is the amount of the asset that is being transferred. This is
	// used for logging purposes only.
	Amount uint64
}

// BackoffExecError is an error returned when the backoff execution fails.
// This error wraps the underlying error returned by the execution function.
// It allows the porter to determine whether the state machine should be halted
// or not.
type BackoffExecError struct {
	execErr error
}

func (e *BackoffExecError) Error() string {
	if e.execErr == nil {
		return "backoff exec error"
	}
	return fmt.Sprintf("backoff exec error: %s", e.execErr.Error())
}

// BackoffCfg configures the behaviour of the proof delivery backoff procedure.
type BackoffCfg struct {
	// SkipInitDelay is a flag that indicates whether we should skip the
	// initial delay before attempting to deliver the proof to the receiver
	// or receiving from the sender.
	SkipInitDelay bool `long:"skipinitdelay" description:"Skip the initial delay before attempting to deliver the proof to the receiver or receiving from the sender."`

	// BackoffResetWait is the amount of time we'll wait before
	// resetting the backoff counter to its initial state.
	BackoffResetWait time.Duration `long:"backoffresetwait" description:"The amount of time to wait before resetting the backoff counter."`

	// NumTries is the number of times we'll try to deliver the proof to the
	// receiver before the BackoffResetWait delay is enforced.
	NumTries int `long:"numtries" description:"The number of proof delivery attempts before the backoff counter is reset."`

	// InitialBackoff is the initial backoff time we'll use to wait before
	// retrying to deliver the proof to the receiver.
	InitialBackoff time.Duration `long:"initialbackoff" description:"The initial backoff time to wait before retrying to deliver the proof to the receiver."`

	// MaxBackoff is the maximum backoff time we'll use to wait before
	// retrying to deliver the proof to the receiver.
	MaxBackoff time.Duration `long:"maxbackoff" description:"The maximum backoff time to wait before retrying to deliver the proof to the receiver."`
}

// BackoffHandler is a handler for the backoff procedure.
type BackoffHandler struct {
	// cfg contains the backoff configuration parameters.
	cfg *BackoffCfg

	// transferLog is a log for recording proof delivery and retrieval
	// attempts.
	transferLog TransferLog
}

// initialDelay performs an initial delay based on the delivery log to ensure
// that we don't spam the courier service with proof delivery attempts.
func (b *BackoffHandler) initialDelay(ctx context.Context,
	proofLocator Locator, proofTransferType TransferType) error {

	// If the skip initial transfer delay flag is set, we'll skip the
	// initial delay.
	if b.cfg.SkipInitDelay {
		return nil
	}

	locatorHash, err := proofLocator.Hash()
	if err != nil {
		return err
	}
	log.Debugf("Handling initial proof transfer delay (locator_hash=%x)",
		locatorHash[:])

	// Query delivery log to ensure a sensible rate of delivery attempts.
	timestamps, err := b.transferLog.QueryProofTransferLog(
		ctx, proofLocator, proofTransferType,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve proof transfer attempts "+
			"logs: %w", err)
	}

	if len(timestamps) == 0 {
		log.Debugf("No previous transfer attempts found for proof "+
			"(locator_hash=%x)", locatorHash[:])
		return nil
	}

	log.Debugf("Found timestamp(s) relating to previous proof transfer "+
		"attempt. Number of timestamps: %d", len(timestamps))

	// Determine whether the historical receiver proof transfer attempts
	// occurred far enough in the past to warrant a new set of transfer
	// attempts. Otherwise, wait.
	//
	// At this point we know we have a non-zero number of past transfer
	// attempts.
	timeSinceLastAttempt := timeSinceLastTransferAttempt(timestamps)
	backoffResetWait := b.cfg.BackoffResetWait
	if timeSinceLastAttempt < backoffResetWait {
		waitDuration := backoffResetWait - timeSinceLastAttempt
		log.Debugf("Waiting %v before attempting to transfer proof "+
			"(locator_hash=%x) using backoff procedure",
			waitDuration, locatorHash[:])

		err := b.wait(ctx, waitDuration)
		if err != nil {
			return err
		}
	}

	return nil
}

// Exec attempts to execute the given proof transfer function using a repeating
// backoff time delayed strategy. The backoff strategy is used to ensure that we
// don't spam the courier service with proof transfer attempts.
func (b *BackoffHandler) Exec(ctx context.Context, proofLocator Locator,
	transferType TransferType, transferFunc func() error,
	subscriberEvent func(fn.Event)) error {

	if b.cfg == nil {
		return fmt.Errorf("backoff config not specified")
	}

	locatorHash, err := proofLocator.Hash()
	if err != nil {
		return err
	}
	log.Infof("Starting proof transfer backoff procedure for proof "+
		"(transfer_type=%s, locator_hash=%x)", transferType,
		locatorHash[:])

	// Conditionally perform an initial delay based on the transfer log to
	// ensure that we don't spam the courier service with proof transfer
	// attempts.
	err = b.initialDelay(ctx, proofLocator, transferType)
	if err != nil {
		return err
	}

	var (
		backoff    = b.cfg.InitialBackoff
		numTries   = b.cfg.NumTries
		maxBackoff = b.cfg.MaxBackoff

		// Transfer function return error.
		errExec error = nil
	)

	for i := 0; i < numTries; i++ {
		// Before attempting to deliver the proof, log that
		// an attempted delivery is about to occur.
		err = b.transferLog.LogProofTransferAttempt(
			ctx, proofLocator, transferType,
		)
		if err != nil {
			return fmt.Errorf("unable to log proof delivery "+
				"attempt: %w", err)
		}

		// Execute target proof transfer function.
		errExec = transferFunc()
		if errExec == nil {
			// The target function executed successfully, we can
			// exit the loop.
			break
		}
		// Store execution error in case this is the last attempt.
		errExec = fmt.Errorf("error executing backoff procedure: "+
			"%w", &BackoffExecError{execErr: errExec})

		// If the backoff duration is zero, we'll skip the backoff and
		// immediately attempt to execute the target function again.
		if backoff == 0 {
			continue
		}

		// The target delivery function execution failed. Notify
		// subscribers that a backoff wait event is about to commence.
		waitEvent := NewBackoffWaitEvent(
			backoff, int64(i+1), transferType,
		)
		subscriberEvent(waitEvent)

		log.Debugf("Proof delivery failed with error. Backing off. "+
			"(transfer_type=%s, locator_hash=%x, backoff=%s, "+
			"attempt=%d): %v",
			transferType, locatorHash[:], backoff, i, errExec)

		// Wait before reattempting execution.
		err := b.wait(ctx, backoff)
		if err != nil {
			return fmt.Errorf("backoff wait: %w", err)
		}

		// Increase next backoff duration.
		backoff *= 2
		// Cap the backoff at the maximum backoff.
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	if errExec != nil {
		return fmt.Errorf("proof transfer backoff procedure failed; "+
			"count retries attempted: %d; %w", numTries, errExec)
	}

	return nil
}

// wait blocks for a given amount of time.
func (b *BackoffHandler) wait(ctx context.Context, wait time.Duration) error {
	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return fmt.Errorf("context canceled")
	}
}

// NewBackoffHandler creates a new backoff procedure handle.
func NewBackoffHandler(cfg *BackoffCfg,
	deliveryLog TransferLog) *BackoffHandler {

	return &BackoffHandler{
		cfg:         cfg,
		transferLog: deliveryLog,
	}
}

// HashMailCourierCfg is the config for the hashmail proof courier.
type HashMailCourierCfg struct {
	// ReceiverAckTimeout is the maximum time we'll wait for the receiver to
	// acknowledge the proof.
	ReceiverAckTimeout time.Duration `long:"receiveracktimeout" description:"The maximum time to wait for the receiver to acknowledge the proof."`

	// BackoffCfg configures the behaviour of the proof delivery
	// functionality.
	BackoffCfg *BackoffCfg
}

// HashMailCourier is a hashmail proof courier service handle. It implements the
// Courier interface.
type HashMailCourier struct {
	// cfg is the general courier configuration.
	cfg *CourierCfg

	// backoffHandle is a handle to the backoff procedure used in proof
	// delivery.
	backoffHandle *BackoffHandler

	// recipient describes the recipient of the proof.
	recipient Recipient

	mailbox ProofMailbox

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers map[uint64]*fn.EventReceiver[fn.Event]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex
}

// DeliverProof attempts to delivery a proof to the receiver, using the
// information in the Addr type.
//
// TODO(roasbeef): other delivery context as type param?
func (h *HashMailCourier) DeliverProof(ctx context.Context,
	proof *AnnotatedProof) error {

	log.Infof("Attempting to deliver receiver proof for send of "+
		"asset_id=%v, amt=%v", h.recipient.AssetID, h.recipient.Amount)

	// Compute the stream IDs for the sender and receiver.
	senderStreamID := deriveSenderStreamID(h.recipient)
	receiverStreamID := deriveReceiverStreamID(h.recipient)

	// Interact with the hashmail service using a backoff procedure to
	// ensure that we don't overwhelm the service with delivery attempts.
	deliveryExec := func() error {
		err := h.initMailboxes(
			ctx, senderStreamID, receiverStreamID,
		)
		if err != nil {
			return fmt.Errorf("failed to initialize mailboxes: %w",
				err)
		}

		// Now that the stream has been initialized, we'll write
		// the proof over the stream.
		//
		// TODO(roasbeef): do ecies here
		// (this ^ TODO relates to encrypting proofs for the receiver
		// before uploading to the courier)
		log.Infof("Sending receiver proof via sid=%x",
			senderStreamID)
		err = h.mailbox.WriteProof(
			ctx, senderStreamID, proof.Blob,
		)
		if err != nil {
			return fmt.Errorf("failed to send proof to asset "+
				"transfer receiver: %w", err)
		}

		// Wait to receive the ACK from the remote party over
		// their stream.
		log.Infof("Waiting (%v) for receiver ACK via sid=%x",
			h.cfg.HashMailCfg.ReceiverAckTimeout, receiverStreamID)

		ctxTimeout, cancel := context.WithTimeout(
			ctx, h.cfg.HashMailCfg.ReceiverAckTimeout,
		)
		defer cancel()
		err = h.mailbox.RecvAck(ctxTimeout, receiverStreamID)
		if err != nil {
			return fmt.Errorf("failed to receive ACK from "+
				"receiver within timeout: %w", err)
		}

		return nil
	}
	err := h.backoffHandle.Exec(
		ctx, proof.Locator, SendTransferType, deliveryExec,
		h.publishSubscriberEvent,
	)
	if err != nil {
		return fmt.Errorf("proof backoff delivery attempt has "+
			"failed: %w", err)
	}

	log.Infof("Received ACK from receiver! Cleaning up mailboxes...")

	defer h.Close()

	// Once we receive this ACK, we can clean up our mailbox and also the
	// receiver's mailbox.
	if err := h.mailbox.CleanUp(ctx, senderStreamID); err != nil {
		return fmt.Errorf("failed to cleanup sender mailbox: %w", err)
	}
	if err := h.mailbox.CleanUp(ctx, receiverStreamID); err != nil {
		return fmt.Errorf("failed to cleanup receiver mailbox: %w", err)
	}

	return nil
}

// initMailboxes initializes the mailboxes for the sender and receiver.
func (h *HashMailCourier) initMailboxes(ctx context.Context,
	senderStreamID streamID, receiverStreamID streamID) error {

	// To deliver the proof to the receiver, we'll use our hashmail box to
	// create a new session that we'll use to send the proof over.
	// We'll send on this stream, while the receiver receives on it.
	//
	// TODO(roasbeef): should do this as early in the process as possible.
	log.Infof("Creating sender mailbox w/ sid=%x", senderStreamID)
	if err := h.mailbox.Init(ctx, senderStreamID); err != nil {
		return fmt.Errorf("failed to init sender stream mailbox: %w",
			err)
	}

	// We'll listen on the mailbox corresponding to the receiver's stream
	// ID for a proof delivery ACK.
	//
	// TODO(roasbeef): ok that both sides might be on the same side here?
	log.Infof("Creating receiver mailbox w/ sid=%x", receiverStreamID)
	if err := h.mailbox.Init(ctx, receiverStreamID); err != nil {
		return fmt.Errorf("failed to init receiver ACK mailbox: %w",
			err)
	}

	return nil
}

// timeSinceLastTransferAttempt calculates time duration which has elapsed since
// the last proof transfer attempt (either delivery or retrieval).
func timeSinceLastTransferAttempt(timestamps []time.Time) time.Duration {
	// If there are no previous proof transfer attempts, then we'll return
	// early.
	if len(timestamps) == 0 {
		return time.Duration(0)
	}

	// Otherwise we'll select the latest timestamp and compute the surpassed
	// time relative to the current time.

	// Get the latest timestamp without assuming order.
	latestTimestamp := timestamps[0]
	for _, timestamp := range timestamps {
		if timestamp.After(latestTimestamp) {
			latestTimestamp = timestamp
		}
	}

	return time.Since(latestTimestamp)
}

// publishSubscriberEvent publishes an event to all subscribers.
func (h *HashMailCourier) publishSubscriberEvent(event fn.Event) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	h.subscriberMtx.Lock()
	defer h.subscriberMtx.Unlock()

	for _, sub := range h.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// Close closes the underlying connection to the hashmail server.
func (h *HashMailCourier) Close() error {
	if err := h.mailbox.Close(); err != nil {
		log.Warnf("unable to close mailbox session, "+
			"recipient=%v: %v", err, spew.Sdump(h.recipient))
		return err
	}

	return nil
}

// BackoffWaitEvent is an event that is sent to a subscriber each time we
// wait via the Backoff procedure before retrying to deliver a proof to the
// receiver.
type BackoffWaitEvent struct {
	// timestamp is the time the event was created.
	timestamp time.Time

	// Backoff is the current backoff wait duration.
	Backoff time.Duration

	// TriesCounter is the number of tries we've made so far during the
	// course of the current Backoff procedure to deliver the proof to the
	// receiver.
	TriesCounter int64

	// TransferType is the type of proof transfer attempt. The transfer is
	// either a proof delivery to the transfer counterparty or receiving a
	// proof from the transfer counterparty. Note that the transfer
	// counterparty is usually the proof courier service.
	TransferType TransferType
}

// Timestamp returns the timestamp of the event.
func (e *BackoffWaitEvent) Timestamp() time.Time {
	return e.timestamp
}

// NewBackoffWaitEvent creates a new BackoffWaitEvent.
func NewBackoffWaitEvent(
	backoff time.Duration, triesCounter int64,
	transferType TransferType) *BackoffWaitEvent {

	return &BackoffWaitEvent{
		timestamp:    time.Now().UTC(),
		Backoff:      backoff,
		TriesCounter: triesCounter,
		TransferType: transferType,
	}
}

// ReceiveProof attempts to obtain a proof as identified by the passed locator
// from the source encapsulated within the specified address.
func (h *HashMailCourier) ReceiveProof(ctx context.Context,
	loc Locator) (*AnnotatedProof, error) {

	senderStreamID := deriveSenderStreamID(h.recipient)
	if err := h.mailbox.Init(ctx, senderStreamID); err != nil {
		return nil, err
	}

	log.Infof("Attempting to receive proof via sid=%x", senderStreamID)

	// To receiver the proof from the sender, we'll derive the stream ID
	// they'll use to send the proof, and then wait to receive it.
	proof, err := h.mailbox.ReadProof(ctx, senderStreamID)
	if err != nil {
		return nil, err
	}

	// Now that we've read the proof, we'll create our mailbox (which might
	// already exist) to send an ACK back to the sender.
	receiverStreamID := deriveReceiverStreamID(h.recipient)
	log.Infof("Sending ACK to sender via sid=%x", receiverStreamID)
	if err := h.mailbox.Init(ctx, receiverStreamID); err != nil {
		return nil, err
	}
	if err := h.mailbox.AckProof(ctx, receiverStreamID); err != nil {
		return nil, err
	}

	// Finally, we'll return the proof state back to the caller.
	return &AnnotatedProof{
		Locator: loc,
		Blob:    proof,
	}, nil
}

// SetSubscribers sets the subscribers for the courier. This method is
// thread-safe.
func (h *HashMailCourier) SetSubscribers(
	subscribers map[uint64]*fn.EventReceiver[fn.Event]) {

	h.subscriberMtx.Lock()
	defer h.subscriberMtx.Unlock()

	h.subscribers = subscribers
}

// A compile-time assertion to ensure the HashMailCourier meets the
// proof.Courier interface.
var _ Courier = (*HashMailCourier)(nil)

// UniverseRpcCourierCfg is the config for the universe RPC proof courier.
type UniverseRpcCourierCfg struct {
	// BackoffCfg configures the behaviour of the proof delivery
	// functionality.
	BackoffCfg *BackoffCfg
}

// UniverseRpcCourier is a universe RPC proof courier service handle. It
// implements the Courier interface.
type UniverseRpcCourier struct {
	// recipient describes the recipient of the proof.
	recipient Recipient

	// client is the RPC client that the courier will use to interact with
	// the universe RPC server.
	client unirpc.UniverseClient

	// cfg is the general courier configuration.
	cfg *CourierCfg

	// rawConn is the raw connection that the courier will use to interact
	// with the remote gRPC service.
	rawConn *grpc.ClientConn

	// backoffHandle is a handle to the backoff procedure used in proof
	// delivery.
	backoffHandle *BackoffHandler

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers map[uint64]*fn.EventReceiver[fn.Event]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex
}

// DeliverProof attempts to delivery a proof file to the receiver.
func (c *UniverseRpcCourier) DeliverProof(ctx context.Context,
	annotatedProof *AnnotatedProof) error {

	// Decode annotated proof into proof file.
	proofFile := &File{}
	err := proofFile.Decode(bytes.NewReader(annotatedProof.Blob))
	if err != nil {
		return err
	}

	log.Infof("Universe RPC proof courier attempting to deliver proof "+
		"file (num_proofs=%d) for send event (asset_id=%v, amt=%v)",
		proofFile.NumProofs(), c.recipient.AssetID, c.recipient.Amount)

	// Iterate over each proof in the proof file and submit to the courier
	// service.
	for i := 0; i < proofFile.NumProofs(); i++ {
		transitionProof, err := proofFile.ProofAt(uint32(i))
		if err != nil {
			return err
		}
		proofAsset := transitionProof.Asset

		// Construct asset leaf.
		rpcAsset, err := taprpc.MarshalAsset(
			ctx, &proofAsset, true, true, nil,
		)
		if err != nil {
			return err
		}

		var proofBuf bytes.Buffer
		if err := transitionProof.Encode(&proofBuf); err != nil {
			return fmt.Errorf("error encoding proof file: %w", err)
		}

		assetLeaf := unirpc.AssetLeaf{
			Asset: rpcAsset,
			Proof: proofBuf.Bytes(),
		}

		// Construct universe key.
		outPoint := transitionProof.OutPoint()
		assetKey := unirpc.MarshalAssetKey(
			outPoint, proofAsset.ScriptKey.PubKey,
		)
		assetID := proofAsset.ID()

		var (
			groupPubKey      *btcec.PublicKey
			groupPubKeyBytes []byte
		)
		if proofAsset.GroupKey != nil {
			groupPubKey = &proofAsset.GroupKey.GroupPubKey
			groupPubKeyBytes = groupPubKey.SerializeCompressed()
		}

		universeID := unirpc.MarshalUniverseID(
			assetID[:], groupPubKeyBytes,
		)
		universeKey := unirpc.UniverseKey{
			Id:      universeID,
			LeafKey: assetKey,
		}

		// Before attempting to deliver the proof, log that an attempted
		// delivery is about to occur.
		loc := Locator{
			AssetID:   &assetID,
			GroupKey:  groupPubKey,
			ScriptKey: *proofAsset.ScriptKey.PubKey,
			OutPoint:  &outPoint,
		}

		// Setup delivery routine and start backoff procedure.
		deliverFunc := func() error {
			// Submit proof to courier.
			_, err = c.client.InsertProof(ctx, &unirpc.AssetProof{
				Key:       &universeKey,
				AssetLeaf: &assetLeaf,
			})
			if err != nil {
				return fmt.Errorf("error inserting proof "+
					"into universe courier service: %w",
					err)
			}

			return nil
		}
		err = c.backoffHandle.Exec(
			ctx, loc, SendTransferType, deliverFunc,
			c.publishSubscriberEvent,
		)
		if err != nil {
			return fmt.Errorf("proof backoff delivery attempt has "+
				"failed: %w", err)
		}
	}

	return err
}

// ReceiveProof attempts to obtain a proof file from the courier service. The
// final proof in the target proof file is identified by the given locator.
func (c *UniverseRpcCourier) ReceiveProof(ctx context.Context,
	originLocator Locator) (*AnnotatedProof, error) {

	fetchProof := func(ctx context.Context, loc Locator) (Blob, error) {
		var groupKeyBytes []byte
		if loc.GroupKey != nil {
			groupKeyBytes = loc.GroupKey.SerializeCompressed()
		}

		if loc.OutPoint == nil {
			return nil, fmt.Errorf("proof locator for asset %x "+
				"is missing outpoint", loc.AssetID[:])
		}

		universeKey := unirpc.UniverseKey{
			Id: unirpc.MarshalUniverseID(
				loc.AssetID[:], groupKeyBytes,
			),
			LeafKey: unirpc.MarshalAssetKey(
				*loc.OutPoint, &loc.ScriptKey,
			),
		}

		// Setup proof receive/query routine and start backoff
		// procedure.
		var proofBlob []byte
		receiveFunc := func() error {
			// Retrieve proof from courier.
			resp, err := c.client.QueryProof(ctx, &universeKey)
			if err != nil {
				return fmt.Errorf("error retrieving proof "+
					"from universe courier service: %w",
					err)
			}

			proofBlob = resp.AssetLeaf.Proof

			return nil
		}
		err := c.backoffHandle.Exec(
			ctx, loc, ReceiveTransferType, receiveFunc,
			c.publishSubscriberEvent,
		)
		if err != nil {
			return nil, fmt.Errorf("proof backoff receive "+
				"attempt has failed: %w", err)
		}

		return proofBlob, nil
	}

	proofFile, err := FetchProofProvenance(
		ctx, c.cfg.LocalArchive, originLocator, fetchProof,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching proof provenance: %w",
			err)
	}

	// Encode the full proof file.
	var buf bytes.Buffer
	if err := proofFile.Encode(&buf); err != nil {
		return nil, fmt.Errorf("error encoding proof file: %w", err)
	}
	proofFileBlob := buf.Bytes()

	return &AnnotatedProof{
		Locator: originLocator,
		Blob:    proofFileBlob,
	}, nil
}

// SetSubscribers sets the subscribers for the courier. This method is
// thread-safe.
func (c *UniverseRpcCourier) SetSubscribers(
	subscribers map[uint64]*fn.EventReceiver[fn.Event]) {

	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	c.subscribers = subscribers
}

// publishSubscriberEvent publishes an event to all subscribers.
func (c *UniverseRpcCourier) publishSubscriberEvent(event fn.Event) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	for _, sub := range c.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// Close closes the courier's connection to the remote gRPC service.
func (c *UniverseRpcCourier) Close() error {
	return c.rawConn.Close()
}

// A compile-time assertion to ensure the UniverseRpcCourier meets the
// proof.Courier interface.
var _ Courier = (*UniverseRpcCourier)(nil)

// TransferType is the type of proof transfer attempt. The transfer is
// either a proof delivery to the transfer counterparty or receiving a proof
// from the transfer counterparty. Note that the transfer counterparty is
// usually the proof courier service.
type TransferType string

const (
	// SendTransferType signifies that a proof was sent to the transfer
	// counterparty.
	SendTransferType TransferType = "send"

	// ReceiveTransferType signifies that a proof was received from the
	// proof transfer counterparty.
	ReceiveTransferType TransferType = "receive"
)

// TransferLog is an interface that allows the courier to log the attempted
// delivery/receive of a proof.
type TransferLog interface {
	// LogProofTransferAttempt logs a new proof transfer attempt.
	LogProofTransferAttempt(context.Context, Locator, TransferType) error

	// QueryProofTransferLog returns timestamps which correspond to logged
	// proof delivery attempts.
	QueryProofTransferLog(context.Context, Locator,
		TransferType) ([]time.Time, error)
}

// FetchProofProvenance iterates backwards through the main chain of proofs
// until it reaches the genesis point (the asset is the genesis asset) and then
// returns the full proof file with the full provenance for the asset.
func FetchProofProvenance(ctx context.Context, localArchive Archiver,
	originLocator Locator,
	fetchSingleProof func(context.Context, Locator) (Blob, error)) (*File,
	error) {

	// In order to reconstruct the proof file we must collect all the
	// transition proofs that make up the main chain of proofs. That is
	// accomplished by iterating backwards through the main chain of proofs
	// until we reach the genesis point (minting proof). The local archive
	// can be a proof file based archive or a single proof based archive. If
	// we do get a full proof file from the local archive, we do have a
	// shortcut to the full remaining provenance, and we can stop the
	// iterative lookup.

	// We will update the locator at each iteration.
	currentLocator := originLocator

	// reversedProofs is a slice of transition proofs ordered from latest to
	// earliest (the issuance proof comes last in the slice). This ordering
	// is a reversal of that found in the proof file.
	var reversedProofs []Blob
	for {
		// Before we attempt to fetch the proof from the potentially
		// remote universe, we'll check our local archive to see if we
		// already have it. This doesn't make sense in all cases, so we
		// allow the local archive to be nil, in which case we just skip
		// this step. The local universe might give us a single proof or
		// a full file, depending on its type. If we get a full file, we
		// are already done.
		var (
			fullProof Blob
			err       error
		)
		if localArchive != nil {
			fullProof, err = localArchive.FetchProof(
				ctx, currentLocator,
			)
		}

		// If we don't have a local archive, then the IsFile() check
		// returns false, and we skip this block.
		if err == nil && fullProof.IsFile() {
			// The file in the local archive contains the full
			// provenance from the current proof back to the
			// genesis.
			proofFile, err := fullProof.AsFile()
			if err != nil {
				return nil, fmt.Errorf("unable to decode "+
					"proof file: %w", err)
			}

			// So if this is the first proof we've fetched, we're
			// already done.
			if len(reversedProofs) == 0 {
				return proofFile, nil
			}

			// If we have already fetched some proofs, we'll need to
			// append them to the proof file we just fetched.
			for i := len(reversedProofs) - 1; i >= 0; i-- {
				err := proofFile.AppendProofRaw(
					reversedProofs[i],
				)
				if err != nil {
					return nil, fmt.Errorf("error "+
						"appending proof to proof "+
						"file: %w", err)
				}
			}

			return proofFile, nil
		}

		// Setup proof receive/query routine and start backoff
		// procedure.
		proofBlob, err := fetchSingleProof(ctx, currentLocator)
		if err != nil {
			return nil, fmt.Errorf("fetching single proof "+
				"failed: %w", err)
		}

		// Decode just the asset leaf record from the proof.
		var proofAsset asset.Asset
		assetRecord := AssetLeafRecord(&proofAsset)
		err = SparseDecode(bytes.NewReader(proofBlob), assetRecord)
		if err != nil {
			return nil, fmt.Errorf("unable to decode proof: %w",
				err)
		}

		reversedProofs = append(reversedProofs, proofBlob)

		// Break if we've reached the genesis point (the asset is the
		// genesis asset).
		if proofAsset.IsGenesisAsset() {
			break
		}

		// Update locator with principal input to the current outpoint.
		prevID, err := proofAsset.PrimaryPrevID()
		if err != nil {
			return nil, err
		}

		// Parse script key public key.
		scriptKeyPubKey, err := btcec.ParsePubKey(prevID.ScriptKey[:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse script key "+
				"public key from Proof.PrevID: %w", err)
		}

		currentLocator = Locator{
			AssetID:   &prevID.ID,
			GroupKey:  originLocator.GroupKey,
			ScriptKey: *scriptKeyPubKey,
			OutPoint:  &prevID.OutPoint,
		}
	}

	// Append proofs to proof file in reverse order to their collected
	// order.
	proofFile := &File{}
	for i := len(reversedProofs) - 1; i >= 0; i-- {
		err := proofFile.AppendProofRaw(reversedProofs[i])
		if err != nil {
			return nil, fmt.Errorf("error appending proof to "+
				"proof file: %w", err)
		}
	}

	return proofFile, nil
}
