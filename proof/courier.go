package proof

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"fmt"

	"github.com/lightninglabs/lightning-node-connect/hashmailrpc"
	"github.com/lightninglabs/taro/address"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Courier abstracts away from the final proof retrival/delivery process as
// part of the non-interactive send flow. A sender can use this given the
// abstracted Addr/source type to send a proof to the receiver. Conversely, a
// receiver can use this to fetch a proof from the sender.
//
// TODO(roasbeef): FileSystemCourier, RpcCourier
type Courier[Addr any] interface {
	// DeliverProof attempts to delivery a proof to the receiver, using the
	// information in the Addr type.
	DeliverProof(context.Context, Addr, *AnnotatedProof) error

	// ReceiveProof attempts to obtain a proof as identified by the passed
	// locator from the source encapsulated within the specified address.
	ReceiveProof(context.Context, Addr, Locator) (*AnnotatedProof, error)
}

// ProofMailbox represents an abstract store-and-forward maillbox that can be
// used to send/receive proofs.
type ProofMailbox interface {
	// Init creates a mailbox given the specified stream ID.
	Init(ctx context.Context, sid streamID) error

	// WriteProof writes the proof to the mailbox specified by the sid.
	WriteProof(ctx context.Context, sid streamID, proof Blob) error

	// ReadProof reads a proof from the mailbox. This is a blocking method.
	ReadProof(ctx context.Context, sid streamID) (Blob, error)

	// AckProof sends an ACK from the receiver to the sender that a proof
	// has been recevied.
	AckProof(ctx context.Context, sid streamID) error

	// RecvAck waits for the sender to receive the ack from the receiver.
	RecvAck(ctx context.Context, sid streamID) error

	// CleanUp atempts to tear down the mailbox as specified by the passed
	// sid.
	CleanUp(ctx context.Context, sid streamID) error
}

// HashMailBox is an implementation of the ProofMailbox interface backed by the
// hashmailrpc.HashMailClient.
type HashMailBox struct {
	client hashmailrpc.HashMailClient
}

// serverDialOpts returns the set of server options needed to connect to the
// server using a TLS connection.
func serverDialOpts() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	creds := credentials.NewTLS(&tls.Config{})
	opts = append(opts, grpc.WithTransportCredentials(creds))

	return opts, nil
}

// NewHashMailBox makes a new mailbox by dialing to the server specified by the
// address above.
func NewHashMailBox(serverAddr string) (*HashMailBox, error) {
	dialOpts, err := serverDialOpts()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(serverAddr, dialOpts...)
	if err != nil {
		return nil, err
	}

	client := hashmailrpc.NewHashMailClient(conn)

	return &HashMailBox{
		client: client,
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
// recevied.
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

// CleanUp atempts to tear down the mailbox as specified by the passed sid.
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

// A compile-time assertion to ensure that the HashMailBox meets the
// ProofMailbox interface.
var _ ProofMailbox = (*HashMailBox)(nil)

// streamID wraps the 64-byte stream ID the mailbox scheme uses.
type streamID [64]byte

// deriveSenderStreamID derives the stream ID for the sender in the asset
// transfer.
func deriveSenderStreamID(addr address.Taro) streamID {
	sid := sha512.Sum512(addr.ScriptKey.SerializeCompressed())

	return sid
}

// deriveReceiverStreamID derives the stream ID for the receiver in the asset
// transfer.
func deriveReceiverStreamID(addr address.Taro) streamID {
	scriptKey := addr.ScriptKey.SerializeCompressed()
	sid := sha512.Sum512(scriptKey)
	sid[63] ^= 0x01

	return sid
}

// HashMailCourier is an implementation of the Courier interfaces that
type HashMailCourier struct {
	mailbox ProofMailbox
}

// NewHashMailCourier implements the Courier interface using the specified
// ProofMailbox. This instance of the Courier relies on the taro address itself
// as the parametrized address type.
func NewHashMailCourier(mailbox ProofMailbox) (*HashMailCourier, error) {
	return &HashMailCourier{
		mailbox: mailbox,
	}, nil
}

// DeliverProof attempts to delivery a proof to the receiver, using the
// information in the Addr type.
//
// TODO(roasbeef): other delivery context as type param?
func (h *HashMailCourier) DeliverProof(ctx context.Context, addr address.Taro,
	proof *AnnotatedProof) error {

	log.Infof("Attempting to deliver receiver proof for send of "+
		"asset_id=%x, amt=%v", addr.ID(), addr.Amount)

	// To deliver the proof to the receiver, we'll use our hashmail box to
	// first create a new session that we'll use to send the proof over.
	// We'll send on this stream, while the receiver receives on it.
	//
	// TODO(roasbeef): should do this as early in the process as possible.
	senderStreamID := deriveSenderStreamID(addr)
	log.Infof("Creating sender mailbox w/ sid=%x", senderStreamID)
	if err := h.mailbox.Init(ctx, senderStreamID); err != nil {
		return err
	}

	// Now that the stream has been initialized, we'll write the proof over
	// the stream.
	//
	// TODO(roasbeef): do ecies here
	log.Infof("Sending receiver proof via sid=%x", senderStreamID)
	err := h.mailbox.WriteProof(ctx, senderStreamID, proof.Blob)
	if err != nil {
		return err
	}

	// With the proof delivered, we'll now wait to receive the ACK from the
	// receiver. To do this, we'll use the receiver's stream ID to listen
	// on the mailbox.
	//
	// TODO(roasbeef): ok that both sides might be on the same side here?
	receiverStreamID := deriveReceiverStreamID(addr)
	log.Infof("Creating receiver mailbox w/ sid=%x", receiverStreamID)
	if err := h.mailbox.Init(ctx, receiverStreamID); err != nil {
		return err
	}

	// We'll wait to receive the ACK from the remote party over their
	// stream.
	log.Infof("Waiting for receiver ACK via sid=%x", receiverStreamID)
	if err := h.mailbox.RecvAck(ctx, receiverStreamID); err != nil {
		return err
	}

	log.Infof("Received ACK from receiver! Cleaning up mailboxes...")

	// Once we receive this ACK, we can clean up our mailbox and also the
	// receiver's mailbox.
	if err := h.mailbox.CleanUp(ctx, senderStreamID); err != nil {
		return err
	}
	return h.mailbox.CleanUp(ctx, receiverStreamID)
}

// ReceiveProof attempts to obtain a proof as identified by the passed locator
// from the source encapsulated within the specified address.
func (h *HashMailCourier) ReceiveProof(ctx context.Context, addr address.Taro,
	loc Locator) (*AnnotatedProof, error) {

	senderStreamID := deriveSenderStreamID(addr)
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
	receiverStreamID := deriveReceiverStreamID(addr)
	log.Infof("Sending ACK to sender via sid=%x", receiverStreamID)
	if err := h.mailbox.Init(ctx, receiverStreamID); err != nil {
		return nil, err
	}
	if err := h.mailbox.AckProof(ctx, receiverStreamID); err != nil {
		return nil, err
	}

	// Finally, we'll return the proof state back to the caller.
	assetID := addr.ID()
	return &AnnotatedProof{
		Locator: Locator{
			AssetID:   &assetID,
			ScriptKey: addr.ScriptKey,
		},
		Blob: Blob(proof),
	}, nil
}

// A compile-time assertion to ensure the HashMailCourier meets the
// proof.Courier interface.
var _ Courier[address.Taro] = (*HashMailCourier)(nil)
