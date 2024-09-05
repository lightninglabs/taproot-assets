package rfqmsg

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestAcceptWireMsgDataVersion is the latest supported quote accept
	// wire message data field version.
	latestAcceptWireMsgDataVersion = V1
)

// AcceptWireMsg is a struct that represents the message data field for a quote
// accept wire message.
type AcceptWireMsg struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID is the unique identifier of the quote request.
	ID tlv.RecordT[tlv.TlvType1, ID]

	// Expiry is the expiry Unix timestamp (in seconds) of the quote
	// request. This timestamp defines the lifetime of both the suggested
	// rate tick and the quote request.
	Expiry tlv.RecordT[tlv.TlvType2, uint64]

	// Sig is a signature over the serialized contents of the message.
	Sig tlv.RecordT[tlv.TlvType3, [64]byte]

	// InAssetPrice represents the accepted price as a fixed point,
	// representing the number of in asset units per BTC. If the in asset is
	// BTC, this represents the number of milli-satoshi per BTC
	// (100_000_000_000).
	InAssetPrice tlv.RecordT[tlv.TlvType4, Uint64FixedPoint]

	// OutAssetPrice represents the accepted price as a fixed point,
	// representing the number of out asset units per BTC. If the out asset
	// is BTC, this represents the number of milli-satoshi per BTC
	// (100_000_000_000).
	OutAssetPrice tlv.RecordT[tlv.TlvType5, Uint64FixedPoint]
}

// newAcceptWireMsgDataFromBuy creates a new AcceptWireMsg from a buy
// accept message.
func newAcceptWireMsgDataFromBuy(q BuyAccept) AcceptWireMsg {
	return AcceptWireMsg{
		Version: tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version),
		ID:      tlv.NewRecordT[tlv.TlvType1](q.ID),
		Expiry: tlv.NewPrimitiveRecord[tlv.TlvType2](
			uint64(q.Price.Expiry.Unix()),
		),
		Sig: tlv.NewPrimitiveRecord[tlv.TlvType3](q.sig),
		InAssetPrice: tlv.NewRecordT[tlv.TlvType4](
			q.Price.InAssetPrice,
		),
		OutAssetPrice: tlv.NewRecordT[tlv.TlvType5](
			q.Price.OutAssetPrice,
		),
	}
}

// newAcceptWireMsgDataFromSell creates a new AcceptWireMsg from a sell
// accept message.
func newAcceptWireMsgDataFromSell(q SellAccept) AcceptWireMsg {
	return AcceptWireMsg{
		Version: tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version),
		ID:      tlv.NewRecordT[tlv.TlvType1](q.ID),
		Expiry: tlv.NewPrimitiveRecord[tlv.TlvType2](
			uint64(q.Price.Expiry.Unix()),
		),
		Sig: tlv.NewPrimitiveRecord[tlv.TlvType3](q.sig),
		InAssetPrice: tlv.NewRecordT[tlv.TlvType4](
			q.Price.InAssetPrice,
		),
		OutAssetPrice: tlv.NewRecordT[tlv.TlvType5](
			q.Price.OutAssetPrice,
		),
	}
}

// Validate ensures that the quote accept message is valid.
func (m *AcceptWireMsg) Validate() error {
	// Ensure the version specified in the version field is supported.
	// We explicitly only accept the latest version here, as this is a
	// breaking change in the way the prices are encoded.
	if m.Version.Val != latestAcceptWireMsgDataVersion {
		return fmt.Errorf("unsupported quote accept message data "+
			"version: %d; consider upgrading to latest version",
			m.Version.Val)
	}

	// Ensure that the expiry is set to a future time.
	if m.Expiry.Val <= uint64(time.Now().Unix()) {
		return fmt.Errorf("expiry must be set to a future time")
	}

	// Ensure that the in asset price is set.
	if m.InAssetPrice.Val.Value.ToUint64() == 0 {
		return fmt.Errorf("in asset price must be specified")
	}

	// Ensure that the out asset price is set.
	if m.OutAssetPrice.Val.Value.ToUint64() == 0 {
		return fmt.Errorf("out asset price must be specified")
	}

	return nil
}

// Encode serializes the AcceptWireMsg to the given io.Writer.
func (m *AcceptWireMsg) Encode(w io.Writer) error {
	// Validate the message before encoding.
	err := m.Validate()
	if err != nil {
		return err
	}

	records := []tlv.Record{
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.Sig.Record(),
		m.InAssetPrice.Record(),
		m.OutAssetPrice.Record(),
	}

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AcceptWireMsg from the given io.Reader.
func (m *AcceptWireMsg) Decode(r io.Reader) error {
	// Create a tlv stream with all the fields.
	tlvStream, err := tlv.NewStream(
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.Sig.Record(),
		m.InAssetPrice.Record(),
		m.OutAssetPrice.Record(),
	)
	if err != nil {
		return err
	}

	// Decode the reader's contents into the tlv stream.
	return tlvStream.DecodeP2P(r)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (m *AcceptWireMsg) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := m.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// String returns a human-readable string representation of the message.
func (m *AcceptWireMsg) String() string {
	return fmt.Sprintf("AcceptWireMsg(id=%x, expiry=%d)", m.ID.Val[:],
		m.Expiry.Val)
}

// NewIncomingAcceptFromWire creates a new quote accept message from an incoming
// wire message.
//
// This is an incoming accept wire message, and we don't yet know what request
// it is in response to. We will need to match it to an outgoing request to
// fully convert it to the correct type.
func NewIncomingAcceptFromWire(wireMsg WireMessage) (*AcceptWireMsg, error) {
	// Ensure that the message type is a quote accept message.
	if wireMsg.MsgType != MsgTypeAccept {
		return nil, ErrUnknownMessageType
	}

	var msgData AcceptWireMsg
	err := msgData.Decode(bytes.NewBuffer(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode incoming quote "+
			"accept message data: %w", err)
	}

	if err := msgData.Validate(); err != nil {
		return nil, fmt.Errorf("unable to validate incoming "+
			"quote accept message: %w", err)
	}

	return &msgData, nil
}
