package rfq

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// MaxNumOutputs is the maximum number of asset outputs that are allowed
	// in a single record. This mainly affects the maximum number of asset
	// UTXOs that can reside within a single commitment. This number should
	// in practice be very small (probably close to 1), as all outputs must
	// be from the same asset group but from different tranches to be
	// encoded as an individual record.
	MaxNumOutputs = 2048
)

var (
	// ErrListInvalid is the error that's returned when a list of encoded
	// entries is invalid.
	ErrListInvalid = errors.New("encoded list is invalid")
)

type (
	// HtlcAssetAmountsTlvType is the TLV record type for the asset balance
	// modifications list found in a HTLC custom record set.
	HtlcAssetAmountsTlvType = tlv.TlvType65536

	// HtlcRfqIDTlvType is the TLV record type for the RFQ ID found in an
	// HTLC custom record set.
	HtlcRfqIDTlvType = tlv.TlvType65537
)

// Htlc is a record that represents the capacity change related to an in-flight
// HTLC. This entails all the (asset_id, amount) tuples and other information
// that we may need to be able to update the TAP portion of a commitment
// balance.
type Htlc struct {
	// Amounts is a list of asset balances that are changed by the HTLC.
	Amounts tlv.RecordT[HtlcAssetAmountsTlvType, assetBalanceListRecord]

	// RfqID is the ID of the RFQ quote agreement that this HTLC is
	// associated with.
	RfqID tlv.OptionalRecordT[HtlcRfqIDTlvType, rfqmsg.ID]
}

// NoneHtlcRfqID returns an empty optional record for the HTLC RFQ ID.
func NoneHtlcRfqID() tlv.OptionalRecordT[HtlcRfqIDTlvType, rfqmsg.ID] {
	return tlv.OptionalRecordT[HtlcRfqIDTlvType, rfqmsg.ID]{
		Option: lfn.None[tlv.RecordT[HtlcRfqIDTlvType, rfqmsg.ID]](),
	}
}

// SomeHtlcRfqID returns an option some TLV record for the HTLC RFQ ID.
func SomeHtlcRfqID(
	id rfqmsg.ID) tlv.OptionalRecordT[HtlcRfqIDTlvType, rfqmsg.ID] {

	return tlv.SomeRecordT(
		tlv.NewPrimitiveRecord[HtlcRfqIDTlvType, rfqmsg.ID](id),
	)
}

// NewHtlc creates a new Htlc record with the given funded assets.
func NewHtlc(amounts []*AssetBalance,
	rfqID tlv.OptionalRecordT[HtlcRfqIDTlvType, rfqmsg.ID]) *Htlc {

	return &Htlc{
		Amounts: tlv.NewRecordT[HtlcAssetAmountsTlvType](
			assetBalanceListRecord{
				balances: amounts,
			},
		),
		RfqID: rfqID,
	}
}

// Balances returns the list of asset balances that are updated in the Htlc
// struct.
func (o *Htlc) Balances() []*AssetBalance {
	return o.Amounts.Val.balances
}

// Records returns the records that make up the Htlc.
func (o *Htlc) Records() []tlv.Record {
	records := []tlv.Record{
		o.Amounts.Record(),
	}

	o.RfqID.WhenSome(func(r tlv.RecordT[HtlcRfqIDTlvType, rfqmsg.ID]) {
		records = append(records, r.Record())
	})

	return records
}

// Encode serializes the Htlc to the given io.Writer.
func (o *Htlc) Encode(w io.Writer) error {
	tlvRecords := o.Records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the Htlc from the given io.Reader.
func (o *Htlc) Decode(r io.Reader) error {
	rfqID := o.RfqID.Zero()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(
		o.Amounts.Record(),
		rfqID.Record(),
	)
	if err != nil {
		return err
	}

	typeMap, err := tlvStream.DecodeWithParsedTypesP2P(r)
	if err != nil {
		return err
	}

	if val, ok := typeMap[o.RfqID.TlvType()]; ok && val == nil {
		o.RfqID = tlv.SomeRecordT(rfqID)
	}

	return nil
}

// Bytes returns the serialized Htlc record.
func (o *Htlc) Bytes() []byte {
	var buf bytes.Buffer
	_ = o.Encode(&buf)
	return buf.Bytes()
}

// DecodeHtlc deserializes a Htlc from the given blob.
func DecodeHtlc(blob tlv.Blob) (*Htlc, error) {
	var h Htlc
	err := h.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// AssetBalance is a record that represents the amount of an asset that is
// being transferred or is available to be spent.
type AssetBalance struct {
	// AssetID is the ID of the asset that this output is associated with.
	AssetID tlv.RecordT[tlv.TlvType0, asset.ID]

	// Amount is the amount of the asset that this output represents.
	Amount tlv.RecordT[tlv.TlvType1, uint64]
}

// NewAssetBalance creates a new AssetBalance record with the given asset ID and
// amount.
func NewAssetBalance(assetID asset.ID, amount uint64) *AssetBalance {
	return &AssetBalance{
		AssetID: tlv.NewRecordT[tlv.TlvType0](assetID),
		Amount:  tlv.NewPrimitiveRecord[tlv.TlvType1](amount),
	}
}

// records returns the records that make up the AssetBalance.
func (o *AssetBalance) records() []tlv.Record {
	return []tlv.Record{
		o.AssetID.Record(),
		o.Amount.Record(),
	}
}

// encode serializes the AssetBalance to the given io.Writer.
func (o *AssetBalance) encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// decode deserializes the AssetBalance from the given io.Reader.
func (o *AssetBalance) decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Sum returns the sum of the amounts of all the asset balances in the list.
func Sum(balances []*AssetBalance) uint64 {
	var sum uint64
	for _, balance := range balances {
		sum += balance.Amount.Val
	}
	return sum
}

// assetBalanceListRecord is a record that represents a list of asset balances.
type assetBalanceListRecord struct {
	balances []*AssetBalance
}

// Sum returns the sum of the amounts of all the asset balances in the list.
func (l *assetBalanceListRecord) Sum() uint64 {
	return Sum(l.balances)
}

// Record creates a Record out of a assetBalanceListRecord using the
// eAssetBalanceList and dAssetBalanceList functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *assetBalanceListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetBalanceList(&buf, &l.balances, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.balances, size, eAssetBalanceList, dAssetBalanceList,
	)
}

// Encode serializes the assetBalanceListRecord to the given io.Writer.
func (l *assetBalanceListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the assetBalanceListRecord from the given io.Reader.
func (l *assetBalanceListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eAssetBalanceList is an encoder for assetBalanceListRecord.
func eAssetBalanceList(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetBalance); ok {
		numBalances := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numBalances, buf); err != nil {
			return err
		}
		var outputBuf bytes.Buffer
		for _, balance := range *v {
			if err := balance.encode(&outputBuf); err != nil {
				return err
			}
			balanceBytes := outputBuf.Bytes()
			err := asset.InlineVarBytesEncoder(
				w, &balanceBytes, buf,
			)
			if err != nil {
				return err
			}
			outputBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]*AssetBalance")
}

// dAssetBalanceList is a decoder for assetBalanceListRecord.
func dAssetBalanceList(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]*AssetBalance); ok {
		numBalances, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of balances we accept.
		if numBalances > MaxNumOutputs {
			return fmt.Errorf("%w: too many balances",
				ErrListInvalid)
		}

		if numBalances == 0 {
			return nil
		}

		outputs := make([]*AssetBalance, numBalances)
		for i := uint64(0); i < numBalances; i++ {
			var outputBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &outputBytes, buf, tlv.MaxRecordSize,
			)
			if err != nil {
				return err
			}
			outputs[i] = &AssetBalance{}
			err = outputs[i].decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = outputs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]*AssetBalance")
}
