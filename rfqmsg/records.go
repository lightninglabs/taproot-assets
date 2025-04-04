package rfqmsg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/lnwire"
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
	// HtlcAmountRecordType is a type alias for the TLV type that is used to
	// encode an asset ID and amount list within the custom records of an
	// HTLC record on the wire.
	HtlcAmountRecordType = tlv.TlvType65536

	// HtlcRfqIDType is the type alias for the TLV type that is used to
	// encode an RFQ id within the custom records of an HTLC record on the
	// wire.
	HtlcRfqIDType = tlv.TlvType65538
)

// SomeRfqIDRecord creates an optional record that represents an RFQ ID.
func SomeRfqIDRecord(id ID) tlv.OptionalRecordT[HtlcRfqIDType, ID] {
	return tlv.SomeRecordT(tlv.NewPrimitiveRecord[HtlcRfqIDType, ID](id))
}

// Htlc is a record that represents the capacity change related to an in-flight
// HTLC. This entails all the (asset_id, amount) tuples and other information
// that we may need to be able to update the TAP portion of a commitment
// balance.
type Htlc struct {
	// Amounts is a list of asset balances that are changed by the HTLC.
	Amounts tlv.RecordT[HtlcAmountRecordType, AssetBalanceListRecord]

	// RfqID is the RFQ ID that corresponds to the HTLC.
	RfqID tlv.OptionalRecordT[HtlcRfqIDType, ID]
}

// NewHtlc creates a new Htlc record with the given funded assets.
func NewHtlc(amounts []*AssetBalance, rfqID fn.Option[ID]) *Htlc {
	htlc := &Htlc{
		Amounts: tlv.NewRecordT[HtlcAmountRecordType](
			AssetBalanceListRecord{
				Balances: amounts,
			},
		),
	}
	rfqID.WhenSome(func(id ID) {
		htlc.RfqID = SomeRfqIDRecord(id)
	})

	return htlc
}

// Balances returns the list of asset Balances that are updated in the Htlc
// struct.
func (h *Htlc) Balances() []*AssetBalance {
	return h.Amounts.Val.Balances
}

// SpecifierChecker checks whether the passed specifier and asset ID match. If
// the specifier contains a group key, it will check whether the asset belongs
// to that group.
type SpecifierChecker func(ctx context.Context, specifier asset.Specifier,
	id asset.ID) (bool, error)

// SumAssetBalance returns the sum of the asset balances for the given asset.
func (h *Htlc) SumAssetBalance(ctx context.Context,
	assetSpecifier asset.Specifier,
	specifierChecker SpecifierChecker) (rfqmath.BigInt,
	error) {

	balanceTotal := rfqmath.NewBigIntFromUint64(0)

	if specifierChecker == nil {
		return balanceTotal, fmt.Errorf("checker is nil")
	}

	for idx := range h.Amounts.Val.Balances {
		balance := h.Amounts.Val.Balances[idx]

		match, err := specifierChecker(
			ctx, assetSpecifier, balance.AssetID.Val,
		)
		if err != nil {
			return balanceTotal, err
		}

		if !match {
			continue
		}

		amt := rfqmath.NewBigIntFromUint64(balance.Amount.Val)
		balanceTotal = balanceTotal.Add(amt)
	}

	return balanceTotal, nil
}

// Records returns the records that make up the Htlc.
func (h *Htlc) Records() []tlv.Record {
	var records []tlv.Record

	// Don't encode the asset amounts if there are none.
	if len(h.Amounts.Val.Balances) > 0 {
		records = append(records, h.Amounts.Record())
	}

	h.RfqID.WhenSome(func(r tlv.RecordT[HtlcRfqIDType, ID]) {
		records = append(records, r.Record())
	})

	return records
}

// Encode serializes the Htlc to the given io.Writer.
func (h *Htlc) Encode(w io.Writer) error {
	tlvRecords := h.Records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the Htlc from the given io.Reader.
func (h *Htlc) Decode(r io.Reader) error {
	rfqID := h.RfqID.Zero()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(
		h.Amounts.Record(),
		rfqID.Record(),
	)
	if err != nil {
		return err
	}

	typeMap, err := tlvStream.DecodeWithParsedTypesP2P(r)
	if err != nil {
		return err
	}

	if val, ok := typeMap[h.RfqID.TlvType()]; ok && val == nil {
		h.RfqID = tlv.SomeRecordT(rfqID)
	}

	return nil
}

// Bytes returns the serialized Htlc record.
func (h *Htlc) Bytes() []byte {
	var buf bytes.Buffer
	_ = h.Encode(&buf)
	return buf.Bytes()
}

// ToCustomRecords converts the Htlc record to a map of custom records.
func (h *Htlc) ToCustomRecords() (lnwire.CustomRecords, error) {
	return tlv.RecordsToMap(h.Records())
}

// AsJson returns the Htlc record as a JSON blob.
func (h *Htlc) AsJson() ([]byte, error) {
	j := &JsonHtlc{
		Balances: make([]*JsonAssetTranche, len(h.Balances())),
	}

	h.RfqID.ValOpt().WhenSome(func(id ID) {
		j.RfqID = hex.EncodeToString(id[:])
	})

	for idx, balance := range h.Balances() {
		j.Balances[idx] = &JsonAssetTranche{
			AssetID: hex.EncodeToString(balance.AssetID.Val[:]),
			Amount:  balance.Amount.Val,
		}
	}

	return json.Marshal(j)
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

// HtlcFromCustomRecords creates a new Htlc record from the given custom
// records.
func HtlcFromCustomRecords(records lnwire.CustomRecords) (*Htlc, error) {
	encoded, err := records.Serialize()
	if err != nil {
		return nil, fmt.Errorf("unable to serialize custom records: %w",
			err)
	}

	return DecodeHtlc(encoded)
}

// HasAssetHTLCCustomRecords returns true if the given custom records contain
// the custom records that we'd expect an asset HTLC to carry.
func HasAssetHTLCCustomRecords(records lnwire.CustomRecords) bool {
	var (
		amountType HtlcAmountRecordType
		rfqIDType  HtlcRfqIDType
	)
	for key := range records {
		if key == uint64(amountType.TypeVal()) {
			return true
		}

		if key == uint64(rfqIDType.TypeVal()) {
			return true
		}
	}

	return false
}

// HasAssetHTLCEntries returns true if the given blob contains the custom
// records that we'd expect an asset HTLC to carry. If the blob is not a valid
// custom records blob, this function will return false.
func HasAssetHTLCEntries(blob tlv.Blob) bool {
	customRecords, err := lnwire.ParseCustomRecords(blob)
	if err != nil {
		return false
	}

	return HasAssetHTLCCustomRecords(customRecords)
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
func (a *AssetBalance) records() []tlv.Record {
	return []tlv.Record{
		a.AssetID.Record(),
		a.Amount.Record(),
	}
}

// Encode serializes the AssetBalance to the given io.Writer.
func (a *AssetBalance) Encode(w io.Writer) error {
	tlvRecords := a.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AssetBalance from the given io.Reader.
func (a *AssetBalance) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(a.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Sum returns the sum of the amounts of all the asset Balances in the list.
func Sum(balances []*AssetBalance) uint64 {
	var sum uint64
	for _, balance := range balances {
		sum += balance.Amount.Val
	}
	return sum
}

// Bytes returns the serialized AssetBalance record.
func (a *AssetBalance) Bytes() []byte {
	var buf bytes.Buffer
	_ = a.Encode(&buf)
	return buf.Bytes()
}

// DecodeAssetBalance deserializes a AssetBalance from the given blob.
func DecodeAssetBalance(blob tlv.Blob) (*AssetBalance, error) {
	var a AssetBalance
	err := a.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// AssetBalanceListRecord is a record that represents a list of asset Balances.
type AssetBalanceListRecord struct {
	Balances []*AssetBalance
}

// Sum returns the sum of the amounts of all the asset Balances in the list.
func (l *AssetBalanceListRecord) Sum() uint64 {
	return Sum(l.Balances)
}

// Record creates a Record out of a AssetBalanceListRecord using the
// eAssetBalanceList and dAssetBalanceList functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *AssetBalanceListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetBalanceList(&buf, &l.Balances, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.Balances, size, eAssetBalanceList, dAssetBalanceList,
	)
}

// Encode serializes the AssetBalanceListRecord to the given io.Writer.
func (l *AssetBalanceListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AssetBalanceListRecord from the given io.Reader.
func (l *AssetBalanceListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eAssetBalanceList is an encoder for AssetBalanceListRecord.
func eAssetBalanceList(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetBalance); ok {
		numBalances := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numBalances, buf); err != nil {
			return err
		}
		var outputBuf bytes.Buffer
		for _, balance := range *v {
			if err := balance.Encode(&outputBuf); err != nil {
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

// dAssetBalanceList is a decoder for AssetBalanceListRecord.
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
			err = outputs[i].Decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = outputs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]*AssetBalance")
}

func IdEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*ID); ok {
		id := [32]byte(*t)
		return tlv.EBytes32(w, &id, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "MessageID")
}

func IdDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	const idBytesLen = 32

	if typ, ok := val.(*ID); ok {
		var idBytes [idBytesLen]byte

		err := tlv.DBytes32(r, &idBytes, buf, idBytesLen)
		if err != nil {
			return err
		}

		id := ID(idBytes)

		*typ = id
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "MessageID", l, idBytesLen)
}

// TlvFixedPointEncoder is a function that can be used to encode a TlvFixedPoint
// to a writer.
func TlvFixedPointEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TlvFixedPoint); ok {
		err := tlv.EUint8T(w, t.fp.Scale, buf)
		if err != nil {
			return fmt.Errorf("unable to encode scale: %w", err)
		}

		cBytes := t.fp.Coefficient.Bytes()
		err = tlv.EVarBytes(w, &cBytes, buf)
		if err != nil {
			return fmt.Errorf("unable to encode coefficient "+
				"bytes: %w", err)
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "*TlvFixedPoint")
}

// TlvFixedPointDecoder is a function that can be used to decode a TlvFixedPoint
// from a reader.
func TlvFixedPointDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	// Enforce the maximum record size.
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

	if typ, ok := val.(*TlvFixedPoint); ok {
		// Decode the scale.
		var scale uint8
		if err := tlv.DUint8(r, &scale, buf, 1); err != nil {
			return err
		}

		// Decode the coefficient.
		var bytesLen uint64
		if l > 1 {
			bytesLen = l - 1
		}

		var cBytes []byte
		if err := tlv.DVarBytes(r, &cBytes, buf, bytesLen); err != nil {
			return err
		}

		var coefficient rfqmath.BigInt
		coefficient = coefficient.FromBytes(cBytes)

		*typ = NewTlvFixedPointFromBigInt(rfqmath.BigIntFixedPoint{
			Coefficient: coefficient,
			Scale:       scale,
		})
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "*TlvFixedPoint", l, 9)
}
