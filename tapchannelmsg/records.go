package tapchannelmsg

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
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

	// MaxNumHTLCs is the maximum number of HTLCs that are allowed in a
	// single record.
	MaxNumHTLCs = input.MaxHTLCNumber

	// OutputMaxSize is the maximum size of an asset output record. This is
	// the sum of the maximum sizes of the fields in the record.
	OutputMaxSize = 32 + 8 + proof.FileMaxProofSizeBytes
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

	// HtlcSigsRecordType is a type alias for the TLV type that is used to
	// encode the signatures of an HTLC record on the wire.
	HtlcSigsRecordType = tlv.TlvType65537

	// HtlcRfqIDType is the type alias for the TLV type that is used to
	// encode an RFQ id within the custom records of an HTLC record on the
	// wire.
	HtlcRfqIDType = tlv.TlvType65538
)

// OpenChannel is a record that represents the capacity information related to
// a commitment. This entails all the (asset_id, amount, proof) tuples and other
// information that we may need to be able to sign the TAP portion of the
// commitment transaction.
type OpenChannel struct {
	// FundedAssets is a list of asset outputs that was committed to the
	// funding output of a commitment.
	FundedAssets tlv.RecordT[tlv.TlvType0, AssetOutputListRecord]
}

// NewOpenChannel creates a new OpenChannel record with the given funded assets.
func NewOpenChannel(fundedAssets []*AssetOutput) *OpenChannel {
	return &OpenChannel{
		FundedAssets: tlv.NewRecordT[tlv.TlvType0](
			AssetOutputListRecord{
				Outputs: fundedAssets,
			},
		),
	}
}

// Assets returns the list of asset outputs that are committed to in the
// OpenChannel struct.
func (o *OpenChannel) Assets() []*AssetOutput {
	return o.FundedAssets.Val.Outputs
}

// records returns the records that make up the OpenChannel.
func (o *OpenChannel) records() []tlv.Record {
	return []tlv.Record{
		o.FundedAssets.Record(),
	}
}

// Encode serializes the OpenChannel to the given io.Writer.
func (o *OpenChannel) Encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the OpenChannel from the given io.Reader.
func (o *OpenChannel) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized OpenChannel record.
func (o *OpenChannel) Bytes() []byte {
	var buf bytes.Buffer
	_ = o.Encode(&buf)
	return buf.Bytes()
}

// DecodeOpenChannel deserializes an OpenChannel from the given blob.
func DecodeOpenChannel(blob tlv.Blob) (*OpenChannel, error) {
	var o OpenChannel
	err := o.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &o, nil
}

// AuxLeaves is a record that represents the auxiliary leaves that correspond to
// a commitment.
type AuxLeaves struct {
	// LocalAuxLeaf is the auxiliary leaf that corresponds to the local
	// commitment.
	LocalAuxLeaf tlv.OptionalRecordT[tlv.TlvType0, TapLeafRecord]

	// RemoteAuxLeaf is the auxiliary leaf that corresponds to the remote
	// commitment.
	RemoteAuxLeaf tlv.OptionalRecordT[tlv.TlvType1, TapLeafRecord]

	// OutgoingHtlcLeaves is a map of HTLC indices to auxiliary leaves that
	// correspond to the outgoing HTLCs.
	OutgoingHtlcLeaves tlv.RecordT[tlv.TlvType2, HtlcAuxLeafMapRecord]

	// IncomingHtlcLeaves is a map of HTLC indices to auxiliary leaves that
	// correspond to the incoming HTLCs.
	IncomingHtlcLeaves tlv.RecordT[tlv.TlvType3, HtlcAuxLeafMapRecord]
}

// NewAuxLeaves creates a new AuxLeaves record with the given local, remote,
// incoming, and outgoing auxiliary leaves.
func NewAuxLeaves(local, remote input.AuxTapLeaf, outgoing,
	incoming input.AuxTapLeaves) AuxLeaves {

	leaves := AuxLeaves{
		OutgoingHtlcLeaves: tlv.NewRecordT[tlv.TlvType2](
			NewHtlcAuxLeafMapRecord(outgoing),
		),
		IncomingHtlcLeaves: tlv.NewRecordT[tlv.TlvType3](
			NewHtlcAuxLeafMapRecord(incoming),
		),
	}

	local.WhenSome(func(leaf txscript.TapLeaf) {
		leaves.LocalAuxLeaf = tlv.SomeRecordT[tlv.TlvType0](
			tlv.NewRecordT[tlv.TlvType0](TapLeafRecord{
				Leaf: leaf,
			}),
		)
	})

	remote.WhenSome(func(leaf txscript.TapLeaf) {
		leaves.RemoteAuxLeaf = tlv.SomeRecordT[tlv.TlvType1](
			tlv.NewRecordT[tlv.TlvType1](TapLeafRecord{
				Leaf: leaf,
			}),
		)
	})

	return leaves
}

// DecodeAuxLeaves deserializes an OpenChannel from the given blob.
func DecodeAuxLeaves(blob tlv.Blob) (*AuxLeaves, error) {
	var l AuxLeaves
	err := l.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &l, nil
}

// Encode serializes the AuxLeaves to the given io.Writer.
func (o *AuxLeaves) Encode(w io.Writer) error {
	records := []tlv.Record{
		o.OutgoingHtlcLeaves.Record(),
		o.IncomingHtlcLeaves.Record(),
	}

	o.LocalAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType0, TapLeafRecord]) {
			records = append(records, r.Record())
		},
	)
	o.RemoteAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, TapLeafRecord]) {
			records = append(records, r.Record())
		},
	)

	tlv.SortRecords(records)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AuxLeaves from the given io.Reader.
func (o *AuxLeaves) Decode(r io.Reader) error {
	localAuxLeaf := o.LocalAuxLeaf.Zero()
	remoteAuxLeaf := o.RemoteAuxLeaf.Zero()

	tlvStream, err := tlv.NewStream(
		localAuxLeaf.Record(),
		remoteAuxLeaf.Record(),
		o.OutgoingHtlcLeaves.Record(),
		o.IncomingHtlcLeaves.Record(),
	)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[localAuxLeaf.TlvType()]; ok {
		o.LocalAuxLeaf = tlv.SomeRecordT(localAuxLeaf)
	}

	if _, ok := tlvs[remoteAuxLeaf.TlvType()]; ok {
		o.RemoteAuxLeaf = tlv.SomeRecordT(remoteAuxLeaf)
	}

	return nil
}

// Bytes returns the serialized AuxLeaves record.
func (o *AuxLeaves) Bytes() []byte {
	var buf bytes.Buffer
	_ = o.Encode(&buf)
	return buf.Bytes()
}

// Record creates a Record out of a AuxLeaves using the
// eHtlcAuxLeafMapRecord and dHtlcAuxLeafMapRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (o *AuxLeaves) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		if err := eAuxLeaves(&buf, o, &scratch); err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(0, o, size, eAuxLeaves, dAuxLeaves)
}

// eAuxLeaves is an encoder for AuxLeaves.
func eAuxLeaves(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*AuxLeaves); ok {
		var leavesBuf bytes.Buffer
		if err := v.Encode(&leavesBuf); err != nil {
			return err
		}

		leavesBytes := leavesBuf.Bytes()
		return asset.InlineVarBytesEncoder(w, &leavesBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*AuxLeaves")
}

// dAuxLeaves is a decoder for AuxLeaves.
func dAuxLeaves(r io.Reader, val interface{}, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*AuxLeaves); ok {
		var leavesBytes []byte
		err := asset.InlineVarBytesDecoder(
			r, &leavesBytes, buf, tlv.MaxRecordSize,
		)
		if err != nil {
			return err
		}

		var auxLeaves AuxLeaves
		err = auxLeaves.Decode(bytes.NewReader(leavesBytes))
		if err != nil {
			return err
		}

		*typ = auxLeaves
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*AuxLeaves")
}

// Commitment is a record that represents the current state of a commitment.
// This entails all the (asset_id, amount, proof) tuples and other information
// that we may need to be able to sign the TAP portion of the commitment
// transaction.
type Commitment struct {
	// LocalAssets is a list of all asset outputs that represent the current
	// local asset balance of the commitment.
	LocalAssets tlv.RecordT[tlv.TlvType0, AssetOutputListRecord]

	// RemoteAssets is a list of all asset outputs that represents the
	// current remote asset balance of the commitment.
	RemoteAssets tlv.RecordT[tlv.TlvType1, AssetOutputListRecord]

	// OutgoingHtlcAssets is a list of all outgoing in-flight HTLCs and the
	// asset balance change that they represent.
	OutgoingHtlcAssets tlv.RecordT[tlv.TlvType2, HtlcAssetOutput]

	// IncomingHtlcAssets is a list of all incoming in-flight HTLCs and the
	// asset balance change that they represent.
	IncomingHtlcAssets tlv.RecordT[tlv.TlvType3, HtlcAssetOutput]

	// AuxLeaves are the auxiliary leaves that correspond to the commitment.
	AuxLeaves tlv.RecordT[tlv.TlvType4, AuxLeaves]
}

// NewCommitment creates a new Commitment record with the given local and remote
// assets, and incoming and outgoing HTLCs.
func NewCommitment(localAssets, remoteAssets []*AssetOutput, outgoingHtlcs,
	incomingHtlcs map[input.HtlcIndex][]*AssetOutput,
	auxLeaves lnwallet.CommitAuxLeaves) *Commitment {

	return &Commitment{
		LocalAssets: tlv.NewRecordT[tlv.TlvType0](
			AssetOutputListRecord{
				Outputs: localAssets,
			},
		),
		RemoteAssets: tlv.NewRecordT[tlv.TlvType1](
			AssetOutputListRecord{
				Outputs: remoteAssets,
			},
		),
		OutgoingHtlcAssets: tlv.NewRecordT[tlv.TlvType2](
			NewHtlcAssetOutput(outgoingHtlcs),
		),
		IncomingHtlcAssets: tlv.NewRecordT[tlv.TlvType3](
			NewHtlcAssetOutput(incomingHtlcs),
		),
		AuxLeaves: tlv.NewRecordT[tlv.TlvType4](
			NewAuxLeaves(
				auxLeaves.LocalAuxLeaf, auxLeaves.RemoteAuxLeaf,
				auxLeaves.OutgoingHtlcLeaves,
				auxLeaves.IncomingHtlcLeaves,
			),
		),
	}
}

// records returns the records that make up the Commitment.
func (c *Commitment) records() []tlv.Record {
	return []tlv.Record{
		c.LocalAssets.Record(),
		c.RemoteAssets.Record(),
		c.OutgoingHtlcAssets.Record(),
		c.IncomingHtlcAssets.Record(),
		c.AuxLeaves.Record(),
	}
}

// LocalOutputs returns the local asset outputs that are committed to in the
// Commitment struct.
func (c *Commitment) LocalOutputs() []*AssetOutput {
	return fn.Map(
		c.LocalAssets.Val.Outputs, func(o *AssetOutput) *AssetOutput {
			return o
		},
	)
}

// RemoteOutputs returns the remote asset outputs that are committed to in the
// Commitment struct.
func (c *Commitment) RemoteOutputs() []*AssetOutput {
	return fn.Map(
		c.RemoteAssets.Val.Outputs, func(o *AssetOutput) *AssetOutput {
			return o
		},
	)
}

// Encode serializes the Commitment to the given io.Writer.
func (c *Commitment) Encode(w io.Writer) error {
	tlvRecords := c.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the Commitment from the given io.Reader.
func (c *Commitment) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(c.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized Commitment record.
func (c *Commitment) Bytes() []byte {
	var buf bytes.Buffer
	_ = c.Encode(&buf)
	return buf.Bytes()
}

// Leaves returns the auxiliary leaves that correspond to the commitment.
func (c *Commitment) Leaves() lnwallet.CommitAuxLeaves {
	leaves := lnwallet.CommitAuxLeaves{
		OutgoingHtlcLeaves: make(input.AuxTapLeaves),
		IncomingHtlcLeaves: make(input.AuxTapLeaves),
	}
	c.AuxLeaves.Val.LocalAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType0, TapLeafRecord]) {
			leaves.LocalAuxLeaf = lfn.Some(r.Val.Leaf)
		},
	)
	c.AuxLeaves.Val.RemoteAuxLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, TapLeafRecord]) {
			leaves.RemoteAuxLeaf = lfn.Some(r.Val.Leaf)
		},
	)

	outgoing := c.AuxLeaves.Val.OutgoingHtlcLeaves.Val.HtlcAuxLeaves
	for htlcIndex := range outgoing {
		outgoingLeaf := outgoing[htlcIndex]

		var leaf input.HtlcAuxLeaf
		outgoingLeaf.AuxLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType0, TapLeafRecord]) {
				leaf.AuxTapLeaf = lfn.Some(r.Val.Leaf)
			},
		)
		outgoingLeaf.SecondLevelLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType1, TapLeafRecord]) {
				leaf.SecondLevelLeaf = lfn.Some(r.Val.Leaf)
			},
		)

		leaves.OutgoingHtlcLeaves[htlcIndex] = leaf
	}

	incoming := c.AuxLeaves.Val.IncomingHtlcLeaves.Val.HtlcAuxLeaves
	for htlcIndex := range incoming {
		incomingLeaf := incoming[htlcIndex]

		var leaf input.HtlcAuxLeaf
		incomingLeaf.AuxLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType0, TapLeafRecord]) {
				leaf.AuxTapLeaf = lfn.Some(r.Val.Leaf)
			},
		)
		incomingLeaf.SecondLevelLeaf.WhenSome(
			func(r tlv.RecordT[tlv.TlvType1, TapLeafRecord]) {
				leaf.SecondLevelLeaf = lfn.Some(r.Val.Leaf)
			},
		)

		leaves.IncomingHtlcLeaves[htlcIndex] = leaf
	}

	return leaves
}

// DecodeCommitment deserializes a Commitment from the given blob.
func DecodeCommitment(blob tlv.Blob) (*Commitment, error) {
	var c Commitment
	err := c.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// NoneRfqIDRecord creates an optional record that represents a None RFQ ID.
func NoneRfqIDRecord() tlv.OptionalRecordT[HtlcRfqIDType, rfqmsg.ID] {
	return tlv.OptionalRecordT[HtlcRfqIDType, rfqmsg.ID]{
		Option: lfn.None[tlv.RecordT[HtlcRfqIDType, rfqmsg.ID]](),
	}
}

// SomeRfqIDRecord creates an optional record that represents an RFQ ID.
func SomeRfqIDRecord(
	id rfqmsg.ID) tlv.OptionalRecordT[HtlcRfqIDType, rfqmsg.ID] {

	return tlv.SomeRecordT(
		tlv.NewPrimitiveRecord[HtlcRfqIDType, rfqmsg.ID](id),
	)
}

// Htlc is a record that represents the capacity change related to an in-flight
// HTLC. This entails all the (asset_id, amount) tuples and other information
// that we may need to be able to update the TAP portion of a commitment
// balance.
type Htlc struct {
	// Amounts is a list of asset balances that are changed by the HTLC.
	Amounts tlv.RecordT[HtlcAmountRecordType, AssetBalanceListRecord]

	// RfqID is the RFQ ID that corresponds to the HTLC.
	RfqID tlv.OptionalRecordT[HtlcRfqIDType, rfqmsg.ID]
}

// NewHtlc creates a new Htlc record with the given funded assets.
func NewHtlc(amounts []*AssetBalance, rfqID fn.Option[rfqmsg.ID]) *Htlc {
	htlc := &Htlc{
		Amounts: tlv.NewRecordT[HtlcAmountRecordType](
			AssetBalanceListRecord{
				Balances: amounts,
			},
		),
	}
	rfqID.WhenSome(func(id rfqmsg.ID) {
		htlc.RfqID = SomeRfqIDRecord(id)
	})

	return htlc
}

// Balances returns the list of asset Balances that are updated in the Htlc
// struct.
func (h *Htlc) Balances() []*AssetBalance {
	return h.Amounts.Val.Balances
}

// Records returns the records that make up the Htlc.
func (h *Htlc) Records() []tlv.Record {
	records := []tlv.Record{
		h.Amounts.Record(),
	}

	h.RfqID.WhenSome(func(r tlv.RecordT[HtlcRfqIDType, rfqmsg.ID]) {
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

// DecodeHtlc deserializes a Htlc from the given blob.
func DecodeHtlc(blob tlv.Blob) (*Htlc, error) {
	var h Htlc
	err := h.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// HtlcAuxLeaf is a record that represents the auxiliary leaf of an HTLC and
// the optional second level leaf. The second level leaf is optional because it
// is not set in every case of the HTLC creation flow.
type HtlcAuxLeaf struct {
	// AuxLeaf is the auxiliary leaf that corresponds to the HTLC.
	AuxLeaf tlv.OptionalRecordT[tlv.TlvType0, TapLeafRecord]

	// SecondLevelLeaf is the auxiliary leaf that corresponds to the second
	// level HTLC. If this is not set, it means that the commitment
	// transaction isn't complete yet and the second level leaf couldn't yet
	// be created
	SecondLevelLeaf tlv.OptionalRecordT[tlv.TlvType1, TapLeafRecord]
}

// NewHtlcAuxLeaf creates a new HtlcAuxLeaf record with the given funded assets.
func NewHtlcAuxLeaf(leaf input.HtlcAuxLeaf) HtlcAuxLeaf {
	var auxLeaf HtlcAuxLeaf

	leaf.AuxTapLeaf.WhenSome(func(leaf txscript.TapLeaf) {
		auxLeaf.AuxLeaf = tlv.SomeRecordT[tlv.TlvType0](
			tlv.NewRecordT[tlv.TlvType0](TapLeafRecord{
				Leaf: leaf,
			}),
		)
	})

	leaf.SecondLevelLeaf.WhenSome(func(leaf txscript.TapLeaf) {
		auxLeaf.SecondLevelLeaf = tlv.SomeRecordT[tlv.TlvType1](
			tlv.NewRecordT[tlv.TlvType1](TapLeafRecord{
				Leaf: leaf,
			}),
		)
	})

	return auxLeaf
}

// Encode serializes the HtlcAuxLeaf to the given io.Writer.
func (h *HtlcAuxLeaf) Encode(w io.Writer) error {
	var records []tlv.Record
	h.AuxLeaf.WhenSome(func(r tlv.RecordT[tlv.TlvType0, TapLeafRecord]) {
		records = append(records, r.Record())
	})
	h.SecondLevelLeaf.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, TapLeafRecord]) {
			records = append(records, r.Record())
		},
	)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the HtlcAuxLeaf from the given io.Reader.
func (h *HtlcAuxLeaf) Decode(r io.Reader) error {
	auxLeaf := h.AuxLeaf.Zero()
	secondLevelLeaf := h.SecondLevelLeaf.Zero()

	tlvStream, err := tlv.NewStream(
		auxLeaf.Record(),
		secondLevelLeaf.Record(),
	)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[auxLeaf.TlvType()]; ok {
		h.AuxLeaf = tlv.SomeRecordT(auxLeaf)
	}

	if _, ok := tlvs[secondLevelLeaf.TlvType()]; ok {
		h.SecondLevelLeaf = tlv.SomeRecordT(secondLevelLeaf)
	}

	return nil
}

// Bytes returns the serialized HtlcAuxLeaf record.
func (h *HtlcAuxLeaf) Bytes() []byte {
	var buf bytes.Buffer
	_ = h.Encode(&buf)
	return buf.Bytes()
}

// DecodeHtlcAuxLeaf deserializes a HtlcAuxLeaf from the given blob.
func DecodeHtlcAuxLeaf(blob tlv.Blob) (*HtlcAuxLeaf, error) {
	var h HtlcAuxLeaf
	err := h.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// HtlcAuxLeafMapRecord is a record that represents a map of HTLC indices to
// HtlcAuxLeaf records.
type HtlcAuxLeafMapRecord struct {
	HtlcAuxLeaves map[input.HtlcIndex]HtlcAuxLeaf
}

// NewHtlcAuxLeafMapRecord creates a new HtlcAuxLeafMapRecord record with the
// given HTLC aux leaves.
func NewHtlcAuxLeafMapRecord(
	leaves map[input.HtlcIndex]input.HtlcAuxLeaf) HtlcAuxLeafMapRecord {

	if leaves == nil {
		return HtlcAuxLeafMapRecord{}
	}

	htlcLeaves := make(map[input.HtlcIndex]HtlcAuxLeaf)
	for htlcIndex := range leaves {
		htlcLeaves[htlcIndex] = NewHtlcAuxLeaf(leaves[htlcIndex])
	}

	return HtlcAuxLeafMapRecord{
		HtlcAuxLeaves: htlcLeaves,
	}
}

// Record creates a Record out of a HtlcAuxLeafMapRecord using the
// eHtlcAuxLeafMapRecord and dHtlcAuxLeafMapRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *HtlcAuxLeafMapRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eHtlcAuxLeafMapRecord(&buf, &l.HtlcAuxLeaves, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.HtlcAuxLeaves, size, eHtlcAuxLeafMapRecord,
		dHtlcAuxLeafMapRecord,
	)
}

// Encode serializes the htlcPartialSigsRecord to the given io.Writer.
func (l *HtlcAuxLeafMapRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the htlcPartialSigsRecord from the given io.Reader.
func (l *HtlcAuxLeafMapRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eHtlcAuxLeafMapRecord is an encoder for HtlcAuxLeafMapRecord.
func eHtlcAuxLeafMapRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*map[input.HtlcIndex]HtlcAuxLeaf); ok {
		numHtlcs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numHtlcs, buf); err != nil {
			return err
		}
		var htlcBuf bytes.Buffer
		for htlcIndex, auxLeaf := range *v {
			err := tlv.WriteVarInt(w, htlcIndex, buf)
			if err != nil {
				return err
			}
			if err := auxLeaf.Encode(&htlcBuf); err != nil {
				return err
			}
			leafBytes := htlcBuf.Bytes()
			err = asset.InlineVarBytesEncoder(
				w, &leafBytes, buf,
			)
			if err != nil {
				return err
			}
			htlcBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*map[input.HtlcIndex]HtlcAuxLeaf",
	)
}

// dHtlcAuxLeafMapRecord is a decoder for HtlcAuxLeafMapRecord.
func dHtlcAuxLeafMapRecord(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*map[input.HtlcIndex]HtlcAuxLeaf); ok {
		numHtlcs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of HTLCs we accept.
		if numHtlcs > MaxNumHTLCs {
			return fmt.Errorf("%w: too many HTLCs", ErrListInvalid)
		}

		if numHtlcs == 0 {
			return nil
		}

		htlcs := make(map[input.HtlcIndex]HtlcAuxLeaf, numHtlcs)
		for i := uint64(0); i < numHtlcs; i++ {
			htlcIndex, err := tlv.ReadVarInt(r, buf)
			if err != nil {
				return err
			}

			var leavesBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &leavesBytes, buf, tlv.MaxRecordSize,
			)
			if err != nil {
				return err
			}
			var rec HtlcAuxLeaf
			err = rec.Decode(bytes.NewReader(leavesBytes))
			if err != nil {
				return err
			}

			htlcs[htlcIndex] = rec
		}
		*typ = htlcs
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*map[input.HtlcIndex]HtlcAuxLeaf",
	)
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

// AssetOutput is a record that represents a single asset UTXO.
type AssetOutput struct {
	// AssetBalance is the asset ID and amount of the output.
	AssetBalance

	// Proof is the last transition proof that proves this output was
	// committed to in the Bitcoin transaction that anchors this asset
	// output.
	Proof tlv.RecordT[tlv.TlvType2, proof.Proof]
}

// NewAssetOutput creates a new AssetOutput record with the given asset ID,
// amount, and proof.
func NewAssetOutput(assetID asset.ID, amount uint64,
	p proof.Proof) *AssetOutput {

	return &AssetOutput{
		AssetBalance: AssetBalance{
			AssetID: tlv.NewRecordT[tlv.TlvType0](assetID),
			Amount:  tlv.NewPrimitiveRecord[tlv.TlvType1](amount),
		},
		Proof: tlv.NewRecordT[tlv.TlvType2](p),
	}
}

// records returns the records that make up the AssetOutput.
func (o *AssetOutput) records() []tlv.Record {
	return []tlv.Record{
		o.AssetID.Record(),
		o.Amount.Record(),
		o.Proof.Record(),
	}
}

// Encode serializes the AssetOutput to the given io.Writer.
func (o *AssetOutput) Encode(w io.Writer) error {
	tlvRecords := o.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AssetOutput from the given io.Reader.
func (o *AssetOutput) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(o.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized AssetOutput record.
func (o *AssetOutput) Bytes() []byte {
	var buf bytes.Buffer
	_ = o.Encode(&buf)
	return buf.Bytes()
}

// DecodeAssetOutput deserializes a AssetOutput from the given blob.
func DecodeAssetOutput(blob tlv.Blob) (*AssetOutput, error) {
	var o AssetOutput
	err := o.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &o, nil
}

// OutputSum returns the sum of the amounts of all the asset outputs in the
// list.
func OutputSum(outputs []*AssetOutput) uint64 {
	var sum uint64
	for _, output := range outputs {
		sum += output.Amount.Val
	}
	return sum
}

// HtlcAssetOutput is a record that represents a list of asset outputs that are
// associated with a particular HTLC index.
type HtlcAssetOutput struct {
	HtlcOutputs map[input.HtlcIndex]AssetOutputListRecord
}

// NewHtlcAssetOutput creates a new HtlcAssetOutput record with the given HTLC
// outputs.
func NewHtlcAssetOutput(
	htlcOutputs map[input.HtlcIndex][]*AssetOutput) HtlcAssetOutput {

	if htlcOutputs == nil {
		return HtlcAssetOutput{}
	}

	htlcOutputsRecord := make(map[input.HtlcIndex]AssetOutputListRecord)
	for htlcIndex := range htlcOutputs {
		htlcOutputsRecord[htlcIndex] = AssetOutputListRecord{
			Outputs: htlcOutputs[htlcIndex],
		}
	}

	return HtlcAssetOutput{
		HtlcOutputs: htlcOutputsRecord,
	}
}

// Record creates a Record out of a HtlcAssetOutput using the
// eHtlcAssetOutput and dHtlcAssetOutput functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (h *HtlcAssetOutput) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eHtlcAssetOutput(&buf, &h.HtlcOutputs, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &h.HtlcOutputs, size, eHtlcAssetOutput, dHtlcAssetOutput,
	)
}

// Encode serializes the HtlcAssetOutput to the given io.Writer.
func (h *HtlcAssetOutput) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(h.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the HtlcAssetOutput from the given io.Reader.
func (h *HtlcAssetOutput) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(h.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eHtlcAssetOutput is an encoder for HtlcAssetOutput.
func eHtlcAssetOutput(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*map[input.HtlcIndex]AssetOutputListRecord); ok {
		numHtlcs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numHtlcs, buf); err != nil {
			return err
		}
		var htlcBuf bytes.Buffer
		for htlcIndex, balance := range *v {
			err := tlv.WriteVarInt(w, htlcIndex, buf)
			if err != nil {
				return err
			}
			if err := balance.Encode(&htlcBuf); err != nil {
				return err
			}
			balanceBytes := htlcBuf.Bytes()
			err = asset.InlineVarBytesEncoder(
				w, &balanceBytes, buf,
			)
			if err != nil {
				return err
			}
			htlcBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "map[input.HtlcIndex]AssetOutputListRecord",
	)
}

// dHtlcAssetOutput is a decoder for HtlcAssetOutput.
func dHtlcAssetOutput(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*map[input.HtlcIndex]AssetOutputListRecord); ok {
		numHtlcs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of HTLCs we accept.
		if numHtlcs > MaxNumHTLCs {
			return fmt.Errorf("%w: too many HTLCs", ErrListInvalid)
		}

		if numHtlcs == 0 {
			return nil
		}

		htlcs := make(
			map[input.HtlcIndex]AssetOutputListRecord, numHtlcs,
		)
		for i := uint64(0); i < numHtlcs; i++ {
			htlcIndex, err := tlv.ReadVarInt(r, buf)
			if err != nil {
				return err
			}

			var balanceBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &balanceBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			var rec AssetOutputListRecord
			err = rec.Decode(bytes.NewReader(balanceBytes))
			if err != nil {
				return err
			}

			htlcs[htlcIndex] = rec
		}
		*typ = htlcs
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "map[input.HtlcIndex]AssetOutputListRecord",
	)
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

// AssetOutputListRecord is a record that represents a list of asset outputs.
type AssetOutputListRecord struct {
	Outputs []*AssetOutput
}

// Sum returns the sum of the amounts of all the asset outputs in the list.
func (l *AssetOutputListRecord) Sum() uint64 {
	var sum uint64
	for _, output := range l.Outputs {
		sum += output.Amount.Val
	}
	return sum
}

// Record creates a Record out of a AssetOutputListRecord using the passed
// eAssetOutputList and dAssetOutputList functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *AssetOutputListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetOutputList(&buf, &l.Outputs, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.Outputs, size, eAssetOutputList, dAssetOutputList,
	)
}

// Encode serializes the AssetOutputListRecord to the given io.Writer.
func (l *AssetOutputListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AssetOutputListRecord from the given io.Reader.
func (l *AssetOutputListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eAssetOutputList is an encoder for AssetOutputListRecord.
func eAssetOutputList(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetOutput); ok {
		numOutputs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numOutputs, buf); err != nil {
			return err
		}
		var outputBuf bytes.Buffer
		for _, output := range *v {
			if err := output.Encode(&outputBuf); err != nil {
				return err
			}
			outputBytes := outputBuf.Bytes()
			err := asset.InlineVarBytesEncoder(w, &outputBytes, buf)
			if err != nil {
				return err
			}
			outputBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetOutput")
}

// dAssetOutputList is a decoder for AssetOutputListRecord.
func dAssetOutputList(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]*AssetOutput); ok {
		numOutputs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of outputs we accept.
		if numOutputs > MaxNumOutputs {
			return fmt.Errorf("%w: too many outputs",
				ErrListInvalid)
		}

		if numOutputs == 0 {
			return nil
		}

		outputs := make([]*AssetOutput, numOutputs)
		for i := uint64(0); i < numOutputs; i++ {
			var outputBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &outputBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			outputs[i] = &AssetOutput{}
			err = outputs[i].Decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = outputs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetOutput")
}

// TapLeafRecord is a record that represents a TapLeaf.
type TapLeafRecord struct {
	Leaf txscript.TapLeaf
}

// Record creates a Record out of a TapLeafRecord using the passed
// eTapLeafRecord and dTapLeafRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *TapLeafRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eTapLeafRecord(&buf, l, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(0, l, size, eTapLeafRecord, dTapLeafRecord)
}

// Encode serializes the TapLeafRecord to the given io.Writer.
func (l *TapLeafRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the TapLeafRecord from the given io.Reader.
func (l *TapLeafRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eTapLeafRecord is an encoder for TapLeafRecord.
func eTapLeafRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*TapLeafRecord); ok {
		err := tlv.EUint8T(w, uint8(v.Leaf.LeafVersion), buf)
		if err != nil {
			return err
		}

		scriptLen := uint64(len(v.Leaf.Script))
		if err := tlv.WriteVarInt(w, scriptLen, buf); err != nil {
			return err
		}
		return asset.InlineVarBytesEncoder(w, &v.Leaf.Script, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*TapLeafRecord")
}

// dTapLeafRecord is a decoder for TapLeafRecord.
func dTapLeafRecord(r io.Reader, val interface{}, buf *[8]byte,
	l uint64) error {

	if typ, ok := val.(*TapLeafRecord); ok {
		var leafVersion uint8
		if err := tlv.DUint8(r, &leafVersion, buf, 1); err != nil {
			return err
		}

		leaf := txscript.TapLeaf{
			LeafVersion: txscript.TapscriptLeafVersion(leafVersion),
		}

		scriptLen, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the size of script we accept.
		if scriptLen > tlv.MaxRecordSize {
			return fmt.Errorf("%w: script too long", ErrListInvalid)
		}

		err = asset.InlineVarBytesDecoder(
			r, &leaf.Script, buf, tlv.MaxRecordSize,
		)
		if err != nil {
			return err
		}

		*typ = TapLeafRecord{
			Leaf: leaf,
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*TapLeafRecord")
}
