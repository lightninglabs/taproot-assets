package tapchannelmsg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/maps"
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

	// BtcKeyShutdownType is the type alias for the TLV type that is used to
	// encode the BTC internal key of the shutdown record on the wire.
	BtcKeyShutdownType = tlv.TlvType65539

	// AssetKeyShutdownType is the type alias for the TLV type that is used
	// to encode the asset internal key of the shutdown record on the wire.
	AssetKeyShutdownType = tlv.TlvType65540

	// ScriptKeysShutdownType is the type alias for the TLV type that is
	// used to encode the script keys of the shutdown record on the wire.
	ScriptKeysShutdownType = tlv.TlvType65541

	// ProofDeliveryAddrShutdownType is the type alias for the TLV type that
	// is used to encode the proof delivery address of the shutdown record
	// on the wire.
	ProofDeliveryAddrShutdownType = tlv.TlvType65542
)

// OpenChannel is a record that represents the capacity information related to
// a commitment. This entails all the (asset_id, amount, proof) tuples and other
// information that we may need to be able to sign the TAP portion of the
// commitment transaction.
type OpenChannel struct {
	// FundedAssets is a list of asset outputs that was committed to the
	// funding output of a commitment.
	FundedAssets tlv.RecordT[tlv.TlvType0, AssetOutputListRecord]

	// DecimalDisplay is the asset's unit precision. We place this value on
	// the channel directly and not into each funding asset balance struct
	// since even for a channel with multiple tranches of fungible assets,
	// this value needs to be the same for all assets. Otherwise, they would
	// not be fungible.
	DecimalDisplay tlv.RecordT[tlv.TlvType1, uint8]

	// GroupKey is the optional group key used to fund this channel.
	GroupKey tlv.OptionalRecordT[tlv.TlvType2, *btcec.PublicKey]
}

// NewOpenChannel creates a new OpenChannel record with the given funded assets.
func NewOpenChannel(fundedAssets []*AssetOutput, decimalDisplay uint8,
	groupKey *btcec.PublicKey) *OpenChannel {

	var optGroupRecord tlv.OptionalRecordT[tlv.TlvType2, *btcec.PublicKey]
	if groupKey != nil {
		optGroupRecord = tlv.SomeRecordT[tlv.TlvType2](
			tlv.NewPrimitiveRecord[tlv.TlvType2](
				groupKey,
			),
		)
	}

	return &OpenChannel{
		FundedAssets: tlv.NewRecordT[tlv.TlvType0](
			AssetOutputListRecord{
				Outputs: fundedAssets,
			},
		),
		DecimalDisplay: tlv.NewPrimitiveRecord[tlv.TlvType1](
			decimalDisplay,
		),
		GroupKey: optGroupRecord,
	}
}

// Assets returns the list of asset outputs that are committed to in the
// OpenChannel struct.
func (o *OpenChannel) Assets() []*AssetOutput {
	return o.FundedAssets.Val.Outputs
}

// Encode serializes the OpenChannel to the given io.Writer.
func (o *OpenChannel) Encode(w io.Writer) error {
	tlvRecords := []tlv.Record{
		o.FundedAssets.Record(),
		o.DecimalDisplay.Record(),
	}

	o.GroupKey.WhenSome(
		func(r tlv.RecordT[tlv.TlvType2, *btcec.PublicKey]) {
			tlvRecords = append(tlvRecords, r.Record())
		},
	)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the OpenChannel from the given io.Reader.
func (o *OpenChannel) Decode(r io.Reader) error {
	groupKey := o.GroupKey.Zero()

	tlvRecords := []tlv.Record{
		o.FundedAssets.Record(),
		o.DecimalDisplay.Record(),
		groupKey.Record(),
	}

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[groupKey.TlvType()]; ok {
		o.GroupKey = tlv.SomeRecordT(groupKey)
	}

	return nil
}

// Bytes returns the serialized OpenChannel record.
func (o *OpenChannel) Bytes() []byte {
	var buf bytes.Buffer
	_ = o.Encode(&buf)
	return buf.Bytes()
}

// HasAllAssetIDs checks if the OpenChannel contains all asset IDs in the
// provided set. It returns true if all asset IDs are present, false otherwise.
func (o *OpenChannel) HasAllAssetIDs(ids fn.Set[asset.ID]) bool {
	// There is a possibility that we're checking the asset ID from an HTLC
	// that hasn't been materialized yet and could actually contain a group
	// key x-coordinate. That should only be the case if there is a single
	// asset ID.
	if len(ids) == 1 && o.GroupKey.IsSome() {
		assetID := ids.ToSlice()[0]
		groupKeyMatch := lfn.MapOptionZ(
			o.GroupKey.ValOpt(),
			func(groupKey *btcec.PublicKey) bool {
				if groupKey == nil {
					return false
				}

				return bytes.Equal(
					assetID[:], schnorr.SerializePubKey(
						groupKey,
					),
				)
			},
		)

		// Only if we get a match do we short-circuit the explicit asset
		// ID check.
		if groupKeyMatch {
			return true
		}
	}

	availableIDs := fn.NewSet(fn.Map(
		o.Assets(), func(output *AssetOutput) asset.ID {
			return output.AssetID.Val
		},
	)...)

	return ids.Subset(availableIDs)
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
	incoming input.HtlcAuxLeaves) AuxLeaves {

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
		OutgoingHtlcLeaves: make(input.HtlcAuxLeaves),
		IncomingHtlcLeaves: make(input.HtlcAuxLeaves),
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

// CommitSig is a record that represents the commitment signatures for a certain
// commit height.
type CommitSig struct {
	// HtlcPartialSigs is a map of HTLC indices to partial signatures and
	// nonces for the HTLCs.
	HtlcPartialSigs tlv.RecordT[HtlcSigsRecordType, HtlcPartialSigsRecord]
}

// NewCommitSig creates a new CommitSig record with the given partial Sigs.
func NewCommitSig(htlcSigs [][]*AssetSig) *CommitSig {
	var htlcPartialSigs []AssetSigListRecord
	if len(htlcSigs) > 0 {
		htlcPartialSigs = make([]AssetSigListRecord, len(htlcSigs))
		for idx := range htlcSigs {
			htlcPartialSigs[idx] = AssetSigListRecord{
				Sigs: htlcSigs[idx],
			}
		}
	}

	return &CommitSig{
		HtlcPartialSigs: tlv.NewRecordT[HtlcSigsRecordType](
			HtlcPartialSigsRecord{
				HtlcPartialSigs: htlcPartialSigs,
			},
		),
	}
}

// records returns the records that make up the CommitSig.
func (c *CommitSig) records() []tlv.Record {
	return []tlv.Record{
		c.HtlcPartialSigs.Record(),
	}
}

// Encode serializes the CommitSig to the given io.Writer.
func (c *CommitSig) Encode(w io.Writer) error {
	tlvRecords := c.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the CommitSig from the given io.Reader.
func (c *CommitSig) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(c.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized CommitSig record.
func (c *CommitSig) Bytes() []byte {
	var buf bytes.Buffer
	_ = c.Encode(&buf)
	return buf.Bytes()
}

// DecodeCommitSig deserializes a CommitSig from the given blob.
func DecodeCommitSig(blob tlv.Blob) (*CommitSig, error) {
	var c CommitSig
	err := c.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &c, nil
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

// AssetSig is a record that represents the signature for spending an asset
// output.
type AssetSig struct {
	// AssetID is the asset ID that the signature is for.
	AssetID tlv.RecordT[tlv.TlvType0, asset.ID]

	// Sig is the signature for the asset spend.
	Sig tlv.RecordT[tlv.TlvType1, lnwire.Sig]

	// SigHashType is the sigHash type that was used to create the
	// signature.
	SigHashType tlv.RecordT[tlv.TlvType2, uint32]
}

// NewAssetSig creates a new AssetSig record with the given
// asset ID and partial sig.
func NewAssetSig(assetID asset.ID, sig lnwire.Sig,
	sigHashType txscript.SigHashType) *AssetSig {

	return &AssetSig{
		AssetID: tlv.NewRecordT[tlv.TlvType0](assetID),
		Sig:     tlv.NewRecordT[tlv.TlvType1](sig),
		SigHashType: tlv.NewPrimitiveRecord[tlv.TlvType2](
			uint32(sigHashType),
		),
	}
}

// records returns the records that make up the AssetSig.
func (a *AssetSig) records() []tlv.Record {
	return []tlv.Record{
		a.AssetID.Record(),
		a.Sig.Record(),
		a.SigHashType.Record(),
	}
}

// Encode serializes the AssetOutput to the given io.Writer.
func (a *AssetSig) Encode(w io.Writer) error {
	tlvRecords := a.records()

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AssetSig from the given io.Reader.
func (a *AssetSig) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(a.records()...)
	if err != nil {
		return err
	}

	err = tlvStream.Decode(r)
	if err != nil {
		return err
	}

	// We need to force the signature type to be a Schnorr signature for the
	// unit tests to pass.
	a.Sig.Val.ForceSchnorr()

	return nil
}

// Bytes returns the serialized AssetSig record.
func (a *AssetSig) Bytes() []byte {
	var buf bytes.Buffer
	_ = a.Encode(&buf)
	return buf.Bytes()
}

// DecodeAssetSig deserializes a AssetSig from the given blob.
func DecodeAssetSig(blob tlv.Blob) (*AssetSig, error) {
	var a AssetSig
	err := a.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// AssetSigListRecord is a record that represents a list of asset signatures.
type AssetSigListRecord struct {
	Sigs []*AssetSig
}

// Record creates a Record out of a AssetSigListRecord using the passed
// eAssetSigListRecord and dAssetSigListRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (l *AssetSigListRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eAssetSigListRecord(&buf, &l.Sigs, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &l.Sigs, size, eAssetSigListRecord, dAssetSigListRecord,
	)
}

// Encode serializes the AssetSigListRecord to the given io.Writer.
func (l *AssetSigListRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AssetSigListRecord from the given io.Reader.
func (l *AssetSigListRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized AssetSigListRecord record.
func (l *AssetSigListRecord) Bytes() []byte {
	var buf bytes.Buffer
	_ = l.Encode(&buf)
	return buf.Bytes()
}

// DecodeAssetSigListRecord deserializes a AssetSigListRecord from the
// given blob.
func DecodeAssetSigListRecord(rec []byte) (*AssetSigListRecord, error) {
	var h AssetSigListRecord
	err := h.Decode(bytes.NewReader(rec))
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// eAssetSigListRecord is an encoder for AssetSigListRecord.
func eAssetSigListRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]*AssetSig); ok {
		numOutputs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numOutputs, buf); err != nil {
			return err
		}
		var sigsBuf bytes.Buffer
		for _, sig := range *v {
			if err := sig.Encode(&sigsBuf); err != nil {
				return err
			}
			sigBytes := sigsBuf.Bytes()
			err := asset.InlineVarBytesEncoder(w, &sigBytes, buf)
			if err != nil {
				return err
			}
			sigsBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetSig")
}

// dAssetSigListRecord is a decoder for AssetSigListRecord.
func dAssetSigListRecord(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]*AssetSig); ok {
		numSigs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of Sigs we accept.
		if numSigs > MaxNumOutputs {
			return fmt.Errorf("%w: too many signatures",
				ErrListInvalid)
		}

		if numSigs == 0 {
			return nil
		}

		sigs := make([]*AssetSig, numSigs)
		for i := uint64(0); i < numSigs; i++ {
			var outputBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &outputBytes, buf, OutputMaxSize,
			)
			if err != nil {
				return err
			}
			sigs[i] = &AssetSig{}
			err = sigs[i].Decode(bytes.NewReader(outputBytes))
			if err != nil {
				return err
			}
		}
		*typ = sigs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*[]*AssetSig")
}

// HtlcPartialSigsRecord is a record that represents a map of HTLC indices to
// partial signatures (with nonce).
type HtlcPartialSigsRecord struct {
	HtlcPartialSigs []AssetSigListRecord
}

// Record creates a Record out of a HtlcPartialSigsRecord using the
// eHtlcPartialSigsRecord and dHtlcPartialSigsRecord functions.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (h *HtlcPartialSigsRecord) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eHtlcPartialSigsRecord(
			&buf, &h.HtlcPartialSigs, &scratch,
		)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, &h.HtlcPartialSigs, size, eHtlcPartialSigsRecord,
		dHtlcPartialSigsRecord,
	)
}

// Encode serializes the HtlcPartialSigsRecord to the given io.Writer.
func (h *HtlcPartialSigsRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(h.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the HtlcPartialSigsRecord from the given io.Reader.
func (h *HtlcPartialSigsRecord) Decode(r io.Reader) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(h.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eHtlcPartialSigsRecord is an encoder for HtlcPartialSigsRecord.
func eHtlcPartialSigsRecord(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]AssetSigListRecord); ok {
		numHtlcs := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numHtlcs, buf); err != nil {
			return err
		}
		var htlcBuf bytes.Buffer
		for _, auxSig := range *v {
			if err := auxSig.Encode(&htlcBuf); err != nil {
				return err
			}
			htlcBytes := htlcBuf.Bytes()
			err := asset.InlineVarBytesEncoder(
				w, &htlcBytes, buf,
			)
			if err != nil {
				return err
			}
			htlcBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*[]AssetSigListRecord",
	)
}

// dHtlcPartialSigsRecord is a decoder for HtlcPartialSigsRecord.
func dHtlcPartialSigsRecord(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*[]AssetSigListRecord); ok {
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

		htlcs := make([]AssetSigListRecord, numHtlcs)
		for i := uint64(0); i < numHtlcs; i++ {
			var htlcBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &htlcBytes, buf, tlv.MaxRecordSize,
			)
			if err != nil {
				return err
			}
			var rec AssetSigListRecord
			err = rec.Decode(bytes.NewReader(htlcBytes))
			if err != nil {
				return err
			}

			htlcs[i] = rec
		}
		*typ = htlcs
		return nil
	}
	return tlv.NewTypeForEncodingErr(
		val, "*[]AssetSigListRecord",
	)
}

// HtlcAuxLeafMapRecord is a record that represents a map of HTLC indices to
// HtlcAuxLeaf records.
type HtlcAuxLeafMapRecord struct {
	HtlcAuxLeaves map[input.HtlcIndex]HtlcAuxLeaf
}

// NewHtlcAuxLeafMapRecord creates a new HtlcAuxLeafMapRecord record with the
// given HTLC aux leaves.
func NewHtlcAuxLeafMapRecord(leaves input.HtlcAuxLeaves) HtlcAuxLeafMapRecord {
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

// Encode serializes the HtlcPartialSigsRecord to the given io.Writer.
func (l *HtlcAuxLeafMapRecord) Encode(w io.Writer) error {
	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(l.Record())
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the HtlcPartialSigsRecord from the given io.Reader.
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

// AssetOutput is a record that represents a single asset UTXO.
type AssetOutput struct {
	// AssetBalance is the asset ID and amount of the output.
	rfqmsg.AssetBalance

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
		AssetBalance: rfqmsg.AssetBalance{
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

// Sum returns the sum of the amounts of all the asset outputs in the list.
func (h *HtlcAssetOutput) Sum() uint64 {
	return OutputSum(h.Outputs())
}

// Outputs returns a flat list of all the asset outputs in the list.
func (h *HtlcAssetOutput) Outputs() []*AssetOutput {
	return fn.FlatMap(
		maps.Values(h.HtlcOutputs),
		func(r AssetOutputListRecord) []*AssetOutput {
			return r.Outputs
		},
	)
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

// FilterByHtlcIndex returns a slice of AssetOutputs that are associated with
// the given htlc index.
func (h *HtlcAssetOutput) FilterByHtlcIndex(id input.HtlcIndex) []*AssetOutput {
	if h.HtlcOutputs == nil {
		return nil
	}

	if outputs, ok := h.HtlcOutputs[id]; ok {
		return outputs.Outputs
	}

	return nil
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

// ScriptKeyMap is a map of asset IDs to script keys.
type ScriptKeyMap map[asset.ID]btcec.PublicKey

// eScriptKeyMap is an encoder for ScriptKeyMap.
func eScriptKeyMap(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*ScriptKeyMap); ok {
		numKeys := uint64(len(*v))
		if err := tlv.WriteVarInt(w, numKeys, buf); err != nil {
			return err
		}

		for assetID, key := range *v {
			if _, err := w.Write(assetID[:]); err != nil {
				return err
			}

			_, err := w.Write(key.SerializeCompressed())
			if err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "ScriptKeyMap")
}

// dScriptKeyMap is a decoder for ScriptKeyMap.
func dScriptKeyMap(r io.Reader, val interface{}, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*ScriptKeyMap); ok {
		numKeys, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		if numKeys == 0 {
			return nil
		}

		keys := make(ScriptKeyMap, numKeys)
		for i := uint64(0); i < numKeys; i++ {
			var assetID asset.ID
			if _, err := io.ReadFull(r, assetID[:]); err != nil {
				return err
			}

			var keyBytes [33]byte
			if _, err := io.ReadFull(r, keyBytes[:]); err != nil {
				return err
			}

			key, err := btcec.ParsePubKey(keyBytes[:])
			if err != nil {
				return err
			}

			keys[assetID] = *key
		}

		*typ = keys

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "*ScriptKeyMap")
}

// Record creates a Record out of a ScriptKeyMap.
func (s *ScriptKeyMap) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eScriptKeyMap(&buf, s, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, s, size, eScriptKeyMap, dScriptKeyMap,
	)
}

// AuxShutdownMsg contains the additional records to be sent along with the
// shutdown message for co-op closes for an asset channel.
type AuxShutdownMsg struct {
	// BtcInternalKey is the internal key that the sender will use in the
	// BTC shutdown addr. This is used to construct the final set of
	// proofs.
	BtcInternalKey tlv.RecordT[BtcKeyShutdownType, *btcec.PublicKey]

	// AssetInternalKey is the internal key to used to anchor the asset of
	// the sending party in the co-op close transaction.
	AssetInternalKey tlv.RecordT[AssetKeyShutdownType, *btcec.PublicKey]

	// ScriptKeys maps asset IDs to script keys to be used to send the
	// assets to the sending party in the co-op close transaction.
	ScriptKeys tlv.RecordT[ScriptKeysShutdownType, ScriptKeyMap]

	// ProofDeliveryAddr is an optional type that contains the delivery
	// address for the proofs of the co-op close outputs of the local node.
	ProofDeliveryAddr tlv.OptionalRecordT[
		ProofDeliveryAddrShutdownType, []byte,
	]
}

// NewAuxShutdownMsg creates a new AuxShutdownMsg with the given internal key
// and script key map.
func NewAuxShutdownMsg(btcInternalKey, assetInternalKey *btcec.PublicKey,
	scriptKeys ScriptKeyMap, proofDeliveryAddr *url.URL) *AuxShutdownMsg {

	var deliveryAddr tlv.OptionalRecordT[
		ProofDeliveryAddrShutdownType, []byte,
	]
	if proofDeliveryAddr != nil {
		deliveryAddrBytes := []byte(proofDeliveryAddr.String())
		rec := tlv.NewPrimitiveRecord[ProofDeliveryAddrShutdownType](
			deliveryAddrBytes,
		)
		deliveryAddr = tlv.SomeRecordT[ProofDeliveryAddrShutdownType](
			rec,
		)
	}

	return &AuxShutdownMsg{
		BtcInternalKey: tlv.NewPrimitiveRecord[BtcKeyShutdownType](
			btcInternalKey,
		),
		AssetInternalKey: tlv.NewPrimitiveRecord[AssetKeyShutdownType](
			assetInternalKey,
		),
		ScriptKeys: tlv.NewRecordT[ScriptKeysShutdownType](
			scriptKeys,
		),
		ProofDeliveryAddr: deliveryAddr,
	}
}

// EncodeRecords returns the records that make up the AuxShutdownMsg for
// encoding.
func (a *AuxShutdownMsg) EncodeRecords() []tlv.Record {
	records := []tlv.Record{
		a.BtcInternalKey.Record(),
		a.AssetInternalKey.Record(),
		a.ScriptKeys.Record(),
	}

	a.ProofDeliveryAddr.WhenSome(
		func(r tlv.RecordT[ProofDeliveryAddrShutdownType, []byte]) {
			records = append(records, r.Record())
		},
	)

	return records
}

// Encode serializes the AuxShutdownMsg to the given io.Writer.
func (a *AuxShutdownMsg) Encode(w io.Writer) error {
	tlvStream, err := tlv.NewStream(a.EncodeRecords()...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the AuxShutdownMsg from the given io.Reader.
func (a *AuxShutdownMsg) Decode(r io.Reader) error {
	deliveryAddr := a.ProofDeliveryAddr.Zero()

	records := []tlv.Record{
		a.BtcInternalKey.Record(),
		a.AssetInternalKey.Record(),
		a.ScriptKeys.Record(),
		deliveryAddr.Record(),
	}

	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypesP2P(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[deliveryAddr.TlvType()]; ok {
		a.ProofDeliveryAddr = tlv.SomeRecordT(deliveryAddr)
	}

	return nil
}

// DecodeAuxShutdownMsg deserializes a AuxShutdownMsg from the given blob.
func DecodeAuxShutdownMsg(blob tlv.Blob) (*AuxShutdownMsg, error) {
	var s AuxShutdownMsg
	err := s.Decode(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// VpktList is a record that represents a list of vPkts.
type VpktList struct {
	// Pkts is the list of vPkts.
	Pkts []*tappsbt.VPacket
}

// NewVpktList creates a new VpktList record with the given list of vPkts.
func NewVpktList(pkts []*tappsbt.VPacket) VpktList {
	return VpktList{
		Pkts: pkts,
	}
}

// Record returns a tlv.Record that represents the VpktList.
func (v *VpktList) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eVpktList(&buf, v, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	return tlv.MakeDynamicRecord(0, v, size, eVpktList, dVpktList)
}

func eVpktList(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*VpktList); ok {
		numPkts := uint64(len(v.Pkts))
		if err := tlv.WriteVarInt(w, numPkts, buf); err != nil {
			return err
		}

		for _, pkt := range v.Pkts {
			if err := pkt.Serialize(w); err != nil {
				return err
			}
		}

		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*VpktList")
}

const maxNumVpkts = 1_000

func dVpktList(r io.Reader, val interface{}, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*VpktList); ok {
		numPkts, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		if numPkts == 0 {
			return nil
		}

		if numPkts > maxNumVpkts {
			return fmt.Errorf("too many vPkts: %d (limit=%v)",
				numPkts, maxNumVpkts)
		}

		pkts := make([]*tappsbt.VPacket, numPkts)
		for i := uint64(0); i < numPkts; i++ {
			pkt, err := tappsbt.NewFromRawBytes(r, false)
			if err != nil {
				return err
			}

			pkts[i] = pkt
		}

		*typ = VpktList{
			Pkts: pkts,
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "*VpktList")
}

// TapscriptSigDesc contains the information needed to re-sign for a given set
// of vPkts. For normal tapscript outputs, this is the taptweak and also the
// serialized control block. These are needed for second level HTLC outputs, as
// we can't sign the vPkts until we know the sweeping transaction.
type TapscriptSigDesc struct {
	TapTweak tlv.RecordT[tlv.TlvType0, []byte]

	CtrlBlock tlv.RecordT[tlv.TlvType1, []byte]
}

// NewTapscriptSigDesc creates a new tapscriptSigDesc with the given tap tweak
// and ctrlBlock.
func NewTapscriptSigDesc(tapTweak, ctrlBlock []byte) TapscriptSigDesc {
	return TapscriptSigDesc{
		TapTweak:  tlv.NewPrimitiveRecord[tlv.TlvType0](tapTweak),
		CtrlBlock: tlv.NewPrimitiveRecord[tlv.TlvType1](ctrlBlock),
	}
}

// Encode attempts to encode the target tapscriptSigDesc into the passed
// io.Writer.
func (t *TapscriptSigDesc) Encode(w io.Writer) error {
	tlvStream, err := tlv.NewStream(
		t.TapTweak.Record(), t.CtrlBlock.Record(),
	)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode attempts to decode the target tapscriptSigDesc from the passed
// io.Reader.
func (t *TapscriptSigDesc) Decode(r io.Reader) error {
	tlvStream, err := tlv.NewStream(
		t.TapTweak.Record(), t.CtrlBlock.Record(),
	)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// eTapscriptSigDesc is an encoder for tapscriptSigDesc.
func eTapscriptSigDesc(w io.Writer, val interface{}, _ *[8]byte) error {
	if v, ok := val.(*TapscriptSigDesc); ok {
		return v.Encode(w)
	}

	return tlv.NewTypeForEncodingErr(val, "*tapscriptSigDesc")
}

// dTapscriptSigDesc is a decoder for tapscriptSigDesc.
func dTapscriptSigDesc(r io.Reader, val interface{},
	_ *[8]byte, _ uint64) error {

	if typ, ok := val.(*TapscriptSigDesc); ok {
		return typ.Decode(r)
	}

	return tlv.NewTypeForEncodingErr(val, "*tapscriptSigDesc")
}

// Record returns a tlv.Record that represents the tapscriptSigDesc.
func (t *TapscriptSigDesc) Record() tlv.Record {
	size := func() uint64 {
		var (
			buf     bytes.Buffer
			scratch [8]byte
		)
		err := eTapscriptSigDesc(&buf, t, &scratch)
		if err != nil {
			panic(err)
		}

		return uint64(buf.Len())
	}

	return tlv.MakeDynamicRecord(
		0, t, size, eTapscriptSigDesc, dTapscriptSigDesc,
	)
}

// ContractResolution houses all the information we need to resolve a contract
// on chain. This includes a series of pre-populated and pre-signed vPackets.
// The internal key, and other on-chain anchor information may be missing from
// these packets.
type ContractResolution struct {
	// firstLevelSweepVpkts is a list of pre-signed vPackets that can be
	// anchored into an output in a transaction where the referenced
	// previous inputs are spent to sweep an asset.
	firstLevelSweepVpkts tlv.RecordT[tlv.TlvType0, VpktList]

	// secondLevelSweepVpkts is a list of pre-signed vPackets that can be
	// anchored into an output in a transaction where the referenced
	// previous inputs are spent to sweep an asset.
	secondLevelSweepVpkts tlv.OptionalRecordT[tlv.TlvType1, VpktList]

	// secondLevelSigDescs is a list of tapscriptSigDescs that contain the
	// information we need to sign for each second level vPkt once the
	// sweeping transaction is known.
	secondLevelSigDescs tlv.OptionalRecordT[tlv.TlvType2, TapscriptSigDesc]
}

// NewContractResolution creates a new ContractResolution with the given list
// of vpkts.
func NewContractResolution(firstLevelPkts, secondLevelPkts []*tappsbt.VPacket,
	secondLevelSweepDesc lfn.Option[TapscriptSigDesc]) ContractResolution {

	c := ContractResolution{
		firstLevelSweepVpkts: tlv.NewRecordT[tlv.TlvType0](
			NewVpktList(firstLevelPkts),
		),
	}

	if len(secondLevelPkts) != 0 {
		c.secondLevelSweepVpkts = tlv.SomeRecordT(
			tlv.NewRecordT[tlv.TlvType1](
				NewVpktList(secondLevelPkts),
			),
		)
	}

	secondLevelSweepDesc.WhenSome(func(sigDesc TapscriptSigDesc) {
		c.secondLevelSigDescs = tlv.SomeRecordT(
			tlv.NewRecordT[tlv.TlvType2](sigDesc),
		)
	})

	return c
}

// Records returns the records that make up the ContractResolution.
func (c *ContractResolution) Records() []tlv.Record {
	records := []tlv.Record{
		c.firstLevelSweepVpkts.Record(),
	}

	c.secondLevelSweepVpkts.WhenSome(
		func(r tlv.RecordT[tlv.TlvType1, VpktList]) {
			records = append(records, r.Record())
		},
	)
	c.secondLevelSigDescs.WhenSome(
		func(r tlv.RecordT[tlv.TlvType2, TapscriptSigDesc]) {
			records = append(records, r.Record())
		},
	)

	return records
}

// Encode serializes the ContractResolution to the given io.Writer.
func (c *ContractResolution) Encode(w io.Writer) error {
	tlvStream, err := tlv.NewStream(c.Records()...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the ContractResolution from the given io.Reader.
func (c *ContractResolution) Decode(r io.Reader) error {
	sweepZero := c.secondLevelSweepVpkts.Zero()
	sigZero := c.secondLevelSigDescs.Zero()

	tlvStream, err := tlv.NewStream(
		c.firstLevelSweepVpkts.Record(),
		sweepZero.Record(),
		sigZero.Record(),
	)
	if err != nil {
		return err
	}

	tlvs, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	if _, ok := tlvs[sweepZero.TlvType()]; ok {
		c.secondLevelSweepVpkts = tlv.SomeRecordT(sweepZero)
	}
	if _, ok := tlvs[sigZero.TlvType()]; ok {
		c.secondLevelSigDescs = tlv.SomeRecordT(sigZero)
	}

	return nil
}

// SigDescs returns the list of tapscriptSigDescs.
func (c *ContractResolution) SigDescs() lfn.Option[TapscriptSigDesc] {
	return c.secondLevelSigDescs.ValOpt()
}

// Vpkts1 returns the set of first level Vpkts.
func (c *ContractResolution) Vpkts1() []*tappsbt.VPacket {
	return c.firstLevelSweepVpkts.Val.Pkts
}

// Vpkts2 returns the set of first level Vpkts.
func (c *ContractResolution) Vpkts2() []*tappsbt.VPacket {
	var vPkts []*tappsbt.VPacket
	c.secondLevelSweepVpkts.WhenSomeV(func(v VpktList) {
		vPkts = v.Pkts
	})

	return vPkts
}
