package universe

import (
	"bytes"
	"crypto/sha256"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

type (
	// IgnoreTupleType is the TLV type for the tuple field in a
	// SignedIgnoreTuple.
	IgnoreTupleType = tlv.TlvType0

	// IgnoreSignatureType is the TLV type for the signature field in a
	// SignedIgnoreTuple.
	IgnoreSignatureType = tlv.TlvType2
)

// IgnoreTuple represents an asset previous ID that we want to ignore.
type IgnoreTuple struct {
	asset.PrevID

	// Amount is the total asset unit amount associated with asset.PrevID.
	Amount uint64
}

func ignoreTupleEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*IgnoreTuple); ok {
		err := asset.OutPointEncoder(w, &t.OutPoint, buf)
		if err != nil {
			return err
		}
		if err := asset.IDEncoder(w, &t.ID, buf); err != nil {
			return err
		}
		err = asset.SerializedKeyEncoder(w, &t.ScriptKey, buf)
		if err != nil {
			return err
		}

		return tlv.EUint64(w, &t.Amount, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*PrevID")
}

func ignoreTupleDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*IgnoreTuple); ok {
		var prevID asset.PrevID
		err := asset.OutPointDecoder(r, &prevID.OutPoint, buf, 0)
		if err != nil {
			return err
		}
		err = asset.IDDecoder(r, &prevID.ID, buf, sha256.Size)
		if err != nil {
			return err
		}
		if err = asset.SerializedKeyDecoder(
			r, &prevID.ScriptKey, buf,
			btcec.PubKeyBytesLenCompressed,
		); err != nil {
			return err
		}

		var amt uint64
		if err = tlv.DUint64(r, &amt, buf, 8); err != nil {
			return err
		}

		*typ = IgnoreTuple{
			PrevID: prevID,
			Amount: amt,
		}
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "*PrevID", l, l)
}

// Record returns the TLV record for the IgnoreTuple.
func (i *IgnoreTuple) Record() tlv.Record {
	const recordSize = 8 + 36 + sha256.Size + btcec.PubKeyBytesLenCompressed

	return tlv.MakeStaticRecord(
		0, i, recordSize,
		ignoreTupleEncoder, ignoreTupleDecoder,
	)
}

// IgnoreTuples is a slice of IgnoreTuple.
type IgnoreTuples = []*IgnoreTuple

// IgnoreSignature is a Schnorr signature over an IgnoreTuple.
//
// TODO(roasbeef): sig validate methods, sig gen above
type IgnoreSig struct {
	schnorr.Signature
}

// Record returns the TLV record for the IgnoreSig.
func (s *IgnoreSig) Record() tlv.Record {
	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeStaticRecord(
		0, &s.Signature, schnorr.SignatureSize,
		asset.SchnorrSignatureEncoder, asset.SchnorrSignatureDecoder,
	)
}

// Encode serializes the IgnoreSig to the given io.Writer.
func (s *IgnoreSig) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(s.Record())
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes the IgnoreSig from the given io.Reader.
func (s *IgnoreSig) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(s.Record())
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// SignedIgnoreTuple wraps an IgnoreTuple with a signature.
type SignedIgnoreTuple struct {
	// IgnoreTuple is the tuple that is being signed.
	IgnoreTuple tlv.RecordT[IgnoreTupleType, IgnoreTuple]

	// Sig is the signature over the tuple.
	Sig tlv.RecordT[IgnoreSignatureType, IgnoreSig]
}

// NewSignedIgnoreTuple creates a new SignedIgnoreTuple with the given tuple and
// sig.
func NewSignedIgnoreTuple(tuple IgnoreTuple, sig IgnoreSig) SignedIgnoreTuple {
	return SignedIgnoreTuple{
		IgnoreTuple: tlv.NewRecordT[IgnoreTupleType](tuple),
		Sig:         tlv.NewRecordT[IgnoreSignatureType](sig),
	}
}

// records returns the records that make up the SignedIgnoreTuple.
func (s *SignedIgnoreTuple) records() []tlv.Record {
	return []tlv.Record{
		s.IgnoreTuple.Record(),
		s.Sig.Record(),
	}
}

// Encode serializes the SignedIgnoreTuple to the given io.Writer.
func (s *SignedIgnoreTuple) Encode(w io.Writer) error {
	tlvRecords := s.records()

	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the SignedIgnoreTuple from the given io.Reader.
func (s *SignedIgnoreTuple) Decode(r io.Reader) error {
	tlvStream, err := tlv.NewStream(s.records()...)
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

// Bytes returns the serialized SignedIgnoreTuple record.
func (s *SignedIgnoreTuple) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := s.Encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UniverseLeafNode returns an MS-SMT leaf for the SignedIgnoreTuple.
func (i *SignedIgnoreTuple) UniverseLeafNode() (*mssmt.LeafNode, error) {
	// Serialize the raw value of the tuple to insert into
	// the tree.
	rawVal, err := i.Bytes()
	if err != nil {
		return nil, err
	}

	return mssmt.NewLeafNode(rawVal, i.IgnoreTuple.Val.Amount), nil
}

// UniverseKey returns the universe tree key for the SignedIgnoreTuple.
func (i *SignedIgnoreTuple) UniverseKey() [32]byte {
	return i.IgnoreTuple.Val.Hash()
}

// DecodeSignedIgnoreTuple deserializes a SignedIgnoreTuple from the given blob.
func DecodeSignedIgnoreTuple(blob []byte) (SignedIgnoreTuple, error) {
	var s SignedIgnoreTuple
	err := s.Decode(bytes.NewReader(blob))
	if err != nil {
		var s SignedIgnoreTuple
		return s, err
	}

	return s, nil
}
