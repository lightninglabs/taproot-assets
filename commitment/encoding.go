package commitment

import (
	"bytes"
	"io"

	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

func ProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*Proof); ok {
		return t.Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "*Proof")
}

func ProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*Proof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof Proof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}
		*typ = proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*Proof")
}

func AssetProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**AssetProof); ok {
		records := []tlv.Record{
			AssetProofVersionRecord(&(*t).Version),
			AssetProofAssetIDRecord(&(*t).AssetID),
			AssetProofRecord(&(*t).Proof),
		}
		stream, err := tlv.NewStream(records...)
		if err != nil {
			return err
		}
		return stream.Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "*commitment.AssetProof")
}

func AssetProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**AssetProof); ok {
		var streamBytes []byte
		if err := tlv.DVarBytes(r, &streamBytes, buf, l); err != nil {
			return err
		}
		var proof AssetProof
		records := []tlv.Record{
			AssetProofVersionRecord(&proof.Version),
			AssetProofAssetIDRecord(&proof.AssetID),
			AssetProofRecord(&proof.Proof),
		}
		stream, err := tlv.NewStream(records...)
		if err != nil {
			return err
		}
		if err := stream.Decode(bytes.NewReader(streamBytes)); err != nil {
			return err
		}
		*typ = &proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*commitment.AssetProof")
}

func TaroProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TaroProof); ok {
		records := []tlv.Record{
			TaroProofVersionRecord(&(*t).Version),
			TaroProofRecord(&(*t).Proof),
		}
		stream, err := tlv.NewStream(records...)
		if err != nil {
			return err
		}
		return stream.Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "commitment.TaroProof")
}

func TaroProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*TaroProof); ok {
		var streamBytes []byte
		if err := tlv.DVarBytes(r, &streamBytes, buf, l); err != nil {
			return err
		}
		var proof TaroProof
		records := []tlv.Record{
			TaroProofVersionRecord(&proof.Version),
			TaroProofRecord(&proof.Proof),
		}
		stream, err := tlv.NewStream(records...)
		if err != nil {
			return err
		}
		if err := stream.Decode(bytes.NewReader(streamBytes)); err != nil {
			return err
		}
		*typ = proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "commitment.TaroProof")
}

func TreeProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*mssmt.Proof); ok {
		return t.Compress().Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "mssmt.Proof")
}

func TreeProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*mssmt.Proof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof mssmt.CompressedProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}

		fullProof, err := proof.Decompress()
		if err != nil {
			return err
		}

		*typ = *fullProof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "mssmt.Proof")
}
