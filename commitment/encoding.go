package commitment

import (
	"bytes"
	"io"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

func AssetProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**AssetProof); ok {
		records := []tlv.Record{
			AssetProofVersionRecord(&(*t).Version),
			AssetProofAssetIDRecord(&(*t).TapKey),
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
	// We currently only use this with tlv.DecodeP2P, but in case we ever
	// don't, we still want to enforce a limit.
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

	if typ, ok := val.(**AssetProof); ok {
		var streamBytes []byte
		if err := tlv.DVarBytes(r, &streamBytes, buf, l); err != nil {
			return err
		}
		var proof AssetProof
		records := []tlv.Record{
			AssetProofVersionRecord(&proof.Version),
			AssetProofAssetIDRecord(&proof.TapKey),
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

func TaprootAssetProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TaprootAssetProof); ok {
		records := []tlv.Record{
			TaprootAssetProofVersionRecord(&(*t).Version),
			TaprootAssetProofRecord(&(*t).Proof),
		}
		stream, err := tlv.NewStream(records...)
		if err != nil {
			return err
		}
		return stream.Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "commitment.TaprootAssetProof")
}

func TaprootAssetProofDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	// We currently only use this with tlv.DecodeP2P, but in case we ever
	// don't, we still want to enforce a limit.
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

	if typ, ok := val.(*TaprootAssetProof); ok {
		var streamBytes []byte
		if err := tlv.DVarBytes(r, &streamBytes, buf, l); err != nil {
			return err
		}
		var proof TaprootAssetProof
		records := []tlv.Record{
			TaprootAssetProofVersionRecord(&proof.Version),
			TaprootAssetProofRecord(&proof.Proof),
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
	return tlv.NewTypeForEncodingErr(val, "commitment.TaprootAssetProof")
}

func TreeProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*mssmt.Proof); ok {
		return t.Compress().Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "mssmt.Proof")
}

func TreeProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	// We currently only use this with tlv.DecodeP2P, but in case we ever
	// don't, we still want to enforce a limit.
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

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

func TapscriptPreimageEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**TapscriptPreimage); ok {
		// We'll encode the pre-image as 1 byte for the type of the
		// pre-image, and then the pre-image itself.
		siblingType := uint8((*t).siblingType)
		if err := tlv.EUint8(w, &siblingType, buf); err != nil {
			return err
		}

		return tlv.EVarBytes(w, &(*t).siblingPreimage, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "*TapscriptPreimage")
}

func TapscriptPreimageDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	// We currently only use this with tlv.DecodeP2P, but in case we ever
	// don't, we still want to enforce a limit.
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

	if l == 0 {
		return ErrInvalidTapscriptPreimageLen
	}

	if typ, ok := val.(**TapscriptPreimage); ok {
		var preimage TapscriptPreimage

		// First, read out the single byte for the sibling type.
		var siblingType uint8
		err := tlv.DUint8(r, &siblingType, buf, 1)
		if err != nil {
			return err
		}

		preimage.siblingType = TapscriptPreimageType(siblingType)

		// Now we'll read out the pre-image itself.
		err = tlv.DVarBytes(r, &preimage.siblingPreimage, buf, l-1)
		if err != nil {
			return err
		}

		*typ = &preimage
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "*TapscriptPreimage", l, l)
}
