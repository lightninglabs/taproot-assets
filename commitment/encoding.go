package commitment

import (
	"bytes"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

func TapCommitmentVersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TapCommitmentVersion); ok {
		return tlv.EUint8T(w, uint8(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "Version")
}

func TapCommitmentVersionDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	if typ, ok := val.(*TapCommitmentVersion); ok {
		var t uint8
		if err := tlv.DUint8(r, &t, buf, l); err != nil {
			return err
		}
		*typ = TapCommitmentVersion(t)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "Version", l, 1)
}

func AssetProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**AssetProof); ok {
		records := asset.CombineRecords(
			(*t).Records(), (*t).UnknownOddTypes,
		)
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
		stream, err := tlv.NewStream(proof.Records()...)
		if err != nil {
			return err
		}

		unknownOddTypes, err := asset.TlvStrictDecodeP2P(
			stream, bytes.NewReader(streamBytes),
			KnownAssetProofTypes,
		)
		if err != nil {
			return err
		}

		proof.UnknownOddTypes = unknownOddTypes

		*typ = &proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*commitment.AssetProof")
}

func TaprootAssetProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TaprootAssetProof); ok {
		records := asset.CombineRecords(
			(*t).Records(), (*t).UnknownOddTypes,
		)
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
		stream, err := tlv.NewStream(proof.Records()...)
		if err != nil {
			return err
		}

		unknownOddTypes, err := asset.TlvStrictDecodeP2P(
			stream, bytes.NewReader(streamBytes),
			KnownTaprootAssetProofTypes,
		)
		if err != nil {
			return err
		}

		proof.UnknownOddTypes = unknownOddTypes

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
