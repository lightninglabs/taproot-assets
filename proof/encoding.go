package proof

import (
	"bytes"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

func BlockHeaderEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*wire.BlockHeader); ok {
		return t.Serialize(w)
	}
	return tlv.NewTypeForEncodingErr(val, "wire.BlockHeader")
}

func BlockHeaderDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*wire.BlockHeader); ok {
		var headerBytes []byte
		if err := tlv.DVarBytes(r, &headerBytes, buf, l); err != nil {
			return err
		}
		var header wire.BlockHeader
		err := header.Deserialize(bytes.NewReader(headerBytes))
		if err != nil {
			return err
		}
		*typ = header
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "wire.BlockHeader")
}

func TxEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*wire.MsgTx); ok {
		return t.Serialize(w)
	}
	return tlv.NewTypeForEncodingErr(val, "wire.MsgTx")
}

func TxDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*wire.MsgTx); ok {
		var txBytes []byte
		if err := tlv.DVarBytes(r, &txBytes, buf, l); err != nil {
			return err
		}
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
			return err
		}
		*typ = tx
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "wire.MsgTx")
}

func TxMerkleProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TxMerkleProof); ok {
		return t.Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "TxMerkleProof")
}

func TxMerkleProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*TxMerkleProof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof TxMerkleProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}
		*typ = proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "TxMerkleProof")
}

func TaprootProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TaprootProof); ok {
		return t.Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "TaprootProof")
}

func TaprootProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*TaprootProof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof TaprootProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}
		*typ = proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "TaprootProof")
}

func SplitRootProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**TaprootProof); ok {
		return (*t).Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "TaprootProof")
}

func SplitRootProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**TaprootProof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof TaprootProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}
		*typ = &proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "TaprootProof")
}

func TaprootProofsEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*[]TaprootProof); ok {
		numProofs := uint64(len(*t))
		if err := tlv.WriteVarInt(w, numProofs, buf); err != nil {
			return err
		}
		var proofBuf bytes.Buffer
		for _, proof := range *t {
			if err := proof.Encode(&proofBuf); err != nil {
				return err
			}
			proofBytes := proofBuf.Bytes()
			err := asset.VarBytesEncoder(w, &proofBytes, buf)
			if err != nil {
				return err
			}
			proofBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]TaprootProof")
}

func TaprootProofsDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*[]TaprootProof); ok {
		numProofs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}
		proofs := make([]TaprootProof, 0, numProofs)
		for i := uint64(0); i < numProofs; i++ {
			var proofBytes []byte
			err := asset.VarBytesDecoder(r, &proofBytes, buf, 0)
			if err != nil {
				return err
			}
			var proof TaprootProof
			err = proof.Decode(bytes.NewReader(proofBytes))
			if err != nil {
				return err
			}
			proofs = append(proofs, proof)
		}
		*typ = proofs
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]TaprootProof")
}

func AdditionalInputsEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*[]File); ok {
		numInputs := uint64(len(*t))
		if err := tlv.WriteVarInt(w, numInputs, buf); err != nil {
			return err
		}
		var inputFileBuf bytes.Buffer
		for _, inputFile := range *t {
			if err := inputFile.Encode(&inputFileBuf); err != nil {
				return err
			}
			inputFileBytes := inputFileBuf.Bytes()
			err := asset.VarBytesEncoder(w, &inputFileBytes, buf)
			if err != nil {
				return err
			}
			inputFileBuf.Reset()
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]File")
}

func AdditionalInputsDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*[]File); ok {
		numInputs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}
		inputFiles := make([]File, 0, numInputs)
		for i := uint64(0); i < numInputs; i++ {
			var inputFileBytes []byte
			err := asset.VarBytesDecoder(r, &inputFileBytes, buf, 0)
			if err != nil {
				return err
			}
			var inputFile File
			err = inputFile.Decode(bytes.NewReader(inputFileBytes))
			if err != nil {
				return err
			}
			inputFiles = append(inputFiles, inputFile)
		}
		*typ = inputFiles
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]File")
}

func CommitmentProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**CommitmentProof); ok {
		return (*t).Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "*CommitmentProof")
}

func CommitmentProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**CommitmentProof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof CommitmentProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}
		*typ = &proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*CommitmentProof")
}

func TapscriptProofEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**TapscriptProof); ok {
		return (*t).Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "*TapscriptProof")
}

func TapscriptProofDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**TapscriptProof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof TapscriptProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}
		*typ = &proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*TapscriptProof")
}

func TapscriptPreimageEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**TapscriptPreimage); ok {
		// We'll encode the pre-image as 1 byte for the type of the
		// pre-image, and then the pre-image itself.
		siblingType := uint8((*t).SiblingType)
		if err := tlv.EUint8(w, &siblingType, buf); err != nil {
			return err
		}

		return tlv.EVarBytes(w, &(*t).SiblingPreimage, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "*TapscriptPreimage")
}

func TapscriptPreimageDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	if typ, ok := val.(**TapscriptPreimage); ok {
		var preimage TapscriptPreimage

		// First, read out the single byte for the sibling type.
		var siblingType uint8
		err := tlv.DUint8(r, &siblingType, buf, 1)
		if err != nil {
			return err
		}

		preimage.SiblingType = TapscriptPreimageType(siblingType)

		// Now we'll read out the pre-image itself.
		err = tlv.DVarBytes(r, &preimage.SiblingPreimage, buf, l-1)
		if err != nil {
			return err
		}

		*typ = &preimage
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "*TapscriptPreimage", l, l)
}

func BoolEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*bool); ok {
		var intVal uint8
		if t != nil && *t {
			intVal = 1
		}

		return tlv.EUint8(w, &intVal, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "bool")
}

func BoolDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*bool); ok {
		var intVal uint8
		if err := tlv.DUint8(r, &intVal, buf, l); err != nil {
			return err
		}

		*typ = intVal == 1
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "bool")
}
