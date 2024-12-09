package proof

import (
	"bytes"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/tlv"
)

// Encoder encodes a proof to the given writer.
func Encoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*Proof); ok {
		return (*t).Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "Proof")
}

// Decoder decodes a proof from the given reader.
func Decoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if l > FileMaxProofSizeBytes {
		return tlv.ErrRecordTooLarge
	}
	if typ, ok := val.(*Proof); ok {
		var proofBytes []byte
		if err := tlv.DVarBytes(r, &proofBytes, buf, l); err != nil {
			return err
		}
		var proof Proof
		err := proof.Decode(bytes.NewReader(proofBytes))
		if err != nil {
			return err
		}
		*typ = proof
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "Proof")
}

func VersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*TransitionVersion); ok {
		return tlv.EUint32T(w, uint32(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "TransitionVersion")
}

func VersionDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*TransitionVersion); ok {
		var t uint32
		if err := tlv.DUint32(r, &t, buf, l); err != nil {
			return err
		}
		*typ = TransitionVersion(t)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "TransitionVersion", l, 1)
}

func BlockHeaderEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*wire.BlockHeader); ok {
		return t.Serialize(w)
	}
	return tlv.NewTypeForEncodingErr(val, "wire.BlockHeader")
}

func BlockHeaderDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if l != wire.MaxBlockHeaderPayload {
		return tlv.NewTypeForEncodingErr(val, "wire.BlockHeader")
	}

	if typ, ok := val.(*wire.BlockHeader); ok {
		var headerBytes [wire.MaxBlockHeaderPayload]byte
		if _, err := io.ReadFull(r, headerBytes[:]); err != nil {
			return err
		}
		var header wire.BlockHeader
		err := header.Deserialize(bytes.NewReader(headerBytes[:]))
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
	if l > blockchain.MaxBlockWeight {
		return tlv.ErrRecordTooLarge
	}

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
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

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
	if l > MaxTaprootProofSizeBytes {
		return tlv.ErrRecordTooLarge
	}

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
	if l > MaxTaprootProofSizeBytes {
		return tlv.ErrRecordTooLarge
	}

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
			err := asset.InlineVarBytesEncoder(w, &proofBytes, buf)
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

		// Avoid OOM by limiting the number of taproot proofs we accept.
		if numProofs > MaxNumTaprootProofs {
			return fmt.Errorf("%w: too many taproot proofs",
				ErrProofInvalid)
		}

		proofs := make([]TaprootProof, 0, numProofs)
		for i := uint64(0); i < numProofs; i++ {
			var proofBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &proofBytes, buf, MaxTaprootProofSizeBytes,
			)
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
			err := asset.InlineVarBytesEncoder(w, &inputFileBytes, buf)
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
	if l > FileMaxSizeBytes {
		return tlv.ErrRecordTooLarge
	}

	if typ, ok := val.(*[]File); ok {
		numInputs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// We only allow this many previous witnesses, so there can't
		// be more additional inputs as witnesses.
		if numInputs > math.MaxUint16 {
			return tlv.ErrRecordTooLarge
		}

		inputFiles := make([]File, 0, numInputs)
		for i := uint64(0); i < numInputs; i++ {
			var inputFileBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &inputFileBytes, buf, FileMaxSizeBytes,
			)
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
	if l > tlv.MaxRecordSize {
		return tlv.ErrRecordTooLarge
	}

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
	if l > tlv.MaxRecordSize*2 {
		return tlv.ErrRecordTooLarge
	}

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

func MetaRevealEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**MetaReveal); ok {
		return (*t).Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "*MetaReveal")
}

func MetaRevealDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if l > MetaDataMaxSizeBytes {
		return tlv.ErrRecordTooLarge
	}

	if typ, ok := val.(**MetaReveal); ok {
		var revealBytes []byte
		if err := tlv.DVarBytes(r, &revealBytes, buf, l); err != nil {
			return err
		}
		var reveal MetaReveal
		err := reveal.Decode(bytes.NewReader(revealBytes))
		if err != nil {
			return err
		}
		*typ = &reveal
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*MetaReveal")
}

func MetaTypeEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*MetaType); ok {
		return tlv.EUint8T(w, uint8(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "MetaType")
}

func MetaTypeDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*MetaType); ok {
		var metaType uint8
		if err := tlv.DUint8(r, &metaType, buf, l); err != nil {
			return err
		}
		*typ = MetaType(metaType)
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "MetaType")
}

func GenesisRevealEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**asset.Genesis); ok {
		return asset.GenesisEncoder(w, (*t), buf)
	}

	return tlv.NewTypeForEncodingErr(val, "GenesisReveal")
}

func GenesisRevealDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**asset.Genesis); ok {
		var genesis asset.Genesis
		if err := asset.GenesisDecoder(r, &genesis, buf, l); err != nil {
			return err
		}

		*typ = &genesis
		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "GenesisReveal")
}

func GroupKeyRevealEncoder(w io.Writer, val any, buf *[8]byte) error {
	// TODO(ffranr): When encoding V1 and onwards, we must fill rawKey,
	//  tapscriptRoot, and version. Ensuring these fields are populated will
	//  mean that older tapd nodes will reject the group key reveal cleanly
	//  (and not try to erroneously parse an unsupported group key reveal).

	if t, ok := val.(*asset.GroupKeyReveal); ok {
		key := (*t).RawKey()
		if err := asset.SerializedKeyEncoder(w, &key, buf); err != nil {
			return err
		}
		root := (*t).TapscriptRoot()
		return tlv.EVarBytes(w, &root, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "GroupKeyReveal")
}

func GroupKeyRevealDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if l < btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("%w: group key reveal too short",
			ErrProofInvalid)
	}

	if typ, ok := val.(*asset.GroupKeyReveal); ok {
		var rawKey asset.SerializedKey
		err := asset.SerializedKeyDecoder(
			r, &rawKey, buf, btcec.PubKeyBytesLenCompressed,
		)
		if err != nil {
			return err
		}

		// Compute remaining bytes. This calculation will not underflow
		// because we have already verified that the length is at least
		// the size of the compressed public key.
		remaining := l - btcec.PubKeyBytesLenCompressed

		// Attempt to read the tapscript root bytes if they are present.
		var tapscriptRootBytes []byte
		if remaining >= 32 {
			// At this point, there are at least 32 bytes remaining
			// which means that there is a tapscript root present.
			// Read the tapscript root bytes.
			err = tlv.DVarBytes(r, &tapscriptRootBytes, buf, 32)
			if err != nil {
				return err
			}

			// Update the remaining bytes length counter.
			remaining -= 32
		}

		// Set a nil taproot root to an empty slice. This ensures that
		// the encoding/decoding round trip is consistent.
		if tapscriptRootBytes == nil {
			tapscriptRootBytes = []byte{}
		}

		// If there are still bytes remaining, then the next byte should
		// be the group key reveal version.
		var version asset.GroupKeyRevealVersion
		if remaining > 0 {
			var v uint64
			err = tlv.DUint8(r, &v, buf, 1)
			if err != nil {
				return err
			}

			version = asset.GroupKeyRevealVersion(v)

			// Update the remaining bytes length counter.
			remaining -= 1
		}

		// If the parsed version is greater the latest group key reveal
		// version, then we reject the group key reveal.
		//
		// It is important to cleanly reject future versions of group
		// key reveals that are not supported by this version of tapd.
		// This safeguards compatibility for future upgrades to the
		// group key reveal format.
		if version > asset.LatestGroupKeyRevealVersion {
			return fmt.Errorf("unsupported group key reveal "+
				"version %d", version)
		}

		// If this is a version 0 group key reveal, then we can return
		// the group key reveal now.
		if version == asset.GroupKeyRevealVersion0 {
			*typ = asset.NewGroupKeyRevealV0(
				rawKey, tapscriptRootBytes,
			)
			return nil
		}

		// At this point, we know this is a version 1 group key reveal.
		// Future versions could parse different fields from this point
		// on.
		//
		// For clarity and robustness, we explicitly check for version
		// 1.
		if version != asset.GroupKeyRevealVersion1 {
			return fmt.Errorf("code error: expected group reveal "+
				"version 1, got %d", version)
		}

		// We can now cast the tapscript root bytes to a hash.
		var tapscriptRoot chainhash.Hash
		copy(tapscriptRoot[:], tapscriptRootBytes)

		// The remaining bytes should constitute the custom tapscript
		// tree root.
		var customTapscriptRoot fn.Option[chainhash.Hash]
		if remaining >= chainhash.HashSize {
			var rootBytes [32]byte
			err = tlv.DBytes32(
				r, &rootBytes, buf,
				chainhash.HashSize,
			)
			if err != nil {
				return fmt.Errorf("unable to read custom "+
					"tapscript tree root: %w", err)
			}

			var root chainhash.Hash
			copy(root[:], rootBytes[:])
			customTapscriptRoot = fn.Some(root)
		}

		*typ = asset.NewGroupKeyRevealV1(
			rawKey, tapscriptRoot, customTapscriptRoot,
		)

		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "GroupKeyReveal")
}
