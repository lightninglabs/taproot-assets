package proof

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/url"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
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

func CommitmentProofsEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*map[asset.SerializedKey]commitment.Proof); ok {
		numProofs := uint64(len(*t))
		if err := tlv.WriteVarInt(w, numProofs, buf); err != nil {
			return err
		}

		var proofBuf bytes.Buffer
		for key, proof := range *t {
			var keyBytes [33]byte
			copy(keyBytes[:], key[:])

			err := tlv.EBytes33(w, &keyBytes, buf)
			if err != nil {
				return err
			}

			if err := proof.Encode(&proofBuf); err != nil {
				return err
			}

			proofBytes := proofBuf.Bytes()
			err = asset.InlineVarBytesEncoder(w, &proofBytes, buf)
			if err != nil {
				return err
			}

			proofBuf.Reset()
		}
		return nil
	}

	return tlv.NewTypeForEncodingErr(
		val, "map[asset.SerializedKey]CommitmentProof",
	)
}

func CommitmentProofsDecoder(r io.Reader, val any, buf *[8]byte,
	_ uint64) error {

	if typ, ok := val.(*map[asset.SerializedKey]commitment.Proof); ok {
		numProofs, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// Avoid OOM by limiting the number of commitment proofs we
		// accept.
		if numProofs > MaxNumTaprootProofs {
			return fmt.Errorf("%w: too many commitment proofs",
				ErrProofInvalid)
		}

		proofs := make(
			map[asset.SerializedKey]commitment.Proof, numProofs,
		)
		for i := uint64(0); i < numProofs; i++ {
			var keyBytes [33]byte

			err := tlv.DBytes33(
				r, &keyBytes, buf,
				btcec.PubKeyBytesLenCompressed,
			)
			if err != nil {
				return err
			}

			var proofBytes []byte
			err = asset.InlineVarBytesDecoder(
				r, &proofBytes, buf, MaxTaprootProofSizeBytes,
			)
			if err != nil {
				return err
			}

			var key asset.SerializedKey
			copy(key[:], keyBytes[:])

			var proof commitment.Proof
			err = proof.Decode(bytes.NewReader(proofBytes))
			if err != nil {
				return err
			}

			proofs[key] = proof
		}

		*typ = proofs
		return nil
	}

	return tlv.NewTypeForEncodingErr(
		val, "map[asset.SerializedKey]CommitmentProof",
	)
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

// EUint32Option encodes a uint32 option. If the value is not set, we'll encode
// it as a zero-length record. But that means that the type and length fields
// will still be encoded, which is different from the record not being present
// at all. If the distinction should be made (e.g. to not re-encode old records
// that didn't have that field at all with the new zero-length record), the
// caller needs to handle that by conditionally including or not including the
// record.
func EUint32Option(w io.Writer, val interface{}, buf *[8]byte) error {
	if t, ok := val.(*fn.Option[uint32]); ok {
		return fn.MapOptionZ(*t, func(value uint32) error {
			return tlv.EUint32T(w, value, buf)
		})
	}
	return tlv.NewTypeForEncodingErr(val, "*fn.Option[uint32]")
}

// DUint32Option decodes a uint32 option.
func DUint32Option(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if t, ok := val.(*fn.Option[uint32]); ok {
		if l == 0 {
			*t = fn.None[uint32]()
			return nil
		}

		var newVal uint32
		if err := tlv.DUint32(r, &newVal, buf, l); err != nil {
			return err
		}

		*t = fn.Some(newVal)

		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "*fn.Option[uint32]", l, l)
}

// UrlSliceOptionEncoder encodes a URL option. If the value is not set, or the
// slice is empty, we'll encode it as a zero-length record. But that means that
// the type and length fields will still be encoded, which is different from the
// record not being present at all. If the distinction should be made (e.g. to
// not re-encode old records that didn't have that field at all with the new
// zero-length record), the caller needs to handle that by conditionally
// including or not including the record.
func UrlSliceOptionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*fn.Option[[]url.URL]); ok {
		return fn.MapOptionZ(*t, func(value []url.URL) error {
			numValues := uint64(len(value))
			if numValues == 0 {
				return nil
			}

			err := tlv.WriteVarInt(w, numValues, buf)
			if err != nil {
				return err
			}

			for _, addr := range value {
				addrBytes := []byte(addr.String())
				err := asset.InlineVarBytesEncoder(
					w, &addrBytes, buf,
				)
				if err != nil {
					return err
				}
			}

			return nil
		})
	}
	return tlv.NewTypeForEncodingErr(val, "*fn.Option[[]url.URL]")
}

// UrlSliceOptionDecoder decodes a URL option.
func UrlSliceOptionDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if l > MaxNumCanonicalUniverseURLs*MaxCanonicalUniverseURLLength {
		return tlv.ErrRecordTooLarge
	}

	if t, ok := val.(*fn.Option[[]url.URL]); ok {
		if l == 0 {
			*t = fn.None[[]url.URL]()

			return nil
		}

		numValues, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		if numValues > MaxNumCanonicalUniverseURLs {
			return tlv.ErrRecordTooLarge
		}

		urls := make([]url.URL, 0, numValues)
		for i := uint64(0); i < numValues; i++ {
			var urlBytes []byte
			err := asset.InlineVarBytesDecoder(
				r, &urlBytes, buf,
				MaxCanonicalUniverseURLLength,
			)
			if err != nil {
				return err
			}

			addr, err := url.ParseRequestURI(string(urlBytes))
			if err != nil {
				return err
			}
			urls = append(urls, *addr)
		}

		*t = fn.Some(urls)

		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "*fn.Option[[]url.URL]", l, l)
}

// PublicKeyOptionEncoder encodes a public key option. If the value is not set,
// we'll encode it as a zero-length record. But that means that the type and
// length fields will still be encoded, which is different from the record not
// being present at all. If the distinction should be made (e.g. to not
// re-encode old records that didn't have that field at all with the new
// zero-length record), the caller needs to handle that by conditionally
// including or not including the record.
func PublicKeyOptionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*fn.Option[btcec.PublicKey]); ok {
		return fn.MapOptionZ(*t, func(value btcec.PublicKey) error {
			if value == emptyKey {
				return nil
			}

			ptr := &value
			return asset.CompressedPubKeyEncoder(w, &ptr, buf)
		})
	}
	return tlv.NewTypeForEncodingErr(val, "*fn.Option[btcec.PublicKey]")
}

// PublicKeyOptionDecoder decodes a public key option.
func PublicKeyOptionDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	if l > btcec.PubKeyBytesLenCompressed {
		return tlv.ErrRecordTooLarge
	}

	if t, ok := val.(*fn.Option[btcec.PublicKey]); ok {
		if l == 0 {
			*t = fn.None[btcec.PublicKey]()

			return nil
		}

		var result *btcec.PublicKey
		err := asset.CompressedPubKeyDecoder(r, &result, buf, l)
		if err != nil {
			return err
		}

		if result == nil || *result == emptyKey {
			*t = fn.None[btcec.PublicKey]()

			return nil
		}

		*t = fn.Some(*result)

		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "*fn.Option[btcec.PublicKey]", l, l,
	)
}
