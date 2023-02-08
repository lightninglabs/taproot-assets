package asset

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrTooManyInputs is returned when an asset TLV atempts to reference
	// too many inputs.
	ErrTooManyInputs = errors.New("witnesses: witness elements")

	// ErrByteSliceTooLarge is returned when an encoded byte slice is too
	// large.
	ErrByteSliceTooLarge = errors.New("bytes: too large")
)

func VarIntEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*uint64); ok {
		return tlv.WriteVarInt(w, *t, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "uint64")
}

func VarIntDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*uint64); ok {
		num, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}
		*typ = num
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "uint64", 8, l)
}

func VarBytesEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*[]byte); ok {
		if err := tlv.WriteVarInt(w, uint64(len(*t)), buf); err != nil {
			return err
		}
		return tlv.EVarBytes(w, t, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "[]byte")
}

func VarBytesDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*[]byte); ok {
		bytesLen, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// We'll limit all decoded byte slices to prevent memory blow
		// ups or panics.
		if bytesLen > (2<<24)-1 {
			return fmt.Errorf("%w: %v", ErrByteSliceTooLarge,
				bytesLen)
		}

		var bytes []byte
		if err := tlv.DVarBytes(r, &bytes, buf, bytesLen); err != nil {
			return err
		}
		*typ = bytes
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]byte")
}

func OutPointEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*wire.OutPoint); ok {
		hash := [32]byte(t.Hash)
		if err := tlv.EBytes32(w, &hash, buf); err != nil {
			return err
		}
		return tlv.EUint32T(w, t.Index, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "wire.OutPoint")
}

func OutPointDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*wire.OutPoint); ok {
		var hash [32]byte
		if err := tlv.DBytes32(r, &hash, buf, 32); err != nil {
			return err
		}
		var index uint32
		if err := tlv.DUint32(r, &index, buf, 4); err != nil {
			return err
		}
		*typ = wire.OutPoint{Hash: chainhash.Hash(hash), Index: index}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "wire.OutPoint")
}

func CompressedPubKeyEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**btcec.PublicKey); ok {
		var keyBytes [btcec.PubKeyBytesLenCompressed]byte
		copy(keyBytes[:], (*t).SerializeCompressed())
		return tlv.EBytes33(w, &keyBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*btcec.PublicKey")
}

func CompressedPubKeyDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**btcec.PublicKey); ok {
		var keyBytes [btcec.PubKeyBytesLenCompressed]byte
		err := tlv.DBytes33(r, &keyBytes, buf, btcec.PubKeyBytesLenCompressed)
		if err != nil {
			return err
		}
		var key *btcec.PublicKey
		// Handle empty key, which is not on the curve.
		if keyBytes == [btcec.PubKeyBytesLenCompressed]byte{} {
			key = &btcec.PublicKey{}
		} else {
			key, err = btcec.ParsePubKey(keyBytes[:])
			if err != nil {
				return err
			}
		}
		*typ = key
		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "*btcec.PublicKey", l, btcec.PubKeyBytesLenCompressed,
	)
}

func SchnorrSignatureEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*schnorr.Signature); ok {
		var sigBytes [schnorr.SignatureSize]byte
		copy(sigBytes[:], t.Serialize())
		return tlv.EBytes64(w, &sigBytes, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "schnorr.Signature")
}

func SchnorrSignatureDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*schnorr.Signature); ok {
		var sigBytes [schnorr.SignatureSize]byte
		err := tlv.DBytes64(r, &sigBytes, buf, schnorr.SignatureSize)
		if err != nil {
			return err
		}
		sig, err := schnorr.ParseSignature(sigBytes[:])
		if err != nil {
			return err
		}
		*typ = *sig
		return nil
	}
	return tlv.NewTypeForDecodingErr(
		val, "schnorr.Signature", l, schnorr.SignatureSize,
	)
}

func VersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*Version); ok {
		return tlv.EUint8T(w, uint8(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "Version")
}

func VersionDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*Version); ok {
		var t uint8
		if err := tlv.DUint8(r, &t, buf, l); err != nil {
			return err
		}
		*typ = Version(t)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "Version", l, 1)
}

func IDEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*ID); ok {
		id := [sha256.Size]byte(*t)
		return tlv.EBytes32(w, &id, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "ID")
}

func IDDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*ID); ok {
		var id [sha256.Size]byte
		if err := tlv.DBytes32(r, &id, buf, l); err != nil {
			return err
		}
		*typ = ID(id)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "ID", l, sha256.Size)
}

func SerializedKeyEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*SerializedKey); ok {
		id := [btcec.PubKeyBytesLenCompressed]byte(*t)

		withParity := id[:]
		return tlv.EVarBytes(w, &withParity, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "SerializedKey")
}

func SerializedKeyDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*SerializedKey); ok {
		var keyBytes [btcec.PubKeyBytesLenCompressed]byte
		err := tlv.DBytes33(r, &keyBytes, buf, btcec.PubKeyBytesLenCompressed)
		if err != nil {
			return err
		}

		// Handle empty key, which is not on the curve.
		if keyBytes == [btcec.PubKeyBytesLenCompressed]byte{} {
			*typ = SerializedKey{}
			return nil
		}

		pubKey, err := btcec.ParsePubKey(keyBytes[:])
		if err != nil {
			return err
		}
		*typ = ToSerialized(pubKey)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "SerializedKey", l, btcec.PubKeyBytesLenCompressed)
}

func TypeEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*Type); ok {
		return tlv.EUint8T(w, uint8(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "Type")
}

func TypeDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*Type); ok {
		var t uint8
		if err := tlv.DUint8(r, &t, buf, l); err != nil {
			return err
		}
		*typ = Type(t)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "Type", l, 1)
}

func GenesisEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*Genesis); ok {
		err := OutPointEncoder(w, &t.FirstPrevOut, buf)
		if err != nil {
			return err
		}
		tagBytes := []byte(t.Tag)
		if err := VarBytesEncoder(w, &tagBytes, buf); err != nil {
			return err
		}
		if err := VarBytesEncoder(w, &t.Metadata, buf); err != nil {
			return err
		}
		if err := tlv.EUint32T(w, t.OutputIndex, buf); err != nil {
			return err
		}
		return TypeEncoder(w, &t.Type, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "Genesis")
}

func GenesisDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*Genesis); ok {
		var genesis Genesis
		err := OutPointDecoder(r, &genesis.FirstPrevOut, buf, 0)
		if err != nil {
			return err
		}
		var tag []byte
		if err = VarBytesDecoder(r, &tag, buf, 0); err != nil {
			return err
		}
		genesis.Tag = string(tag)
		err = VarBytesDecoder(r, &genesis.Metadata, buf, 0)
		if err != nil {
			return err
		}
		err = tlv.DUint32(r, &genesis.OutputIndex, buf, 4)
		if err != nil {
			return err
		}
		err = TypeDecoder(r, &genesis.Type, buf, 1)
		if err != nil {
			return err
		}
		*typ = genesis
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "Genesis")
}

func PrevIDEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**PrevID); ok {
		if err := OutPointEncoder(w, &(**t).OutPoint, buf); err != nil {
			return err
		}
		if err := IDEncoder(w, &(**t).ID, buf); err != nil {
			return err
		}
		return SerializedKeyEncoder(w, &(**t).ScriptKey, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*PrevID")
}

func PrevIDDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**PrevID); ok {
		var prevID PrevID
		err := OutPointDecoder(r, &prevID.OutPoint, buf, 0)
		if err != nil {
			return err
		}
		if err = IDDecoder(r, &prevID.ID, buf, sha256.Size); err != nil {
			return err
		}
		if err = SerializedKeyDecoder(
			r, &prevID.ScriptKey, buf, btcec.PubKeyBytesLenCompressed,
		); err != nil {
			return err
		}
		*typ = &prevID
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "*PrevID", l, l)
}

func TxWitnessEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*wire.TxWitness); ok {
		if err := tlv.WriteVarInt(w, uint64(len(*t)), buf); err != nil {
			return err
		}
		for _, part := range *t {
			part := part
			if err := VarBytesEncoder(w, &part, buf); err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*wire.TxWitness")
}

func TxWitnessDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*wire.TxWitness); ok {
		numItems, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// We won't accept anything beyond the set of max witness
		// elements. We're being generous here, as for the bitcoin VM
		// the true stack limit is much smaller.
		if numItems > math.MaxUint16 {
			return ErrTooManyInputs
		}

		witness := make(wire.TxWitness, 0, numItems)
		for i := uint64(0); i < numItems; i++ {
			var item []byte
			if err := VarBytesDecoder(r, &item, buf, 0); err != nil {
				return err
			}
			witness = append(witness, item)
		}
		*typ = witness
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*wire.TxWitness")
}

func WitnessEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*[]Witness); ok {
		if err := tlv.WriteVarInt(w, uint64(len(*t)), buf); err != nil {
			return err
		}
		for _, assetWitness := range *t {
			var streamBuf bytes.Buffer
			if err := assetWitness.Encode(&streamBuf); err != nil {
				return err
			}
			streamBytes := streamBuf.Bytes()
			err := VarBytesEncoder(w, &streamBytes, buf)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]Witness")
}

func WitnessDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(*[]Witness); ok {
		numItems, err := tlv.ReadVarInt(r, buf)
		if err != nil {
			return err
		}

		// We use a varint, but will practically limit the number of
		// witnesses to a sane number.
		//
		// TODO(roasbeef): just use a uint8 here?
		if numItems > math.MaxUint16 {
			return fmt.Errorf("%w: %v", ErrTooManyInputs, numItems)
		}

		*typ = make([]Witness, 0, numItems)
		for i := uint64(0); i < numItems; i++ {
			var streamBytes []byte
			err := VarBytesDecoder(r, &streamBytes, buf, 0)
			if err != nil {
				return err
			}
			var assetWitness Witness
			err = assetWitness.Decode(bytes.NewReader(streamBytes))
			if err != nil {
				return err
			}
			*typ = append(*typ, assetWitness)
		}
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "[]Witness")
}

func SplitCommitmentEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**SplitCommitment); ok {
		// TODO: Make nested TLVs?
		var proof bytes.Buffer
		if err := (*t).Proof.Compress().Encode(&proof); err != nil {
			return err
		}
		proofBytes := proof.Bytes()
		if err := VarBytesEncoder(w, &proofBytes, buf); err != nil {
			return err
		}
		var rootAsset bytes.Buffer
		if err := (*t).RootAsset.Encode(&rootAsset); err != nil {
			return err
		}
		rootAssetBytes := rootAsset.Bytes()
		return VarBytesEncoder(w, &rootAssetBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*SplitCommitment")
}

func SplitCommitmentDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**SplitCommitment); ok {
		var proofBytes []byte
		if err := VarBytesDecoder(r, &proofBytes, buf, l); err != nil {
			return err
		}

		var proof mssmt.CompressedProof
		if err := proof.Decode(bytes.NewReader(proofBytes)); err != nil {
			return err
		}

		var rootAssetBytes []byte
		err := VarBytesDecoder(r, &rootAssetBytes, buf, l)
		if err != nil {
			return err
		}

		var rootAsset Asset
		err = rootAsset.Decode(bytes.NewReader(rootAssetBytes))
		if err != nil {
			return err
		}

		fullProof, err := proof.Decompress()
		if err != nil {
			return err
		}

		*typ = &SplitCommitment{
			Proof:     *fullProof,
			RootAsset: rootAsset,
		}

		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "*SplitCommitment", l, 40)
}

func SplitCommitmentRootEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*mssmt.Node); ok {
		key := [32]byte((*t).NodeHash())
		if err := tlv.EBytes32(w, &key, buf); err != nil {
			return err
		}
		return tlv.EUint64T(w, (*t).NodeSum(), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "mssmt.Node")
}

func SplitCommitmentRootDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*mssmt.Node); ok {
		var key [32]byte
		if err := tlv.DBytes32(r, &key, buf, 32); err != nil {
			return err
		}
		var sum uint64
		if err := tlv.DUint64(r, &sum, buf, 8); err != nil {
			return err
		}
		*typ = mssmt.NewComputedNode(key, sum)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "mssmt.Node", l, 40)
}

func ScriptVersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*ScriptVersion); ok {
		return tlv.EUint16T(w, uint16(*t), buf)
	}
	return tlv.NewTypeForEncodingErr(val, "ScriptVersion")
}

func ScriptVersionDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*ScriptVersion); ok {
		var t uint16
		if err := tlv.DUint16(r, &t, buf, l); err != nil {
			return err
		}
		*typ = ScriptVersion(t)
		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "ScriptVersion", l, 2)
}

func GroupKeyEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**GroupKey); ok {
		key := &(*t).GroupPubKey
		if err := CompressedPubKeyEncoder(w, &key, buf); err != nil {
			return err
		}
		sig := (*t).Sig
		return SchnorrSignatureEncoder(w, &sig, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*GroupKey")
}

func GroupKeyDecoder(r io.Reader, val any, buf *[8]byte, _ uint64) error {
	if typ, ok := val.(**GroupKey); ok {
		var (
			groupKey    GroupKey
			groupPubKey *btcec.PublicKey
		)
		err := CompressedPubKeyDecoder(
			r, &groupPubKey, buf, btcec.PubKeyBytesLenCompressed,
		)
		if err != nil {
			return err
		}
		err = SchnorrSignatureDecoder(
			r, &groupKey.Sig, buf, schnorr.SignatureSize,
		)
		if err != nil {
			return err
		}
		groupKey.GroupPubKey = *groupPubKey
		*typ = &groupKey
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "*GroupKey")
}

func LeafEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**Asset); ok {
		return (*t).Encode(w)
	}
	return tlv.NewTypeForEncodingErr(val, "Asset")
}

func LeafDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(**Asset); ok {
		var assetBytes []byte
		if err := tlv.DVarBytes(r, &assetBytes, buf, l); err != nil {
			return err
		}
		asset := &Asset{}
		if err := asset.Decode(bytes.NewReader(assetBytes)); err != nil {
			return err
		}
		*typ = asset
		return nil
	}
	return tlv.NewTypeForEncodingErr(val, "Asset")
}
