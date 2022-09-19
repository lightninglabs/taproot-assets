package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// MaxFileSize represents the maximum file size in bytes allowed for a
	// proof file.
	//
	// TODO: Come up with a more sensible value.
	MaxFileSize = math.MaxUint32
)

var (
	// ErrInvalidChecksum is an error returned when an invalid proof file
	// checksum is detected while deserializing it.
	ErrInvalidChecksum = errors.New("invalid proof file checksum")

	// ErrExceedsMaxFileSize is an error returned when a proof file exceeds
	// the maximum size allowed.
	ErrExceedsMaxFileSize = fmt.Errorf(
		"proof file exceeds maximum size of %d bytes", MaxFileSize,
	)
)

// Version denotes the versioning scheme for proof files.
type Version uint32

const (
	// V0 is the first version of the proof file.
	V0 Version = 0
)

// File represents a proof file comprised of proofs for all of an asset's state
// transitions back to its genesis state.
type File struct {
	// Version is the version of the proof file.
	Version Version

	// Proofs are the proofs contained within the proof file starting from
	// the genesis proof.
	Proofs []Proof
}

// NewFile returns a new proof file given a version and a series of state
// transition proofs.
func NewFile(v Version, proofs ...Proof) File {
	return File{
		Version: v,
		Proofs:  proofs,
	}
}

// AssetSnapshot commits to the result of a valid proof within a proof file.
// This represents the state of an asset's lineage at a given point in time.
type AssetSnapshot struct {
	// Asset is the resulting asset of a valid proof.
	Asset *asset.Asset

	// OutPoint is the outpoint that commits to the asset specified above.
	OutPoint wire.OutPoint

	// AnchorBlockHash is the block hash that anchors the Bitcoin
	// transaction for this Taro state transition.
	AnchorBlockHash chainhash.Hash

	// AnchorBlockHeight is the height of the block hash above.
	AnchorBlockHeight uint32

	// AnchorTxIndex is the transaction index within the above block where
	// the AnchorTx can be found.
	AnchorTxIndex uint32

	// AnchorTx is the transaction that commits to the above asset.
	AnchorTx *wire.MsgTx

	// OutputIndex is the output index in the above transaction that
	// commits to the output.
	OutputIndex uint32

	// InternalKey is the internal key used to commit to the above asset in
	// the AnchorTx.
	InternalKey *btcec.PublicKey

	// ScriptRoot is the Taro commitment root committed to using the above
	// internal key in the Anchor transaction.
	ScriptRoot *commitment.TaroCommitment

	// SplitAsset is the optional indicator that the asset in the snapshot
	// resulted from splitting an asset. If this is true then the root asset
	// of the split can be found in the asset witness' split commitment.
	SplitAsset bool
}

// encodeNoChecksum encodes the proof file into `w` without its checksum.
func (f *File) encodeNoChecksum(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, uint32(f.Version))
	if err != nil {
		return err
	}

	var buf [8]byte
	if err := tlv.WriteVarInt(w, uint64(len(f.Proofs)), &buf); err != nil {
		return err
	}
	for _, proof := range f.Proofs {
		var proofBuf bytes.Buffer
		if err = proof.Encode(&proofBuf); err != nil {
			return err
		}
		err := tlv.WriteVarInt(w, uint64(len(proofBuf.Bytes())), &buf)
		if err != nil {
			return err
		}
		proofBytes := proofBuf.Bytes()
		if err := tlv.EVarBytes(w, &proofBytes, &buf); err != nil {
			return err
		}
	}

	return nil
}

// Encode encodes the proof file into `w` including its checksum.
func (f *File) Encode(w io.Writer) error {
	var buf bytes.Buffer
	if err := f.encodeNoChecksum(&buf); err != nil {
		return err
	}
	checksum := sha256.Sum256(buf.Bytes())
	if _, err := w.Write(checksum[:]); err != nil {
		return err
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

// Decode decodes a proof file from `r`.
func (f *File) Decode(r io.Reader) error {
	// Verify that the checksum is valid before processing the file's
	// contents.
	var checksum [32]byte
	if _, err := r.Read(checksum[:]); err != nil {
		return err
	}

	// Simple DoS prevention measure for too large proof files.
	fileLimit := &io.LimitedReader{R: r, N: MaxFileSize}
	fileBytes, err := ioutil.ReadAll(fileLimit)
	if err != nil {
		if fileLimit.N <= 0 {
			return ErrExceedsMaxFileSize
		}
		return err
	}
	if sha256.Sum256(fileBytes) != checksum {
		return ErrInvalidChecksum
	}

	file := bytes.NewReader(fileBytes)

	var version uint32
	if err = binary.Read(file, binary.BigEndian, &version); err != nil {
		return err
	}
	f.Version = Version(version)

	var buf [8]byte
	numProofs, err := tlv.ReadVarInt(file, &buf)
	if err != nil {
		return err
	}
	f.Proofs = make([]Proof, 0, numProofs)
	for i := uint64(0); i < numProofs; i++ {
		proofLen, err := tlv.ReadVarInt(file, &buf)
		if err != nil {
			return err
		}
		var serializedProof []byte
		err = tlv.DVarBytes(file, &serializedProof, &buf, proofLen)
		if err != nil {
			return err
		}
		var proof Proof
		err = proof.Decode(bytes.NewReader(serializedProof))
		if err != nil {
			return err
		}
		f.Proofs = append(f.Proofs, proof)
	}

	return nil
}
