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

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
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

// Result commits to the result of a valid proof within a proof file.
type Result struct {
	// Asset is the resulting asset of a valid proof.
	Asset *asset.Asset

	// OutPoint is the outpoint in which the resulting asset was included
	// in.
	OutPoint wire.OutPoint
}

// Verify attempts to verify a full proof file starting from the asset's
// genesis.
func (f File) Verify() (*Result, error) {
	var prev *Result
	for _, proof := range f.Proofs {
		result, err := proof.Verify(prev)
		if err != nil {
			return nil, err
		}
		prev = result
	}
	return prev, nil
}

// encodeNoChecksum encodes the proof file into `w` without its checksum.
func (f File) encodeNoChecksum(w io.Writer) error {
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
func (f File) Encode(w io.Writer) error {
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
