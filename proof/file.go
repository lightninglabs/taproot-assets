package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrInvalidChecksum is an error returned when an invalid proof file
	// checksum is detected while deserializing it.
	ErrInvalidChecksum = errors.New("invalid proof file checksum")

	// ErrNoProofAvailable is the error that's returned when a proof is
	// attempted to be fetched from an empty file.
	ErrNoProofAvailable = errors.New("no proof available")

	// ErrUnknownVersion is returned when a proof with an unknown proof
	// version is being used.
	ErrUnknownVersion = errors.New("proof: unknown proof version")

	// ErrProofFileInvalid is the error that's returned when a proof file is
	// invalid.
	ErrProofFileInvalid = errors.New("proof file is invalid")
)

// Version denotes the versioning scheme for proof files.
type Version uint32

const (
	// V0 is the first version of the proof file.
	V0 Version = 0

	// FileMaxNumProofs is the maximum number of proofs we expect/allow to
	// be encoded within a single proof file. Given that there can only be
	// one transfer per block, this value would be enough to transfer an
	// asset every 10 minutes for 8 years straight. This limitation might be
	// lifted at some point when proofs can be compressed into a single
	// zero-knowledge proof.
	FileMaxNumProofs = 420000

	// FileMaxProofSizeBytes is the maximum size of a single proof in a
	// proof file. The maximum size of a meta reveal is 1 MiB, so this value
	// would cap the number of additional inputs within a proof to roughly
	// 128 of assets with such large meta data.
	FileMaxProofSizeBytes = 128 * MetaDataMaxSizeBytes

	// FileMaxSizeBytes is the maximum size of a single proof file. This is
	// not just FileMaxNumProofs * FileMaxProofSizeBytes as only the minting
	// proof can commit to a large chunk of meta data. The other proofs are
	// much smaller, assuming they don't all have additional inputs. But we
	// must cap this value somewhere to avoid OOM attacks.
	FileMaxSizeBytes = 500 * 1024 * 1024
)

// hashedProof is a struct that contains an encoded proof and its chained
// checksum.
type hashedProof struct {
	// proofBytes is the encoded proof that is hashed.
	proofBytes []byte

	// hash is the SHA256 sum of (prev_hash || proof).
	hash [sha256.Size]byte
}

// File represents a proof file comprised of proofs for all of an asset's state
// transitions back to its genesis state.
type File struct {
	// Version is the version of the proof file.
	Version Version

	// proofs are the proofs contained within the proof file starting from
	// the genesis proof.
	proofs []*hashedProof
}

// NewEmptyFile returns a new empty file with the given version.
func NewEmptyFile(v Version) *File {
	return &File{
		Version: v,
	}
}

// NewFile returns a new proof file given a version and a series of state
// transition proofs.
func NewFile(v Version, proofs ...Proof) (*File, error) {
	var (
		prevHash     [sha256.Size]byte
		linkedProofs = make([]*hashedProof, len(proofs))
	)

	// We start out with the zero hash as the previous hash and then create
	// the checksum of SHA256(prev_hash || proof) as our incremental
	// checksum for each of the proofs, basically building a proof chain
	// similar to Bitcoin's time chain.
	for idx := range proofs {
		proof := proofs[idx]

		proofBytes, err := encodeProof(&proof)
		if err != nil {
			return nil, err
		}

		linkedProofs[idx] = &hashedProof{
			proofBytes: proofBytes,
			hash:       hashProof(proofBytes, prevHash),
		}
		prevHash = linkedProofs[idx].hash
	}

	return &File{
		Version: v,
		proofs:  linkedProofs,
	}, nil
}

// Encode encodes the proof file into `w` including its checksum.
func (f *File) Encode(w io.Writer) error {
	num, err := w.Write(FilePrefixMagicBytes[:])
	if err != nil {
		return err
	}
	if num != PrefixMagicBytesLength {
		return errors.New("failed to write prefix magic bytes")
	}

	err = binary.Write(w, binary.BigEndian, uint32(f.Version))
	if err != nil {
		return err
	}

	var tlvBuf [8]byte
	if err := tlv.WriteVarInt(w, uint64(len(f.proofs)), &tlvBuf); err != nil {
		return err
	}
	for _, proof := range f.proofs {
		proof := proof

		// To the file we write the proof, followed by its hash, which
		// is SHA256(prev_hash || proof). That way if we serially read
		// the whole file using the zero hash as the first prev_hash,
		// then we can make sure we have no data corruption if the
		// serially built hash is equal to the last proof's hash. On the
		// other hand, if we want to append a proof to a file, we just
		// need to read the last proof, use its hash as the prev_hash
		// for the one to append, and we're done.
		err := tlv.WriteVarInt(w, uint64(len(proof.proofBytes)), &tlvBuf)
		if err != nil {
			return err
		}
		if _, err := w.Write(proof.proofBytes); err != nil {
			return err
		}

		// The hash is not part of the proof's TLV stream, so we didn't
		// count it above.
		if _, err := w.Write(proof.hash[:]); err != nil {
			return err
		}
	}

	return nil
}

// Decode decodes a proof file from `r`.
func (f *File) Decode(r io.Reader) error {
	var prefixMagicBytes [PrefixMagicBytesLength]byte
	num, err := r.Read(prefixMagicBytes[:])
	if err != nil {
		return err
	}
	if num != PrefixMagicBytesLength {
		return errors.New("failed to read prefix magic bytes")
	}

	if prefixMagicBytes != FilePrefixMagicBytes {
		return fmt.Errorf("invalid prefix magic bytes, expected %s, "+
			"got %s", string(FilePrefixMagicBytes[:]),
			string(prefixMagicBytes[:]))
	}

	var version uint32
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}
	f.Version = Version(version)

	var tlvBuf [8]byte
	numProofs, err := tlv.ReadVarInt(r, &tlvBuf)
	if err != nil {
		return err
	}

	// Cap the number of proofs there can be within a single file to avoid
	// OOM attacks. See the comment for FileMaxNumProofs for the reasoning
	// behind the value chosen.
	if numProofs > FileMaxNumProofs {
		return fmt.Errorf("%w: too many proofs in file",
			ErrProofFileInvalid)
	}

	var prevHash, currentHash, proofHash [sha256.Size]byte
	f.proofs = make([]*hashedProof, numProofs)
	for i := uint64(0); i < numProofs; i++ {
		// We need to find out how many bytes we expect for the proof,
		// so we can limit the TLV reader.
		numProofBytes, err := tlv.ReadVarInt(r, &tlvBuf)
		if err != nil {
			return err
		}

		// We also need to cap the size of an individual proof. See the
		// comment for FileMaxProofSizeBytes for the reasoning behind the
		// value chosen.
		if numProofBytes > FileMaxProofSizeBytes {
			return fmt.Errorf("%w: proof in file too large",
				ErrProofFileInvalid)
		}

		// Read all bytes that belong to the proof. We don't decode the
		// proof itself as we usually only need the last proof anyway.
		proofBytes := make([]byte, numProofBytes)
		if _, err := io.ReadFull(r, proofBytes); err != nil {
			return err
		}

		// We now read the proof's hash in the file which reflects the
		// current checksum.
		if _, err := io.ReadFull(r, proofHash[:]); err != nil {
			return err
		}

		// Now that we have read both the proof and the expected
		// checksum of it, we calculate our own checksum and verify they
		// match.
		currentHash = hashProof(proofBytes, prevHash)
		if proofHash != currentHash {
			return ErrInvalidChecksum
		}

		f.proofs[i] = &hashedProof{
			proofBytes: proofBytes,
			hash:       currentHash,
		}
		prevHash = currentHash
	}

	return nil
}

// IsUnknownVersion returns true if a proof has a version that is not
// recognized by this implementation of tap.
func (f *File) IsUnknownVersion() bool {
	switch f.Version {
	case V0:
		return false
	default:
		return true
	}
}

// IsEmpty returns true if the file does not contain any proofs.
func (f *File) IsEmpty() bool {
	return len(f.proofs) == 0
}

// IsValid combines multiple sanity checks for proof file validity.
func (f *File) IsValid() error {
	if f.IsEmpty() {
		return ErrNoProofAvailable
	}

	if f.IsUnknownVersion() {
		return ErrUnknownVersion
	}

	return nil
}

// NumProofs returns the number of proofs contained in this file.
func (f *File) NumProofs() int {
	return len(f.proofs)
}

// ProofAt returns the proof at the given index. If the file is empty, this
// returns ErrNoProofAvailable.
func (f *File) ProofAt(index uint32) (*Proof, error) {
	if err := f.IsValid(); err != nil {
		return nil, err
	}

	if index > uint32(len(f.proofs))-1 {
		return nil, fmt.Errorf("invalid index %d", index)
	}

	var (
		proof  = &Proof{}
		reader = bytes.NewReader(f.proofs[index].proofBytes)
	)
	if err := proof.Decode(reader); err != nil {
		return nil, fmt.Errorf("error decoding proof: %w", err)
	}

	return proof, nil
}

// LocateProof calls the given predicate for each proof in the file and returns
// the first proof (and the index) where the predicate returns true, starting
// from the end of the file. If no proof is found, this returns
// ErrNoProofAvailable.
func (f *File) LocateProof(cb func(*Proof) bool) (*Proof, uint32, error) {
	for i := f.NumProofs() - 1; i >= 0; i-- {
		p, err := f.ProofAt(uint32(i))
		if err != nil {
			return nil, 0, err
		}
		if cb(p) {
			return p, uint32(i), nil
		}
	}

	return nil, 0, ErrNoProofAvailable
}

// RawProofAt returns the raw proof at the given index as a byte slice. If the
// file is empty, this returns nil.
func (f *File) RawProofAt(index uint32) ([]byte, error) {
	if err := f.IsValid(); err != nil {
		return nil, err
	}

	if index > uint32(len(f.proofs))-1 {
		return nil, fmt.Errorf("invalid index %d", index)
	}

	proofCopy := make([]byte, len(f.proofs[index].proofBytes))
	copy(proofCopy, f.proofs[index].proofBytes)

	return proofCopy, nil
}

// LastProof returns the last proof in the chain of proofs. If the file is
// empty, this return nil.
func (f *File) LastProof() (*Proof, error) {
	if err := f.IsValid(); err != nil {
		return nil, err
	}

	return f.ProofAt(uint32(len(f.proofs)) - 1)
}

// RawLastProof returns the raw last proof in the chain of proofs as a byte
// slice. If the file is empty, this return nil.
func (f *File) RawLastProof() ([]byte, error) {
	if err := f.IsValid(); err != nil {
		return nil, err
	}

	return f.RawProofAt(uint32(len(f.proofs)) - 1)
}

// AppendProof appends a proof to the file and calculates its chained hash.
func (f *File) AppendProof(proof Proof) error {
	var prevHash [sha256.Size]byte
	if f.IsUnknownVersion() {
		return ErrUnknownVersion
	}

	if !f.IsEmpty() {
		prevHash = f.proofs[len(f.proofs)-1].hash
	}

	proofBytes, err := encodeProof(&proof)
	if err != nil {
		return err
	}

	f.proofs = append(f.proofs, &hashedProof{
		proofBytes: proofBytes,
		hash:       hashProof(proofBytes, prevHash),
	})

	return nil
}

// AppendProofRaw appends a raw proof to the file and calculates its chained
// hash.
func (f *File) AppendProofRaw(proof []byte) error {
	if f.IsUnknownVersion() {
		return ErrUnknownVersion
	}

	var prevHash [sha256.Size]byte
	if !f.IsEmpty() {
		prevHash = f.proofs[len(f.proofs)-1].hash
	}

	f.proofs = append(f.proofs, &hashedProof{
		proofBytes: proof,
		hash:       hashProof(proof, prevHash),
	})

	return nil
}

// ReplaceLastProof attempts to replace the last proof in the file with another
// one, updating its chained hash in the process.
func (f *File) ReplaceLastProof(proof Proof) error {
	return f.ReplaceProofAt(uint32(len(f.proofs)-1), proof)
}

// ReplaceProofAt attempts to replace the proof at the given index with another
// one, updating its chained hash in the process.
func (f *File) ReplaceProofAt(index uint32, proof Proof) error {
	if err := f.IsValid(); err != nil {
		return err
	}

	if index >= uint32(len(f.proofs)) {
		return fmt.Errorf("invalid index %d", index)
	}

	var prevHash [sha256.Size]byte
	if index > 0 {
		// The prevHash is the hash of the previous proof. It is all
		// zero if this is the first proof in the file.
		prevHash = f.proofs[index-1].hash
	}

	proofBytes, err := encodeProof(&proof)
	if err != nil {
		return err
	}

	f.proofs[index] = &hashedProof{
		proofBytes: proofBytes,
		hash:       hashProof(proofBytes, prevHash),
	}

	// We now need to re-hash all proofs after this one.
	for i := index + 1; i < uint32(len(f.proofs)); i++ {
		f.proofs[i].hash = hashProof(
			f.proofs[i].proofBytes, f.proofs[i-1].hash,
		)
	}

	return nil
}

// encodeProof encodes the given proof and returns its raw bytes.
func encodeProof(proof *Proof) ([]byte, error) {
	var buf bytes.Buffer
	if err := proof.Encode(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// hashProof hashes a proof's content together with the previous hash and
// re-uses the given buffer:
//
//	SHA256(prev_hash || proof_bytes).
func hashProof(proofBytes []byte, prevHash [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(prevHash[:])
	_, _ = h.Write(proofBytes)
	return *(*[32]byte)(h.Sum(nil))
}

// AssetSnapshot commits to the result of a valid proof within a proof file.
// This represents the state of an asset's lineage at a given point in time.
type AssetSnapshot struct {
	// Asset is the resulting asset of a valid proof.
	Asset *asset.Asset

	// OutPoint is the outpoint that commits to the asset specified above.
	OutPoint wire.OutPoint

	// AnchorBlockHash is the block hash that anchors the Bitcoin
	// transaction for this Taproot Asset state transition.
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

	// ScriptRoot is the Taproot Asset commitment root committed to using
	// the above internal key in the Anchor transaction.
	ScriptRoot *commitment.TapCommitment

	// TapscriptSibling is the pre-image to the tapscript hash of the
	// sibling to the Taproot Asset root. If this is nil then it means the
	// Taproot Asset root is the only tapscript leaf in the tree.
	TapscriptSibling *commitment.TapscriptPreimage

	// SplitAsset is the optional indicator that the asset in the snapshot
	// resulted from splitting an asset. If this is true then the root asset
	// of the split can be found in the asset witness' split commitment.
	SplitAsset bool

	// MetaReveal is the pre-image to the meta data hash of the above
	// asset. This is only populated if the asset is a genesis asset, and
	// the proof had a valid meta reveal.
	MetaReveal *MetaReveal
}
