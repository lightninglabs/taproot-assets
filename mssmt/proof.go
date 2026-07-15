package mssmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt/arith"
)

var (
	// ErrInvalidCompressedProof is returned when a compressed proof has an
	// invalid combination of explicit nodes and default hash bits.
	ErrInvalidCompressedProof = errors.New("mssmt: invalid compressed proof")
)

// Proof represents a merkle proof for a MS-SMT.
type Proof struct {
	// Nodes represents the siblings that should be hashed with the leaf and
	// its parents to arrive at the root of the MS-SMT.
	Nodes []Node
}

// CompressedProof represents a compressed MS-SMT merkle proof. Since merkle
// proofs for a MS-SMT are always constant size (255 nodes), we replace its
// empty nodes by a bit vector.
type CompressedProof struct {
	// Bits determines whether a sibling node within a proof is part of the
	// empty tree. This allows us to efficiently compress proofs by not
	// including any pre-computed nodes.
	Bits []bool

	// Nodes represents the non-empty siblings that should be hashed with
	// the leaf and its parents to arrive at the root of the MS-SMT.
	Nodes []Node
}

// NewProof initializes a new merkle proof for the given leaf node.
func NewProof(nodes []Node) *Proof {
	return &Proof{
		Nodes: nodes,
	}
}

// NewProofFromCompressedBytes initializes a new merkle proof from its
// compressed byte representation.
func NewProofFromCompressedBytes(compressedProofBytes []byte) (Proof, error) {
	var zero Proof

	if len(compressedProofBytes) == 0 {
		return zero, fmt.Errorf("compressed proof bytes are empty")
	}

	var compressedProof CompressedProof
	reader := bytes.NewReader(compressedProofBytes)
	if err := compressedProof.Decode(reader); err != nil {
		return zero, fmt.Errorf("decode compressed proof: %w", err)
	}

	// Fail if extra data follows a valid proof encoding.
	if remaining := reader.Len(); remaining != 0 {
		return zero, fmt.Errorf("trailing data after compressed "+
			"proof: %d bytes", remaining)
	}

	p, err := compressedProof.Decompress()
	if err != nil {
		return zero, fmt.Errorf("decompress proof: %w", err)
	}
	if p == nil {
		return zero, fmt.Errorf("decompressor returned nil proof")
	}

	return *p, nil
}

// Root returns the root node obtained by walking up the tree.
func (p Proof) Root(key [32]byte, leaf Node) (*BranchNode, error) {
	return walkUp(&key, leaf, p.Nodes, nil)
}

// rootSum walks up from the given leaf to the root and returns the
// (hash, sum) pair of the resulting root branch, computed directly from
// sibling hashes and sums without materialising any BranchNode. If the proof
// branch sum overflows uint64, the returned boolean is false.
//
// The hot loop is allocation-free: the per-level branch encoding is laid
// out in a single stack-resident 72-byte buffer, and sha256.Sum256
// returns the digest by value.
func (p *Proof) rootSum(key *[hashSize]byte, leaf Node) (NodeHash, uint64,
	bool) {

	h, s := leaf.NodeHash(), leaf.NodeSum()
	var buf [hashSize*2 + 8]byte
	for i := lastBitIndex; i >= 0; i-- {
		sibling := p.Nodes[lastBitIndex-i]
		sh, ss := sibling.NodeHash(), sibling.NodeSum()

		var lh, rh NodeHash
		var ls, rs uint64
		if bitIndex(uint8(i), key) == 0 {
			lh, ls, rh, rs = h, s, sh, ss
		} else {
			lh, ls, rh, rs = sh, ss, h, s
		}

		// The sum is the order-independent component. Reject proofs
		// whose branch sums overflow uint64.
		var err error
		s, err = arith.Add(ls, rs).Unpack()
		if err != nil {
			return NodeHash{}, 0, false
		}

		copy(buf[:hashSize], lh[:])
		copy(buf[hashSize:hashSize*2], rh[:])
		binary.BigEndian.PutUint64(buf[hashSize*2:], s)
		h = sha256.Sum256(buf[:])
	}
	return h, s, true
}

// Copy returns a deep copy of the proof.
func (p Proof) Copy() *Proof {
	nodesCopy := make([]Node, len(p.Nodes))
	for idx := range p.Nodes {
		nodesCopy[idx] = p.Nodes[idx].Copy()
	}
	return &Proof{Nodes: nodesCopy}
}

// Compress compresses a merkle proof by replacing its empty nodes with a bit
// vector.
func (p Proof) Compress() *CompressedProof {
	var (
		bits  = make([]bool, len(p.Nodes))
		nodes []Node
	)
	for idx := range p.Nodes {
		node := p.Nodes[idx]

		// The proof nodes start at the leaf, while the EmptyTree starts
		// at the root.
		if node.NodeHash() == EmptyTree[MaxTreeLevels-idx].NodeHash() {
			bits[idx] = true
		} else {
			nodes = append(nodes, node)
		}
	}
	return &CompressedProof{
		Bits:  bits,
		Nodes: nodes,
	}
}

// Decompress decompresses a compressed merkle proof by replacing its bit vector
// with the empty nodes it represents.
func (p *CompressedProof) Decompress() (*Proof, error) {
	nextNodeIdx := 0
	nodes := make([]Node, len(p.Bits))

	// The number of 0 bits should match the number of pre-populated nodes.
	numExpectedNodes := fn.Reduce(p.Bits, func(count int, bit bool) int {
		if !bit {
			return count + 1
		}

		return count
	})

	if numExpectedNodes != len(p.Nodes) {
		return nil, fmt.Errorf("%w, num_nodes=%v, num_expected=%v",
			ErrInvalidCompressedProof, len(p.Nodes), numExpectedNodes)
	}

	for i, bitSet := range p.Bits {
		if bitSet {
			// The proof nodes start at the leaf, while the
			// EmptyTree starts at the root.
			nodes[i] = EmptyTree[MaxTreeLevels-i]
		} else {
			nodes[i] = p.Nodes[nextNodeIdx]
			nextNodeIdx++
		}
	}

	return NewProof(nodes), nil
}
