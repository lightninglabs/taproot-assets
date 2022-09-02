package mssmt

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// A reasonable max leaf size to prevent large allocations when
	// deserializing them.
	maxLeafSize = 1<<24 - 1 // Approx. 16 MB.
)

var (
	byteOrder = binary.BigEndian

	ErrExceedsMaxLeafSize = fmt.Errorf(
		"proof leaf exceeds maximum size of %d bytes", maxLeafSize,
	)
)

// PackBits packs a bit vector into a byte slice.
func PackBits(bits []bool) []byte {
	bytes := make([]byte, (len(bits)+8-1)/8) // Round up to nearest byte.
	for i, isBitSet := range bits {
		if !isBitSet {
			continue
		}
		byteIdx := i / 8
		bitIdx := i % 8
		bytes[byteIdx] |= byte(1 << bitIdx)
	}
	return bytes
}

// UnpackBits unpacks a byte slice into a bit vector.
func UnpackBits(bytes []byte) []bool {
	bits := make([]bool, len(bytes)*8)
	for i := 0; i < len(bits); i++ {
		byteIdx := i / 8
		byteVal := bytes[byteIdx]
		bitIdx := i % 8
		bits[i] = (byteVal>>bitIdx)&1 == 1
	}
	return bits
}

// Encode encodes the compressed proof into the provided Writer.
func (p *CompressedProof) Encode(w io.Writer) error {
	if err := binary.Write(w, byteOrder, uint16(len(p.Nodes))); err != nil {
		return err
	}
	for _, node := range p.Nodes {
		key := node.NodeHash()
		if _, err := w.Write(key[:]); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, node.NodeSum()); err != nil {
			return err
		}
	}

	bitsBytes := PackBits(p.Bits)
	_, err := w.Write(bitsBytes[:])
	return err
}

// Decode decodes the compressed proof encoded within Reader.
func (p *CompressedProof) Decode(r io.Reader) error {
	var numNodes uint16
	if err := binary.Read(r, byteOrder, &numNodes); err != nil {
		return err
	}
	nodes := make([]Node, 0, numNodes)
	for i := uint16(0); i < numNodes; i++ {
		var keyBytes [sha256.Size]byte
		if _, err := r.Read(keyBytes[:]); err != nil {
			return err
		}
		var sum uint64
		if err := binary.Read(r, byteOrder, &sum); err != nil {
			return err
		}
		nodes = append(nodes, NewComputedNode(NodeHash(keyBytes), sum))
	}

	var bitsBytes [MaxTreeLevels / 8]byte
	if _, err := r.Read(bitsBytes[:]); err != nil {
		return err
	}
	bits := UnpackBits(bitsBytes[:])

	*p = CompressedProof{
		Bits:  bits,
		Nodes: nodes,
	}
	return nil
}
