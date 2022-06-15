package mssmt

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

	// nextNodeIdx is the index of the next node to include in a
	// decompressed proof.
	nextNodeIdx int
}

// NewProof initializes a new merkle proof for the given leaf node.
func NewProof(nodes []Node) *Proof {
	return &Proof{
		Nodes: nodes,
	}
}

// Root returns the root node obtained by walking up the tree.
func (p Proof) Root(key [32]byte, leaf *LeafNode) *BranchNode {
	return walkUp(&key, leaf, p.Nodes, nil)
}

// Proof returns a deep copy of the proof.
func (p Proof) Copy() *Proof {
	nodesCopy := make([]Node, 0, len(p.Nodes))
	for _, node := range p.Nodes {
		nodesCopy = append(nodesCopy, node.Copy())
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
	for i, node := range p.Nodes {
		// The proof nodes start at the leaf, while the EmptyTree starts
		// at the root.
		if node.NodeKey() == EmptyTree[MaxTreeLevels-i].NodeKey() {
			bits[i] = true
		} else {
			nodes = append(nodes, node)
		}
	}
	return &CompressedProof{
		Bits:  bits,
		Nodes: nodes,
	}
}

// resetNodeIdx resets the node index back to the start.
func (p *CompressedProof) resetNodeIdx() {
	p.nextNodeIdx = 0
}

// nextNode pops the next node from the proof stack.
func (p *CompressedProof) nextNode() Node {
	nextNode := p.Nodes[p.nextNodeIdx]
	p.nextNodeIdx++
	return nextNode
}

// Decompress decompresses a compressed merkle proof by replacing its bit vector
// with the empty nodes it represents.
func (p *CompressedProof) Decompress() *Proof {
	p.resetNodeIdx()
	nodes := make([]Node, len(p.Bits))
	for i, bitSet := range p.Bits {
		if bitSet {
			// The proof nodes start at the leaf, while the
			// EmptyTree starts at the root.
			nodes[i] = EmptyTree[MaxTreeLevels-i]
		} else {
			nodes[i] = p.nextNode()
		}
	}
	return NewProof(nodes)
}
