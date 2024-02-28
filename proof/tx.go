package proof

import (
	"errors"
	"io"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
)

// TxMerkleProof represents a simplified version of BIP-0037 transaction merkle
// proofs for a single transaction.
type TxMerkleProof struct {
	// Nodes is the list of nodes to hash along with the transaction being
	// proved to arrive at the block's merkle root.
	Nodes []chainhash.Hash

	// Bits indicates the direction for each node found in Nodes above. A
	// 0 bit indicates a left direction or a right direction otherwise.
	Bits []bool
}

// NewTxMerkleProof computes the merkle proof for a specific transaction found
// within a block's set of transactions.
func NewTxMerkleProof(txs []*wire.MsgTx, txIdx int) (*TxMerkleProof, error) {
	if len(txs) <= txIdx {
		return nil, errors.New("invalid transaction index for block")
	}
	blockTxs := make([]*btcutil.Tx, 0, len(txs))
	for _, tx := range txs {
		blockTxs = append(blockTxs, btcutil.NewTx(tx))
	}

	// Compute the full merkle tree for the set of transactions.
	hashes := blockchain.BuildMerkleTreeStore(blockTxs, false)

	// Only one transaction found within the block, return immediately.
	if len(hashes) == 1 {
		return &TxMerkleProof{
			Nodes: []chainhash.Hash{},
			Bits:  []bool{},
		}, nil
	}

	// With the full merkle tree computed above, we'll iterate through it
	// level by level, starting from the transaction leaf, up to the root.
	var (
		nextPoT    = nextPowerOfTwo(len(txs))
		currentIdx = txIdx
		nodes      []chainhash.Hash
		bits       []bool
	)
	for level := 0; ; level++ {
		// We determine the direction of our sibling based on our
		// current index within the tree level.
		var sibling chainhash.Hash
		isRightSibling := currentIdx%2 == 0
		if isRightSibling {
			// If we are the left child, a right sibling may not
			// exist.
			hash := hashes[currentIdx+1]
			switch {
			case hash != nil:
				sibling = *hash
			case hashes[currentIdx] != nil:
				sibling = *hashes[currentIdx]
			default:
				return nil, errors.New("invalid merkle tree")
			}
		} else {
			// If we are the right child, there'll always be a left
			// sibling.
			sibling = *hashes[currentIdx-1]
		}
		nodes = append(nodes, sibling)
		bits = append(bits, isRightSibling)

		// Obtain the next set of hashes for the next level in the tree.
		var nextLevelOffset int
		if level == 0 {
			nextLevelOffset = nextPoT // Avoids division by 0.
		} else {
			nextLevelOffset = (nextPoT >> level)
		}
		hashes = hashes[nextLevelOffset:]

		// Update the currentIdx to reflect the next level in the tree.
		// We divide by 2 since we always hash in pairs.
		currentIdx /= 2

		// We've arrived at the root so our proof is complete.
		if len(hashes) == 1 {
			return &TxMerkleProof{
				Nodes: nodes,
				Bits:  bits,
			}, nil
		}
	}
}

// Verify verifies a merkle proof for `tx` by ensuring the end result matches
// the expected `merkleRoot`.
func (p TxMerkleProof) Verify(tx *wire.MsgTx, merkleRoot chainhash.Hash) bool {
	current := tx.TxHash()
	for i := range p.Nodes {
		var left, right *chainhash.Hash
		if p.Bits[i] {
			left, right = &current, &p.Nodes[i]
		} else {
			right, left = &current, &p.Nodes[i]
		}
		current = blockchain.HashMerkleBranches(left, right)
	}
	return current == merkleRoot
}

// Encode encodes a TxMerkleProof into `w`.
func (p TxMerkleProof) Encode(w io.Writer) error {
	numNodes := uint64(len(p.Nodes))
	var buf [8]byte
	if err := tlv.WriteVarInt(w, numNodes, &buf); err != nil {
		return err
	}
	for _, node := range p.Nodes {
		hash := [32]byte(node)
		if err := tlv.EBytes32(w, &hash, &buf); err != nil {
			return err
		}
	}

	bits := packBits(p.Bits)
	return tlv.EVarBytes(w, &bits, &buf)
}

// Decode decodes a TxMerkleProof from `r`.
func (p *TxMerkleProof) Decode(r io.Reader) error {
	var buf [8]byte
	numNodes, err := tlv.ReadVarInt(r, &buf)
	if err != nil {
		return err
	}

	if numNodes > MerkleProofMaxNodes {
		return tlv.ErrRecordTooLarge
	}

	p.Nodes = make([]chainhash.Hash, 0, numNodes)
	for i := uint64(0); i < numNodes; i++ {
		var hash [chainhash.HashSize]byte
		err = tlv.DBytes32(r, &hash, &buf, chainhash.HashSize)
		if err != nil {
			return err
		}
		p.Nodes = append(p.Nodes, chainhash.Hash(hash))
	}

	var packedBits []byte
	err = tlv.DVarBytes(r, &packedBits, &buf, packedBitsLen(numNodes))
	if err != nil {
		return err
	}
	bits := unpackBits(packedBits)
	p.Bits = bits[:len(p.Nodes)]

	return nil
}
