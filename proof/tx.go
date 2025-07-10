package proof

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/taprpc"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrTxMerkleProofExists is an error returned when a transaction
	// merkle proof already exists in the store.
	ErrTxMerkleProofExists = errors.New("tx merkle proof already exists")

	// ErrHashMismatch is returned when the hash of the outpoint does not
	// match the hash of the transaction.
	ErrHashMismatch = errors.New("outpoint hash does not match tx hash")

	// ErrOutputIndexInvalid is returned when the output index of the
	// outpoint is invalid for the transaction.
	ErrOutputIndexInvalid = errors.New("output index is invalid for tx")

	// ErrClaimedOutputScriptMismatch is returned when the claimed output
	// script does not match the constructed Taproot output key script.
	ErrClaimedOutputScriptMismatch = errors.New(
		"claimed output pk script doesn't match constructed Taproot " +
			"output key pk script",
	)
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

// TxProof is a struct that contains all the necessary elements to prove the
// existence of a certain outpoint in a block.
type TxProof struct {
	// MsgTx is the transaction that contains the outpoint.
	MsgTx wire.MsgTx

	// BlockHeader is the header of the block that contains the transaction.
	BlockHeader wire.BlockHeader

	// BlockHeight is the height at which the block was mined.
	BlockHeight uint32

	// MerkleProof is the proof that the transaction is included in the
	// block and its merkle root.
	MerkleProof TxMerkleProof

	// ClaimedOutPoint is the outpoint that is being proved to exist in the
	// transaction.
	ClaimedOutPoint wire.OutPoint

	// InternalKey is the Taproot internal key used to construct the P2TR
	// output that is claimed by the outpoint above. Must be provided
	// alongside the Taproot Merkle root to prove knowledge of the output's
	// construction.
	InternalKey btcec.PublicKey

	// MerkleRoot is the claimed output's Taproot Merkle root, if
	// applicable. This, alongside the internal key, is used to prove
	// knowledge of the output's construction. If this is not provided
	// (empty or nil), a BIP-0086 output key construction is assumed.
	MerkleRoot []byte
}

// Verify validates the Bitcoin Merkle Inclusion Proof.
func (p *TxProof) Verify(headerVerifier HeaderVerifier,
	merkleVerifier MerkleVerifier) error {

	txHash := p.MsgTx.TxHash()

	// Part 1: Verify the claimed outpoint references the provided
	// transaction.
	if p.ClaimedOutPoint.Hash != txHash {
		return ErrHashMismatch
	}

	if p.ClaimedOutPoint.Index >= uint32(len(p.MsgTx.TxOut)) {
		return ErrOutputIndexInvalid
	}

	// Part 2: Verify the claimed outpoint is indeed a P2TR output and the
	// construction details are valid.
	taprootKey := txscript.ComputeTaprootKeyNoScript(&p.InternalKey)
	if len(p.MerkleRoot) > 0 {
		taprootKey = txscript.ComputeTaprootOutputKey(
			&p.InternalKey, p.MerkleRoot,
		)
	}

	expectedPkScript, err := txscript.PayToTaprootScript(taprootKey)
	if err != nil {
		return fmt.Errorf("error computing taproot output: %w", err)
	}

	claimedTxOut := p.MsgTx.TxOut[p.ClaimedOutPoint.Index]
	if !bytes.Equal(claimedTxOut.PkScript, expectedPkScript) {
		return ErrClaimedOutputScriptMismatch
	}

	// Part 3: Verify the transaction is included in the given block.
	err = merkleVerifier(
		&p.MsgTx, &p.MerkleProof, p.BlockHeader.MerkleRoot,
	)
	if err != nil {
		return err
	}

	// Part 4: Verify the block header is valid and matches the given block
	// height.
	err = headerVerifier(p.BlockHeader, p.BlockHeight)
	if err != nil {
		return err
	}

	return nil
}

// MarshalTxProof converts a TxProof to its gRPC representation.
func MarshalTxProof(p TxProof) (*mboxrpc.BitcoinMerkleInclusionProof, error) {
	serialize := func(serFn func(at io.Writer) error) ([]byte, error) {
		var buf bytes.Buffer
		if err := serFn(&buf); err != nil {
			return nil, fmt.Errorf("error serializing: %w", err)
		}
		return buf.Bytes(), nil
	}

	rawTxData, err := serialize(p.MsgTx.Serialize)
	if err != nil {
		return nil, fmt.Errorf("error serializing raw tx data: %w", err)
	}

	rawBlockHeaderData, err := serialize(p.BlockHeader.Serialize)
	if err != nil {
		return nil, fmt.Errorf("error serializing raw block header "+
			"data: %w", err)
	}

	txMerkleProof := &mboxrpc.MerkleProof{
		SiblingHashes: make([][]byte, len(p.MerkleProof.Nodes)),
		Bits:          make([]bool, len(p.MerkleProof.Bits)),
	}
	for idx, node := range p.MerkleProof.Nodes {
		txMerkleProof.SiblingHashes[idx] = node[:]
	}
	copy(txMerkleProof.Bits, p.MerkleProof.Bits)

	return &mboxrpc.BitcoinMerkleInclusionProof{
		RawTxData:          rawTxData,
		RawBlockHeaderData: rawBlockHeaderData,
		BlockHeight:        p.BlockHeight,
		MerkleProof:        txMerkleProof,
		ClaimedOutpoint: &taprpc.OutPoint{
			Txid:        p.ClaimedOutPoint.Hash[:],
			OutputIndex: p.ClaimedOutPoint.Index,
		},
		InternalKey: p.InternalKey.SerializeCompressed(),
		MerkleRoot:  p.MerkleRoot,
	}, nil
}

// UnmarshalTxProof converts a gRPC TxProof to its internal representation.
func UnmarshalTxProof(
	rpcProof *mboxrpc.BitcoinMerkleInclusionProof) (*TxProof, error) {

	var p TxProof
	err := p.MsgTx.Deserialize(bytes.NewReader(rpcProof.RawTxData))
	if err != nil {
		return nil, fmt.Errorf("error decoding raw tx data: %w", err)
	}

	err = p.BlockHeader.Deserialize(
		bytes.NewReader(rpcProof.RawBlockHeaderData),
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding raw block header "+
			"data: %w", err)
	}

	p.BlockHeight = rpcProof.BlockHeight
	if p.BlockHeight == 0 {
		return nil, fmt.Errorf("block height is missing")
	}

	if rpcProof.MerkleProof == nil {
		return nil, fmt.Errorf("merkle proof is missing")
	}

	mp := rpcProof.MerkleProof
	if len(mp.SiblingHashes) == 0 {
		return nil, fmt.Errorf("merkle proof sibling hashes are " +
			"missing")
	}

	if len(mp.SiblingHashes) != len(mp.Bits) {
		return nil, fmt.Errorf("merkle proof sibling hashes and " +
			"bits length mismatch")
	}

	p.MerkleProof.Nodes = make([]chainhash.Hash, len(mp.SiblingHashes))
	for idx, siblingHash := range mp.SiblingHashes {
		hash, err := chainhash.NewHash(siblingHash)
		if err != nil {
			return nil, fmt.Errorf("error decoding sibling "+
				"hash: %w", err)
		}

		p.MerkleProof.Nodes[idx] = *hash
	}

	p.MerkleProof.Bits = make([]bool, len(mp.Bits))
	copy(p.MerkleProof.Bits, mp.Bits)

	if rpcProof.ClaimedOutpoint == nil {
		return nil, fmt.Errorf("claimed outpoint is missing")
	}

	opHash, err := chainhash.NewHash(rpcProof.ClaimedOutpoint.Txid)
	if err != nil {
		return nil, fmt.Errorf("error decoding outpoint txid: %w",
			err)
	}

	p.ClaimedOutPoint = wire.OutPoint{
		Hash:  *opHash,
		Index: rpcProof.ClaimedOutpoint.OutputIndex,
	}

	internalKey, err := btcec.ParsePubKey(rpcProof.InternalKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding internal key: %w", err)
	}
	p.InternalKey = *internalKey

	// The merkle root is optional. If it is provided, it needs to be
	// exactly 32 bytes long though.
	switch len(rpcProof.MerkleRoot) {
	case 0, 32:
		p.MerkleRoot = rpcProof.MerkleRoot

	default:
		return nil, fmt.Errorf("merkle root must be empty or "+
			"exactly 32 bytes long, got %d bytes",
			len(rpcProof.MerkleRoot))
	}

	return &p, nil
}
