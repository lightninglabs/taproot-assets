package proof

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// VerifiedBlockContext is an indivisible, verified description of the block
// that confirms an anchor transaction. Implementations are sealed within this
// package so callers can't construct a context that mixes a header, height and
// transaction merkle proof from different confirmations.
type VerifiedBlockContext interface {
	// AnchorTxID returns the transaction this block context proves.
	AnchorTxID() chainhash.Hash

	// BlockHash returns the hash of the confirming block.
	BlockHash() chainhash.Hash

	// BlockHeight returns the height of the confirming block.
	BlockHeight() uint32

	// TxIndex returns the anchor transaction's index in the block.
	TxIndex() uint32

	// BlockHeader returns the confirming block header by value.
	BlockHeader() wire.BlockHeader

	apply(*Proof)
	isVerifiedBlockContext()
}

// verifiedBlockContext is the sole implementation of VerifiedBlockContext.
type verifiedBlockContext struct {
	anchorTxID    chainhash.Hash
	blockHeader   wire.BlockHeader
	blockHeight   uint32
	txMerkleProof TxMerkleProof
}

// NewVerifiedBlockContext validates and constructs an indivisible block
// context for an anchor transaction.
func NewVerifiedBlockContext(anchorTx *wire.MsgTx,
	blockHeader wire.BlockHeader, blockHeight uint32,
	txMerkleProof TxMerkleProof) (VerifiedBlockContext, error) {

	if anchorTx == nil {
		return nil, ErrInvalidTxMerkleProof
	}
	if len(txMerkleProof.Nodes) != len(txMerkleProof.Bits) ||
		len(txMerkleProof.Nodes) > 32 {

		return nil, ErrInvalidTxMerkleProof
	}

	validProof := txMerkleProof.Verify(anchorTx, blockHeader.MerkleRoot)
	if !validProof {
		return nil, ErrInvalidTxMerkleProof
	}

	return &verifiedBlockContext{
		anchorTxID:    anchorTx.TxHash(),
		blockHeader:   blockHeader,
		blockHeight:   blockHeight,
		txMerkleProof: cloneTxMerkleProof(txMerkleProof),
	}, nil
}

// AnchorTxID returns the transaction this block context proves.
func (c *verifiedBlockContext) AnchorTxID() chainhash.Hash {
	return c.anchorTxID
}

// BlockHash returns the hash of the confirming block.
func (c *verifiedBlockContext) BlockHash() chainhash.Hash {
	return c.blockHeader.BlockHash()
}

// BlockHeight returns the height of the confirming block.
func (c *verifiedBlockContext) BlockHeight() uint32 {
	return c.blockHeight
}

// TxIndex returns the anchor transaction's index in the block.
func (c *verifiedBlockContext) TxIndex() uint32 {
	return c.txMerkleProof.TxIndex()
}

// BlockHeader returns the confirming block header by value.
func (c *verifiedBlockContext) BlockHeader() wire.BlockHeader {
	return c.blockHeader
}

func (c *verifiedBlockContext) apply(proof *Proof) {
	proof.BlockHeader = c.blockHeader
	proof.BlockHeight = c.blockHeight
	proof.TxMerkleProof = cloneTxMerkleProof(c.txMerkleProof)
}

func (c *verifiedBlockContext) isVerifiedBlockContext() {}

// cloneTxMerkleProof ensures a verified context doesn't retain slices owned by
// its caller and that each restamped proof owns its own slices.
func cloneTxMerkleProof(txMerkleProof TxMerkleProof) TxMerkleProof {
	return TxMerkleProof{
		Nodes: append(
			[]chainhash.Hash(nil), txMerkleProof.Nodes...,
		),
		Bits: append([]bool(nil), txMerkleProof.Bits...),
	}
}

// AnchorTxIDs returns every distinct anchor transaction in the full proof DAG
// in dependency-first order. Additional input proof files are traversed before
// the proof which spends them.
func (f *File) AnchorTxIDs() ([]chainhash.Hash, error) {
	if err := f.IsValid(); err != nil {
		return nil, fmt.Errorf("validating proof file: %w", err)
	}

	seen := make(map[chainhash.Hash]struct{})
	txIDs := make([]chainhash.Hash, 0, f.NumProofs())
	err := f.walkProofDAG(func(proof *Proof) {
		txID := proof.AnchorTx.TxHash()
		if _, ok := seen[txID]; ok {
			return
		}

		seen[txID] = struct{}{}
		txIDs = append(txIDs, txID)
	})
	if err != nil {
		return nil, err
	}

	return txIDs, nil
}

// walkProofDAG visits all proofs in dependency-first order.
func (f *File) walkProofDAG(visit func(*Proof)) error {
	for proofIdx := 0; proofIdx < f.NumProofs(); proofIdx++ {
		proof, err := f.ProofAt(uint32(proofIdx))
		if err != nil {
			return fmt.Errorf(
				"decoding proof %d: %w", proofIdx, err,
			)
		}

		for inputIdx := range proof.AdditionalInputs {
			input := &proof.AdditionalInputs[inputIdx]
			err := input.walkProofDAG(visit)
			if err != nil {
				return fmt.Errorf(
					"walking input %d of proof %d: %w",
					inputIdx, proofIdx, err,
				)
			}
		}

		visit(proof)
	}

	return nil
}

// RestampAnchor replaces the block context of every occurrence of the
// context's anchor transaction in the full proof DAG. Parent proof files and
// all following proofs are rehashed as the replacement propagates outward.
// The file is rewritten in place; the returned Restamped binds its encoding
// to the anchors the traversal visited, so a caller storing the result can
// rebuild its provenance without a second traversal.
func (f *File) RestampAnchor(context VerifiedBlockContext) (*Restamped,
	error) {

	if context == nil {
		return nil, ErrInvalidTxMerkleProof
	}
	if err := f.IsValid(); err != nil {
		return nil, fmt.Errorf("validating proof file: %w", err)
	}

	anchors := &anchorSet{seen: make(map[chainhash.Hash]struct{})}
	matches, err := f.restampAnchor(context, anchors)
	if err != nil {
		return nil, err
	}

	var encoded bytes.Buffer
	if err := f.Encode(&encoded); err != nil {
		return nil, fmt.Errorf("encoding restamped file: %w", err)
	}

	return &Restamped{
		matches: matches,
		blob:    encoded.Bytes(),
		anchors: anchors.txIDs,
	}, nil
}

// Restamped is the outcome of a RestampAnchor traversal: the rewritten
// file's encoding bound to every distinct anchor transaction in it. Only
// RestampAnchor constructs one, so the bytes and the anchors always come
// from the same traversal.
type Restamped struct {
	matches uint64
	blob    Blob
	anchors []chainhash.Hash
}

// Matches is the number of proof occurrences whose block context the
// traversal replaced.
func (r *Restamped) Matches() uint64 {
	return r.matches
}

// Blob is the encoding of the file as the traversal left it.
func (r *Restamped) Blob() Blob {
	return r.blob
}

// AnchorTxIDs is every distinct anchor transaction in the file in
// dependency-first order, as AnchorTxIDs reports them.
func (r *Restamped) AnchorTxIDs() []chainhash.Hash {
	return r.anchors
}

// anchorSet accumulates distinct anchor transactions in visiting order.
type anchorSet struct {
	seen  map[chainhash.Hash]struct{}
	txIDs []chainhash.Hash
}

func (a *anchorSet) add(txID chainhash.Hash) {
	if _, ok := a.seen[txID]; ok {
		return
	}

	a.seen[txID] = struct{}{}
	a.txIDs = append(a.txIDs, txID)
}

func (f *File) restampAnchor(context VerifiedBlockContext,
	anchors *anchorSet) (uint64, error) {

	var matches uint64
	for proofIdx := 0; proofIdx < f.NumProofs(); proofIdx++ {
		proof, err := f.ProofAt(uint32(proofIdx))
		if err != nil {
			return 0, fmt.Errorf(
				"decoding proof %d: %w", proofIdx, err,
			)
		}

		proofChanged := false
		for inputIdx := range proof.AdditionalInputs {
			inputMatches, err := proof.AdditionalInputs[inputIdx].
				restampAnchor(context, anchors)
			if err != nil {
				return 0, fmt.Errorf(
					"restamping input %d of proof %d: %w",
					inputIdx, proofIdx, err,
				)
			}

			matches += inputMatches
			proofChanged = proofChanged || inputMatches > 0
		}

		txID := proof.AnchorTx.TxHash()
		anchors.add(txID)
		if txID == context.AnchorTxID() {
			context.apply(proof)
			matches++
			proofChanged = true
		}

		if !proofChanged {
			continue
		}

		err = f.ReplaceProofAt(uint32(proofIdx), *proof)
		if err != nil {
			return 0, fmt.Errorf(
				"replacing proof %d: %w", proofIdx, err,
			)
		}
	}

	return matches, nil
}
