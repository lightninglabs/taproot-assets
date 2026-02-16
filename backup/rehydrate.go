package backup

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
)

// ChainQuerier is the interface needed to fetch blockchain data during proof
// rehydration. The tapgarden.ChainBridge interface satisfies this.
type ChainQuerier interface {
	// GetBlockByHeight returns a full block given its height.
	GetBlockByHeight(ctx context.Context,
		blockHeight int64) (*wire.MsgBlock, error)
}

// RehydrateProofFile takes a stripped proof blob and its hints, fetches the
// missing blockchain data from the chain, and returns a fully reconstructed
// proof file blob.
func RehydrateProofFile(ctx context.Context, strippedBlob []byte,
	hints FileHints, chain ChainQuerier) ([]byte, error) {

	file, err := proof.DecodeFile(strippedBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to decode stripped proof "+
			"file: %w", err)
	}

	numProofs := file.NumProofs()
	if numProofs != len(hints.Hints) {
		return nil, fmt.Errorf("hint count mismatch: %d proofs "+
			"but %d hints", numProofs, len(hints.Hints))
	}

	rehydrated := make([]proof.Proof, numProofs)

	for i := 0; i < numProofs; i++ {
		p, err := file.ProofAt(uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to decode proof at "+
				"index %d: %w", i, err)
		}

		hint := hints.Hints[i]

		// Fetch the block from the chain.
		block, err := chain.GetBlockByHeight(
			ctx, int64(hint.BlockHeight),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch block at "+
				"height %d for proof %d: %w",
				hint.BlockHeight, i, err)
		}

		// Set the block header.
		p.BlockHeader = block.Header

		// Set the block height.
		p.BlockHeight = hint.BlockHeight

		// Find the anchor transaction in the block.
		tx, txIdx, err := findTxInBlock(
			block, hint.AnchorTxHash,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to find anchor tx "+
				"in block at height %d for proof %d: %w",
				hint.BlockHeight, i, err)
		}

		p.AnchorTx = *tx

		// Reconstruct the merkle proof.
		merkleProof, err := proof.NewTxMerkleProof(
			block.Transactions, txIdx,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to construct merkle "+
				"proof for proof %d: %w", i, err)
		}

		p.TxMerkleProof = *merkleProof

		rehydrated[i] = *p
	}

	// Build a new file from the rehydrated proofs.
	fullFile, err := proof.NewFile(file.Version, rehydrated...)
	if err != nil {
		return nil, fmt.Errorf("failed to create rehydrated proof "+
			"file: %w", err)
	}

	fullBlob, err := proof.EncodeFile(fullFile)
	if err != nil {
		return nil, fmt.Errorf("failed to encode rehydrated proof "+
			"file: %w", err)
	}

	return fullBlob, nil
}

// findTxInBlock scans a block's transactions for one matching the given txid.
// Returns the transaction and its index within the block.
func findTxInBlock(block *wire.MsgBlock,
	txHash chainhash.Hash) (*wire.MsgTx, int, error) {

	for i, tx := range block.Transactions {
		if tx.TxHash() == txHash {
			return tx, i, nil
		}
	}

	return nil, 0, fmt.Errorf("transaction %s not found in block",
		txHash)
}
