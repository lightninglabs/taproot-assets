package tapchannel

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/lnwire"
)

// proofParamsForShortChanID creates proof params using the block referenced by
// the given short channel ID.
func proofParamsForShortChanID(ctx context.Context,
	chainBridge tapgarden.ChainBridge,
	scid lnwire.ShortChannelID) (proof.BaseProofParams, error) {

	var zero proof.BaseProofParams

	block, err := chainBridge.GetBlockByHeight(ctx, int64(scid.BlockHeight))
	if err != nil {
		return zero, err
	}

	txIndex := int(scid.TxIndex)
	if txIndex >= len(block.Transactions) {
		return zero, fmt.Errorf("tx index %d out of range for block %v",
			txIndex, block.BlockHash())
	}

	return proof.BaseProofParams{
		Block:       block,
		BlockHeight: scid.BlockHeight,
		Tx:          block.Transactions[txIndex],
		TxIndex:     txIndex,
	}, nil
}

// updateProofsFromShortChanID fills the block-related fields on the provided
// proofs using the funding transaction identified by the short channel ID.
func updateProofsFromShortChanID(ctx context.Context,
	chainBridge tapgarden.ChainBridge, scid lnwire.ShortChannelID,
	proofs []*proof.Proof) error {

	if len(proofs) == 0 {
		return nil
	}

	params, err := proofParamsForShortChanID(ctx, chainBridge, scid)
	if err != nil {
		return err
	}

	for idx, p := range proofs {
		if p == nil {
			return fmt.Errorf("nil proof at index %d", idx)
		}

		err := p.UpdateTransitionProof(&params)
		if err != nil {
			return fmt.Errorf("unable to update transition "+
				"proof: %w", err)
		}
	}

	return nil
}

// proofParamsForCommitTx creates proof params using the given block height and
// commitment transaction. The transaction must be included in the block at that
// height.
func proofParamsForCommitTx(ctx context.Context,
	chainBridge tapgarden.ChainBridge, blockHeight uint32,
	commitTx wire.MsgTx) (proof.BaseProofParams, error) {

	var zero proof.BaseProofParams

	block, err := chainBridge.GetBlockByHeight(ctx, int64(blockHeight))
	if err != nil {
		return zero, err
	}

	txHash := commitTx.TxHash()
	txIdx := -1
	for idx, tx := range block.Transactions {
		if tx.TxHash() == txHash {
			txIdx = idx
			break
		}
	}
	if txIdx < 0 {
		return zero, fmt.Errorf("commit tx %v not found in block %v",
			txHash, block.BlockHash())
	}

	return proof.BaseProofParams{
		Block:       block,
		BlockHeight: blockHeight,
		Tx:          block.Transactions[txIdx],
		TxIndex:     txIdx,
	}, nil
}
