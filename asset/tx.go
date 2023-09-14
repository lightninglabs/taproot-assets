package asset

import (
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/mssmt"
)

// Forked from tapscript/tx/virtualTxIn to remove checks for non-nil PrevIDs on
// inputs and full consumption of inputs.
func VirtualGenesisTxIn(newAsset *Asset) (*wire.TxIn, mssmt.Tree, error) {
	inputTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// TODO(bhandras): thread the context through.
	ctx := context.TODO()

	// Strip any group witness if present.
	copyNoWitness := newAsset.Copy()
	if copyNoWitness.HasGenesisWitnessForGroup() {
		copyNoWitness.PrevWitnesses[0].TxWitness = nil
	}

	key := ZeroPrevID.Hash()
	leaf, err := copyNoWitness.Leaf()
	if err != nil {
		return nil, nil, err
	}

	_, err = inputTree.Insert(ctx, key, leaf)
	if err != nil {
		return nil, nil, err
	}

	treeRoot, err := inputTree.Root(context.Background())
	if err != nil {
		return nil, nil, err
	}

	// Re-implement tapscript/tx/virtualTxInPrevOut directly here.
	// TODO(roasbeef): document empty hash usage here
	virtualTxInPrevOut := func(root mssmt.Node) *wire.OutPoint {
		// Grab the hash digest of the SMT node. This'll be used to
		// generate the virtual prev out for this tx in.
		//
		// TODO(roasbeef): this already contains the sum, so can just
		// use it directly?
		rootKey := root.NodeHash()

		// Map this to: nodeHash || nodeSum.
		h := sha256.New()
		_, _ = h.Write(rootKey[:])
		_ = binary.Write(h, binary.BigEndian, root.NodeSum())

		// Using the standard zeroIndex for virtual prev outs.
		return wire.NewOutPoint(
			(*chainhash.Hash)(h.Sum(nil)), 0,
		)
	}
	prevOut := virtualTxInPrevOut(treeRoot)

	return wire.NewTxIn(prevOut, nil, nil), inputTree, nil
}

// GenesisPrevOutFetcher returns a Taproot Asset input's `PrevOutFetcher` to be
// used throughout signing when the input asset is a genesis grouped asset.
func GenesisPrevOutFetcher(prevAsset Asset) (*txscript.CannedPrevOutputFetcher,
	error) {

	prevOut, err := InputGenesisAssetPrevOut(prevAsset)
	if err != nil {
		return nil, err
	}

	return txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	), nil
}

// InputGenesisAssetPrevOut returns a TxOut that represents the input asset in a
// Taproot Asset virtual TX, but uses tweaked group key of the input asset to
// enable group witness validation.
func InputGenesisAssetPrevOut(prevAsset Asset) (*wire.TxOut, error) {
	switch prevAsset.ScriptVersion {
	case ScriptV0:
		// If the input asset is a genesis asset that is part of an
		// asset group, we need to validate the group witness against
		// the tweaked group key and not the genesis asset script key.
		validationKey := &prevAsset.GroupKey.GroupPubKey
		pkScript, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_1).
			AddData(schnorr.SerializePubKey(validationKey)).
			Script()

		if err != nil {
			return nil, err
		}

		return &wire.TxOut{
			Value:    int64(prevAsset.Amount),
			PkScript: pkScript,
		}, nil
	default:
		return nil, ErrUnknownVersion
	}
}
