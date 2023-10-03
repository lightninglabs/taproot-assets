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

const (
	// zeroIndex is a constant that stores the usual zero index we use for
	// the virtual prev outs created in the VM.
	zeroIndex = 0
)

// ComputeTaprootScript computes the on-chain SegWit v1 script, known as
// Taproot, based on the given `witnessProgram`.
func ComputeTaprootScript(witnessProgram []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(witnessProgram[:]).
		Script()
}

// VirtualTxInPrevOut returns the prevout of the Taproot Asset virtual
// transaction's single input as a hash of the root node's key concatenated by
// its sum.
func VirtualTxInPrevOut(root mssmt.Node) *wire.OutPoint {
	// Grab the hash digest of the SMT node. This'll be used to generate
	// the virtual prev out for this tx in.
	//
	// TODO(roasbeef): this already contains the sum, so can just use it
	// directly?
	rootKey := root.NodeHash()

	// Map this to: nodeHash || nodeSum.
	h := sha256.New()
	_, _ = h.Write(rootKey[:])
	_ = binary.Write(h, binary.BigEndian, root.NodeSum())

	return wire.NewOutPoint(
		(*chainhash.Hash)(h.Sum(nil)), zeroIndex,
	)
}

// VirtualTxWithInput returns a copy of the `virtualTx` amended to include all
// input-specific details.
//
// This is used to further bind a given witness to the "true" input it spends.
// We'll use the index of the serialized input to bind the prev index, which
// represents the "leaf index" of the virtual input MS-SMT.
func VirtualTxWithInput(virtualTx *wire.MsgTx, input *Asset,
	idx uint32, witness wire.TxWitness) *wire.MsgTx {

	txCopy := virtualTx.Copy()
	txCopy.LockTime = uint32(input.LockTime)
	txCopy.TxIn[zeroIndex].PreviousOutPoint.Index = idx
	txCopy.TxIn[zeroIndex].Sequence = uint32(input.RelativeLockTime)
	txCopy.TxIn[zeroIndex].Witness = witness
	return txCopy
}

// VirtualGenesisTxIn computes the single input of a Taproot Asset virtual
// transaction that represents a grouped asset genesis. The input prevout's hash
// is the root of a MS-SMT committing to only the genesis asset.
func VirtualGenesisTxIn(newAsset *Asset) (*wire.TxIn, mssmt.Tree, error) {
	inputTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// TODO(bhandras): thread the context through.
	ctx := context.TODO()

	// Strip any group witness if present.
	copyNoWitness := newAsset.Copy()
	if copyNoWitness.HasGenesisWitnessForGroup() {
		copyNoWitness.PrevWitnesses[0].TxWitness = nil
	}

	// For genesis grouped assets, we always use the ZeroPrevID for the
	// MS-SMT key since the asset has no real PrevID to use.
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

	prevOut := VirtualTxInPrevOut(treeRoot)

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
