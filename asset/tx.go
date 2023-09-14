package asset

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
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

// RawKeyGenesisSigner implements the GenesisSigner interface using a raw
// private key.
type RawKeyGenesisSigner struct {
	privKey *btcec.PrivateKey
}

// NewRawKeyGenesisSigner creates a new RawKeyGenesisSigner instance given the
// passed public key.
func NewRawKeyGenesisSigner(priv *btcec.PrivateKey) *RawKeyGenesisSigner {
	return &RawKeyGenesisSigner{
		privKey: priv,
	}
}

// SignGenesis tweaks the public key identified by the passed key
// descriptor with the the first passed Genesis description, and signs
// the second passed Genesis description with the tweaked public key.
// For minting the first asset in a group, only one Genesis object is
// needed, since we tweak with and sign over the same Genesis object.
// The final tweaked public key and the signature are returned.
func (r *RawKeyGenesisSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	virtualTx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature,
	error) {

	signerPubKey := r.privKey.PubKey()

	if !signDesc.KeyDesc.PubKey.IsEqual(signerPubKey) {
		return nil, fmt.Errorf("cannot sign with key")
	}

	sig, err := SignVirtualTx(r.privKey, signDesc, virtualTx, prevOut)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// A compile-time assertion to ensure RawKeyGenesisSigner meets the
// GenesisSigner interface.
var _ GenesisSigner = (*RawKeyGenesisSigner)(nil)

type RawGroupTxBuilder struct{}

func (m *RawGroupTxBuilder) BuildGenesisTx(newAsset *Asset) (*wire.MsgTx,
	*wire.TxOut, error) {

	// First, we check that the passed asset is a genesis grouped asset
	// that has no group witness.
	if !newAsset.NeedsGenesisWitnessForGroup() {
		return nil, nil, fmt.Errorf("asset is not a genesis grouped" +
			"asset")
	}

	prevOut, err := InputGenesisAssetPrevOut(*newAsset)
	if err != nil {
		return nil, nil, err
	}

	// Now, create the virtual transaction that represents this asset
	// minting.
	virtualTx, err := virtualGenesisTx(newAsset)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot tweak group key: %w", err)
	}
	populatedVirtualTx := virtualGenesisTxWithInput(
		virtualTx, newAsset, 0, nil,
	)

	return populatedVirtualTx, prevOut, nil
}

// A compile time assertion to ensure that RawGroupTxBuilder meets the
// GenesisTxBuilder interface.
var _ GenesisTxBuilder = (*RawGroupTxBuilder)(nil)
