package vm

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
)

// HasGenesisWitness determines whether an asset has a valid genesis witness,
// which should only have one input with a zero PrevID and empty witness and
// split commitment proof.
func HasGenesisWitness(asset *asset.Asset) bool {
	if len(asset.PrevWitnesses) != 1 {
		return false
	}

	witness := asset.PrevWitnesses[0]
	if witness.PrevID == nil || len(witness.TxWitness) > 0 ||
		witness.SplitCommitment != nil {
		return false
	}

	return *witness.PrevID == zeroPrevID
}

// HasSplitCommitmentWitness returns true if an asset has a split commitment
// witness.
func HasSplitCommitmentWitness(asset *asset.Asset) bool {
	if len(asset.PrevWitnesses) != 1 {
		return false
	}

	witness := asset.PrevWitnesses[0]

	return witness.PrevID != nil && len(witness.TxWitness) == 0 &&
		witness.SplitCommitment != nil
}

// PayToTaprootScript creates a pk script for a pay-to-taproot output key.
func PayToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}
