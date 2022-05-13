package vm

import "github.com/lightninglabs/taro/asset"

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

func HasSplitCommitmentWitness(asset *asset.Asset) bool {
	if len(asset.PrevWitnesses) != 1 {
		return false
	}
	witness := asset.PrevWitnesses[0]
	return witness.PrevID != nil && len(witness.TxWitness) == 0 &&
		witness.SplitCommitment != nil
}
