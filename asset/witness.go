package asset

import "github.com/btcsuite/btcd/btcec/v2"

// IsSplitCommitWitness returns true if the witness is a split-commitment
// witness.
func IsSplitCommitWitness(witness Witness) bool {
	return witness.PrevID != nil && len(witness.TxWitness) == 0 &&
		witness.SplitCommitment != nil
}

// IsBurnKey returns true if the given script key is a valid burn key for the
// given witness.
func IsBurnKey(scriptKey *btcec.PublicKey, witness Witness) bool {
	var prevID PrevID

	// If this is a split output, then we need to look up the first PrevID
	// in the split root asset.
	if IsSplitCommitWitness(witness) {
		rootAsset := witness.SplitCommitment.RootAsset
		if len(rootAsset.PrevWitnesses) == 0 ||
			rootAsset.PrevWitnesses[0].PrevID == nil {

			return false
		}

		prevID = *rootAsset.PrevWitnesses[0].PrevID
	} else {
		if witness.PrevID == nil {
			return false
		}
		prevID = *witness.PrevID
	}

	return scriptKey.IsEqual(DeriveBurnKey(prevID))
}
