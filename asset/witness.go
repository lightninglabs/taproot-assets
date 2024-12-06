package asset

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/taproot-assets/fn"
)

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

// GenChallengeNUMS generates a variant of the NUMS script key that is modified
// by the provided challenge.
//
//	The resulting scriptkey is:
//	res := NUMS + challenge*G
func GenChallengeNUMS(challengeBytesOpt fn.Option[[32]byte]) ScriptKey {
	var (
		nums, g, res btcec.JacobianPoint
		challenge    secp256k1.ModNScalar
	)

	if challengeBytesOpt.IsNone() {
		return NUMSScriptKey
	}

	var challengeBytes [32]byte

	challengeBytesOpt.WhenSome(func(b [32]byte) {
		challengeBytes = b
	})

	// Convert the NUMS key to a Jacobian point.
	NUMSPubKey.AsJacobian(&nums)

	// Multiply G by 1 to get G as a Jacobian point.
	secp256k1.ScalarBaseMultNonConst(
		new(secp256k1.ModNScalar).SetInt(1), &g,
	)

	// Convert the challenge to a scalar.
	challenge.SetByteSlice(challengeBytes[:])

	// Calculate res = challenge * G.
	secp256k1.ScalarMultNonConst(&challenge, &g, &res)

	// Calculate res = nums + res.
	secp256k1.AddNonConst(&nums, &res, &res)

	res.ToAffine()

	resultPubKey := btcec.NewPublicKey(&res.X, &res.Y)

	return NewScriptKey(resultPubKey)
}
