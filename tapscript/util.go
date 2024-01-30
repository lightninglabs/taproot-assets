package tapscript

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// PayToAddrScript constructs a P2TR script that embeds a Taproot Asset
// commitment by tweaking the receiver key by a Tapscript tree that contains the
// Taproot Asset commitment root. The Taproot Asset commitment must be
// reconstructed by the receiver, and they also need to Tapscript sibling hash
// used here if present.
func PayToAddrScript(internalKey btcec.PublicKey, sibling *chainhash.Hash,
	commitment commitment.TapCommitment) ([]byte, error) {

	tapscriptRoot := commitment.TapscriptRoot(sibling)
	outputKey := txscript.ComputeTaprootOutputKey(
		&internalKey, tapscriptRoot[:],
	)

	return PayToTaprootScript(outputKey)
}

// PayToTaprootScript creates a pk script for a pay-to-taproot output key.
func PayToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}

// FlipParity turns the given public key from even to odd parity or vice versa.
func FlipParity(pubKey *btcec.PublicKey) *btcec.PublicKey {
	keyCompressed := pubKey.SerializeCompressed()
	keyCompressed[0] ^= 1

	// We already know the given key is a valid point on the curve, so we
	// don't need to check the error here as the flipped key will also be
	// valid.
	flippedKey, _ := btcec.ParsePubKey(keyCompressed)
	return flippedKey
}

// EstimateFee provides a worst-case fee and vsize estimate for a transaction
// built from the given inputs and outputs. This mirrors the fee estimation
// implemented in btcwallet/wallet/txauthor/author.go:NewUnsignedTransaction()
// EstimateFee assumes that a change output (or a dummy output for change) is
// included in the set of given outputs.
func EstimateFee(inputScripts [][]byte, outputs []*wire.TxOut,
	feeRate chainfee.SatPerKWeight) (int, btcutil.Amount) {

	// Count the types of input scripts.
	var nested, p2wpkh, p2tr, p2pkh int
	for _, pkScript := range inputScripts {
		switch {
		// If this is a p2sh output, we assume this is a
		// nested P2WKH.
		case txscript.IsPayToScriptHash(pkScript):
			nested++
		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			p2wpkh++
		case txscript.IsPayToTaproot(pkScript):
			p2tr++
		default:
			p2pkh++
		}
	}

	// The change output is already in the set of given outputs, so we don't
	// need to account for an additional output.
	maxSignedSize := txsizes.EstimateVirtualSize(
		p2pkh, p2tr, p2wpkh, nested, outputs, 0,
	)
	maxRequiredFee := feeRate.FeePerKVByte().FeeForVSize(
		int64(maxSignedSize),
	)

	return maxSignedSize, maxRequiredFee
}
