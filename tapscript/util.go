package tapscript

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/commitment"
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
