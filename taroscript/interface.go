package taroscript

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
)

// TaroKeyFamily is the key family used to generate internal keys that taro
// will use creating internal taproot keys and also any other keys used for
// asset script keys. This was derived via: sum(map(lambda y: ord(y), 'taro')).
// In order words: take the word taro and return the integer representation of
// each character and sum those. We get 438, then divide that by 2, to allow
// use to fit this into just a 2-byte integer and to ensure compatibility with
// the remote signer.
const TaroKeyFamily = 219

// TxValidator is the interface used to validate an asset transfer
// with the Taro VM.
type TxValidator interface {
	// Execute creates an instance of the Taro VM and validates
	// an asset transfer, including the attached witnesses.
	Execute(newAsset *asset.Asset, splitAsset *commitment.SplitAsset,
		prevAssets commitment.InputSet) error
}

// Signer is the interface used to compute the witness for a Taro virtual TX.
type Signer interface {
	// SignVirtualTx generates a signature according to the passed signing
	// descriptor and TX.
	//
	// NOTE: We currently assume the signature requested is for the/ BIP 86
	// spending type.
	SignVirtualTx(signDesc *lndclient.SignDescriptor, tx *wire.MsgTx,
		prevOut *wire.TxOut) (*schnorr.Signature, error)
}
