package taroscript

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
)

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

	// NOTE: We currently assume the signature requested is for the
	// BIP 86 spending type.
	SignVirtualTx(signDesc *lndclient.SignDescriptor, tx *wire.MsgTx,
		prevOut *wire.TxOut) (*schnorr.Signature, error)
}
