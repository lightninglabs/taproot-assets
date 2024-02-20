package tapscript

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
)

// TxValidator is the interface used to validate an asset transfer
// with the Taproot Asset VM.
type TxValidator interface {
	// Execute creates an instance of the Taproot Asset VM and validates
	// an asset transfer, including the attached witnesses.
	Execute(newAsset *asset.Asset, splitAssets []*commitment.SplitAsset,
		prevAssets commitment.InputSet) error
}

// WitnessValidator is the interface used to validate the witnesses of an asset
// transfer. This method may be used in partially constructed asset transfers
// to only check signature validity.
type WitnessValidator interface {
	// ValidateWitnesses validates the generated witnesses of an asset
	// transfer.
	ValidateWitnesses(newAsset *asset.Asset,
		splitAssets []*commitment.SplitAsset,
		prevAssets commitment.InputSet) error
}

// Signer is the interface used to compute the witness for a Taproot Asset
// virtual TX.
type Signer interface {
	// SignVirtualTx generates a signature according to the passed signing
	// descriptor and TX.
	SignVirtualTx(signDesc *lndclient.SignDescriptor, tx *wire.MsgTx,
		prevOut *wire.TxOut) (*schnorr.Signature, error)
}
