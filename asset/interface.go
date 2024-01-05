package asset

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
)

// GenesisSigner is used to sign the assetID using the group key public key
// for a given asset.
type GenesisSigner interface {
	// SignVirtualTx generates a signature according to the passed signing
	// descriptor and TX.
	SignVirtualTx(signDesc *lndclient.SignDescriptor, tx *wire.MsgTx,
		prevOut *wire.TxOut) (*schnorr.Signature, error)
}

// GenesisTxBuilder is used to construct the virtual transaction that represents
// asset minting for grouped assets. This transaction is used to generate a
// group witness that authorizes the minting of an asset into the asset group.
type GenesisTxBuilder interface {
	// BuildGenesisTx constructs a virtual transaction and prevOut that
	// represent the genesis state transition for a grouped asset. This
	// output is used to create a group witness for the grouped asset.
	BuildGenesisTx(newAsset *Asset) (*wire.MsgTx, *wire.TxOut, error)
}
