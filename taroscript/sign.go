package taroscript

import (
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
)

// Signer...
type Signer interface {
	// SignVirtualTx...
	//
	// TODO(roasbeef): assumes bip 86 spend type
	SignVirtualTx(signDesc *input.SignDescriptor, tx *wire.MsgTx,
		prevOut *wire.TxOut) (*schnorr.Signature, error)
}
