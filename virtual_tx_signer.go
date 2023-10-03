package taprootassets

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

// LndRpcVirtualTxSigner is an implementation of the tapscript.Signer
// interface backed by an active lnd node.
type LndRpcVirtualTxSigner struct {
	lnd *lndclient.LndServices
}

// NewLndRpcVirtualTxSigner returns a new tx signer instance backed by the
// passed connection to a remote lnd node.
func NewLndRpcVirtualTxSigner(lnd *lndclient.LndServices) *LndRpcVirtualTxSigner {
	return &LndRpcVirtualTxSigner{
		lnd: lnd,
	}
}

// SignVirtualTx generates a signature according to the passed signing
// descriptor and virtual TX.
func (l *LndRpcVirtualTxSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	sigs, err := l.lnd.Signer.SignOutputRaw(
		context.Background(), tx, []*lndclient.SignDescriptor{signDesc},
		[]*wire.TxOut{prevOut},
	)
	if err != nil {
		return nil, err
	}

	// Our signer should only ever produce one signature or fail before this
	// point, so accessing the signature directly is safe.
	virtualTxSig, err := schnorr.ParseSignature(sigs[0])
	if err != nil {
		return nil, err
	}

	return virtualTxSig, nil
}

// Compile time assertions to ensure LndRpcVirtualTxSigner meets the
// tapscript.Signer and asset.GenesisSigner interfaces.
var _ tapscript.Signer = (*LndRpcVirtualTxSigner)(nil)

var _ asset.GenesisSigner = (*LndRpcVirtualTxSigner)(nil)
