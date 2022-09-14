package taro

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/taroscript"
)

// LndRpcVirtualTxSigner is an implementation of the taroscript.Signer
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

// NOTE: We currently assume the signature requested is for the BIP 86
// spending type, and that the passed key is the internal key.
func (l *LndRpcVirtualTxSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	sigs, err := l.lnd.Signer.SignOutputRaw(
		context.Background(), tx,
		[]*lndclient.SignDescriptor{signDesc}, []*wire.TxOut{prevOut},
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

// A compile time assertion to ensure LndRpcVirtualTxSigner meets the
// taroscript.Signer interface.
var _ taroscript.Signer = (*LndRpcVirtualTxSigner)(nil)
