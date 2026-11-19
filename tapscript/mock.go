package tapscript

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
)

type MockSigner struct {
	PrivKey *btcec.PrivateKey
}

func NewMockSigner(privKey *btcec.PrivateKey) *MockSigner {
	return &MockSigner{
		PrivKey: privKey,
	}
}

func (m *MockSigner) SignVirtualTx(signDesc *asset.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	return asset.SignVirtualTx(m.PrivKey, signDesc, tx, prevOut)
}

var _ Signer = (*MockSigner)(nil)
