package tapscript

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

type MockSigner struct {
	PrivKey *btcec.PrivateKey
}

func NewMockSigner(privKey *btcec.PrivateKey) *MockSigner {
	return &MockSigner{
		PrivKey: privKey,
	}
}

func (m *MockSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	return assetmock.SignVirtualTx(m.PrivKey, signDesc, tx, prevOut)
}

var _ tapscript.Signer = (*MockSigner)(nil)
