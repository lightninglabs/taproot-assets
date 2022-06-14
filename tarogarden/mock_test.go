package tarogarden_test

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type mockWalletAnchor struct {
}

func (m *mockWalletAnchor) FundPsbt(packet *psbt.Packet, minConfs uint32,
	feeRate chainfee.SatPerKWeight) (tarogarden.FundedPsbt, error) {

	return tarogarden.FundedPsbt{}, nil
}

func (m *mockWalletAnchor) SignAndFinalizePsbt(*psbt.Packet) (*psbt.Packet, error) {
	return nil, nil
}

func (m *mockWalletAnchor) ImportPubKey(*btcec.PublicKey) error {
	return nil
}

func (m *mockWalletAnchor) UnlockInput() error {
	return nil
}

type mockChainBridge struct {
}

func (m *mockChainBridge) RegisterConfirmationsNtfn(txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32) (*chainntnfs.ConfirmationEvent, error) {

	return nil, nil
}

func (m *mockChainBridge) RegisterSpendNtfn(outpoint *wire.OutPoint, pkScript []byte,
	heightHint uint32) (*chainntnfs.SpendEvent, error) {
	return nil, nil
}

func (m *mockChainBridge) RegisterBlockEpochNtfn(*chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {
	return nil, nil
}

func (m *mockChainBridge) Start() error {
	return nil
}

func (m *mockChainBridge) Started() bool {
	return true
}

func (m *mockChainBridge) Stop() error {
	return nil
}

func (m *mockChainBridge) CurrentHeight() (uint32, error) {
	return 0, nil
}

func (m *mockChainBridge) PublishTransaction(*wire.MsgTx) error {
	return nil
}

func (m *mockChainBridge) EstimateFee(confTarget uint32) (chainfee.SatPerKWeight, error) {
	return 0, nil
}

type mockKeyRing struct {
	famIndex keychain.KeyFamily
	keyIndex uint32

	keys map[keychain.KeyLocator]*btcec.PrivateKey

	reqKeys chan *keychain.KeyDescriptor
}

func newMockKeyRing() *mockKeyRing {
	return &mockKeyRing{
		keys:    make(map[keychain.KeyLocator]*btcec.PrivateKey),
		reqKeys: make(chan *keychain.KeyDescriptor),
	}
}

func (m *mockKeyRing) DeriveNextKey(keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {
	defer func() {
		m.famIndex++
		m.keyIndex++
	}()

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return keychain.KeyDescriptor{}, nil
	}

	loc := keychain.KeyLocator{
		Index:  m.keyIndex,
		Family: m.famIndex,
	}

	m.keys[loc] = priv

	desc := keychain.KeyDescriptor{
		PubKey:     priv.PubKey(),
		KeyLocator: loc,
	}

	m.reqKeys <- &desc

	return desc, nil
}

func (m *mockKeyRing) DeriveKey(keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {
	return keychain.KeyDescriptor{}, nil
}

type mockGenSigner struct {
}

func (m *mockGenSigner) SignGenesis(keychain.KeyDescriptor,
	asset.Genesis) (*btcec.PublicKey, *schnorr.Signature, error) {

	return nil, nil, nil
}
