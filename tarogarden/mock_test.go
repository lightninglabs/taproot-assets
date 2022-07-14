package tarogarden_test

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type mockWalletAnchor struct {
	fundPsbtSignal     chan *tarogarden.FundedPsbt
	signPsbtSignal     chan struct{}
	importPubKeySignal chan *btcec.PublicKey
}

func newMockWalletAnchor() *mockWalletAnchor {
	return &mockWalletAnchor{
		fundPsbtSignal:     make(chan *tarogarden.FundedPsbt),
		signPsbtSignal:     make(chan struct{}),
		importPubKeySignal: make(chan *btcec.PublicKey),
	}
}

func (m *mockWalletAnchor) FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs uint32,
	feeRate chainfee.SatPerKWeight) (tarogarden.FundedPsbt, error) {

	// Take the PSBT packet and add an additional input and output to
	// simulate the wallet funding the transaction.
	packet.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: 5,
		},
	})
	packet.Inputs = append(packet.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    100000,
			PkScript: []byte{0x1},
		},
		SighashType: txscript.SigHashDefault,
	})
	packet.UnsignedTx.AddTxOut(&wire.TxOut{
		Value:    50000,
		PkScript: []byte{0x2},
	})
	packet.Outputs = append(packet.Outputs, psbt.POutput{})

	// We always have the change output be the first output, so this means
	// the taro commitment will live in the second output.
	pkt := tarogarden.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: 0,
	}

	m.fundPsbtSignal <- &pkt

	return pkt, nil
}

func (m *mockWalletAnchor) SignAndFinalizePsbt(ctx context.Context, pkt *psbt.Packet) (*psbt.Packet, error) {

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	default:
	}

	// We'll modify the packet by attaching a "signature" so the PSBT
	// appears to actually be finalized.
	pkt.Inputs[0].FinalScriptSig = []byte{}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	case m.signPsbtSignal <- struct{}{}:
	}

	return pkt, nil
}

func (m *mockWalletAnchor) ImportPubKey(ctx context.Context, pub *btcec.PublicKey) error {
	m.importPubKeySignal <- pub
	return nil
}

func (m *mockWalletAnchor) UnlockInput(ctx context.Context) error {
	return nil
}

type mockChainBridge struct {
	feeEstimateSignal chan struct{}
	publishReq        chan struct{}
	confReqSignal     chan int

	reqCount int
	confReqs map[int]*chainntnfs.ConfirmationEvent
}

func newMockChainBridge() *mockChainBridge {
	return &mockChainBridge{
		feeEstimateSignal: make(chan struct{}),
		publishReq:        make(chan struct{}),
		confReqs:          make(map[int]*chainntnfs.ConfirmationEvent),
		confReqSignal:     make(chan int),
	}
}

func (m *mockChainBridge) sendConfNtfn(reqNo int, blockHash *chainhash.Hash,
	blockHeight, blockIndex int) {
	req := m.confReqs[reqNo]
	req.Confirmed <- &chainntnfs.TxConfirmation{
		BlockHash:   blockHash,
		BlockHeight: uint32(blockHeight),
		TxIndex:     uint32(blockIndex),
	}
}

func (m *mockChainBridge) RegisterConfirmationsNtfn(ctx context.Context,
	txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32,
	includeBlock bool) (*chainntnfs.ConfirmationEvent, error) {

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	default:
	}

	defer func() {
		m.reqCount++
	}()

	req := &chainntnfs.ConfirmationEvent{
		Confirmed: make(chan *chainntnfs.TxConfirmation),
	}

	m.confReqs[m.reqCount] = req

	select {
	case m.confReqSignal <- m.reqCount:
	case <-ctx.Done():
	}

	return req, nil
}

func (m *mockChainBridge) CurrentHeight(_ context.Context) (uint32, error) {
	return 0, nil
}

func (m *mockChainBridge) PublishTransaction(ctx context.Context, _ *wire.MsgTx) error {
	m.publishReq <- struct{}{}
	return nil
}

func (m *mockChainBridge) EstimateFee(ctx context.Context, confTarget uint32) (chainfee.SatPerKWeight, error) {
	select {
	case m.feeEstimateSignal <- struct{}{}:

	case <-ctx.Done():
		return 0, fmt.Errorf("shutting down")
	}

	return 253, nil
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

func (m *mockKeyRing) DeriveNextKey(ctx context.Context,
	keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	select {
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	default:
	}

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

	select {
	case m.reqKeys <- &desc:
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	}

	return desc, nil
}

func (m *mockKeyRing) DeriveKey(ctx context.Context, keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {
	select {
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	default:
	}

	return keychain.KeyDescriptor{}, nil
}

type mockGenSigner struct {
	keyRing *mockKeyRing
}

func newMockGenSigner(keyRing *mockKeyRing) *mockGenSigner {
	return &mockGenSigner{
		keyRing: keyRing,
	}
}

func (m *mockGenSigner) SignGenesis(desc keychain.KeyDescriptor,
	gen asset.Genesis) (*btcec.PublicKey, *schnorr.Signature, error) {

	priv := m.keyRing.keys[desc.KeyLocator]
	signer := asset.NewRawKeyGenesisSigner(priv)
	return signer.SignGenesis(desc, gen)
}
