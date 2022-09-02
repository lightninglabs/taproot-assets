package tarogarden

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
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type MockWalletAnchor struct {
	FundPsbtSignal     chan *FundedPsbt
	SignPsbtSignal     chan struct{}
	ImportPubKeySignal chan *btcec.PublicKey
}

func NewMockWalletAnchor() *MockWalletAnchor {
	return &MockWalletAnchor{
		FundPsbtSignal:     make(chan *FundedPsbt),
		SignPsbtSignal:     make(chan struct{}),
		ImportPubKeySignal: make(chan *btcec.PublicKey),
	}
}

func (m *MockWalletAnchor) FundPsbt(_ context.Context, packet *psbt.Packet,
	_ uint32, _ chainfee.SatPerKWeight) (FundedPsbt, error) {

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

	// We always have the change output be the second output, so this means
	// the taro commitment will live in the first output.
	pkt := FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: 1,
	}

	m.FundPsbtSignal <- &pkt

	return pkt, nil
}

func (m *MockWalletAnchor) SignAndFinalizePsbt(ctx context.Context,
	pkt *psbt.Packet) (*psbt.Packet, error) {

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
	case m.SignPsbtSignal <- struct{}{}:
	}

	return pkt, nil
}

func (m *MockWalletAnchor) ImportPubKey(_ context.Context,
	pub *btcec.PublicKey) error {

	m.ImportPubKeySignal <- pub

	return nil
}

func (m *MockWalletAnchor) UnlockInput(_ context.Context) error {
	return nil
}

type MockChainBridge struct {
	FeeEstimateSignal chan struct{}
	PublishReq        chan *wire.MsgTx
	ConfReqSignal     chan int

	ReqCount int
	ConfReqs map[int]*chainntnfs.ConfirmationEvent
}

func NewMockChainBridge() *MockChainBridge {
	return &MockChainBridge{
		FeeEstimateSignal: make(chan struct{}),
		PublishReq:        make(chan *wire.MsgTx),
		ConfReqs:          make(map[int]*chainntnfs.ConfirmationEvent),
		ConfReqSignal:     make(chan int),
	}
}

func (m *MockChainBridge) SendConfNtfn(reqNo int, blockHash *chainhash.Hash,
	blockHeight, blockIndex int, block *wire.MsgBlock,
	tx *wire.MsgTx) {

	req := m.ConfReqs[reqNo]
	req.Confirmed <- &chainntnfs.TxConfirmation{
		BlockHash:   blockHash,
		BlockHeight: uint32(blockHeight),
		TxIndex:     uint32(blockIndex),
		Block:       block,
		Tx:          tx,
	}
}

func (m *MockChainBridge) RegisterConfirmationsNtfn(ctx context.Context,
	_ *chainhash.Hash, _ []byte, _, _ uint32,
	_ bool) (*chainntnfs.ConfirmationEvent, chan error, error) {

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("shutting down")
	default:
	}

	defer func() {
		m.ReqCount++
	}()

	req := &chainntnfs.ConfirmationEvent{
		Confirmed: make(chan *chainntnfs.TxConfirmation),
	}
	errChan := make(chan error)

	m.ConfReqs[m.ReqCount] = req

	select {
	case m.ConfReqSignal <- m.ReqCount:
	case <-ctx.Done():
	}

	return req, errChan, nil
}

func (m *MockChainBridge) CurrentHeight(_ context.Context) (uint32, error) {
	return 0, nil
}

func (m *MockChainBridge) PublishTransaction(_ context.Context,
	tx *wire.MsgTx) error {

	m.PublishReq <- tx
	return nil
}

func (m *MockChainBridge) EstimateFee(ctx context.Context,
	_ uint32) (chainfee.SatPerKWeight, error) {

	select {
	case m.FeeEstimateSignal <- struct{}{}:

	case <-ctx.Done():
		return 0, fmt.Errorf("shutting down")
	}

	return 253, nil
}

type MockKeyRing struct {
	FamIndex keychain.KeyFamily
	KeyIndex uint32

	Keys map[keychain.KeyLocator]*btcec.PrivateKey

	ReqKeys chan *keychain.KeyDescriptor
}

func NewMockKeyRing() *MockKeyRing {
	return &MockKeyRing{
		Keys:    make(map[keychain.KeyLocator]*btcec.PrivateKey),
		ReqKeys: make(chan *keychain.KeyDescriptor),
	}
}

func (m *MockKeyRing) DeriveNextKey(ctx context.Context,
	keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	select {
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	default:
	}

	defer func() {
		m.FamIndex++
		m.KeyIndex++
	}()

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return keychain.KeyDescriptor{}, nil
	}

	loc := keychain.KeyLocator{
		Index:  m.KeyIndex,
		Family: m.FamIndex,
	}

	m.Keys[loc] = priv

	desc := keychain.KeyDescriptor{
		PubKey:     priv.PubKey(),
		KeyLocator: loc,
	}

	select {
	case m.ReqKeys <- &desc:
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	}

	return desc, nil
}

func (m *MockKeyRing) DeriveKey(ctx context.Context,
	_ keychain.KeyLocator) (keychain.KeyDescriptor, error) {

	select {
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	default:
	}

	return keychain.KeyDescriptor{}, nil
}

type MockGenSigner struct {
	KeyRing *MockKeyRing
}

func NewMockGenSigner(keyRing *MockKeyRing) *MockGenSigner {
	return &MockGenSigner{
		KeyRing: keyRing,
	}
}

func (m *MockGenSigner) SignGenesis(desc keychain.KeyDescriptor,
	gen asset.Genesis) (*btcec.PublicKey, *schnorr.Signature, error) {

	priv := m.KeyRing.Keys[desc.KeyLocator]
	signer := asset.NewRawKeyGenesisSigner(priv)
	return signer.SignGenesis(desc, gen)
}
