package tarogarden

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// RandSeedlings creates a new set of random seedlings for testing.
func RandSeedlings(t testing.TB, numSeedlings int) map[string]*Seedling {
	seedlings := make(map[string]*Seedling)
	for i := 0; i < numSeedlings; i++ {
		assetName := hex.EncodeToString(test.RandBytes(32))
		seedlings[assetName] = &Seedling{
			AssetType:      asset.Type(rand.Int31n(2)),
			AssetName:      assetName,
			Metadata:       test.RandBytes(32),
			Amount:         uint64(rand.Int31()),
			EnableEmission: test.RandBool(),
		}
	}

	return seedlings
}

// RandSeedlingMintingBatch creates a new minting batch with only random
// seedlings populated for testing.
func RandSeedlingMintingBatch(t testing.TB, numSeedlings int) *MintingBatch {
	return &MintingBatch{
		BatchKey: keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Index:  uint32(rand.Int31()),
				Family: keychain.KeyFamily(rand.Int31()),
			},
		},
		Seedlings:    RandSeedlings(t, numSeedlings),
		HeightHint:   rand.Uint32(),
		CreationTime: time.Now(),
	}
}

type MockWalletAnchor struct {
	FundPsbtSignal     chan *FundedPsbt
	SignPsbtSignal     chan struct{}
	ImportPubKeySignal chan *btcec.PublicKey
	ListUnspentSignal  chan struct{}
	SubscribeTxSignal  chan struct{}
	SubscribeTx        chan lndclient.Transaction
	ListTxnsSignal     chan struct{}

	Transactions  []lndclient.Transaction
	ImportedUtxos []*lnwallet.Utxo
}

func NewMockWalletAnchor() *MockWalletAnchor {
	return &MockWalletAnchor{
		FundPsbtSignal:     make(chan *FundedPsbt),
		SignPsbtSignal:     make(chan struct{}),
		ImportPubKeySignal: make(chan *btcec.PublicKey),
		ListUnspentSignal:  make(chan struct{}),
		SubscribeTxSignal:  make(chan struct{}),
		SubscribeTx:        make(chan lndclient.Transaction),
		ListTxnsSignal:     make(chan struct{}),
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

func (m *MockWalletAnchor) ImportTaprootOutput(ctx context.Context,
	pub *btcec.PublicKey) (btcutil.Address, error) {

	select {
	case m.ImportPubKeySignal <- pub:

	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	}

	return btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(pub), &chaincfg.RegressionNetParams,
	)
}

func (m *MockWalletAnchor) UnlockInput(_ context.Context) error {
	return nil
}

// ListUnspentImportScripts lists all UTXOs of the imported Taproot scripts.
func (m *MockWalletAnchor) ListUnspentImportScripts(
	ctx context.Context) ([]*lnwallet.Utxo, error) {

	select {
	case m.ListUnspentSignal <- struct{}{}:

	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	}

	return m.ImportedUtxos, nil
}

// ImportTapscript imports a Taproot output script into the wallet to track it
// on-chain in a watch-only manner.
func (m *MockWalletAnchor) ImportTapscript(_ context.Context,
	tapscript *waddrmgr.Tapscript) (btcutil.Address, error) {

	taprootKey, err := tapscript.TaprootKey()
	if err != nil {
		return nil, err
	}

	return btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey),
		&chaincfg.RegressionNetParams,
	)
}

// SubscribeTransactions creates a uni-directional stream from the server to the
// client in which any newly discovered transactions relevant to the wallet are
// sent over.
func (m *MockWalletAnchor) SubscribeTransactions(
	ctx context.Context) (<-chan lndclient.Transaction, <-chan error, error) {

	select {
	case m.SubscribeTxSignal <- struct{}{}:

	case <-ctx.Done():
		return nil, nil, fmt.Errorf("shutting down")
	}

	errChan := make(chan error)
	return m.SubscribeTx, errChan, nil
}

// ListTransactions returns all known transactions of the backing lnd node. It
// takes a start and end block height which can be used to limit the block range
// that we query over. These values can be left as zero to include all blocks.
// To include unconfirmed transactions in the query, endHeight must be set to
// -1.
func (m *MockWalletAnchor) ListTransactions(ctx context.Context, _, _ int32,
	_ string) ([]lndclient.Transaction, error) {

	select {
	case m.ListTxnsSignal <- struct{}{}:

	case <-ctx.Done():
		return nil, fmt.Errorf("shutting down")
	}

	return m.Transactions, nil
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

// GetBlock returns a chain block given its hash.
func (m *MockChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	return &wire.MsgBlock{}, nil
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

// DeriveNextTaroKey attempts to derive the *next* key within the Taro key
// family.
func (m *MockKeyRing) DeriveNextTaroKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	return m.DeriveNextKey(ctx, asset.TaroKeyFamily)
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
	initialGen asset.Genesis, currentGen *asset.Genesis) (*btcec.PublicKey,
	*schnorr.Signature, error) {

	priv := m.KeyRing.Keys[desc.KeyLocator]
	signer := asset.NewRawKeyGenesisSigner(priv)
	return signer.SignGenesis(desc, initialGen, currentGen)
}

type MockProofArchive struct {
}

func (m *MockProofArchive) FetchProof(ctx context.Context,
	id proof.Locator) (proof.Blob, error) {

	return nil, nil
}

func (m *MockProofArchive) ImportProofs(ctx context.Context,
	headerVerifier proof.HeaderVerifier,
	proofs ...*proof.AnnotatedProof) error {

	return nil
}
