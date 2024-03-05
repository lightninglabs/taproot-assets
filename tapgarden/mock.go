package tapgarden

import (
	"bytes"
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
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// RandSeedlings creates a new set of random seedlings for testing.
func RandSeedlings(t testing.TB, numSeedlings int) map[string]*Seedling {
	seedlings := make(map[string]*Seedling)
	for i := 0; i < numSeedlings; i++ {
		metaBlob := test.RandBytes(32)
		assetName := hex.EncodeToString(test.RandBytes(32))
		seedlings[assetName] = &Seedling{
			// For now, we only test the v0 and v1 versions.
			AssetVersion: asset.Version(rand.Int31n(2)),
			AssetType:    asset.Type(rand.Int31n(2)),
			AssetName:    assetName,
			Meta: &proof.MetaReveal{
				Data: metaBlob,
			},
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
	FundPsbtSignal     chan *tapsend.FundedPsbt
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
		FundPsbtSignal:     make(chan *tapsend.FundedPsbt),
		SignPsbtSignal:     make(chan struct{}),
		ImportPubKeySignal: make(chan *btcec.PublicKey),
		ListUnspentSignal:  make(chan struct{}),
		SubscribeTxSignal:  make(chan struct{}),
		SubscribeTx:        make(chan lndclient.Transaction),
		ListTxnsSignal:     make(chan struct{}),
	}
}

func (m *MockWalletAnchor) FundPsbt(_ context.Context, packet *psbt.Packet,
	_ uint32, _ chainfee.SatPerKWeight) (*tapsend.FundedPsbt, error) {

	// Take the PSBT packet and add an additional input and output to
	// simulate the wallet funding the transaction.
	packet.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: rand.Uint32(),
		},
	})

	// Use a P2TR input by default.
	anchorInput := psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    100000,
			PkScript: bytes.Clone(tapsend.GenesisDummyScript),
		},
		SighashType: txscript.SigHashDefault,
	}
	packet.Inputs = append(packet.Inputs, anchorInput)

	// Use a non-P2TR change output by default so we avoid generating
	// exclusion proofs.
	changeOutput := wire.TxOut{
		Value:    50000,
		PkScript: bytes.Clone(tapsend.GenesisDummyScript),
	}
	changeOutput.PkScript[0] = txscript.OP_0
	packet.UnsignedTx.AddTxOut(&changeOutput)
	packet.Outputs = append(packet.Outputs, psbt.POutput{})

	// We always have the change output be the second output, so this means
	// the Taproot Asset commitment will live in the first output.
	pkt := &tapsend.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: 1,
	}

	m.FundPsbtSignal <- pkt

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
	BlockEpochSignal  chan struct{}

	NewBlocks chan int32

	ReqCount int
	ConfReqs map[int]*chainntnfs.ConfirmationEvent

	failFeeEstimates bool
	emptyConf        bool
	errConf          bool
	confErr          chan error
}

func NewMockChainBridge() *MockChainBridge {
	return &MockChainBridge{
		FeeEstimateSignal: make(chan struct{}),
		PublishReq:        make(chan *wire.MsgTx),
		ConfReqs:          make(map[int]*chainntnfs.ConfirmationEvent),
		ConfReqSignal:     make(chan int),
		BlockEpochSignal:  make(chan struct{}, 1),
		NewBlocks:         make(chan int32),
	}
}

func (m *MockChainBridge) FailFeeEstimates(enable bool) {
	m.failFeeEstimates = enable
}

func (m *MockChainBridge) FailConf(enable bool) {
	m.errConf = enable
}
func (m *MockChainBridge) EmptyConf(enable bool) {
	m.emptyConf = enable
}

func (m *MockChainBridge) SendConfNtfn(reqNo int, blockHash *chainhash.Hash,
	blockHeight, blockIndex int, block *wire.MsgBlock,
	tx *wire.MsgTx) {

	req := m.ConfReqs[reqNo]
	if m.emptyConf {
		req.Confirmed <- nil
		return
	}

	req.Confirmed <- &chainntnfs.TxConfirmation{
		BlockHash:   blockHash,
		BlockHeight: uint32(blockHeight),
		TxIndex:     uint32(blockIndex),
		Block:       block,
		Tx:          tx,
	}
}

func (m *MockChainBridge) RegisterConfirmationsNtfn(ctx context.Context,
	_ *chainhash.Hash, _ []byte, _, _ uint32, _ bool,
	_ chan struct{}) (*chainntnfs.ConfirmationEvent, chan error, error) {

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
		Cancel:    func() {},
	}
	m.confErr = make(chan error, 1)

	m.ConfReqs[m.ReqCount] = req

	select {
	case m.ConfReqSignal <- m.ReqCount:
	case <-ctx.Done():
	}

	if m.errConf {
		m.confErr <- fmt.Errorf("confirmation error")
	}

	return req, m.confErr, nil
}

func (m *MockChainBridge) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("shutting down")
	default:
	}

	select {
	case m.BlockEpochSignal <- struct{}{}:
	case <-ctx.Done():
	}

	return m.NewBlocks, make(chan error), nil
}

// GetBlock returns a chain block given its hash.
func (m *MockChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	return &wire.MsgBlock{}, nil
}

// GetBlockHash returns the hash of the block in the best blockchain at the
// given height.
func (m *MockChainBridge) GetBlockHash(ctx context.Context,
	blockHeight int64) (chainhash.Hash, error) {

	return chainhash.Hash{}, nil
}

// VerifyBlock returns an error if a block (with given header and height) is not
// present on-chain. It also checks to ensure that block height corresponds to
// the given block header.
func (m *MockChainBridge) VerifyBlock(_ context.Context,
	_ wire.BlockHeader, _ uint32) error {

	return nil
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

	if m.failFeeEstimates {
		return 0, fmt.Errorf("failed to estimate fee")
	}

	return 253, nil
}

func GenMockGroupVerifier() func(*btcec.PublicKey) error {
	return func(groupKey *btcec.PublicKey) error {
		return nil
	}
}

type MockAssetSyncer struct {
	Assets map[asset.ID]*asset.AssetGroup

	FetchedAssets chan *asset.AssetGroup

	FetchErrs bool
}

func NewMockAssetSyncer() *MockAssetSyncer {
	return &MockAssetSyncer{
		Assets:        make(map[asset.ID]*asset.AssetGroup),
		FetchedAssets: make(chan *asset.AssetGroup, 1),
		FetchErrs:     false,
	}
}

func (m *MockAssetSyncer) AddAsset(newAsset asset.Asset) {
	assetGroup := &asset.AssetGroup{
		Genesis: &newAsset.Genesis,
	}

	if newAsset.GroupKey != nil {
		assetGroup.GroupKey = newAsset.GroupKey
	}

	m.Assets[newAsset.ID()] = assetGroup
}

func (m *MockAssetSyncer) RemoveAsset(id asset.ID) {
	delete(m.Assets, id)
}

func (m *MockAssetSyncer) FetchAsset(id asset.ID) (*asset.AssetGroup, error) {
	bookDelay := time.Millisecond * 25

	assetGroup, ok := m.Assets[id]
	switch {
	case ok:
		// Broadcast the fetched asset so it can be added to the address
		// book.
		m.FetchedAssets <- assetGroup

		// Wait for the address book to be updated.
		time.Sleep(bookDelay)
		return assetGroup, nil

	case m.FetchErrs:
		return nil, fmt.Errorf("failed to fetch asset info")

	default:
		return nil, nil
	}
}

func (m *MockAssetSyncer) SyncAssetInfo(_ context.Context,
	id *asset.ID) error {

	if id == nil {
		return fmt.Errorf("no asset ID provided")
	}

	_, err := m.FetchAsset(*id)
	return err
}

func (m *MockAssetSyncer) EnableAssetSync(_ context.Context,
	groupInfo *asset.AssetGroup) error {

	return nil
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

// DeriveNextTaprootAssetKey attempts to derive the *next* key within the
// Taproot Asset key family.
func (m *MockKeyRing) DeriveNextTaprootAssetKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	return m.DeriveNextKey(ctx, asset.TaprootAssetsKeyFamily)
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
		return keychain.KeyDescriptor{}, err
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

func (m *MockKeyRing) IsLocalKey(context.Context, keychain.KeyDescriptor) bool {
	return true
}

type MockGenSigner struct {
	KeyRing *MockKeyRing
}

func NewMockGenSigner(keyRing *MockKeyRing) *MockGenSigner {
	return &MockGenSigner{
		KeyRing: keyRing,
	}
}

func (m *MockGenSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	virtualTx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature,
	error) {

	priv := m.KeyRing.Keys[signDesc.KeyDesc.KeyLocator]
	signer := asset.NewMockGenesisSigner(priv)
	return signer.SignVirtualTx(signDesc, virtualTx, prevOut)
}

// A compile-time assertion to ensure MockGenSigner meets the GenesisSigner
// interface.
var _ asset.GenesisSigner = (*MockGenSigner)(nil)

type MockProofArchive struct {
}

func (m *MockProofArchive) FetchProof(ctx context.Context,
	id proof.Locator) (proof.Blob, error) {

	return nil, nil
}

func (m *MockProofArchive) HasProof(ctx context.Context,
	id proof.Locator) (bool, error) {

	return false, nil
}

func (m *MockProofArchive) FetchProofs(ctx context.Context,
	id asset.ID) ([]*proof.AnnotatedProof, error) {

	return nil, nil
}

func (m *MockProofArchive) ImportProofs(context.Context,
	proof.HeaderVerifier, proof.MerkleVerifier, proof.GroupVerifier,
	bool, ...*proof.AnnotatedProof) error {

	return nil
}

type MockProofWatcher struct {
}

func (m *MockProofWatcher) WatchProofs([]*proof.Proof,
	proof.UpdateCallback) error {

	return nil
}

func (m *MockProofWatcher) MaybeWatch(*proof.File, proof.UpdateCallback) error {
	return nil
}

func (m *MockProofWatcher) ShouldWatch(*proof.Proof) bool {
	return true
}

func (m *MockProofWatcher) DefaultUpdateCallback() proof.UpdateCallback {
	return func([]*proof.Proof) error {
		return nil
	}
}

type FallibleTapscriptTreeMgr struct {
	store               MintingStore
	FailLoad, FailStore bool
}

func (mgr FallibleTapscriptTreeMgr) DeleteTapscriptTree(ctx context.Context,
	rootHash chainhash.Hash) error {

	return mgr.store.DeleteTapscriptTree(ctx, rootHash)
}

func (mgr FallibleTapscriptTreeMgr) LoadTapscriptTree(ctx context.Context,
	rootHash chainhash.Hash) (*asset.TapscriptTreeNodes, error) {

	if mgr.FailLoad {
		return nil, fmt.Errorf("failed to load tapscript tree")
	}

	return mgr.store.LoadTapscriptTree(ctx, rootHash)
}

func (mgr FallibleTapscriptTreeMgr) StoreTapscriptTree(ctx context.Context,
	treeNodes asset.TapscriptTreeNodes) (*chainhash.Hash, error) {

	if mgr.FailStore {
		return nil, fmt.Errorf("unable to store tapscript tree")
	}

	return mgr.store.StoreTapscriptTree(ctx, treeNodes)
}

func NewFallibleTapscriptTreeMgr(store MintingStore) FallibleTapscriptTreeMgr {
	return FallibleTapscriptTreeMgr{
		store: store,
	}
}

var _ asset.TapscriptTreeManager = (*FallibleTapscriptTreeMgr)(nil)
