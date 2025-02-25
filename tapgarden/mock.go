package tapgarden

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
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
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// RandGroupAnchorSeedling generates a random seedling for a group anchor asset.
func RandGroupAnchorSeedling(t testing.TB, groupAnchorName string,
	uniCommitments bool) Seedling {

	scriptKey, _ := test.RandKeyDesc(t)

	// For now, we only test the v0 and v1 versions.
	assetVersion := asset.Version(test.RandIntn(2))
	assetType := asset.Normal

	assetGenesis := asset.RandGenesis(t, assetType)

	// Create asset group key.
	groupPrivateDesc, groupPrivateKey := test.RandKeyDesc(t)

	// Generate the signature for our group genesis asset.
	genSigner := asset.NewMockGenesisSigner(groupPrivateKey)
	genTxBuilder := asset.MockGroupTxBuilder{}

	genProtoAsset := asset.RandAssetWithValues(
		t, assetGenesis, nil, asset.RandScriptKey(t),
	)
	groupKeyRequest := asset.NewGroupKeyRequestNoErr(
		t, groupPrivateDesc, fn.None[asset.ExternalKey](), assetGenesis,
		genProtoAsset, nil, fn.None[chainhash.Hash](),
	)
	genTx, err := groupKeyRequest.BuildGroupVirtualTx(&genTxBuilder)
	require.NoError(t, err)

	groupKey, err := asset.DeriveGroupKey(
		genSigner, *genTx, *groupKeyRequest, nil,
	)
	require.NoError(t, err)

	// Generate a delegation key if we're using universe commitments.
	var delegationKey fn.Option[keychain.KeyDescriptor]
	if uniCommitments {
		keyDesc, _ := test.RandKeyDesc(t)
		delegationKey = fn.Some[keychain.KeyDescriptor](keyDesc)
	}

	return Seedling{
		AssetVersion: assetVersion,
		AssetType:    assetType,
		AssetName:    groupAnchorName,
		Meta: &proof.MetaReveal{
			Data: test.RandBytes(32),
		},
		Amount: uint64(test.RandInt[uint32]()),
		GroupInfo: &asset.AssetGroup{
			Genesis:  &assetGenesis,
			GroupKey: groupKey,
		},
		ScriptKey:           asset.NewScriptKeyBip86(scriptKey),
		EnableEmission:      true,
		UniverseCommitments: uniCommitments,
		DelegationKey:       delegationKey,
	}
}

// RandNonAnchorGroupSeedling generates a random seedling for a non-anchor asset
// in an asset group.
func RandNonAnchorGroupSeedling(t testing.TB, assetVersion asset.Version,
	assetType asset.Type, anchorName string, metaDataBlob []byte,
	delegationKey fn.Option[keychain.KeyDescriptor],
	uniCommitments bool) Seedling {

	seedlingName := hex.EncodeToString(test.RandBytes(32))
	scriptKey, _ := test.RandKeyDesc(t)

	seedling := Seedling{
		AssetVersion: assetVersion,
		AssetType:    assetType,
		AssetName:    seedlingName,
		GroupAnchor:  &anchorName,
		Meta: &proof.MetaReveal{
			Data: metaDataBlob,
		},
		Amount:              uint64(test.RandInt[uint32]()),
		ScriptKey:           asset.NewScriptKeyBip86(scriptKey),
		EnableEmission:      true,
		UniverseCommitments: uniCommitments,
		DelegationKey:       delegationKey,
	}
	return seedling
}

// RandGroupSeedlings generates a random set of seedlings which all belong to a
// single asset group.
func RandGroupSeedlings(t testing.TB, numSeedlings int,
	uniCommitments bool) []Seedling {

	// Formulate group anchor seedling.
	anchorName := hex.EncodeToString(test.RandBytes(32))

	anchor := RandGroupAnchorSeedling(t, anchorName, uniCommitments)
	seedlings := []Seedling{
		anchor,
	}

	// Formulate non-anchor group seedlings.
	for i := 0; i < numSeedlings-1; i++ {
		seedling := RandNonAnchorGroupSeedling(
			t, anchor.AssetVersion, anchor.AssetType, anchorName,
			anchor.Meta.Data, anchor.DelegationKey, uniCommitments,
		)
		seedlings = append(seedlings, seedling)
	}

	return seedlings
}

// MintBatchOptions is a set of options for creating a new minting batch.
type MintBatchOptions struct {
	// totalSeedlings specifies the number of seedlings to generate in this
	// minting batch. The seedlings are randomly assigned as grouped or
	// ungrouped.
	totalSeedlings int

	// totalGroups specifies the number of asset groups to generate in this
	// minting batch. Each element in the slice specifies the number of
	// seedlings to generate for the corresponding asset group.
	totalGroups []int

	// universeCommitments specifies whether to generate universe
	// commitments for the asset groups in this minting batch.
	universeCommitments bool
}

// MintBatchOption is a functional option for creating a new minting batch.
type MintBatchOption func(*MintBatchOptions)

// DefaultMintBatchOptions returns a new set of default minting batch options.
func DefaultMintBatchOptions() MintBatchOptions {
	return MintBatchOptions{}
}

// WithTotalSeedlings sets the total number of seedlings to populate in the
// minting batch.
func WithTotalSeedlings(count int) MintBatchOption {
	return func(options *MintBatchOptions) {
		options.totalSeedlings = count
	}
}

// WithTotalGroups sets the total number of asset groups to populate in the
// minting batch. Each element in the slice specifies the number of seedlings
// to generate for the corresponding asset group.
func WithTotalGroups(counts []int) MintBatchOption {
	return func(options *MintBatchOptions) {
		options.totalGroups = counts
	}
}

// WithUniverseCommitments specifies whether to generate universe commitments
// for the asset groups in the minting batch.
func WithUniverseCommitments(enabled bool) MintBatchOption {
	return func(options *MintBatchOptions) {
		options.universeCommitments = enabled
	}
}

// RandMintingBatch creates a new minting batch with only random seedlings
// populated for testing.
func RandMintingBatch(t testing.TB, opts ...MintBatchOption) *MintingBatch {
	// Construct options.
	options := DefaultMintBatchOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// If the total number of seedlings is unset, we set using the total
	// number of seedlings in the asset groups.
	if options.totalSeedlings == 0 {
		for _, count := range options.totalGroups {
			options.totalSeedlings += count
		}
	}

	// Create an empty minting batch.
	batchKey, _ := test.RandKeyDesc(t)
	batch := &MintingBatch{
		BatchKey:            batchKey,
		HeightHint:          test.RandInt[uint32](),
		CreationTime:        time.Now(),
		UniverseCommitments: options.universeCommitments,
	}

	// Generate seedlings for each asset group.
	for idx := range options.totalGroups {
		countSeedlingsInGroup := options.totalGroups[idx]

		groupSeedlings := RandGroupSeedlings(
			t, countSeedlingsInGroup, options.universeCommitments,
		)

		// Add the seedlings to the total seedlings map.
		for _, seedling := range groupSeedlings {
			err := batch.AddSeedling(seedling)
			require.NoError(t, err)
		}
	}

	// If the total number of seedlings generated so far is less than the
	// total number of seedlings requested, we generate the remaining
	// seedlings at random.
	if len(batch.Seedlings) < options.totalSeedlings {
		remaining := options.totalSeedlings - len(batch.Seedlings)
		randSeedlings := RandSeedlings(t, remaining)

		// Add the seedlings to the total seedlings map.
		for _, seedling := range randSeedlings {
			err := batch.AddSeedling(*seedling)
			require.NoError(t, err)
		}
	}

	// Randomly generating seedlings may result in overlaps with existing
	// ones, leading to fewer seedlings than intended. Sanity check to
	// ensure that the total number of seedlings generated matches the
	// requested amount. This check might help debug flakes in tests.
	require.Equal(t, options.totalSeedlings, len(batch.Seedlings))

	return batch
}

// RandSeedlings creates a new set of random seedlings for testing.
func RandSeedlings(t testing.TB, numSeedlings int) map[string]*Seedling {
	seedlings := make(map[string]*Seedling)
	for i := 0; i < numSeedlings; i++ {
		metaBlob := test.RandBytes(32)
		assetName := hex.EncodeToString(test.RandBytes(32))
		scriptKey, _ := test.RandKeyDesc(t)
		seedlings[assetName] = &Seedling{
			// For now, we only test the v0 and v1 versions.
			AssetVersion: asset.Version(test.RandIntn(2)),
			AssetType:    asset.Type(test.RandIntn(2)),
			AssetName:    assetName,
			Meta: &proof.MetaReveal{
				Data: metaBlob,
			},
			Amount:         uint64(test.RandInt[uint32]()),
			ScriptKey:      asset.NewScriptKeyBip86(scriptKey),
			EnableEmission: test.RandBool(),
		}
	}

	return seedlings
}

// RandSeedlingMintingBatch creates a new minting batch with only random
// seedlings populated for testing.
//
// TODO(ffranr): Replace this function with RandMintingBatch. Note also function
// addRandGroupToBatch.
func RandSeedlingMintingBatch(t testing.TB, numSeedlings int) *MintingBatch {
	genesisTx := NewGenesisTx(t, chainfee.FeePerKwFloor)
	BatchKey, _ := test.RandKeyDesc(t)
	return &MintingBatch{
		BatchKey:     BatchKey,
		Seedlings:    RandSeedlings(t, numSeedlings),
		HeightHint:   test.RandInt[uint32](),
		CreationTime: time.Now(),
		GenesisPacket: &FundedMintAnchorPsbt{
			FundedPsbt: tapsend.FundedPsbt{
				Pkt:               &genesisTx,
				ChangeOutputIndex: 1,
			},
			AssetAnchorOutIdx: 0,
		},
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

// NewGenesisTx creates a funded genesis PSBT with the given fee rate.
func NewGenesisTx(t testing.TB, feeRate chainfee.SatPerKWeight) psbt.Packet {
	txTemplate := wire.NewMsgTx(2)
	txTemplate.AddTxOut(tapsend.CreateDummyOutput())
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	require.NoError(t, err)

	FundGenesisTx(genesisPkt, feeRate)
	return *genesisPkt
}

// FundGenesisTx add a genesis input and change output to a 1-output TX.
func FundGenesisTx(packet *psbt.Packet, feeRate chainfee.SatPerKWeight) {
	const anchorBalance = int64(100000)

	// Take the PSBT packet and add an additional input and output to
	// simulate the wallet funding the transaction.
	packet.UnsignedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: test.RandInt[uint32](),
		},
	})

	// Use a P2TR input by default.
	anchorInput := psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    anchorBalance,
			PkScript: bytes.Clone(tapsend.GenesisDummyScript),
		},
		SighashType: txscript.SigHashDefault,
	}
	packet.Inputs = append(packet.Inputs, anchorInput)

	// Use a non-P2TR change output by default so we avoid generating
	// exclusion proofs.
	changeOutput := wire.TxOut{
		Value:    anchorBalance - packet.UnsignedTx.TxOut[0].Value,
		PkScript: bytes.Clone(tapsend.GenesisDummyScript),
	}
	changeOutput.PkScript[0] = txscript.OP_0
	packet.UnsignedTx.AddTxOut(&changeOutput)
	packet.Outputs = append(packet.Outputs, psbt.POutput{})

	// Set a realistic change value.
	_, fee := tapscript.EstimateFee(
		[][]byte{tapsend.GenesisDummyScript}, packet.UnsignedTx.TxOut,
		feeRate,
	)
	packet.UnsignedTx.TxOut[1].Value -= int64(fee)
}

// FundPsbt funds a PSBT.
func (m *MockWalletAnchor) FundPsbt(_ context.Context, packet *psbt.Packet,
	_ uint32, _ chainfee.SatPerKWeight,
	changeIdx int32) (*tapsend.FundedPsbt, error) {

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

	// The change output was added last, so it will be the last output in
	// the list. Update the change index to reflect this.
	changeIdx = int32(len(packet.Outputs) - 1)

	// We always have the change output be the second output, so this means
	// the Taproot Asset commitment will live in the first output.
	pkt := &tapsend.FundedPsbt{
		Pkt:               packet,
		ChangeOutputIndex: changeIdx,
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

// UnlockInput unlocks the set of target inputs after a batch or send
// transaction is abandoned.
func (m *MockWalletAnchor) UnlockInput(context.Context, wire.OutPoint) error {
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

// MinRelayFee estimates the minimum fee rate required for a
// transaction.
func (m *MockWalletAnchor) MinRelayFee(
	ctx context.Context) (chainfee.SatPerKWeight, error) {

	return chainfee.SatPerKWeight(10), nil
}

type MockChainBridge struct {
	FeeEstimateSignal chan struct{}
	PublishReq        chan *wire.MsgTx
	ConfReqSignal     chan int
	BlockEpochSignal  chan struct{}

	NewBlocks chan int32

	ReqCount atomic.Int32
	ConfReqs map[int]*chainntnfs.ConfirmationEvent

	failFeeEstimates atomic.Bool
	errConf          atomic.Int32
	emptyConf        atomic.Int32
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

func (m *MockChainBridge) FailFeeEstimatesOnce() {
	m.failFeeEstimates.Store(true)
}

// FailConfOnce updates the ChainBridge such that the next call to
// RegisterConfirmationNtfn will fail by returning an error on the error channel
// returned from RegisterConfirmationNtfn.
func (m *MockChainBridge) FailConfOnce() {
	// Store the incremented request count so we never store 0 as a value.
	m.errConf.Store(m.ReqCount.Load() + 1)
}

// EmptyConfOnce updates the ChainBridge such that the next confirmation event
// sent via SendConfNtfn will have an empty confirmation.
func (m *MockChainBridge) EmptyConfOnce() {
	// Store the incremented request count so we never store 0 as a value.
	m.emptyConf.Store(m.ReqCount.Load() + 1)
}

func (m *MockChainBridge) SendConfNtfn(reqNo int, blockHash *chainhash.Hash,
	blockHeight, blockIndex int, block *wire.MsgBlock,
	tx *wire.MsgTx) {

	// Compare to the incremented request count since we incremented it
	// when storing the request number.
	req := m.ConfReqs[reqNo]
	if m.emptyConf.Load() == int32(reqNo)+1 {
		m.emptyConf.Store(0)
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
		m.ReqCount.Add(1)
	}()

	req := &chainntnfs.ConfirmationEvent{
		Confirmed: make(chan *chainntnfs.TxConfirmation),
		Cancel:    func() {},
	}
	m.confErr = make(chan error, 1)

	currentReqCount := m.ReqCount.Load()
	m.ConfReqs[int(currentReqCount)] = req

	select {
	case m.ConfReqSignal <- int(currentReqCount):
	case <-ctx.Done():
	}

	// Compare to the incremented request count since we incremented it
	// when storing the request number.
	if m.errConf.CompareAndSwap(currentReqCount+1, 0) {
		m.confErr <- fmt.Errorf("confirmation registration error")
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

func (m *MockChainBridge) GetBlockTimestamp(_ context.Context, _ uint32) int64 {
	return 0
}

func (m *MockChainBridge) PublishTransaction(_ context.Context,
	tx *wire.MsgTx, _ string) error {

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

	if m.failFeeEstimates.Load() {
		m.failFeeEstimates.Store(false)
		return 0, fmt.Errorf("failed to estimate fee")
	}

	return chainfee.FeePerKwFloor, nil
}

// TxBlockHeight returns the block height that the given transaction was
// included in.
func (m *MockChainBridge) TxBlockHeight(context.Context,
	chainhash.Hash) (uint32, error) {

	return 123, nil
}

// MeanBlockTimestamp returns the timestamp of the block at the given height as
// a Unix timestamp in seconds, taking into account the mean time elapsed over
// the previous 11 blocks.
func (m *MockChainBridge) MeanBlockTimestamp(context.Context,
	uint32) (time.Time, error) {

	return time.Now(), nil
}

// GenFileChainLookup generates a chain lookup interface for the given
// proof file that can be used to validate proofs.
func (m *MockChainBridge) GenFileChainLookup(*proof.File) asset.ChainLookup {
	return m
}

// GenProofChainLookup generates a chain lookup interface for the given
// single proof that can be used to validate proofs.
func (m *MockChainBridge) GenProofChainLookup(*proof.Proof) (asset.ChainLookup,
	error) {

	return m, nil
}

var _ asset.ChainLookup = (*MockChainBridge)(nil)
var _ ChainBridge = (*MockChainBridge)(nil)

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
	mock.Mock

	sync.RWMutex

	KeyIndex uint32

	Keys map[keychain.KeyLocator]*btcec.PrivateKey
}

var _ KeyRing = (*MockKeyRing)(nil)

func NewMockKeyRing() *MockKeyRing {
	keyRing := &MockKeyRing{
		Keys: make(map[keychain.KeyLocator]*btcec.PrivateKey),
	}

	keyRing.On(
		"DeriveNextKey", mock.Anything,
		keychain.KeyFamily(asset.TaprootAssetsKeyFamily),
	).Return(nil)
	keyRing.On("DeriveNextTaprootAssetKey", mock.Anything).Return(nil)

	return keyRing
}

// DeriveNextTaprootAssetKey attempts to derive the *next* key within the
// Taproot Asset key family.
func (m *MockKeyRing) DeriveNextTaprootAssetKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	m.Called(ctx)

	return m.DeriveNextKey(ctx, asset.TaprootAssetsKeyFamily)
}

func (m *MockKeyRing) DeriveNextKey(ctx context.Context,
	keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	m.Called(ctx, keyFam)

	select {
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	default:
	}

	m.Lock()
	defer func() {
		m.KeyIndex++
		m.Unlock()
	}()

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}

	loc := keychain.KeyLocator{
		Index:  m.KeyIndex,
		Family: keyFam,
	}

	m.Keys[loc] = priv

	desc := keychain.KeyDescriptor{
		PubKey:     priv.PubKey(),
		KeyLocator: loc,
	}

	return desc, nil
}

func (m *MockKeyRing) IsLocalKey(ctx context.Context,
	d keychain.KeyDescriptor) bool {

	m.Called(ctx, d)

	m.RLock()
	defer m.RUnlock()

	priv, ok := m.Keys[d.KeyLocator]
	if ok && priv.PubKey().IsEqual(d.PubKey) {
		return true
	}

	for _, key := range m.Keys {
		if key.PubKey().IsEqual(d.PubKey) {
			return true
		}
	}

	return false
}

func (m *MockKeyRing) PubKeyAt(t *testing.T, idx uint32) *btcec.PublicKey {
	m.RLock()
	defer m.RUnlock()

	loc := keychain.KeyLocator{
		Index:  idx,
		Family: asset.TaprootAssetsKeyFamily,
	}

	priv, ok := m.Keys[loc]
	if !ok {
		t.Fatalf("script key not found at index %d", idx)
	}

	return priv.PubKey()
}

func (m *MockKeyRing) ScriptKeyAt(t *testing.T, idx uint32) asset.ScriptKey {
	m.RLock()
	defer m.RUnlock()

	loc := keychain.KeyLocator{
		Index:  idx,
		Family: asset.TaprootAssetsKeyFamily,
	}

	priv, ok := m.Keys[loc]
	if !ok {
		t.Fatalf("script key not found at index %d", idx)
	}

	return asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		KeyLocator: loc,
		PubKey:     priv.PubKey(),
	})
}

type MockGenSigner struct {
	KeyRing     *MockKeyRing
	failSigning atomic.Bool
}

func NewMockGenSigner(keyRing *MockKeyRing) *MockGenSigner {
	return &MockGenSigner{
		KeyRing: keyRing,
	}
}

// FailSigningOnce updates the GenSigner such that the next call to
// SignVirtualTx will fail by returning an error.
func (m *MockGenSigner) FailSigningOnce() {
	m.failSigning.Store(true)
}

func (m *MockGenSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	virtualTx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature,
	error) {

	if m.failSigning.CompareAndSwap(true, false) {
		return nil, fmt.Errorf("failed to sign virtual tx")
	}

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
	proof.ChainLookupGenerator, bool, ...*proof.AnnotatedProof) error {

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
