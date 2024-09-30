package itest

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

var (
	zeroHash          chainhash.Hash
	regtestMiningAddr = "n1VgRjYDzJT2TV72PnungWgWu18SWorXZS"
	regtestParams     = &chaincfg.RegressionNetParams
)

// ClientEventStream is a generic interface for a client stream that allows us
// to receive events from a server.
type ClientEventStream[T any] interface {
	Recv() (T, error)
	grpc.ClientStream
}

// EventSubscription holds a generic client stream and its context cancel
// function.
type EventSubscription[T any] struct {
	ClientEventStream[T]
	Cancel context.CancelFunc
}

// CopyRequest is a helper function to copy a request so that we can modify it.
func CopyRequest(req *mintrpc.MintAssetRequest) *mintrpc.MintAssetRequest {
	return proto.Clone(req).(*mintrpc.MintAssetRequest)
}

// CopyRequests is a helper function to copy a slice of requests so that we can
// modify them.
func CopyRequests(
	reqs []*mintrpc.MintAssetRequest) []*mintrpc.MintAssetRequest {

	copied := make([]*mintrpc.MintAssetRequest, len(reqs))
	for idx := range reqs {
		copied[idx] = CopyRequest(reqs[idx])
	}
	return copied
}

// ParseGenInfo converts a taprpc.GenesisInfo into its asset.Genesis
// counterpart.
func ParseGenInfo(t *testing.T, genInfo *taprpc.GenesisInfo) *asset.Genesis {
	genPoint, err := wire.NewOutPointFromString(genInfo.GenesisPoint)
	require.NoError(t, err)

	parsedGenesis := asset.Genesis{
		FirstPrevOut: *genPoint,
		Tag:          genInfo.Name,
		OutputIndex:  genInfo.OutputIndex,
	}
	copy(parsedGenesis.MetaHash[:], genInfo.MetaHash)

	return &parsedGenesis
}

// AssertSendEventExecuteSendState asserts that the send asset event is an
// ExecuteSendState event, and logs the event timestamp if so.
func AssertSendEventExecuteSendState(t *harnessTest,
	event *tapdevrpc.SendAssetEvent, broadcastState string) bool {

	ev := event.GetExecuteSendStateEvent()
	if ev == nil {
		return false
	}

	// Log send state execution.
	timestamp := time.UnixMicro(ev.Timestamp)
	t.Logf("Executing send state (%v): %v",
		timestamp.Format(time.RFC3339Nano),
		ev.SendState)

	return ev.SendState == broadcastState
}

// AssertSendEventProofTransferBackoffWaitTypeSend asserts that the send asset
// event is a ProofTransferBackoffWait event, with the transfer type set as
// send.
func AssertSendEventProofTransferBackoffWaitTypeSend(t *harnessTest,
	event *tapdevrpc.SendAssetEvent) bool {

	ev := event.GetProofTransferBackoffWaitEvent()
	if ev == nil {
		return false
	}

	// We're listening for events on the sender node. We therefore expect to
	// receive deliver transfer type backoff wait events for sending
	// transfers.
	typeSend := tapdevrpc.ProofTransferType_PROOF_TRANSFER_TYPE_SEND
	if ev.TransferType != typeSend {
		return false
	}

	t.Logf("Found event ntfs: %v", ev)
	return true
}

// MineBlocks mine 'num' of blocks and check that blocks are present in
// node blockchain. numTxs should be set to the number of transactions
// (excluding the coinbase) we expect to be included in the first mined block.
func MineBlocks(t *testing.T, client *rpcclient.Client,
	num uint32, numTxs int) []*wire.MsgBlock {

	// If we expect transactions to be included in the blocks we'll mine,
	// we wait here until they are seen in the miner's mempool.
	var txids []*chainhash.Hash
	var err error
	if numTxs > 0 {
		txids, err = waitForNTxsInMempool(
			client, numTxs, minerMempoolTimeout,
		)
		if err != nil {
			t.Fatalf("unable to find txns in mempool: %v", err)
		}
	}

	blocks := make([]*wire.MsgBlock, num)

	backend, err := client.BackendVersion()
	require.NoError(t, err)

	var blockHashes []*chainhash.Hash

	switch backend.(type) {
	case *rpcclient.BitcoindVersion:
		addr, err := btcutil.DecodeAddress(
			regtestMiningAddr, regtestParams,
		)
		require.NoError(t, err)

		blockHashes, err = client.GenerateToAddress(
			int64(num), addr, nil,
		)
		require.NoError(t, err)

	case rpcclient.BtcdVersion:
		blockHashes, err = client.Generate(num)
		require.NoError(t, err)

	default:
		require.Fail(t, "unknown chain backend: %v", backend)
	}

	for i, blockHash := range blockHashes {
		block, err := client.GetBlock(blockHash)
		if err != nil {
			t.Fatalf("unable to get block: %v", err)
		}

		blocks[i] = block
	}

	// Finally, assert that all the transactions were included in the first
	// block.
	for _, txid := range txids {
		AssertTxInBlock(t, blocks[0], txid)
	}

	return blocks
}

type UTXORequest struct {
	Type   lnrpc.AddressType
	Amount int64
}

// MakeOutput creates a new TXO from a given output type and amount.
func MakeOutput(t *harnessTest, wallet *node.HarnessNode,
	addrType lnrpc.AddressType, amount int64) *wire.TxOut {

	addrResp := wallet.RPC.NewAddress(&lnrpc.NewAddressRequest{
		Type: addrType,
	})
	addr, err := btcutil.DecodeAddress(
		addrResp.Address, harnessNetParams,
	)
	require.NoError(t.t, err)

	addrScript := t.lndHarness.PayToAddrScript(addr)

	return wire.NewTxOut(amount, addrScript)
}

// SetNodeUTXOs sets the wallet state for the given node wallet to a set of
// UTXOs of a specific type and value.
func SetNodeUTXOs(t *harnessTest, wallet *node.HarnessNode,
	feeRate btcutil.Amount, reqs []*UTXORequest) {

	minerAddr := t.lndHarness.Miner().NewMinerAddress()

	// Drain any funds held by the node.
	wallet.RPC.SendCoins(&lnrpc.SendCoinsRequest{
		Addr:        minerAddr.EncodeAddress(),
		SendAll:     true,
		SatPerVbyte: 1,
	})
	t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)

	// Build TXOs from the UTXO requests, which will be used by the miner
	// to build a TX.
	aliceOutputs := fn.Map(reqs, func(r *UTXORequest) *wire.TxOut {
		return MakeOutput(t, wallet, r.Type, r.Amount)
	})

	_ = t.lndHarness.Miner().SendOutputsWithoutChange(aliceOutputs, feeRate)
	t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)
	t.lndHarness.WaitForBlockchainSync(wallet)
}

// ResetNodeWallet sets the wallet state of the given node to own 100 P2TR UTXOs
// of BTC, which matches the wallet state when initializing the itest harness.
func ResetNodeWallet(t *harnessTest, wallet *node.HarnessNode) {
	const outputCount = 100
	const txoType = lnrpc.AddressType_TAPROOT_PUBKEY
	const outputValue = 1e8

	resetReqs := make([]*UTXORequest, outputCount)
	for i := 0; i < outputCount; i++ {
		resetReqs[i] = &UTXORequest{
			txoType,
			outputValue,
		}
	}

	SetNodeUTXOs(t, wallet, btcutil.Amount(1), resetReqs)
}

type MintOption func(*MintOptions)

type MintOptions struct {
	mintingTimeout  time.Duration
	siblingBranch   *mintrpc.FinalizeBatchRequest_Branch
	siblingFullTree *mintrpc.FinalizeBatchRequest_FullTree
}

func DefaultMintOptions() *MintOptions {
	return &MintOptions{
		mintingTimeout: defaultWaitTimeout,
	}
}

func WithMintingTimeout(timeout time.Duration) MintOption {
	return func(options *MintOptions) {
		options.mintingTimeout = timeout
	}
}

func WithSiblingBranch(branch mintrpc.FinalizeBatchRequest_Branch) MintOption {
	return func(options *MintOptions) {
		options.siblingBranch = &branch
	}
}

func WithSiblingTree(tree mintrpc.FinalizeBatchRequest_FullTree) MintOption {
	return func(options *MintOptions) {
		options.siblingFullTree = &tree
	}
}

func BuildMintingBatch(t *testing.T, tapClient TapdClient,
	assetRequests []*mintrpc.MintAssetRequest, opts ...MintOption) {

	options := DefaultMintOptions()
	for _, opt := range opts {
		opt(options)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, options.mintingTimeout)
	defer cancel()

	// Mint all the assets in the same batch.
	for idx, assetRequest := range assetRequests {
		assetResp, err := tapClient.MintAsset(ctxt, assetRequest)
		require.NoError(t, err)
		require.NotEmpty(t, assetResp.PendingBatch)
		require.Len(t, assetResp.PendingBatch.Assets, idx+1)
	}
}

func FinalizeBatchUnconfirmed(t *testing.T, minerClient *rpcclient.Client,
	tapClient TapdClient, assetRequests []*mintrpc.MintAssetRequest,
	opts ...MintOption) (chainhash.Hash, []byte) {

	options := DefaultMintOptions()
	for _, opt := range opts {
		opt(options)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, options.mintingTimeout)
	defer cancel()

	finalizeReq := &mintrpc.FinalizeBatchRequest{}

	if options.siblingBranch != nil {
		finalizeReq.BatchSibling = options.siblingBranch
	}
	if options.siblingFullTree != nil {
		finalizeReq.BatchSibling = options.siblingFullTree
	}

	// Instruct the daemon to finalize the batch.
	batchResp, err := tapClient.FinalizeBatch(ctxt, finalizeReq)
	require.NoError(t, err)
	require.NotEmpty(t, batchResp.Batch)
	require.Len(t, batchResp.Batch.Assets, len(assetRequests))
	require.Equal(
		t, mintrpc.BatchState_BATCH_STATE_BROADCAST,
		batchResp.Batch.State,
	)

	WaitForBatchState(
		t, ctxt, tapClient, options.mintingTimeout,
		batchResp.Batch.BatchKey,
		mintrpc.BatchState_BATCH_STATE_BROADCAST,
	)
	hashes, err := waitForNTxsInMempool(
		minerClient, 1, options.mintingTimeout,
	)
	require.NoError(t, err)

	// Make sure the assets were all minted within the same anchor but don't
	// yet have a block hash associated with them.
	listRespUnconfirmed, err := tapClient.ListAssets(
		ctxt, &taprpc.ListAssetRequest{
			IncludeUnconfirmedMints: true,
		},
	)
	require.NoError(t, err)

	for _, u := range listRespUnconfirmed.Assets {
		var groupKey []byte
		if u.AssetGroup != nil {
			groupKey = u.AssetGroup.TweakedGroupKey
		}
		t.Logf("Minted %d units of asset ID %x, group_key=%x (name "+
			"%v,v%d)", u.Amount, u.AssetGenesis.AssetId, groupKey,
			u.AssetGenesis.Name, u.Version)
	}

	unconfirmedAssets := GroupAssetsByName(listRespUnconfirmed.Assets)
	for _, assetRequest := range assetRequests {
		metaReveal := &proof.MetaReveal{
			Data: assetRequest.Asset.AssetMeta.Data,
		}

		validMetaType, err := proof.IsValidMetaType(
			assetRequest.Asset.AssetMeta.Type,
		)
		require.NoError(t, err)

		metaReveal.Type = validMetaType
		if metaReveal.Type == proof.MetaJson {
			updatedMeta, err := metaReveal.SetDecDisplay(
				assetRequest.Asset.DecimalDisplay,
			)
			require.NoError(t, err)

			metaReveal = updatedMeta
		}

		metaHash := metaReveal.MetaHash()

		AssertAssetState(
			t, unconfirmedAssets, assetRequest.Asset.Name,
			metaHash[:],
			AssetAmountCheck(assetRequest.Asset.Amount),
			AssetTypeCheck(assetRequest.Asset.AssetType),
			AssetAnchorCheck(*hashes[0], zeroHash),
			AssetScriptKeyIsLocalCheck(true),
			AssetVersionCheck(assetRequest.Asset.AssetVersion),
			AssetScriptKeyCheck(assetRequest.Asset.ScriptKey),
			AssetIsGroupedCheck(
				assetRequest.Asset.NewGroupedAsset,
				assetRequest.Asset.GroupedAsset,
			),
			AssetGroupTapscriptRootCheck(
				assetRequest.Asset.GroupTapscriptRoot,
			),
			AssetDecimalDisplayCheck(
				assetRequest.Asset.DecimalDisplay,
			),
		)
	}

	return *hashes[0], batchResp.Batch.BatchKey
}

// MintAssetUnconfirmed is a helper function that mints a batch of assets and
// waits until the minting transaction is in the mempool but does not mine a
// block.
func MintAssetUnconfirmed(t *testing.T, minerClient *rpcclient.Client,
	tapClient TapdClient, assetRequests []*mintrpc.MintAssetRequest,
	opts ...MintOption) (chainhash.Hash, []byte) {

	// Submit all the assets in the same batch.
	BuildMintingBatch(t, tapClient, assetRequests, opts...)

	return FinalizeBatchUnconfirmed(
		t, minerClient, tapClient, assetRequests, opts...,
	)
}

// MintAssetsConfirmBatch mints all given assets in the same batch, confirms the
// batch and verifies all asset proofs of the minted assets.
func MintAssetsConfirmBatch(t *testing.T, minerClient *rpcclient.Client,
	tapClient TapdClient, assetRequests []*mintrpc.MintAssetRequest,
	opts ...MintOption) []*taprpc.Asset {

	ctxc, streamCancel := context.WithCancel(context.Background())
	stream, err := tapClient.SubscribeMintEvents(
		ctxc, &mintrpc.SubscribeMintEventsRequest{},
	)
	require.NoError(t, err)
	sub := &EventSubscription[*mintrpc.MintEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	mintTXID, batchKey := MintAssetUnconfirmed(
		t, minerClient, tapClient, assetRequests, opts...,
	)

	return ConfirmBatch(
		t, minerClient, tapClient, assetRequests, sub, mintTXID,
		batchKey, opts...,
	)
}

func ConfirmBatch(t *testing.T, minerClient *rpcclient.Client,
	tapClient TapdClient, assetRequests []*mintrpc.MintAssetRequest,
	sub *EventSubscription[*mintrpc.MintEvent], mintTXID chainhash.Hash,
	batchKey []byte, opts ...MintOption) []*taprpc.Asset {

	options := DefaultMintOptions()
	for _, opt := range opts {
		opt(options)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, options.mintingTimeout)
	defer cancel()

	// Mine a block to confirm the assets.
	block := MineBlocks(t, minerClient, 1, 1)[0]
	blockHash := block.BlockHash()
	WaitForBatchState(
		t, ctxt, tapClient, options.mintingTimeout, batchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)

	AssertMintEvents(t, batchKey, sub)

	// We should be able to fetch the batch, and also find that the txid of
	// the batch tx is populated.
	batchResp, err := tapClient.ListBatches(ctxt, &mintrpc.ListBatchRequest{
		Filter: &mintrpc.ListBatchRequest_BatchKey{
			BatchKey: batchKey,
		},
	})
	require.NoError(t, err)
	require.Len(t, batchResp.Batches, 1)

	batch := batchResp.Batches[0]
	require.NotEmpty(t, batch.Batch.BatchTxid)

	return AssertAssetsMinted(
		t, tapClient, assetRequests, mintTXID, blockHash,
	)
}

func ManualMintSimpleAsset(t *harnessTest, lndNode *node.HarnessNode,
	tapClient *tapdHarness, commitVersion commitment.TapCommitmentVersion,
	req *mintrpc.MintAsset) (*taprpc.Asset, *tapdevrpc.ImportProofRequest) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Set up the needed clients.
	lndClient, err := t.newLndClient(lndNode)
	require.NoError(t.t, err)

	lndServices := &lndClient.LndServices
	walletAnchor := taprootassets.NewLndRpcWalletAnchor(lndServices)

	// First, create and fund a genesis TX to anchor the asset.
	genesisDummyScript := append(
		[]byte{txscript.OP_1, txscript.OP_DATA_32},
		bytes.Repeat([]byte{0x00}, 32)...,
	)
	txTemplate := wire.NewMsgTx(2)
	txTemplate.AddTxOut(&wire.TxOut{
		Value:    int64(btcutil.Amount(1000)),
		PkScript: bytes.Clone(genesisDummyScript),
	})
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	require.NoError(t.t, err)

	fundedPkt, err := walletAnchor.FundPsbt(
		ctxt, genesisPkt, 1, chainfee.SatPerKWeight(3000), -1,
	)
	require.NoError(t.t, err)

	genesisOutpoint := fundedPkt.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	anchorIdx := uint32(0)

	// Next, derive the keys we need to create the asset and the final
	// genesis output.
	assetScriptKey, internalKey := DeriveKeys(t.t, tapClient)

	// Build the asset itself.
	assetMeta := proof.MetaReveal{
		Type: proof.MetaOpaque,
		Data: req.AssetMeta.Data,
	}
	metaHash := assetMeta.MetaHash()
	metaReveals := tapgarden.AssetMetas{
		asset.ToSerialized(assetScriptKey.PubKey): &assetMeta,
	}

	assetGen := asset.Genesis{
		FirstPrevOut: genesisOutpoint,
		Tag:          req.Name,
		MetaHash:     metaHash,
		OutputIndex:  anchorIdx,
		Type:         asset.Type(req.AssetType),
	}
	assetVersion, err := taprpc.UnmarshalAssetVersion(req.AssetVersion)
	require.NoError(t.t, err)

	newAsset, err := asset.New(
		assetGen, req.Amount, 0, 0, assetScriptKey, nil,
		asset.WithAssetVersion(assetVersion),
	)
	require.NoError(t.t, err)

	// From the asset, build the tap commitment and genesis script.
	anchorCommitment, err := commitment.FromAssets(&commitVersion, newAsset)
	require.NoError(t.t, err)

	anchorCommitRoot := anchorCommitment.TapscriptRoot(nil)
	mintPubkey := txscript.ComputeTaprootOutputKey(
		internalKey.PubKey, fn.ByteSlice(anchorCommitRoot),
	)
	genesisScript, err := tapscript.PayToTaprootScript(mintPubkey)
	require.NoError(t.t, err)

	// Add the genesis script to the funded PSBT, and then sign at the
	// anchor level.
	fundedPkt.Pkt.UnsignedTx.TxOut[anchorIdx].PkScript = genesisScript
	signedPkt, err := walletAnchor.SignAndFinalizePsbt(ctxt, fundedPkt.Pkt)
	require.NoError(t.t, err)

	signedTx, err := psbt.Extract(signedPkt)
	require.NoError(t.t, err)

	// Publish and confirm the minting TX. With the confirmation info, we
	// can build the issuance proofs.
	genesisTxHash := signedTx.TxHash()
	err = lndServices.WalletKit.PublishTransaction(
		ctxt, signedTx, "tapd-asset-minting",
	)
	require.NoError(t.t, err)

	lndInfo, err := lndServices.Client.GetInfo(ctxt)
	require.NoError(t.t, err)

	confChan, _, err := lndServices.ChainNotifier.RegisterConfirmationsNtfn(
		ctxt, &genesisTxHash, signedTx.TxOut[0].PkScript, 1,
		int32(lndInfo.BlockHeight), lndclient.WithIncludeBlock(),
	)
	require.NoError(t.t, err)

	confNtfn := chainntnfs.ConfirmationEvent{
		Confirmed: confChan,
		Cancel:    cancel,
	}
	ctxGuard := fn.ContextGuard{
		DefaultTimeout: defaultWaitTimeout,
		Quit:           make(chan struct{}),
	}

	confEventChan := make(chan *chainntnfs.TxConfirmation, 1)
	ctxGuard.Wg.Add(1)
	go func() {
		defer confNtfn.Cancel()
		defer ctxGuard.Wg.Done()

		confRecv := false
		for !confRecv {
			confEvent := <-confNtfn.Confirmed
			confEventChan <- confEvent
			confRecv = true
		}
	}()

	t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)
	ctxGuard.Wg.Wait()

	// Finally, build the issuance proofs and import them into our tap node.
	confEvent := <-confEventChan
	baseProof := proof.MintParams{
		BaseProofParams: proof.BaseProofParams{
			Block:            confEvent.Block,
			BlockHeight:      confEvent.BlockHeight,
			Tx:               confEvent.Tx,
			TxIndex:          int(confEvent.TxIndex),
			OutputIndex:      int(anchorIdx),
			InternalKey:      internalKey.PubKey,
			TaprootAssetRoot: anchorCommitment,
		},
		GenesisPoint: genesisOutpoint,
	}

	err = proof.AddExclusionProofs(
		&baseProof.BaseProofParams, confEvent.Tx, signedPkt.Outputs,
		func(idx uint32) bool { return idx == anchorIdx },
	)
	require.NoError(t.t, err)

	chainBridge := tapgarden.NewMockChainBridge()
	mintingProofs, err := proof.NewMintingBlobs(
		&baseProof, proof.MockHeaderVerifier, proof.MockMerkleVerifier,
		proof.MockGroupVerifier, proof.MockGroupAnchorVerifier,
		chainBridge, proof.WithAssetMetaReveals(metaReveals),
	)
	require.NoError(t.t, err)

	mintProof := mintingProofs[asset.ToSerialized(assetScriptKey.PubKey)]
	proofBlob, err := proof.EncodeAsProofFile(mintProof)
	require.NoError(t.t, err)
	require.True(t.t, proof.IsProofFile(proofBlob))

	importReq := tapdevrpc.ImportProofRequest{
		ProofFile:    proofBlob,
		GenesisPoint: genesisOutpoint.String(),
	}
	_, err = tapClient.ImportProof(ctxb, &importReq)
	require.NoError(t.t, err)

	// After proof import, the minted assets should appear in the output of
	// ListAssets.
	mintReq := []*mintrpc.MintAssetRequest{{
		Asset:         req,
		ShortResponse: false,
	}}
	mintedAsset := AssertAssetsMinted(
		t.t, tapClient, mintReq, confEvent.Tx.TxHash(),
		confEvent.Block.BlockHash(),
	)

	return mintedAsset[0], &importReq
}

// SyncUniverses syncs the universes of two tapd instances and waits until they
// are in sync.
func SyncUniverses(ctx context.Context, t *testing.T, clientTapd,
	universeTapd TapdClient, universeHost string, timeout time.Duration) {

	ctxt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, err := clientTapd.AddFederationServer(
		ctxt, &universerpc.AddFederationServerRequest{
			Servers: []*universerpc.UniverseFederationServer{
				{
					Host: universeHost,
				},
			},
		},
	)
	if err != nil {
		// Only fail the test for other errors than duplicate universe
		// errors, as we might have already added the server in a
		// previous run.
		require.ErrorContains(
			t, err, universe.ErrDuplicateUniverse.Error(),
		)

		// If we've already added the server in a previous run, we'll
		// just need to kick off a sync (as that would otherwise be done
		// by adding the server request already).
		mode := universerpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY
		_, err := clientTapd.SyncUniverse(ctxt, &universerpc.SyncRequest{
			UniverseHost: universeHost,
			SyncMode:     mode,
		})
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		return AssertUniverseStateEqual(t, universeTapd, clientTapd)
	}, timeout, time.Second)
}

// SubscribeSendEvents subscribes to send events and returns the event stream.
func SubscribeSendEvents(t *testing.T,
	tapd TapdClient) *EventSubscription[*tapdevrpc.SendAssetEvent] {

	ctxb := context.Background()
	ctxt, cancel := context.WithCancel(ctxb)

	stream, err := tapd.SubscribeSendAssetEventNtfns(
		ctxt, &tapdevrpc.SubscribeSendAssetEventNtfnsRequest{},
	)
	require.NoError(t, err)

	return &EventSubscription[*tapdevrpc.SendAssetEvent]{
		ClientEventStream: stream,
		Cancel:            cancel,
	}
}

// SubscribeReceiveEvents subscribes to receive events and returns the event
// stream.
func SubscribeReceiveEvents(t *testing.T,
	tapd TapdClient) *EventSubscription[*tapdevrpc.ReceiveAssetEvent] {

	ctxb := context.Background()
	ctxt, cancel := context.WithCancel(ctxb)

	stream, err := tapd.SubscribeReceiveAssetEventNtfns(
		ctxt, &tapdevrpc.SubscribeReceiveAssetEventNtfnsRequest{},
	)
	require.NoError(t, err)

	return &EventSubscription[*tapdevrpc.ReceiveAssetEvent]{
		ClientEventStream: stream,
		Cancel:            cancel,
	}
}

// NewAddrWithEventStream creates a new TAP address and also registers a new
// event stream for receive events for the address.
func NewAddrWithEventStream(t *testing.T, tapd TapdClient,
	req *taprpc.NewAddrRequest) (*taprpc.Addr,
	*EventSubscription[*taprpc.ReceiveEvent]) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	addr, err := tapd.NewAddr(ctxt, req)
	require.NoError(t, err)

	ctxc, cancel := context.WithCancel(ctxb)
	stream, err := tapd.SubscribeReceiveEvents(
		ctxc, &taprpc.SubscribeReceiveEventsRequest{
			FilterAddr: addr.Encoded,
		},
	)
	require.NoError(t, err)

	return addr, &EventSubscription[*taprpc.ReceiveEvent]{
		ClientEventStream: stream,
		Cancel:            cancel,
	}
}
