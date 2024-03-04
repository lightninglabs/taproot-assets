package itest

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var (
	zeroHash          chainhash.Hash
	regtestMiningAddr = "n1VgRjYDzJT2TV72PnungWgWu18SWorXZS"
	regtestParams     = &chaincfg.RegressionNetParams
)

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
	event *taprpc.SendAssetEvent, broadcastState string) bool {

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

// AssertSendEventProofTransferBackoffWait asserts that the send asset event is
// a ProofTransferBackoffWait event, with the transfer type set as send.
func AssertSendEventProofTransferBackoffWaitTypeSend(t *harnessTest,
	event *taprpc.SendAssetEvent) bool {

	ev := event.GetProofTransferBackoffWaitEvent()
	if ev == nil {
		return false
	}

	// We're listening for events on the sender node. We therefore expect to
	// receive deliver transfer type backoff wait events for sending
	// transfers.
	typeSend := taprpc.ProofTransferType_PROOF_TRANSFER_TYPE_SEND
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

	switch backend {
	case rpcclient.BitcoindPost19:
		addr, err := btcutil.DecodeAddress(
			regtestMiningAddr, regtestParams,
		)
		require.NoError(t, err)

		blockHashes, err = client.GenerateToAddress(
			int64(num), addr, nil,
		)
		require.NoError(t, err)

	case rpcclient.Btcd:
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

	minerAddr := t.lndHarness.Miner.NewMinerAddress()

	// Drain any funds held by the node.
	wallet.RPC.SendCoins(&lnrpc.SendCoinsRequest{
		Addr:    minerAddr.EncodeAddress(),
		SendAll: true,
	})
	t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)

	// Build TXOs from the UTXO requests, which will be used by the miner
	// to build a TX.
	aliceOutputs := fn.Map(reqs, func(r *UTXORequest) *wire.TxOut {
		return MakeOutput(t, wallet, r.Type, r.Amount)
	})

	_ = t.lndHarness.Miner.SendOutputsWithoutChange(aliceOutputs, feeRate)
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

// MintAssetUnconfirmed is a helper function that mints a batch of assets and
// waits until the minting transaction is in the mempool but does not mine a
// block.
func MintAssetUnconfirmed(t *testing.T, minerClient *rpcclient.Client,
	tapClient TapdClient, assetRequests []*mintrpc.MintAssetRequest,
	opts ...MintOption) (chainhash.Hash, []byte) {

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
		ctxt, &taprpc.ListAssetRequest{},
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
		metaHash := (&proof.MetaReveal{
			Type: proof.MetaOpaque,
			Data: assetRequest.Asset.AssetMeta.Data,
		}).MetaHash()
		AssertAssetState(
			t, unconfirmedAssets, assetRequest.Asset.Name,
			metaHash[:],
			AssetAmountCheck(assetRequest.Asset.Amount),
			AssetTypeCheck(assetRequest.Asset.AssetType),
			AssetAnchorCheck(*hashes[0], zeroHash),
			AssetScriptKeyIsLocalCheck(true),
			AssetVersionCheck(assetRequest.Asset.AssetVersion),
		)
	}

	return *hashes[0], batchResp.Batch.BatchKey
}

// MintAssetsConfirmBatch mints all given assets in the same batch, confirms the
// batch and verifies all asset proofs of the minted assets.
func MintAssetsConfirmBatch(t *testing.T, minerClient *rpcclient.Client,
	tapClient TapdClient, assetRequests []*mintrpc.MintAssetRequest,
	opts ...MintOption) []*taprpc.Asset {

	mintTXID, batchKey := MintAssetUnconfirmed(
		t, minerClient, tapClient, assetRequests, opts...,
	)

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
	require.NotEmpty(t, batch.BatchTxid)

	return AssertAssetsMinted(t, tapClient, assetRequests, mintTXID, blockHash)
}
