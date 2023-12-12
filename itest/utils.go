package itest

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
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

// ParseOutPoint
func ParseOutPoint(s string) (*wire.OutPoint, error) {
	split := strings.Split(s, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("expecting outpoint to be in format " +
			"of: txid:index")
	}

	index, err := strconv.ParseInt(split[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("unable to decode output index: %v", err)
	}

	txid, err := chainhash.NewHashFromStr(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse hex string: %v", err)
	}

	return &wire.OutPoint{
		Hash:  *txid,
		Index: uint32(index),
	}, nil
}

// ParseGenInfo converts a taprpc.GenesisInfo into its asset.Genesis
// counterpart.
func ParseGenInfo(t *testing.T, genInfo *taprpc.GenesisInfo) *asset.Genesis {
	genPoint, err := ParseOutPoint(genInfo.GenesisPoint)
	require.NoError(t, err)

	parsedGenesis := asset.Genesis{
		FirstPrevOut: *genPoint,
		Tag:          genInfo.Name,
		OutputIndex:  genInfo.OutputIndex,
	}
	copy(parsedGenesis.MetaHash[:], genInfo.MetaHash)

	return &parsedGenesis
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
	makeOutputs := func(req *UTXORequest) *wire.TxOut {
		addrResp := wallet.RPC.NewAddress(
			&lnrpc.NewAddressRequest{
				Type: req.Type,
			},
		)

		addr, err := btcutil.DecodeAddress(
			addrResp.Address, t.lndHarness.Miner.ActiveNet,
		)
		require.NoError(t.t, err)

		addrScript, err := txscript.PayToAddrScript(addr)
		require.NoError(t.t, err)

		return &wire.TxOut{
			PkScript: addrScript,
			Value:    req.Amount,
		}
	}

	aliceOutputs := fn.Map(reqs, makeOutputs)

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
	mintingTimeout time.Duration
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

	// Instruct the daemon to finalize the batch.
	batchResp, err := tapClient.FinalizeBatch(
		ctxt, &mintrpc.FinalizeBatchRequest{},
	)
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
