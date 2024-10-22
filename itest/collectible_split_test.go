package itest

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	prand "math/rand"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// testCollectibleSend tests that we can properly send a collectible asset
// with split commitments.
func testCollectibleSend(t *harnessTest) {
	// First, we'll make a collectible with emission enabled.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			issuableAssets[1],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	groupKey := rpcAssets[0].AssetGroup.TweakedGroupKey
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to complete three transfers of the full value of
	// the asset between our main node and Bob.
	var (
		numSends            = 3
		senderTransferIdx   = 0
		receiverTransferIdx = 0
		fullAmount          = rpcAssets[0].Amount
	)

	for i := 0; i < numSends; i++ {
		// Create an address for the receiver and send the asset. We
		// start with Bob receiving the asset, then sending it back
		// to the main node, and so on.
		if i%2 == 0 {
			receiverAddr, events := NewAddrWithEventStream(
				t.t, secondTapd, &taprpc.NewAddrRequest{
					AssetId: genInfo.AssetId,
					Amt:     fullAmount,
				},
			)

			AssertAddrCreated(
				t.t, secondTapd, rpcAssets[0], receiverAddr,
			)
			sendResp, sendEvents := sendAssetsToAddr(
				t, t.tapd, receiverAddr,
			)
			ConfirmAndAssertOutboundTransfer(
				t.t, t.lndHarness.Miner().Client, t.tapd,
				sendResp, genInfo.AssetId,
				[]uint64{0, fullAmount}, senderTransferIdx,
				senderTransferIdx+1,
			)
			senderTransferIdx++

			AssertNonInteractiveRecvComplete(
				t.t, secondTapd, senderTransferIdx,
			)
			AssertSendEventsComplete(
				t.t, receiverAddr.ScriptKey, sendEvents,
			)
			AssertReceiveEvents(t.t, receiverAddr, events)
		} else {
			receiverAddr, events := NewAddrWithEventStream(
				t.t, t.tapd, &taprpc.NewAddrRequest{
					AssetId: genInfo.AssetId,
					Amt:     fullAmount,
				},
			)

			AssertAddrCreated(
				t.t, t.tapd, rpcAssets[0], receiverAddr,
			)
			sendResp, sendEvents := sendAssetsToAddr(
				t, secondTapd, receiverAddr,
			)
			ConfirmAndAssertOutboundTransfer(
				t.t, t.lndHarness.Miner().Client, secondTapd,
				sendResp, genInfo.AssetId,
				[]uint64{0, fullAmount}, receiverTransferIdx,
				receiverTransferIdx+1,
			)
			receiverTransferIdx++
			AssertNonInteractiveRecvComplete(
				t.t, t.tapd, receiverTransferIdx,
			)
			AssertSendEventsComplete(
				t.t, receiverAddr.ScriptKey, sendEvents,
			)
			AssertReceiveEvents(t.t, receiverAddr, events)
		}
	}

	// Check the final state of both nodes. The main node should list 2
	// zero-value transfers. and Bob should have 1. The main node should
	// show a balance of zero, and Bob should hold the total asset supply.
	AssertTransfer(t.t, t.tapd, 0, 2, []uint64{0, fullAmount})
	AssertTransfer(t.t, t.tapd, 1, 2, []uint64{0, fullAmount})
	AssertBalanceByID(t.t, t.tapd, genInfo.AssetId, 0)

	AssertTransfer(t.t, secondTapd, 0, 1, []uint64{0, fullAmount})
	AssertBalanceByID(t.t, secondTapd, genInfo.AssetId, fullAmount)

	// The second daemon should list one group with one asset.
	listGroupsResp, err := secondTapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	groupKeys := maps.Keys(listGroupsResp.Groups)
	require.Len(t.t, groupKeys, 1)

	rpcGroupKey, err := hex.DecodeString(groupKeys[0])
	require.NoError(t.t, err)
	require.Equal(t.t, groupKey, rpcGroupKey)

	groupedAssets := listGroupsResp.Groups[groupKeys[0]].Assets
	require.Len(t.t, groupedAssets, 1)

	// Sort the assets with a group by amount, descending.
	sort.Slice(groupedAssets, func(i, j int) bool {
		return groupedAssets[i].Amount > groupedAssets[j].Amount
	})

	listAssetsResp, err := secondTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	// Sort all assets by amount, descending.
	allAssets := listAssetsResp.Assets
	sort.Slice(allAssets, func(i, j int) bool {
		return allAssets[i].Amount > allAssets[j].Amount
	})

	// Only compare the spendable asset.
	AssertGroup(t.t, allAssets[0], groupedAssets[0], rpcGroupKey)

	aliceAssetsResp, err := t.tapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{IncludeSpent: true},
	)
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssetsResp)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)

	// Finally, make sure we can still send out the passive asset.
	passiveGen := rpcAssets[1].AssetGenesis
	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: passiveGen.AssetId,
		Amt:     rpcAssets[1].Amount,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, secondTapd, rpcAssets[1], bobAddr)
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		passiveGen.AssetId, []uint64{0, rpcAssets[1].Amount}, 2, 3,
	)

	// There's only one non-interactive receive event.
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 3)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
}

// testCollectibleGroupSend tests that we can properly send a collectible asset
// out of a group of assets.
func testCollectibleGroupSend(t *harnessTest) {
	var (
		minterTimeout  = defaultWaitTimeout
		batchSize      = 50
		batchReqs      = make([]*mintrpc.MintAssetRequest, batchSize)
		baseName       = fmt.Sprintf("jpeg-%d", rand.Int31())
		metaPrefixSize = binary.MaxVarintLen16
		metadataPrefix = make([]byte, metaPrefixSize)
		aliceHost      = t.tapd.rpcHost()
		ctxb           = context.Background()
	)

	// Before we mint a new group, let's first find out how many there
	// already are.
	initialGroups := NumGroups(t.t, t.tapd)

	// Each asset in the batch will share a name and metdata preimage, that
	// will be updated based on the asset's index in the batch.
	collectibleRequestTemplate := mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_COLLECTIBLE,
			Name:      baseName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("foo"),
				Type: 0,
			},
			Amount:          1,
			NewGroupedAsset: false,
		},
	}

	// Update the asset name and metadata to match an index.
	incrementMintAsset := func(asset *mintrpc.MintAsset, idx int) {
		asset.Name = fmt.Sprintf("%s-%d", asset.Name, idx)
		binary.PutUvarint(metadataPrefix, uint64(idx))
		copy(asset.AssetMeta.Data[0:metaPrefixSize], metadataPrefix)
	}

	// Use the first asset of the batch as the asset group anchor.
	collectibleAnchorReq := CopyRequest(&collectibleRequestTemplate)
	incrementMintAsset(collectibleAnchorReq.Asset, 0)
	collectibleAnchorReq.Asset.NewGroupedAsset = true
	batchReqs[0] = collectibleAnchorReq

	// Generate the rest of the batch, with each asset referencing the group
	// anchor we created above.
	for i := 1; i < batchSize; i++ {
		groupedAsset := CopyRequest(&collectibleRequestTemplate)
		incrementMintAsset(groupedAsset.Asset, i)
		groupedAsset.Asset.GroupAnchor = collectibleAnchorReq.Asset.Name
		groupedAsset.Asset.NewGroupedAsset = false
		groupedAsset.Asset.GroupedAsset = true
		batchReqs[i] = groupedAsset
	}

	// Submit the batch for minting. Use an extended timeout for the TX
	// appearing in the mempool, so we can observe the minter hitting its
	// own shorter default timeout.
	LogfTimestamped(t.t, "beginning minting of batch of %d assets",
		batchSize)

	mintBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, batchReqs,
		WithMintingTimeout(minterTimeout),
	)

	LogfTimestamped(t.t, "finished batch mint of %d assets", batchSize)

	// We can re-derive the group key to verify that the correct asset was
	// used as the group anchor.
	collectibleAnchor := VerifyGroupAnchor(
		t.t, mintBatch, collectibleAnchorReq.Asset.Name,
	)
	collectGroupKey := collectibleAnchor.AssetGroup.TweakedGroupKey
	collectGroupKeyStr := hex.EncodeToString(collectGroupKey[:])

	// We should have one group, with the specified number of assets and an
	// equivalent balance, since the group is made of collectibles.
	groupCount := initialGroups + 1
	groupBalance := batchSize

	AssertNumGroups(t.t, t.tapd, groupCount)
	AssertGroupSizes(
		t.t, t.tapd, []string{collectGroupKeyStr},
		[]int{batchSize},
	)
	AssertBalanceByGroup(
		t.t, t.tapd, collectGroupKeyStr, uint64(groupBalance),
	)

	// The universe tree should reflect the same properties about the batch;
	// there should be one root with a group key and balance matching what
	// we asserted previously.
	uniRoots, err := t.tapd.AssetRoots(ctxb, &unirpc.AssetRootRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, uniRoots.UniverseRoots, groupCount)

	AssertUniverseRoot(t.t, t.tapd, groupBalance, nil, collectGroupKey)

	// The universe tree should also have a leaf for each asset minted.
	// TODO(jhb): Resolve issue of 33-byte group key handling.
	collectUniID := unirpc.ID{
		Id: &unirpc.ID_GroupKey{
			GroupKey: collectGroupKey[1:],
		},
		ProofType: unirpc.ProofType_PROOF_TYPE_ISSUANCE,
	}
	uniLeaves, err := t.tapd.AssetLeaves(ctxb, &collectUniID)
	require.NoError(t.t, err)
	require.Len(t.t, uniLeaves.Leaves, batchSize)

	// The universe tree should also have a key for each asset, with all
	// outpoints matching the chain anchor of the group anchor.
	mintOutpoint := collectibleAnchor.ChainAnchor.AnchorOutpoint
	uniKeys, err := t.tapd.AssetLeafKeys(
		ctxb, &unirpc.AssetLeafKeysRequest{
			Id: &collectUniID,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, uniKeys.AssetKeys, batchSize)

	correctOp := fn.All(uniKeys.AssetKeys, func(key *unirpc.AssetKey) bool {
		return key.GetOpStr() == mintOutpoint
	})
	require.True(t.t, correctOp)

	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	_, err = secondTapd.AddFederationServer(
		ctxb, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: aliceHost,
				},
			},
		},
	)
	require.NoError(t.t, err)

	require.Eventually(t.t, func() bool {
		return AssertUniverseStateEqual(t.t, t.tapd, secondTapd)
	}, minterTimeout, time.Second)

	const numAssets = 1
	const sendType = taprpc.AssetType_COLLECTIBLE
	const numSends = 5
	t.Logf("Running send test, sending %d asset(s) of type %v %d times",
		numAssets, sendType, numSends)

	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*numSends)
	defer cancel()

	for i := 1; i <= numSends; i++ {
		send, receive, ok := pickSendNode(
			t.t, ctxt, numAssets, sendType, t.tapd, secondTapd,
		)
		if !ok {
			t.Fatalf("Aborting send test at attempt %d of %d as "+
				"no node has enough balance to send %d "+
				"assets of type %v", i, numSends,
				numAssets, sendType)
			return
		}

		sendAssets(
			t.t, ctxt, numAssets, sendType, send, receive,
			t.lndHarness.Miner().Client,
		)

		t.Logf("Finished %d of %d send operations", i, numSends)
	}
}

// sendAsset sends the given number of assets of the given type from the given
// node to the other node.
func sendAssets(t *testing.T, ctx context.Context, numAssets uint64,
	assetType taprpc.AssetType, send, receive *tapdHarness,
	bitcoinClient *rpcclient.Client) {

	// Query the asset we'll be sending, so we can assert some things about
	// it later.
	sendAsset := send.assetIDWithBalance(t, ctx, numAssets, assetType)
	t.Logf("Sending %d asset(s) with ID %x from %v to %v", numAssets,
		sendAsset.AssetGenesis.AssetId, send.rpcHost(),
		receive.rpcHost())

	// Let's create an address on the receiving node and make sure it's
	// created correctly.
	addr, stream := NewAddrWithEventStream(
		t, receive, &taprpc.NewAddrRequest{
			AssetId: sendAsset.AssetGenesis.AssetId,
			Amt:     numAssets,
			ProofCourierAddr: fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				send.rpcHost(),
			),
		},
	)
	AssertAddrCreated(t, receive, sendAsset, addr)

	// Before we send the asset, we record the existing transfers on the
	// sending node, so we can easily select the new transfer once it
	// appears.
	transfersBefore := send.listTransfersSince(t, ctx, nil)

	// Initiate the send now.
	_, err := send.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{addr.Encoded},
	})
	require.NoError(t, err)

	// Wait for the transfer to appear on the sending node.
	require.Eventually(t, func() bool {
		newTransfers := send.listTransfersSince(t, ctx, transfersBefore)
		return len(newTransfers) == 1
	}, defaultTimeout, wait.PollInterval)

	// And for it to be detected on the receiving node.
	AssertAddrEvent(t, receive, addr, 1, statusDetected)

	// Mine a block to confirm the transfer.
	MineBlocks(t, bitcoinClient, 1, 1)

	// Now the transfer should go to completed eventually.
	AssertAddrEvent(t, receive, addr, 1, statusCompleted)
	AssertReceiveEvents(t, addr, stream)
}

// pickSendNode picks a node at random, checks whether it has enough assets of
// the given type, and returns it. The second return value is the other node,
// which will be the receiving node. The boolean argument returns true if there
// is a node with sufficient balance. If that is false, the test should be
// skipped.
func pickSendNode(t *testing.T, ctx context.Context, minBalance uint64,
	assetType taprpc.AssetType, a, b *tapdHarness) (*tapdHarness,
	*tapdHarness, bool) {

	send, receive := a, b
	if prand.Intn(1) == 0 {
		send, receive = b, a
	}

	// Check if the randomly picked send node has enough balance.
	if send.assetIDWithBalance(t, ctx, minBalance, assetType) != nil {
		return send, receive, true
	}

	// If we get here, the send node doesn't have enough balance. We'll try
	// the other one.
	send, receive = receive, send
	if send.assetIDWithBalance(t, ctx, minBalance, assetType) != nil {
		return send, receive, true
	}

	// None of the nodes have enough balance. We can't run the send test
	// currently.
	return nil, nil, false
}
