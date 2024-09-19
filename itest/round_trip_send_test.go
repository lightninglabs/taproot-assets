package itest

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testRoundTripSend tests that we can properly send the full value of a
// normal asset.
func testRoundTripSend(t *harnessTest) {
	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

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

	// We'll send half of the minted units to Bob, and then have Bob return
	// half of the units he received.
	fullAmt := rpcAssets[0].Amount
	bobAmt := fullAmt / 2
	aliceAmt := bobAmt / 2

	hashLockPreimage := []byte("hash locks are cool")
	scriptLeaf := test.ScriptHashLock(t.t, hashLockPreimage)
	sibling, err := commitment.NewPreimageFromLeaf(scriptLeaf)
	require.NoError(t.t, err)
	siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(sibling)
	require.NoError(t.t, err)

	// First, we'll send half of the units to Bob.
	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              bobAmt,
		TapscriptSibling: siblingBytes,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, secondTapd, rpcAssets[0], bobAddr)
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId, []uint64{bobAmt, bobAmt}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)

	// Now, Alice will request half of the assets she sent to Bob.
	aliceAddr, err := t.tapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              aliceAmt,
		TapscriptSibling: siblingBytes,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, t.tapd, rpcAssets[0], aliceAddr)
	sendResp, _ = sendAssetsToAddr(t, secondTapd, aliceAddr)
	sendRespJSON, err = formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, secondTapd,
		sendResp, genInfo.AssetId, []uint64{aliceAmt, aliceAmt}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)

	// Check the final state of both nodes. Each node should list
	// one transfer, and Alice should have 3/4 of the total units.
	err = wait.NoError(func() error {
		AssertTransfer(t.t, t.tapd, 0, 1, []uint64{bobAmt, bobAmt})
		AssertBalanceByID(
			t.t, t.tapd, genInfo.AssetId, bobAmt+aliceAmt,
		)

		AssertTransfer(
			t.t, secondTapd, 0, 1, []uint64{aliceAmt, aliceAmt},
		)
		AssertBalanceByID(t.t, secondTapd, genInfo.AssetId, aliceAmt)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)

	// As a final test we make sure we can actually sweep the funds in the
	// output with the tapscript sibling with just the hash preimage,
	// burning the assets in the process.
	transferResp, err := secondTapd.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t.t, err)

	// We know the change output is always located at index 0, so the
	// recipient's output is the second one.
	bobToAliceOutput := transferResp.Transfers[0].Outputs[1]
	bobToAliceAnchor := bobToAliceOutput.Anchor
	outpoint, err := wire.NewOutPointFromString(bobToAliceAnchor.Outpoint)
	require.NoError(t.t, err)

	internalKey, err := btcec.ParsePubKey(bobToAliceAnchor.InternalKey)
	require.NoError(t.t, err)

	// Because we know the internal key and the script we want to spend, we
	// can now create the tapscript struct that's used for assembling the
	// control block and fee estimation.
	tapscript := input.TapscriptPartialReveal(
		internalKey, scriptLeaf, bobToAliceAnchor.TaprootAssetRoot,
	)

	// Spend the output again, this time back to a p2wkh address.
	_, p2wkhPkScript := newAddrWithScript(
		t.lndHarness, t.lndHarness.Alice,
		lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	)

	// Create fee estimation for a p2tr input and p2wkh output.
	feeRate := chainfee.FeePerKwFloor
	estimator := input.TxWeightEstimator{}

	// The witness will consist of the preimage and the script plus the
	// control block. The control block will be weighted by the passed
	// tapscript, so we only need to add the length of the other two items.
	estimator.AddTapscriptInput(
		lntypes.WeightUnit(
			len(hashLockPreimage)+len(scriptLeaf.Script)+1,
		), tapscript,
	)
	estimator.AddP2WKHOutput()
	estimatedWeight := estimator.Weight()
	requiredFee := feeRate.FeeForWeight(estimatedWeight)

	tx := wire.NewMsgTx(2)
	tx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: *outpoint,
	}}
	value := bobToAliceAnchor.Value - int64(requiredFee)
	tx.TxOut = []*wire.TxOut{{
		PkScript: p2wkhPkScript,
		Value:    value,
	}}

	// We can now assemble the witness stack.
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	tx.TxIn[0].Witness = wire.TxWitness{
		hashLockPreimage, scriptLeaf.Script, controlBlockBytes,
	}

	// We can now broadcast the transaction and wait for it to be mined.
	// Publish the sweep transaction and then mine it as well.
	var buf bytes.Buffer
	err = tx.Serialize(&buf)
	require.NoError(t.t, err)
	t.lndHarness.Alice.RPC.PublishTransaction(&walletrpc.Transaction{
		TxHex: buf.Bytes(),
	})

	// Mine one block which should contain the sweep transaction.
	block := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	sweepTxHash := tx.TxHash()
	t.lndHarness.Miner().AssertTxInBlock(block, sweepTxHash)

	unspent := t.lndHarness.Alice.RPC.ListUnspent(
		&walletrpc.ListUnspentRequest{
			MinConfs: 1,
		},
	)
	require.NotEmpty(t.t, unspent.Utxos)
	found := false
	for _, utxo := range unspent.Utxos {
		if utxo.PkScript == hex.EncodeToString(p2wkhPkScript) {
			require.Equal(t.t, value, utxo.AmountSat)
			found = true
			break
		}
	}
	require.True(t.t, found)
}

// newAddrWithScript returns a new bitcoin address and its pkScript.
func newAddrWithScript(ht *lntest.HarnessTest, node *node.HarnessNode,
	addrType lnrpc.AddressType) (btcutil.Address, []byte) {

	p2wkhResp := node.RPC.NewAddress(&lnrpc.NewAddressRequest{
		Type: addrType,
	})
	p2wkhAddr, err := btcutil.DecodeAddress(
		p2wkhResp.Address, harnessNetParams,
	)
	require.NoError(ht, err)

	p2wkhPkScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(ht, err)

	return p2wkhAddr, p2wkhPkScript
}
