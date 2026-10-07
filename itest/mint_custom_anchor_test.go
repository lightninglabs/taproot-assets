//nolint:lll
package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
)

// testMintCustomAnchorPsbt proves the complete issue #721 lifecycle with a
// wallet-owned, caller-authored anchor: fund, prepare, externally sign,
// finalize, confirm, and spend the minted asset to a second tapd node.
func testMintCustomAnchorPsbt(t *harnessTest) {
	var (
		ctx       = context.Background()
		aliceTapd = t.tapd
		aliceLnd  = t.tapd.cfg.LndNode
		miner     = t.lndHarness.Miner()
	)

	bobLnd := t.lndHarness.NewNodeWithCoins("custom-anchor-bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	mintReq := CopyRequest(simpleAssets[0])
	mintReq.Asset.Name = "issue-721-custom-anchor-itest"
	mintReq.Asset.Amount = 100
	mintReqs := []*mintrpc.MintAssetRequest{mintReq}

	BuildMintingBatch(t.t, aliceTapd, mintReqs)

	// Use an lnd-owned internal key as the caller-selected asset anchor. The
	// output derivation fields use lnd's BIP-0043 purpose (1017') so tapd can
	// prove the locator belongs to the same wallet before committing it.
	anchorKeyResp := aliceLnd.RPC.DeriveNextKey(&walletrpc.KeyReq{
		KeyFamily: int32(asset.TaprootAssetsKeyFamily),
	})
	anchorInternalKey, err := btcec.ParsePubKey(anchorKeyResp.RawKeyBytes)
	require.NoError(t.t, err)
	anchorOutputKey := txscript.ComputeTaprootKeyNoScript(anchorInternalKey)
	anchorScript, err := txscript.PayToTaprootScript(anchorOutputKey)
	require.NoError(t.t, err)

	const anchorValue = int64(10_000)
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{
		Value:    anchorValue,
		PkScript: anchorScript,
	})
	template, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t.t, err)
	anchorKeyDesc := keychain.KeyDescriptor{
		PubKey: anchorInternalKey,
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(anchorKeyResp.KeyLoc.KeyFamily),
			Index:  uint32(anchorKeyResp.KeyLoc.KeyIndex),
		},
	}
	bip32Derivation, taprootDerivation :=
		tappsbt.Bip32DerivationFromKeyDesc(
			anchorKeyDesc, harnessNetParams.HDCoinType,
		)
	template.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	template.Outputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{taprootDerivation}
	template.Outputs[0].TaprootInternalKey =
		taprootDerivation.XOnlyPubKey
	template.Outputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x50}, Value: []byte("issue-721-anchor"),
	}}
	internalKey, err := schnorr.ParsePubKey(taprootDerivation.XOnlyPubKey)
	require.NoError(t.t, err)
	bip86OutputKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	require.Equal(t.t, schnorr.SerializePubKey(bip86OutputKey),
		anchorScript[2:])

	templateBytes, err := fn.Serialize(template)
	require.NoError(t.t, err)
	fundResp := aliceLnd.RPC.FundPsbt(&walletrpc.FundPsbtRequest{
		Template: &walletrpc.FundPsbtRequest_CoinSelect{
			CoinSelect: &walletrpc.PsbtCoinSelect{
				Psbt: templateBytes,
				ChangeOutput: &walletrpc.PsbtCoinSelect_Add{
					Add: true,
				},
			},
		},
		Fees: &walletrpc.FundPsbtRequest_SatPerVbyte{
			SatPerVbyte: 2,
		},
		MinConfs:    1,
		ChangeType:  walletrpc.ChangeAddressType_CHANGE_ADDRESS_TYPE_P2TR,
		MaxFeeRatio: 1,
	})
	require.NotEmpty(t.t, fundResp.LockedUtxos)
	require.GreaterOrEqual(t.t, fundResp.ChangeOutputIndex, int32(1))

	fundedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, fundedPacket.Inputs)
	require.Equal(t.t, anchorValue,
		fundedPacket.UnsignedTx.TxOut[0].Value)
	require.Equal(t.t, anchorScript,
		fundedPacket.UnsignedTx.TxOut[0].PkScript)

	// FundPsbt initially leases every selected wallet input under its own
	// lock ID. Release those leases before FundBatch asks tapd to acquire
	// the same inputs under the custom-anchor lease ID.
	for _, lease := range fundResp.LockedUtxos {
		_, err := aliceLnd.RPC.WalletKit.ReleaseOutput(
			ctx, &walletrpc.ReleaseOutputRequest{
				Id:       lease.Id,
				Outpoint: lease.Outpoint,
			},
		)
		require.NoError(t.t, err)
	}

	fundBatchResp, err := aliceTapd.FundBatch(
		ctx, &mintrpc.FundBatchRequest{
			AnchorPsbt:             fundResp.FundedPsbt,
			AssetAnchorOutputIndex: 0,
			ChangeOutputIndex:      fundResp.ChangeOutputIndex,
		},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_PENDING,
		fundBatchResp.Batch.Batch.State,
	)

	prepareResp, err := aliceTapd.PrepareBatch(
		ctx, &mintrpc.PrepareBatchRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_COMMITTED,
		prepareResp.Batch.State,
	)
	preparedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(prepareResp.Batch.BatchPsbt), false,
	)
	require.NoError(t.t, err)

	// Preparation is allowed to replace only the selected anchor script.
	require.Equal(t.t, fundedPacket.UnsignedTx.TxIn,
		preparedPacket.UnsignedTx.TxIn)
	require.Equal(t.t, fundedPacket.Inputs, preparedPacket.Inputs)
	require.Equal(t.t, anchorValue,
		preparedPacket.UnsignedTx.TxOut[0].Value)
	require.NotEqual(t.t, anchorScript,
		preparedPacket.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t.t, fundedPacket.Outputs[0].Bip32Derivation,
		preparedPacket.Outputs[0].Bip32Derivation)
	require.Equal(t.t, fundedPacket.Outputs[0].Unknowns,
		preparedPacket.Outputs[0].Unknowns)
	require.Nil(t.t, preparedPacket.Outputs[0].TaprootInternalKey)
	require.Nil(t.t, preparedPacket.Outputs[0].TaprootBip32Derivation)
	for idx := 1; idx < len(fundedPacket.UnsignedTx.TxOut); idx++ {
		require.Equal(t.t, fundedPacket.UnsignedTx.TxOut[idx],
			preparedPacket.UnsignedTx.TxOut[idx])
		require.Equal(t.t, fundedPacket.Outputs[idx],
			preparedPacket.Outputs[idx])
	}

	// WalletKit signs the wallet input and local PSBT finalization is used
	// for compatibility with the remote-signing itest mode.
	signedPacket := FinalizePacket(t.t, aliceLnd.RPC, preparedPacket)
	signedBytes, err := fn.Serialize(signedPacket)
	require.NoError(t.t, err)
	ctxFinalize, cancelFinalize := context.WithTimeout(ctx, defaultWaitTimeout)
	finalizeResp, err := aliceTapd.FinalizeBatch(
		ctxFinalize, &mintrpc.FinalizeBatchRequest{
			SignedPsbt: signedBytes,
		},
	)
	cancelFinalize()
	require.NoError(t.t, err)
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_BROADCAST,
		finalizeResp.Batch.State,
	)

	hashes, err := WaitForNTxsInMempool(miner, 1, defaultWaitTimeout)
	require.NoError(t.t, err)
	require.Len(t.t, hashes, 1)
	block := MineBlocks(t.t, miner, 1, 1)[0]
	ctxWait, cancelWait := context.WithTimeout(ctx, defaultWaitTimeout)
	defer cancelWait()
	WaitForBatchState(
		t.t, ctxWait, aliceTapd, defaultWaitTimeout,
		finalizeResp.Batch.BatchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)
	mintedAssets := AssertAssetsMinted(
		t.t, aliceTapd, mintReqs, *hashes[0], block.BlockHash(),
	)
	require.Len(t.t, mintedAssets, 1)
	mintedAsset := mintedAssets[0]

	const sendAmount = uint64(40)
	bobAddr, err := bobTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: mintedAsset.AssetGenesis.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, mintedAsset, bobAddr)

	sendResp, sendEvents := sendAssetsToAddr(t, aliceTapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, miner, aliceTapd, sendResp,
		mintedAsset.AssetGenesis.AssetId,
		[]uint64{mintedAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
	AssertBalanceByID(
		t.t, bobTapd, mintedAsset.AssetGenesis.AssetId, sendAmount,
	)
}
