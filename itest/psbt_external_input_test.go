package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func testPsbtExternalInput(t *harnessTest) {
	testExternalInputConfirmation(t, false)
}

func testPsbtExternalInputRestart(t *harnessTest) {
	testExternalInputConfirmation(t, true)
}

// testExternalInputConfirmation spends a composed output without importing it
// into the publishing wallet. The restart case pays back into that wallet,
// exercising local output creation when no wallet input supplies a template.
func testExternalInputConfirmation(t *harnessTest, restart bool) {
	ctx := context.Background()
	alice := t.tapd
	miner := t.lndHarness.Miner()
	minted := MintAssetsConfirmBatch(
		t.t, miner, alice,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)[0]
	id := fn.ToArray[asset.ID](minted.AssetGenesis.AssetId)

	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	assetLeaf := txscript.NewBaseTapLeaf([]byte{txscript.OP_TRUE})
	assetTree := input.TapscriptFullTree(asset.NUMSPubKey, assetLeaf)
	externalKey, err := assetTree.TaprootKey()
	require.NoError(t.t, err)
	assetControl, err := assetTree.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	preimage := []byte("external anchor custody")
	btcLeaf := test.ScriptHashLock(t.t, preimage)
	sibling, err := commitment.NewPreimageFromLeaf(btcLeaf)
	require.NoError(t.t, err)

	packet := tappsbt.ForInteractiveSend(
		id, minted.Amount, asset.NewScriptKey(externalKey), 0, 0, 0,
		keychain.KeyDescriptor{PubKey: asset.NUMSPubKey}, asset.V1,
		&address.RegressionNetTap,
	)
	packet.Outputs[0].AnchorOutputTapscriptSibling = sibling
	funded := fundPacket(t, alice, packet)
	packet, err = tappsbt.Decode(funded.FundedPsbt)
	require.NoError(t.t, err)
	require.Empty(t.t, funded.PassiveAssetPsbts)
	packet = signVirtualPacket(t.t, alice, packet)

	btcPacket, err := tapsend.PrepareAnchoringTemplate(
		[]*tappsbt.VPacket{packet},
	)
	require.NoError(t.t, err)
	btcPacket, packets, _, committed := CommitVirtualPsbts(
		t.t, alice, btcPacket, []*tappsbt.VPacket{packet}, nil, -1,
	)
	btcPacket = FinalizePacket(t.t, alice.cfg.LndNode.RPC, btcPacket)
	locked := PublishAndLogTransfer(
		t.t, alice, btcPacket, packets, nil, committed,
	)
	MineBlocks(t.t, miner, 1, 1)
	lockFile := ExportProofFile(
		t.t, alice, id[:], externalKey.SerializeCompressed(), nil,
	)
	decoded, err := proof.DecodeFile(lockFile.RawProofFile)
	require.NoError(t.t, err)
	lockProof, err := decoded.LastProof()
	require.NoError(t.t, err)

	assertExternalNotOwned := func() {
		for _, includeSpent := range []bool{false, true} {
			assets, err := alice.ListAssets(
				ctx, &taprpc.ListAssetRequest{
					IncludeSpent:  includeSpent,
					IncludeLeased: !includeSpent,
					ScriptKeyType: allScriptKeysQuery,
				},
			)
			require.NoError(t.t, err)
			for _, held := range assets.Assets {
				require.NotEqual(
					t.t, externalKey.SerializeCompressed(),
					held.ScriptKey,
				)
			}
		}
	}
	assertExternalNotOwned()
	AssertBalanceByID(t.t, alice, id[:], 0)

	receiver := bob
	if restart {
		receiver = alice
	}
	receiverKey, receiverAnchor := DeriveKeys(
		t.t, receiver,
	)
	spend, err := tappsbt.FromProofs(
		[]*proof.Proof{lockProof}, &address.RegressionNetTap,
		tappsbt.V1,
	)
	require.NoError(t.t, err)
	tappsbt.AddOutput(
		spend, minted.Amount, receiverKey, 0, receiverAnchor, asset.V1,
	)
	require.NoError(t.t, tapsend.PrepareOutputAssets(ctx, spend))
	spend.Outputs[0].Asset.PrevWitnesses[0].TxWitness = wire.TxWitness{
		assetLeaf.Script, assetControl,
	}

	btcPacket, err = tapsend.PrepareAnchoringTemplate(
		[]*tappsbt.VPacket{spend},
	)
	require.NoError(t.t, err)
	btcPacket, packets, _, committed = CommitVirtualPsbts(
		t.t, alice, btcPacket, []*tappsbt.VPacket{spend}, nil, -1,
	)
	btcTree := input.TapscriptPartialReveal(
		asset.NUMSPubKey, btcLeaf,
		locked.Transfer.Outputs[0].Anchor.TaprootAssetRoot,
	)
	btcControl, err := btcTree.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	var witness bytes.Buffer
	require.NoError(t.t, psbt.WriteTxWitness(&witness, wire.TxWitness{
		preimage, btcLeaf.Script, btcControl,
	}))
	btcPacket.Inputs[0].FinalScriptWitness = witness.Bytes()
	btcPacket = FinalizePacket(t.t, alice.cfg.LndNode.RPC, btcPacket)
	published := PublishAndLogTransfer(
		t.t, alice, btcPacket, packets, nil, committed,
		withSkipAnchorTxBroadcast(),
	)
	if restart {
		require.NoError(t.t, alice.stop(false))
		require.NoError(t.t, alice.start(false))
		assertExternalNotOwned()
	}

	var anchor wire.MsgTx
	require.NoError(t.t, anchor.Deserialize(
		bytes.NewReader(published.Transfer.AnchorTx),
	))
	miner.MineBlockWithTx(&anchor)
	finalProof := ExportProofFile(
		t.t, alice, id[:],
		receiverKey.PubKey.SerializeCompressed(), nil,
	)
	verified, err := alice.VerifyProof(ctx, &taprpc.ProofFile{
		RawProofFile: finalProof.RawProofFile,
	})
	require.NoError(t.t, err)
	require.True(t.t, verified.Valid)
	if receiver == bob {
		ImportProofFile(t, bob, finalProof.RawProofFile)
	}
	AssertBalanceByID(t.t, receiver, id[:], minted.Amount)
	assertExternalNotOwned()

	transfers, err := alice.ListTransfers(ctx, &taprpc.ListTransfersRequest{
		AnchorTxid: anchor.TxHash().String(),
	})
	require.NoError(t.t, err)
	require.Len(t.t, transfers.Transfers, 1)
	require.NotZero(t.t, transfers.Transfers[0].AnchorTxBlockHeight)
	if restart {
		require.NoError(t.t, alice.stop(false))
		require.NoError(t.t, alice.start(false))
		AssertBalanceByID(t.t, alice, id[:], minted.Amount)
		assertExternalNotOwned()
	}
}
