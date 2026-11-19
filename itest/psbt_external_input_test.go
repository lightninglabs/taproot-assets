package itest

import (
	"bytes"
	"context"
	"path/filepath"

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
	"github.com/stretchr/testify/require"
)

// externalProofSource is where the publishing wallet finds the proof file of
// the external input.
type externalProofSource uint8

const (
	// externalProofArchive writes the proof file into the publisher's file
	// archive, as for a proof received out of band.
	externalProofArchive externalProofSource = iota

	// externalProofUniverse inserts each proof of the file into the
	// publisher's local universe.
	externalProofUniverse

	// externalProofRequest supplies the proof file with the publish
	// request.
	externalProofRequest
)

func testPsbtExternalInput(t *harnessTest) {
	testExternalInputConfirmation(t, false, externalProofArchive)
}

func testPsbtExternalInputRestart(t *harnessTest) {
	testExternalInputConfirmation(t, true, externalProofArchive)
}

func testPsbtExternalInputUniverseProof(t *harnessTest) {
	testExternalInputConfirmation(t, true, externalProofUniverse)
}

func testPsbtExternalInputRequestProof(t *harnessTest) {
	testExternalInputConfirmation(t, true, externalProofRequest)
}

// testExternalInputConfirmation spends a composed output without importing it
// into the publishing wallet. Another wallet mints the asset and hands over
// only the proof file, so the publisher never stores the asset's metadata. The
// restart case pays back into the publishing wallet, exercising local output
// creation when no wallet input supplies a template, and restarts before the
// anchor confirms, so confirmation reads only what the publisher stored.
func testExternalInputConfirmation(t *harnessTest, restart bool,
	source externalProofSource) {

	ctx := context.Background()
	alice := t.tapd
	miner := t.lndHarness.Miner()

	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	// The asset is ungrouped, so the publisher needs no group key lookup
	// and learns about it from the handed-over proof alone.
	mintReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "external-input",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("external metadata"),
			},
			Amount:       5000,
			AssetVersion: taprpc.AssetVersion_ASSET_VERSION_V1,
		},
	}
	minted := MintAssetsConfirmBatch(
		t.t, miner, bob, []*mintrpc.MintAssetRequest{mintReq},
	)[0]
	id := fn.ToArray[asset.ID](minted.AssetGenesis.AssetId)
	require.NotEqual(
		t.t, make([]byte, 32), minted.AssetGenesis.MetaHash,
	)

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

	// The publishing wallet funds the spend through lnd, which can only
	// size an asset input whose anchor internal key it can derive.
	_, lockAnchor := DeriveKeys(t.t, alice)
	packet := tappsbt.ForInteractiveSend(
		id, minted.Amount, asset.NewScriptKey(externalKey), 0, 0, 0,
		lockAnchor, asset.V1, &address.RegressionNetTap,
	)
	packet.Outputs[0].AnchorOutputTapscriptSibling = sibling
	funded := fundPacket(t, bob, packet)
	packet, err = tappsbt.Decode(funded.FundedPsbt)
	require.NoError(t.t, err)
	require.Empty(t.t, funded.PassiveAssetPsbts)
	packet = signVirtualPacket(t.t, bob, packet)

	btcPacket, err := tapsend.PrepareAnchoringTemplate(
		[]*tappsbt.VPacket{packet},
	)
	require.NoError(t.t, err)
	btcPacket, packets, _, committed := CommitVirtualPsbts(
		t.t, bob, btcPacket, []*tappsbt.VPacket{packet}, nil, -1,
	)
	btcPacket = FinalizePacket(t.t, bob.cfg.LndNode.RPC, btcPacket)
	locked := PublishAndLogTransfer(
		t.t, bob, btcPacket, packets, nil, committed,
	)
	MineBlocks(t.t, miner, 1, 1)
	lockFile := ExportProofFile(
		t.t, bob, id[:], externalKey.SerializeCompressed(), nil,
	)
	decoded, err := proof.DecodeFile(lockFile.RawProofFile)
	require.NoError(t.t, err)
	lockProof, err := decoded.LastProof()
	require.NoError(t.t, err)

	publishOpts := []PublishAndLogTransferOption{
		withSkipAnchorTxBroadcast(),
	}
	switch source {
	// The publishing wallet holds the external proof in its file archive
	// only, as it would for a proof received out of band.
	case externalProofArchive:
		archive, err := proof.NewFileArchiver(filepath.Join(
			alice.cfg.BaseDir, "data", alice.cfg.NetParams.Name,
		))
		require.NoError(t.t, err)
		require.NoError(t.t, archive.ImportProofs(
			ctx, proof.VerifierCtx{}, false,
			&proof.AnnotatedProof{
				Locator: proof.Locator{
					AssetID: &id,
					ScriptKey: *lockProof.Asset.
						ScriptKey.PubKey,
					OutPoint: fn.Ptr(lockProof.OutPoint()),
				},
				Blob: lockFile.RawProofFile,
			},
		))

	// The publishing wallet learns the history from its local universe
	// only.
	case externalProofUniverse:
		for idx := 0; idx < decoded.NumProofs(); idx++ {
			rawProof, err := decoded.RawProofAt(uint32(idx))
			require.NoError(t.t, err)
			InsertProofIntoUniverse(t.t, alice, rawProof)
		}

	// The publishing wallet receives the history with the transfer.
	case externalProofRequest:
		publishOpts = append(
			publishOpts, withInputProofFiles(lockFile.RawProofFile),
		)
	}

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
		lockAnchor.PubKey, btcLeaf,
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
		t.t, alice, btcPacket, packets, nil, committed, publishOpts...,
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
