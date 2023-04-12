package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/tarorpc"
	wrpc "github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// testPsbtScriptHashLockSend tests that we can properly send assets with a hash
// lock back and forth between nodes with the use of PSBTs.
func testPsbtScriptHashLockSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	genBootstrap := genInfo.GenesisBootstrapInfo

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var (
		alice = t.tarod
		bob   = secondTarod
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.PubKey)
	leaf2Hash := leaf2.TapHash()
	tapscript := input.TapscriptPartialReveal(
		bobScriptKey.PubKey, leaf1, leaf2Hash[:],
	)
	rootHash := tapscript.ControlBlock.RootHash(leaf1.Script)

	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	bobAssetScriptKey, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	t.Logf("Bob destination key %x (internal %x, root %x)",
		bobAssetScriptKey.SerializeCompressed(),
		bobScriptKey.PubKey.SerializeCompressed(), rootHash[:])

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob.
	const numUnits = 10
	bobAddr, err := bob.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  numUnits,
		ScriptKey: &tarorpc.ScriptKey{
			PubKey:   schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc:  lndKeyDescToTaro(bobScriptKey.RawKey),
			TapTweak: rootHash[:],
		},
		InternalKey: lndKeyDescToTaro(bobInternalKey),
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bob, rpcAssets[0], bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp := sendAssetsToAddr(t, alice, bobAddr)

	changeUnits := rpcAssets[0].Amount - numUnits
	confirmAndAssertOutboundTransfer(
		t, alice, sendResp, genInfo.AssetId,
		[]uint64{changeUnits, numUnits}, 0, 1,
	)
	_ = sendProof(t, alice, bob, bobAddr.ScriptKey, genInfo)
	assertReceiveComplete(t, bob, 1)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  numUnits / 2,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := taropsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We don't need to sign anything as we're going to spend with a
	// pre-image to the script lock.
	senderOut := fundedPacket.Outputs[0].Asset
	senderOut.PrevWitnesses[0].TxWitness = [][]byte{
		preImage, leaf1.Script, controlBlockBytes,
	}

	for idx := range fundedPacket.Outputs {
		out := fundedPacket.Outputs[idx]
		splitAsset := out.Asset

		if out.IsSplitRoot {
			splitAsset = out.SplitAsset
		}

		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *senderOut.Copy()
	}

	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err = bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{b.Bytes()},
		},
	)
	require.NoError(t.t, err)

	confirmAndAssertOutboundTransfer(
		t, bob, sendResp, genInfo.AssetId,
		[]uint64{numUnits / 2, numUnits / 2}, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr.ScriptKey, genInfo)
	assertReceiveComplete(t, alice, 1)

	aliceAssets, err := alice.ListAssets(ctxb, &tarorpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)
}

// testPsbtScriptCheckSigSend tests that we can properly send assets with a sig
// script back and forth between nodes with the use of PSBTs.
func testPsbtScriptCheckSigSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	genBootstrap := genInfo.GenesisBootstrapInfo

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var (
		alice = t.tarod
		bob   = secondTarod
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.RawKey.PubKey)
	leaf1Hash := leaf1.TapHash()
	leaf2Hash := leaf2.TapHash()
	tapscript := input.TapscriptPartialReveal(
		bobScriptKey.RawKey.PubKey, leaf2, leaf1Hash[:],
	)
	rootHash := tapscript.ControlBlock.RootHash(leaf2.Script)

	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	bobAssetScriptKey, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	t.Logf("Bob destination key %x (internal %x, root %x)",
		bobAssetScriptKey.SerializeCompressed(),
		bobScriptKey.PubKey.SerializeCompressed(), rootHash[:])

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob.
	const numUnits = 10
	bobAddr, err := bob.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  numUnits,
		ScriptKey: &tarorpc.ScriptKey{
			PubKey:   schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc:  lndKeyDescToTaro(bobScriptKey.RawKey),
			TapTweak: rootHash[:],
		},
		InternalKey: lndKeyDescToTaro(bobInternalKey),
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bob, rpcAssets[0], bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp := sendAssetsToAddr(t, alice, bobAddr)

	changeUnits := rpcAssets[0].Amount - numUnits
	confirmAndAssertOutboundTransfer(
		t, alice, sendResp, genInfo.AssetId,
		[]uint64{changeUnits, numUnits}, 0, 1,
	)
	_ = sendProof(t, alice, bob, bobAddr.ScriptKey, genInfo)
	assertReceiveComplete(t, bob, 1)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  numUnits / 2,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := taropsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We can now ask the wallet to sign the script path, since we only need
	// a signature.
	fundedPacket.Inputs[0].TaprootMerkleRoot = rootHash[:]
	fundedPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       leaf2.Script,
			LeafVersion:  leaf2.LeafVersion,
		},
	}
	fundedPacket.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{
		leaf2Hash[:],
	}
	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	signedResp, err := bob.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: b.Bytes(),
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedResp.SignedInputs, uint32(0))

	// Now we'll attempt to complete the transfer.
	sendResp, err = bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	confirmAndAssertOutboundTransfer(
		t, bob, sendResp, genInfo.AssetId,
		[]uint64{numUnits / 2, numUnits / 2}, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr.ScriptKey, genInfo)
	assertReceiveComplete(t, alice, 1)

	aliceAssets, err := alice.ListAssets(ctxb, &tarorpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)
}

// testPsbtInteractiveFullValueSend tests that we can properly send assets back
// and forth, using the full amount, between nodes with the use of PSBTs.
func testPsbtInteractiveFullValueSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTaro

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var (
		sender   = t.tarod
		receiver = secondTarod
		id       [32]byte
		fullAmt  = rpcAssets[0].Amount
	)
	copy(id[:], genInfo.AssetId)

	const numSend = 4
	for i := 0; i < numSend; i++ {
		// Swap the sender and receiver nodes starting at the second
		// iteration.
		if i > 0 {
			sender, receiver = receiver, sender
		}

		// We need to derive two keys, one for the new script key and
		// one for the internal key.
		receiverScriptKey, receiverAnchorIntKeyDesc := deriveKeys(
			t.t, receiver,
		)

		vPkt := taropsbt.ForInteractiveSend(
			id, uint64(fullAmt), receiverScriptKey, 0,
			receiverAnchorIntKeyDesc, chainParams,
		)

		// Next, we'll attempt to complete a transfer with PSBTs from
		// our sender node to our receiver, using the full amount.
		fundResp := fundPacket(t, sender, vPkt)
		signResp, err := sender.SignVirtualPsbt(
			ctxb, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundResp.FundedPsbt,
			},
		)
		require.NoError(t.t, err)

		// Now we'll attempt to complete the transfer.
		sendResp, err := sender.AnchorVirtualPsbts(
			ctxb, &wrpc.AnchorVirtualPsbtsRequest{
				VirtualPsbts: [][]byte{signResp.SignedPsbt},
			},
		)
		require.NoError(t.t, err)

		numOutputs := 1
		confirmAndAssetOutboundTransferWithOutputs(
			t, sender, sendResp, genInfo.AssetId, []uint64{fullAmt},
			i/2, (i/2)+1, numOutputs,
		)
		_ = sendProof(
			t, sender, receiver,
			receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
		)

		senderAssets, err := sender.ListAssets(
			ctxb, &tarorpc.ListAssetRequest{
				WithWitness: true,
			},
		)
		require.NoError(t.t, err)
		require.Len(t.t, senderAssets.Assets, 0)

		receiverAssets, err := receiver.ListAssets(
			ctxb, &tarorpc.ListAssetRequest{
				WithWitness: true,
			},
		)
		require.NoError(t.t, err)
		require.Len(t.t, receiverAssets.Assets, 1)
		require.EqualValues(
			t.t, fullAmt, receiverAssets.Assets[0].Amount,
		)
	}
}

// testPsbtInteractiveSplitSend tests that we can properly send assets back
// and forth, using the full amount, between nodes with the use of PSBTs.
func testPsbtInteractiveSplitSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTaro

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var (
		alice = t.tarod
		bob   = secondTarod
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobAnchorInternalKeyDesc := deriveKeys(
		t.t, bob,
	)

	const changeAmt = 10
	var (
		id            [32]byte
		partialAmount = rpcAssets[0].Amount - changeAmt
	)
	copy(id[:], genInfo.AssetId)
	vPkt := taropsbt.ForInteractiveSend(
		id, partialAmount, bobScriptKey, 0, bobAnchorInternalKeyDesc,
		chainParams,
	)

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob, using the full amount.
	fundResp := fundPacket(t, alice, vPkt)
	signResp, err := alice.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := alice.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	confirmAndAssetOutboundTransferWithOutputs(
		t, alice, sendResp, genInfo.AssetId,
		[]uint64{partialAmount, changeAmt}, 0, 1, 2,
	)
	_ = sendProof(
		t, alice, bob, bobScriptKey.PubKey.SerializeCompressed(),
		genInfo,
	)

	aliceAssets, err := alice.ListAssets(ctxb, &tarorpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)
	require.Len(t.t, aliceAssets.Assets, 1)
	require.EqualValues(t.t, changeAmt, aliceAssets.Assets[0].Amount)

	bobAssets, err := bob.ListAssets(ctxb, &tarorpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 1)
	require.EqualValues(t.t, partialAmount, bobAssets.Assets[0].Amount)
}

func deriveKeys(t *testing.T, tarod *tarodHarness) (asset.ScriptKey,
	keychain.KeyDescriptor) {

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	scriptKeyDesc, err := tarod.NextScriptKey(
		ctxt, &wrpc.NextScriptKeyRequest{
			KeyFamily: uint32(asset.TaroKeyFamily),
		},
	)
	require.NoError(t, err)
	scriptKey, err := taro.UnmarshalScriptKey(scriptKeyDesc.ScriptKey)
	require.NoError(t, err)

	internalKeyDesc, err := tarod.NextInternalKey(
		ctxt, &wrpc.NextInternalKeyRequest{
			KeyFamily: uint32(asset.TaroKeyFamily),
		},
	)
	require.NoError(t, err)
	internalKeyLnd, err := taro.UnmarshalKeyDescriptor(
		internalKeyDesc.InternalKey,
	)
	require.NoError(t, err)

	return *scriptKey, internalKeyLnd
}
