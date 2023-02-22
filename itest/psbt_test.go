package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/tarorpc"
	wrpc "github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/stretchr/testify/require"
)

// testPsbtScriptHashLockSend tests that we can properly send assets with a hash
// lock back and forth between nodes with the use of PSBTs.
func testPsbtScriptHashLockSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	genBootstrap := genInfo.GenesisBootstrapInfo

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob,
		t.universeServer,
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
	bobScriptKey, bobInternalKey := deriveKeys(t.t, t.lndHarness.Bob)

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
			KeyDesc:  lndKeyDescToTaro(bobScriptKey),
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
		t, alice, sendResp, genInfo.AssetId, changeUnits, 0, 1,
	)
	_ = sendProof(t, alice, bob, bobAddr, genInfo)
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
		t, bob, sendResp, genInfo.AssetId, numUnits/2, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr, genInfo)
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
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	genBootstrap := genInfo.GenesisBootstrapInfo

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob,
		t.universeServer,
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
	bobScriptKey, bobInternalKey := deriveKeys(t.t, t.lndHarness.Bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.PubKey)
	leaf1Hash := leaf1.TapHash()
	leaf2Hash := leaf2.TapHash()
	tapscript := input.TapscriptPartialReveal(
		bobScriptKey.PubKey, leaf2, leaf1Hash[:],
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
			KeyDesc:  lndKeyDescToTaro(bobScriptKey),
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
		t, alice, sendResp, genInfo.AssetId, changeUnits, 0, 1,
	)
	_ = sendProof(t, alice, bob, bobAddr, genInfo)
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
		t, bob, sendResp, genInfo.AssetId, numUnits/2, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr, genInfo)
	assertReceiveComplete(t, alice, 1)

	aliceAssets, err := alice.ListAssets(ctxb, &tarorpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)
}

func deriveKeys(t *testing.T, lnd *lntest.HarnessNode) (keychain.KeyDescriptor,
	keychain.KeyDescriptor) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultTimeout)
	defer cancel()

	scriptKeyDesc, err := lnd.WalletKitClient.DeriveNextKey(
		ctxt, &walletrpc.KeyReq{
			KeyFamily: int32(asset.TaroKeyFamily),
		},
	)
	require.NoError(t, err)

	internalKeyDesc, err := lnd.WalletKitClient.DeriveNextKey(
		ctxt, &walletrpc.KeyReq{
			KeyFamily: int32(asset.TaroKeyFamily),
		},
	)
	require.NoError(t, err)

	return test.ParseRPCKeyDescriptor(t, scriptKeyDesc),
		test.ParseRPCKeyDescriptor(t, internalKeyDesc)
}
