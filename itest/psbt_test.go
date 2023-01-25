package itest

import (
	"bytes"
	"context"
	"encoding/base64"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/tarorpc"
	wrpc "github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
)

// testPsbtSend tests that we can properly send assets back and forth between
// nodes with the use of PSBTs.
func testPsbtSend(t *harnessTest) {
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
		// aliceLnd = t.lndHarness.Alice
		bob    = secondTarod
		bobLnd = t.lndHarness.Bob
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKeyDesc, err := bobLnd.WalletKitClient.DeriveNextKey(
		ctxb, &walletrpc.KeyReq{
			KeyFamily: int32(taroscript.TaroKeyFamily),
		},
	)
	require.NoError(t.t, err)
	bobScriptInternalKey, err := btcec.ParsePubKey(
		bobScriptKeyDesc.RawKeyBytes,
	)
	require.NoError(t.t, err)
	bobInternalKeyDesc, err := bobLnd.WalletKitClient.DeriveNextKey(
		ctxb, &walletrpc.KeyReq{
			KeyFamily: int32(taroscript.TaroKeyFamily),
		},
	)
	require.NoError(t.t, err)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptInternalKey)
	leaf2Hash := leaf2.TapHash()
	tapscript := input.TapscriptPartialReveal(
		bobScriptInternalKey, leaf1, leaf2Hash[:],
	)
	rootHash := tapscript.ControlBlock.RootHash(leaf1.Script)

	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	bobAssetScriptKey, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	t.Logf("Bob destination key %x (internal %x, root %x)",
		bobAssetScriptKey.SerializeCompressed(),
		bobScriptInternalKey.SerializeCompressed(), rootHash[:])

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob.
	const numUnits = 10
	bobAddr, err := bob.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  numUnits,
		ScriptKey: &tarorpc.ScriptKey{
			PubKey:   schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc:  lndKeyDescToTaro(bobScriptKeyDesc),
			TapTweak: rootHash[:],
		},
		InternalKey: lndKeyDescToTaro(bobInternalKeyDesc),
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bob, rpcAssets[0], bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp := sendAssetsToAddr(t, alice, bobAddr)
	t.Logf("Send response: %v", spew.Sdump(sendResp))

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
		if out.IsChange || out.Interactive {
			continue
		}

		splitAsset := out.Asset
		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *senderOut.Copy()
	}

	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err = secondTarod.AnchorVirtualPsbts(
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
