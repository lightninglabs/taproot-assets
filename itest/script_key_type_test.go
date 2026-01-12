package itest

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testScriptKeyTypePedersenUnique tests that we can declare a script key with
// the Pedersen unique tweak type, which is used for assets that are sent using
// the future address V2 scheme.
func testScriptKeyTypePedersenUnique(t *harnessTest) {
	ctx := context.Background()

	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0],
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
	activeAsset := rpcAssets[0]
	passiveAsset := rpcAssets[1]

	var (
		activeID, passiveID asset.ID
	)
	copy(activeID[:], activeAsset.AssetGenesis.AssetId)
	copy(passiveID[:], passiveAsset.AssetGenesis.AssetId)

	// We need to derive two sets of keys, one for the new script key and
	// one for the internal key each.
	activeScriptKey, activeAnchorIntKeyDesc1 := DeriveKeys(t.t, t.tapd)
	activeScriptKey = declarePedersenUniqueScriptKey(
		t.t, t.tapd, activeScriptKey, activeID,
	)
	passiveScriptKey, _ := DeriveKeys(t.t, t.tapd)
	passiveScriptKey = declarePedersenUniqueScriptKey(
		t.t, t.tapd, passiveScriptKey, passiveID,
	)

	// We create the output at anchor index 0 for the first address.
	outputAmounts := []uint64{300, 4700, 123}
	vPkt := tappsbt.ForInteractiveSend(
		activeID, outputAmounts[1], activeScriptKey, 0, 0, 0,
		activeAnchorIntKeyDesc1, asset.V0, chainParams,
	)

	// We now fund the packet, so we get the passive assets as well.
	fundResp := fundPacket(t, t.tapd, vPkt)
	require.Len(t.t, fundResp.PassiveAssetPsbts, 1)

	// We now replace the script key of the passive packet with the Pedersen
	// key that we declared above, then sign the packet.
	passiveAssetPkt, err := tappsbt.Decode(fundResp.PassiveAssetPsbts[0])
	require.NoError(t.t, err)
	require.Len(t.t, passiveAssetPkt.Outputs, 1)

	passiveAssetPkt.Outputs[0].ScriptKey = passiveScriptKey
	if passiveAssetPkt.Outputs[0].Asset != nil {
		passiveAssetPkt.Outputs[0].Asset.ScriptKey = passiveScriptKey
	}
	passiveAssetPkt = signVirtualPacket(t.t, t.tapd, passiveAssetPkt)

	// We now also sign the active asset packet.
	activeAssetPkt, err := tappsbt.Decode(fundResp.FundedPsbt)
	require.NoError(t.t, err)

	activeAssetPkt = signVirtualPacket(t.t, t.tapd, activeAssetPkt)

	activeBytes, err := tappsbt.Encode(activeAssetPkt)
	require.NoError(t.t, err)
	passiveBytes, err := tappsbt.Encode(passiveAssetPkt)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := t.tapd.AnchorVirtualPsbts(
		ctx, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{
				activeBytes,
				passiveBytes,
			},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp, activeID[:],
		outputAmounts, 0, 1, 3,
	)

	AssertBalances(
		t.t, t.tapd, 4700, WithAssetID(activeID[:]), WithNumUtxos(1),
		WithScriptKeyType(asset.ScriptKeyUniquePedersen),
	)
	AssertBalances(
		t.t, t.tapd, 5000, WithAssetID(activeID[:]), WithNumUtxos(2),
		WithScriptKeyType(asset.ScriptKeyBip86),
	)
	AssertBalances(
		t.t, t.tapd, 123, WithAssetID(passiveID[:]), WithNumUtxos(1),
		WithScriptKeyType(asset.ScriptKeyUniquePedersen),
	)

	aliceAssets, err := t.tapd.ListAssets(ctx, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got assets: %s", assetsJSON)

	// We should now be able to spend all the outputs, the Pedersen keys
	// should be signed correctly both in the active and passive assets.
	sendAssetAndAssert(
		ctx, t, t.tapd, t.tapd, 4900, 100, activeAsset.AssetGenesis,
		activeAsset, 1, 2, 1,
	)
}

func declarePedersenUniqueScriptKey(t *testing.T, node tapClient,
	sk asset.ScriptKey, assetID asset.ID) asset.ScriptKey {

	pedersenKey, err := asset.DeriveUniqueScriptKey(
		*sk.RawKey.PubKey, assetID,
		asset.ScriptKeyDerivationUniquePedersen,
	)
	require.NoError(t, err)

	// We need to let the wallet of Bob know that we're going to use a
	// script key with a custom root.
	ctxt, cancel := context.WithTimeout(
		context.Background(), defaultTimeout,
	)
	defer cancel()

	_, err = node.DeclareScriptKey(ctxt, &wrpc.DeclareScriptKeyRequest{
		ScriptKey: rpcutils.MarshalScriptKey(pedersenKey),
	})
	require.NoError(t, err)

	return pedersenKey
}
