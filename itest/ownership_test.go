package itest

import (
	"context"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testOwnershipVerification tests the asset ownership proof verficiation flow
// for owned assets. This test also tests the challenge parameter of the
// ownership verification RPCs.
func testOwnershipVerification(t *harnessTest) {
	ctxb := context.Background()

	// Create bob tapd.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// Mint some assets on alice.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	currentUnits := issuableAssets[0].Asset.Amount
	numUnits := currentUnits / 10

	// Bob makes an address in order to receive some of those assets.
	bobAddr, err := bobTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId:      genInfo.AssetId,
			Amt:          numUnits,
			AssetVersion: rpcAssets[0].Version,
		},
	)
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, bobTapd, rpcAssets[0], bobAddr)

	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId,
		[]uint64{currentUnits - numUnits, numUnits}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)

	// Now bob generates an ownership proof for the received assets. This
	// proof does not contain a challenge.
	proof, err := bobTapd.ProveAssetOwnership(
		ctxb, &assetwalletrpc.ProveAssetOwnershipRequest{
			AssetId:   rpcAssets[0].AssetGenesis.AssetId,
			ScriptKey: bobAddr.ScriptKey,
		},
	)
	require.NoError(t.t, err)

	// Alice verifies ownership proof.
	res, err := t.tapd.VerifyAssetOwnership(
		ctxb, &assetwalletrpc.VerifyAssetOwnershipRequest{
			ProofWithWitness: proof.ProofWithWitness,
		},
	)
	require.NoError(t.t, err)
	require.True(t.t, res.ValidProof)

	// Now let's create a dummy 32 byte challenge.
	ownershipChallenge := [32]byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}

	// Bob creates the proof that includes the above challenge.
	proof, err = bobTapd.ProveAssetOwnership(
		ctxb, &assetwalletrpc.ProveAssetOwnershipRequest{
			AssetId:   rpcAssets[0].AssetGenesis.AssetId,
			ScriptKey: bobAddr.ScriptKey,
			Challenge: ownershipChallenge[:],
		},
	)
	require.NoError(t.t, err)

	// Alice verifies ownership proof, providing the challenge.
	res, err = t.tapd.VerifyAssetOwnership(
		ctxb, &assetwalletrpc.VerifyAssetOwnershipRequest{
			ProofWithWitness: proof.ProofWithWitness,
			Challenge:        ownershipChallenge[:],
		},
	)
	require.NoError(t.t, err)
	require.True(t.t, res.ValidProof)

	// Now alice edits a byte of the challenge. This challenge should not
	// match the ownership proof, therefore a failure is expected.
	ownershipChallenge[0] = 8
	_, err = t.tapd.VerifyAssetOwnership(
		ctxb, &assetwalletrpc.VerifyAssetOwnershipRequest{
			ProofWithWitness: proof.ProofWithWitness,
			Challenge:        ownershipChallenge[:],
		},
	)
	require.ErrorContains(t.t, err, "invalid transfer asset witness")

	// Now alice trims the challenge to an 8-byte array. The RPC should
	// fail, we only accept 32-byte values.
	_, err = t.tapd.VerifyAssetOwnership(
		ctxb, &assetwalletrpc.VerifyAssetOwnershipRequest{
			ProofWithWitness: proof.ProofWithWitness,
			Challenge:        ownershipChallenge[:8],
		},
	)
	require.ErrorContains(t.t, err, "challenge must be 32 bytes")
}
