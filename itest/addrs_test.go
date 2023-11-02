package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testAddresses tests the various RPC calls related to addresses.
func testAddresses(t *harnessTest) {
	// First, mint a few assets, so we have some to create addresses for.
	// We mint all of them in individual batches to avoid needing to sign
	// for multiple internal asset transfers when only sending one of them
	// to an external address.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var addresses []*taprpc.Addr
	for idx, a := range rpcAssets {
		// In order to force a split, we don't try to send the full
		// asset.
		addr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
			AssetId:      a.AssetGenesis.AssetId,
			Amt:          a.Amount - 1,
			AssetVersion: a.Version,
		})
		require.NoError(t.t, err)
		addresses = append(addresses, addr)

		AssertAddrCreated(t.t, secondTapd, a, addr)

		sendResp := sendAssetsToAddr(t, t.tapd, addr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)

		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Make sure that eventually we see a single event for the
		// address.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusDetected)

		// Mine a block to make sure the events are marked as confirmed.
		MineBlocks(t.t, t.lndHarness.Miner.Client, 1, 1)

		// Eventually the event should be marked as confirmed.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusConfirmed)

		// To complete the transfer, we'll export the proof from the
		// sender and import it into the receiver for each asset set.
		sendProof(
			t, t.tapd, secondTapd, addr.ScriptKey, a.AssetGenesis,
		)

		// Make sure we have imported and finalized all proofs.
		AssertNonInteractiveRecvComplete(t.t, secondTapd, idx+1)

		// Make sure the asset meta is also fetched correctly.
		assetResp, err := secondTapd.FetchAssetMeta(
			ctxt, &taprpc.FetchAssetMetaRequest{
				Asset: &taprpc.FetchAssetMetaRequest_AssetId{
					AssetId: a.AssetGenesis.AssetId,
				},
			},
		)
		require.NoError(t.t, err)
		require.Equal(t.t, a.AssetGenesis.MetaHash, assetResp.MetaHash)
	}

	// Now sanity check that we can actually list the transfer.
	err := wait.NoError(func() error {
		resp, err := t.tapd.ListTransfers(
			ctxt, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)

		require.Len(t.t, resp.Transfers, len(rpcAssets))
		require.Len(t.t, resp.Transfers[0].Outputs, 2)

		firstOut := resp.Transfers[0].Outputs[0]
		require.EqualValues(t.t, 1, firstOut.Amount)
		require.Equal(
			t.t, addresses[0].AssetVersion, firstOut.AssetVersion,
		)

		firstIn := resp.Transfers[0].Inputs[0]
		require.Equal(
			t.t, rpcAssets[0].AssetGenesis.AssetId, firstIn.AssetId,
		)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)

	// We should now also be able to generate ownership proofs for the
	// received assets.
	for idx := range addresses {
		receiverAddr := addresses[idx]

		// Generate the ownership proof on the receiver node.
		proveResp, err := secondTapd.ProveAssetOwnership(
			ctxt, &wrpc.ProveAssetOwnershipRequest{
				AssetId:   receiverAddr.AssetId,
				ScriptKey: receiverAddr.ScriptKey,
			},
		)
		require.NoError(t.t, err)

		// Verify the ownership proof on the sender node.
		t.Logf("Got ownership proof: %x", proveResp.ProofWithWitness)
		verifyResp, err := t.tapd.VerifyAssetOwnership(
			ctxt, &wrpc.VerifyAssetOwnershipRequest{
				ProofWithWitness: proveResp.ProofWithWitness,
			},
		)
		require.NoError(t.t, err)
		require.True(t.t, verifyResp.ValidProof)
	}
}

// testMultiAddress tests that we can send assets to multiple addresses at the
// same time.
func testMultiAddress(t *harnessTest) {
	// First, mint an asset, so we have one to create addresses for.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)
	mintedAsset := rpcAssets[0]
	mintedGroupAsset := rpcAssets[1]
	genInfo := mintedAsset.AssetGenesis
	groupGenInfo := mintedGroupAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	alice := t.tapd
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = alice
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	runMultiSendTest(ctxt, t, alice, bob, genInfo, mintedAsset, 0, 1)
	runMultiSendTest(
		ctxt, t, alice, bob, groupGenInfo, mintedGroupAsset, 1, 2,
	)
}

// testAddressAssetSyncer tests that we can create addresses for assets that
// were not synced to the address creating node before creating the address.
func testAddressAssetSyncer(t *harnessTest) {
	// We'll kick off the test by making a new node, without hooking it up
	// to any existing Universe server.
	bob := setupTapdHarness(t.t, t, t.lndHarness.Bob, nil)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	miner := t.lndHarness.Miner.Client

	// Now that Bob is active, we'll mint some assets with the main node.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)
	require.Len(t.t, rpcAssets, 2)

	// Bob should not be able to make an address for any assets minted by
	// Alice, as he has not added her as a Universe server.
	firstAsset := rpcAssets[0]
	_, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      firstAsset.AssetGenesis.AssetId,
		Amt:          firstAsset.Amount / 2,
		AssetVersion: firstAsset.Version,
	})
	require.ErrorContains(t.t, err, "asset lookup failed for asset")

	// We'll now add the main node, as a member of Bob's Universe
	// federation. We expect that their state is synchronized shortly after
	// the call returns.
	_, err = bob.AddFederationServer(
		ctxt, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: t.tapd.rpcHost(),
				},
			},
		},
	)
	require.NoError(t.t, err)

	// Bob's Universe stats should show that he now has two assets.
	AssertUniverseStats(t.t, bob, 2, 0, 2, 1)

	// Bob should not be able to make an address for a random asset ID
	// that he nor Alice are aware of.
	randAssetId := test.RandBytes(32)
	_, err = bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: randAssetId,
		Amt:     1,
	})
	require.ErrorContains(t.t, err, "asset lookup failed for asset")

	// Turn off global universe syncing for Bob, so he doesn't observe any
	// future assets minted by Alice.
	globalConfigs := []*unirpc.GlobalFederationSyncConfig{
		{
			ProofType:       unirpc.ProofType_PROOF_TYPE_ISSUANCE,
			AllowSyncInsert: false,
			AllowSyncExport: false,
		},
		{
			ProofType:       unirpc.ProofType_PROOF_TYPE_TRANSFER,
			AllowSyncInsert: false,
			AllowSyncExport: false,
		},
	}

	_, err = bob.UniverseClient.SetFederationSyncConfig(
		ctxb, &unirpc.SetFederationSyncConfigRequest{
			GlobalSyncConfigs: globalConfigs,
		},
	)
	require.NoError(t.t, err)

	configResp, err := bob.UniverseClient.QueryFederationSyncConfig(
		ctxb, &unirpc.QueryFederationSyncConfigRequest{},
	)
	require.NoError(t.t, err)

	// Ensure that the global configs are set as expected.
	require.Equal(t.t, len(configResp.GlobalSyncConfigs), 2)

	for i := range configResp.GlobalSyncConfigs {
		config := configResp.GlobalSyncConfigs[i]

		// Match proof type.
		switch config.ProofType {
		case unirpc.ProofType_PROOF_TYPE_ISSUANCE:
			require.False(t.t, config.AllowSyncInsert)
			require.False(t.t, config.AllowSyncExport)

		case unirpc.ProofType_PROOF_TYPE_TRANSFER:
			require.False(t.t, config.AllowSyncInsert)
			require.False(t.t, config.AllowSyncExport)

		default:
			t.Fatalf("unexpected global proof type: %s",
				config.ProofType)
		}
	}

	// Mint more assets with the main node, which should not sync to Bob.
	secondRpcAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[1], issuableAssets[1],
		},
	)
	require.Len(t.t, secondRpcAssets, 2)

	// Verify that Bob will not sync to Alice by default by manually
	// triggering a sync.
	syncDiff, err := bob.SyncUniverse(ctxt, &unirpc.SyncRequest{
		UniverseHost: t.tapd.rpcHost(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
	})
	require.NoError(t.t, err)
	require.Len(t.t, syncDiff.SyncedUniverses, 0)

	// This helper restarts Bob, disables global universe sync, and adds
	// Alice to his federation.
	restartBobNoUniSync := func(disableSyncer bool) {
		require.NoError(t.t, bob.stop(!*noDelete))
		bob = setupTapdHarness(
			t.t, t, t.lndHarness.Bob, nil,
			func(params *tapdHarnessParams) {
				params.addrAssetSyncerDisable = disableSyncer
			},
		)

		_, err = bob.UniverseClient.SetFederationSyncConfig(
			ctxb, &unirpc.SetFederationSyncConfigRequest{
				GlobalSyncConfigs: globalConfigs,
			},
		)
		require.NoError(t.t, err)

		_, err = bob.AddFederationServer(
			ctxt, &unirpc.AddFederationServerRequest{
				Servers: []*unirpc.UniverseFederationServer{
					{
						Host: t.tapd.rpcHost(),
					},
				},
			},
		)
		require.NoError(t.t, err)
		AssertUniverseStats(t.t, bob, 0, 0, 0, 0)
	}

	// If we restart Bob with the syncer disabled and no automatic sync
	// with Alice, he should be unable to make an address for the new
	// assets.
	restartBobNoUniSync(true)
	firstAsset = secondRpcAssets[0]
	_, err = bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      firstAsset.AssetGenesis.AssetId,
		Amt:          firstAsset.Amount,
		AssetVersion: firstAsset.Version,
	})
	require.ErrorContains(t.t, err, "asset group is unknown")

	// Restart Bob again with the syncer enabled. Bob should be able to make
	// an address for both new assets minted by Alice, even though he has
	// not synced their issuance proofs.
	restartBobNoUniSync(false)
	firstAsset = secondRpcAssets[0]
	firstAddr, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      firstAsset.AssetGenesis.AssetId,
		Amt:          firstAsset.Amount,
		AssetVersion: firstAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddr(t.t, firstAsset, firstAddr)

	secondAsset := secondRpcAssets[1]
	secondGroup := secondAsset.AssetGroup
	secondAddr, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      secondAsset.AssetGenesis.AssetId,
		Amt:          secondAsset.Amount,
		AssetVersion: secondAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddr(t.t, secondAsset, secondAddr)

	// Ensure that the asset group of the second asset has a matching
	// universe config so Bob will sync future issuances.
	resp, err := bob.UniverseClient.QueryFederationSyncConfig(
		ctxt, &unirpc.QueryFederationSyncConfigRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.AssetSyncConfigs, 1)

	groupSyncConfig := resp.AssetSyncConfigs[0]
	require.NotNil(t.t, groupSyncConfig.Id)

	groupUniID, err := tap.UnmarshalUniID(groupSyncConfig.Id)
	uniIDGroupKey := schnorr.SerializePubKey(groupUniID.GroupKey)
	require.NotNil(t.t, groupUniID.GroupKey)
	require.Equal(t.t, secondGroup.TweakedGroupKey[1:], uniIDGroupKey)
	require.Equal(t.t, groupUniID.ProofType, universe.ProofTypeIssuance)

	// Bob's Universe stats should show that he has now synced both assets
	// from the second mint and the single asset group from that mint.
	AssertUniverseStats(t.t, bob, 2, 0, 2, 1)

	// Alice's Universe stats should reflect the extra syncs from the asset
	// group lookups by Bob.
	AssertUniverseStats(t.t, t.tapd, 4, 4, 4, 2)

	// If Alice now mints a reissuance for the second asset group, Bob
	// should successfully sync that new asset.
	secondGroupMember := CopyRequest(issuableAssets[1])
	secondGroupMember.EnableEmission = false
	secondGroupMember.Asset.Name += "-2"
	secondGroupMember.Asset.GroupKey = secondGroup.TweakedGroupKey

	reissuedAsset := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, fn.MakeSlice(secondGroupMember),
	)
	require.Len(t.t, reissuedAsset, 1)

	syncDiff, err = bob.SyncUniverse(ctxt, &unirpc.SyncRequest{
		UniverseHost: t.tapd.rpcHost(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
	})
	require.NoError(t.t, err)
	require.Len(t.t, syncDiff.SyncedUniverses, 1)
}

// runMultiSendTest runs a test that sends assets to multiple addresses at the
// same time.
func runMultiSendTest(ctxt context.Context, t *harnessTest, alice,
	bob *tapdHarness, genInfo *taprpc.GenesisInfo,
	mintedAsset *taprpc.Asset, runIdx, numRuns int) {

	// In order to force a split, we don't try to send the full asset.
	const sendAmt = 100
	var bobAddresses []*taprpc.Addr
	bobAddr1, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	bobAddresses = append(bobAddresses, bobAddr1)
	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr1)

	bobAddr2, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	bobAddresses = append(bobAddresses, bobAddr2)
	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr2)

	// To test that Alice can also receive to multiple addresses in a single
	// transaction as well, we also add two addresses for her.
	aliceAddr1, err := alice.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, alice, mintedAsset, aliceAddr1)

	aliceAddr2, err := alice.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, alice, mintedAsset, aliceAddr2)

	sendResp := sendAssetsToAddr(
		t, alice, bobAddr1, bobAddr2, aliceAddr1, aliceAddr2,
	)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	// Make sure that eventually we see a single event for the address.
	AssertAddrEvent(t.t, bob, bobAddr1, 1, statusDetected)
	AssertAddrEvent(t.t, bob, bobAddr2, 1, statusDetected)
	AssertAddrEvent(t.t, alice, aliceAddr1, 1, statusDetected)
	AssertAddrEvent(t.t, alice, aliceAddr2, 1, statusDetected)

	// Mine a block to make sure the events are marked as confirmed.
	_ = MineBlocks(t.t, t.lndHarness.Miner.Client, 1, 1)[0]

	// Eventually the events should be marked as confirmed.
	AssertAddrEventByStatus(t.t, bob, statusConfirmed, 2)

	// For local addresses, we should already have the proof in the DB at
	// this point, so the status should go to completed directly.
	AssertAddrEventByStatus(t.t, alice, statusCompleted, numRuns*2)

	// To complete the transfer, we'll export the proof from the sender and
	// import it into the receiver for each asset set. This should not be
	// necessary for the sends to Alice, as she is both the sender and
	// receiver and should detect the local proof once it's written to disk.
	for i := range bobAddresses {
		sendProof(t, alice, bob, bobAddresses[i].ScriptKey, genInfo)
	}

	// Make sure we have imported and finalized all proofs.
	AssertNonInteractiveRecvComplete(t.t, bob, numRuns*2)
	AssertNonInteractiveRecvComplete(t.t, alice, numRuns*2)

	// Now sanity check that we can actually list the transfer.
	const (
		numOutputs = 5
		numAddrs   = 4
	)
	changeAmt := mintedAsset.Amount - (sendAmt * numAddrs)
	err = wait.NoError(func() error {
		resp, err := alice.ListTransfers(
			ctxt, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Transfers, numRuns)

		transfer := resp.Transfers[runIdx]
		require.Len(t.t, transfer.Outputs, numOutputs)

		firstOut := transfer.Outputs[0]
		require.EqualValues(t.t, changeAmt, firstOut.Amount)

		firstIn := transfer.Inputs[0]
		require.Equal(t.t, genInfo.AssetId, firstIn.AssetId)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)
}

func sendProof(t *harnessTest, src, dst *tapdHarness, scriptKey []byte,
	genInfo *taprpc.GenesisInfo) *tapdevrpc.ImportProofResponse {

	ctxb := context.Background()

	var proofResp *taprpc.ProofFile
	waitErr := wait.NoError(func() error {
		resp, err := src.ExportProof(ctxb, &taprpc.ExportProofRequest{
			AssetId:   genInfo.AssetId,
			ScriptKey: scriptKey,
		})
		if err != nil {
			return err
		}

		proofResp = resp
		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, waitErr)

	t.Logf("Importing proof %x", proofResp.RawProofFile)

	importResp, err := dst.ImportProof(ctxb, &tapdevrpc.ImportProofRequest{
		ProofFile:    proofResp.RawProofFile,
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.NoError(t.t, err)

	return importResp
}

// sendAssetsToAddr spends the given input asset and sends the amount specified
// in the address to the Taproot output derived from the address.
func sendAssetsToAddr(t *harnessTest, sender *tapdHarness,
	receiverAddrs ...*taprpc.Addr) *taprpc.SendAssetResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	encodedAddrs := make([]string, len(receiverAddrs))
	for i, addr := range receiverAddrs {
		encodedAddrs[i] = addr.Encoded
	}

	resp, err := sender.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: encodedAddrs,
	})
	require.NoError(t.t, err)

	return resp
}

// fundAddressSendPacket asks the wallet to fund a new virtual packet with the
// given address as the single receiver.
func fundAddressSendPacket(t *harnessTest, tapd *tapdHarness,
	rpcAddr *taprpc.Addr) *wrpc.FundVirtualPsbtResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := tapd.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
		Template: &wrpc.FundVirtualPsbtRequest_Raw{
			Raw: &wrpc.TxTemplate{
				Recipients: map[string]uint64{
					rpcAddr.Encoded: 1,
				},
			},
		},
	})
	require.NoError(t.t, err)

	return resp
}

// fundPacket asks the wallet to fund the given virtual packet.
func fundPacket(t *harnessTest, tapd *tapdHarness,
	vPkg *tappsbt.VPacket) *wrpc.FundVirtualPsbtResponse {

	var buf bytes.Buffer
	err := vPkg.Serialize(&buf)
	require.NoError(t.t, err)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := tapd.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
		Template: &wrpc.FundVirtualPsbtRequest_Psbt{
			Psbt: buf.Bytes(),
		},
	})
	require.NoError(t.t, err)

	return resp
}
