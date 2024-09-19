package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// testAddresses tests the various RPC calls related to addresses.
func testAddresses(t *harnessTest) {
	// First, mint a few assets, so we have some to create addresses for.
	// We mint all of them in individual batches to avoid needing to sign
	// for multiple internal asset transfers when only sending one of them
	// to an external address.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var addresses []*taprpc.Addr
	for idx, a := range rpcAssets {
		// In order to force a split, we don't try to send the full
		// asset.
		addr, events := NewAddrWithEventStream(
			t.t, secondTapd, &taprpc.NewAddrRequest{
				AssetId:      a.AssetGenesis.AssetId,
				Amt:          a.Amount - 1,
				AssetVersion: a.Version,
			},
		)
		addresses = append(addresses, addr)

		AssertAddrCreated(t.t, secondTapd, a, addr)

		sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, addr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)

		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Make sure that eventually we see a single event for the
		// address.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusDetected)

		// Mine a block to make sure the events are marked as confirmed.
		MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

		// Eventually the event should be marked as confirmed.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusConfirmed)

		// Make sure we have imported and finalized all proofs.
		AssertNonInteractiveRecvComplete(t.t, secondTapd, idx+1)
		AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

		// Make sure the receiver has received all events in order for
		// the address.
		AssertReceiveEvents(t.t, addr, events)

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

	// Since the assets have been spent to version 1 addresses, trying to
	// receive them to a version 0 address should fail.
	simpleAsset := rpcAssets[0]
	legacyAddr, err := t.tapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:        simpleAsset.AssetGenesis.AssetId,
		Amt:            simpleAsset.Amount / 2,
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V0,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, t.tapd, simpleAsset, legacyAddr)

	_, err = secondTapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{legacyAddr.Encoded},
	})
	require.ErrorContains(
		t.t, err, tapfreighter.ErrMatchingAssetsNotFound.Error(),
	)

	// Mint an asset into a downgraded anchor commitment.
	manualAssetName := "honigbuxxx"
	req := mintrpc.MintAsset{
		AssetVersion: 0,
		AssetType:    taprpc.AssetType_NORMAL,
		Name:         manualAssetName,
		AssetMeta: &taprpc.AssetMeta{
			Data: []byte("not metadata"),
		},
		Amount: 22,
	}
	manualAsset, mintProof := ManualMintSimpleAsset(
		t, t.lndHarness.Alice, t.tapd, commitment.TapCommitmentV0, &req,
	)

	numAssets := 2
	AssertNumAssets(t.t, ctxb, t.tapd, numAssets+1)
	respJSON, err := formatProtoJSON(manualAsset)
	require.NoError(t.t, err)

	t.Logf("manually minted asset: %s", respJSON)

	// Import the issuance proof to the second node so we can try to receive
	// it.
	_, err = secondTapd.ImportProof(ctxb, mintProof)
	require.NoError(t.t, err)

	// Trying to receive the new asset to a version 0 address should
	// succeed.
	manualAssetID := manualAsset.AssetGenesis.AssetId
	oldAddrAmt := manualAsset.Amount / 2
	oldAddr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:        manualAssetID,
		Amt:            oldAddrAmt,
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V0,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, secondTapd, manualAsset, oldAddr)

	_, err = t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{oldAddr.Encoded},
	})
	require.NoError(t.t, err)

	// Confirm the transfer.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)
	AssertAddrEvent(t.t, secondTapd, oldAddr, 1, statusConfirmed)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 3)

	// Trying to receive the new asset to a version 1 address should also
	// succeed.
	newAddr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:        manualAsset.AssetGenesis.AssetId,
		Amt:            manualAsset.Amount / 2,
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V1,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, secondTapd, manualAsset, newAddr)

	_, err = t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{newAddr.Encoded},
	})
	require.NoError(t.t, err)

	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)
	AssertAddrEvent(t.t, secondTapd, newAddr, 1, statusConfirmed)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 4)
}

// testMultiAddress tests that we can send assets to multiple addresses at the
// same time.
func testMultiAddress(t *harnessTest) {
	// First, mint an asset, so we have one to create addresses for.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	runMultiSendTest(ctxt, t, alice, bob, genInfo, mintedAsset, 0, 1)
	runMultiSendTest(
		ctxt, t, alice, bob, groupGenInfo, mintedGroupAsset, 1, 2,
	)

	// If the second node tries to send assets to a set of addresses with
	// mixed versions, that should fail early.
	const sendAmt = 25
	aliceAddr1, err := alice.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:        genInfo.AssetId,
		Amt:            sendAmt,
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V0,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, alice, mintedAsset, aliceAddr1)

	aliceAddr2, err := alice.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:        genInfo.AssetId,
		Amt:            sendAmt,
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V1,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, alice, mintedAsset, aliceAddr2)

	_, err = bob.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{aliceAddr1.Encoded, aliceAddr2.Encoded},
	})

	require.ErrorContains(t.t, err, "mixed address versions")
}

// testAddressAssetSyncer tests that we can create addresses for assets that
// were not synced to the address creating node before creating the address.
func testAddressAssetSyncer(t *harnessTest) {
	// We'll kick off the test by making a new node, without hooking it up
	// to any existing Universe server.
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	miner := t.lndHarness.Miner().Client

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
	AssertUniverseStats(t.t, bob, 2, 2, 1)

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
			t.t, t, t.lndHarness.Bob, t.universeServer,
			func(params *tapdHarnessParams) {
				params.noDefaultUniverseSync = true
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
		AssertUniverseStats(t.t, bob, 0, 0, 0)
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
	AssertUniverseStats(t.t, bob, 2, 2, 1)

	// Alice's Universe stats should reflect the extra syncs from the asset
	// group lookups by Bob.
	AssertUniverseStats(t.t, t.tapd, 4, 4, 2)

	// If Alice now mints a re-issuance for the second asset group, Bob
	// should successfully sync that new asset.
	secondGroupMember := CopyRequest(issuableAssets[1])
	secondGroupMember.Asset.NewGroupedAsset = false
	secondGroupMember.Asset.Name += "-2"
	secondGroupMember.Asset.GroupKey = secondGroup.TweakedGroupKey
	secondGroupMember.Asset.GroupedAsset = true

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
	bobAddr1, bobEvents1 := NewAddrWithEventStream(
		t.t, bob, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		},
	)
	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr1)

	bobAddr2, bobEvents2 := NewAddrWithEventStream(
		t.t, bob, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		})
	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr2)

	// To test that Alice can also receive to multiple addresses in a single
	// transaction as well, we also add two addresses for her.
	aliceAddr1, aliceEvents1 := NewAddrWithEventStream(
		t.t, alice, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		},
	)
	AssertAddrCreated(t.t, alice, mintedAsset, aliceAddr1)

	aliceAddr2, aliceEvents2 := NewAddrWithEventStream(
		t.t, alice, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		},
	)
	AssertAddrCreated(t.t, alice, mintedAsset, aliceAddr2)

	sendResp, sendEvents := sendAssetsToAddr(
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
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// Eventually the events should be marked as confirmed.
	AssertAddrEventByStatus(t.t, bob, statusConfirmed, 2)

	// For local addresses, we should already have the proof in the DB at
	// this point, so the status should go to completed directly.
	AssertAddrEventByStatus(t.t, alice, statusCompleted, numRuns*2)

	// Make sure we have imported and finalized all proofs.
	AssertNonInteractiveRecvComplete(t.t, bob, numRuns*2)
	AssertNonInteractiveRecvComplete(t.t, alice, numRuns*2)
	AssertSendEventsComplete(t.t, bobAddr1.ScriptKey, sendEvents)

	// Make sure the receivers have received all events in order for the
	// addresses.
	AssertReceiveEvents(t.t, bobAddr1, bobEvents1)
	AssertReceiveEvents(t.t, bobAddr2, bobEvents2)
	AssertReceiveEvents(t.t, aliceAddr1, aliceEvents1)
	AssertReceiveEvents(t.t, aliceAddr2, aliceEvents2)

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

	// We start out with two assets at Alice, one normal and one grouped. We
	// then send it to Bob and to ourselves, with change being created. So
	// in each round we turn one of the assets into 3 pieces (two
	// self-transfers via addresses and one change output).
	if runIdx == 0 {
		AssertNumAssets(t.t, ctxt, alice, 3+1)
	} else {
		AssertNumAssets(t.t, ctxt, alice, 3+(runIdx*3))
	}
}

// testUnknownTlvType tests that we can create an address with an unknown TLV
// type and that assets can be sent to it. We then modify a proof similarly and
// make sure it can be imported by a node correctly.
func testUnknownTlvType(t *harnessTest) {
	// First, mint an asset, so we have one to create addresses for.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)
	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	alice := t.tapd
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	// We now create an address for Bob and add some unknown TLV type to it.
	bobAddr, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     123,
	})
	require.NoError(t.t, err)

	decoded, err := address.DecodeAddress(
		bobAddr.Encoded, &address.RegressionNetTap,
	)
	require.NoError(t.t, err)

	decoded.UnknownOddTypes = tlv.TypeMap{
		345: []byte("plz send assets"),
	}
	bobAddr.Encoded, err = decoded.EncodeAddress()
	require.NoError(t.t, err)

	sendResp, sendEvents := sendAssetsToAddr(t, alice, bobAddr)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	AssertAddrEvent(t.t, bob, bobAddr, 1, statusDetected)

	// Mine a block to make sure the events are marked as confirmed.
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// Eventually the event should be marked as confirmed.
	AssertAddrEventByStatus(t.t, bob, statusConfirmed, 1)

	// Make sure we have imported and finalized all proofs.
	AssertNonInteractiveRecvComplete(t.t, bob, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)

	// We export the proof for the address so we can modify it.
	transferProof := exportProof(
		t, bob, sendResp, bobAddr.ScriptKey, genInfo,
	)

	f, err := proof.DecodeFile(transferProof.RawProofFile)
	require.NoError(t.t, err)

	lastProof, err := f.LastProof()
	require.NoError(t.t, err)

	proofCustomTypes := tlv.TypeMap{
		123: []byte("got something to prove"),
	}
	lastProof.UnknownOddTypes = proofCustomTypes
	lastProof.InclusionProof.UnknownOddTypes = tlv.TypeMap{
		345: []byte("it's included"),
	}
	cp := lastProof.InclusionProof.CommitmentProof
	cp.UnknownOddTypes = tlv.TypeMap{
		567: []byte("it's committed"),
	}
	cp.TaprootAssetProof.UnknownOddTypes = tlv.TypeMap{
		789: []byte("there's assets in here..."),
	}
	cp.AssetProof.UnknownOddTypes = tlv.TypeMap{
		987: []byte("...and here"),
	}
	lastProof.ExclusionProofs[0].UnknownOddTypes = tlv.TypeMap{
		321: []byte("it's excluded"),
	}

	// Let's re-encode the proof and import it to the new node.
	err = f.ReplaceLastProof(*lastProof)
	require.NoError(t.t, err)
	modifiedBlob, err := proof.EncodeFile(f)
	require.NoError(t.t, err)

	// We make a new node to import the modified proof.
	charlie := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, charlie.stop(!*noDelete))
	}()

	importProof(t, charlie, modifiedBlob, genInfo.GenesisPoint)

	// When we export it again, it should have the same TLV types.
	transferProof2 := exportProof(
		t, charlie, sendResp, bobAddr.ScriptKey, genInfo,
	)
	f2, err := proof.DecodeFile(transferProof2.RawProofFile)
	require.NoError(t.t, err)

	lastProof2, err := f2.LastProof()
	require.NoError(t.t, err)

	// If the contents are identical to what we uploaded, we just need to
	// check a single value in the proof to be sure all the custom types are
	// there.
	require.Equal(t.t, modifiedBlob, transferProof2.RawProofFile)
	require.True(t.t, bytes.Contains(modifiedBlob, []byte("it's included")))
	require.True(
		t.t, bytes.Contains(modifiedBlob, []byte("it's committed")),
	)
	require.Equal(t.t, proofCustomTypes, lastProof2.UnknownOddTypes)

	// The proof should also still be valid. Importing the proof validates
	// it, but we also want to do it explicitly.
	verifyResp, err := charlie.VerifyProof(ctxb, &taprpc.ProofFile{
		RawProofFile: modifiedBlob,
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.NoError(t.t, err)
	require.True(t.t, verifyResp.Valid)

	// The final test involves adding some extra data to the meta reveal of
	// a proof. That will invalidate the proof, as the commitments are for
	// a different meta. But the meta hash should be calculated differently,
	// showing that the extra data is considered for the meta hash
	// calculation.
	firstProof, err := f2.ProofAt(0)
	require.NoError(t.t, err)

	require.NotNil(t.t, firstProof.MetaReveal)
	hashBeforeUpdate := firstProof.MetaReveal.MetaHash()

	// Let's modify the meta hash with some extra data.
	firstProof.MetaReveal.UnknownOddTypes = tlv.TypeMap{
		123: []byte("extra data"),
	}
	hashAfterUpdate := firstProof.MetaReveal.MetaHash()

	require.NotEqual(t.t, hashBeforeUpdate, hashAfterUpdate)

	// We should not be able to verify the proof anymore.
	err = f2.ReplaceProofAt(0, *firstProof)
	require.NoError(t.t, err)
	modifiedBlob2, err := proof.EncodeFile(f2)
	require.NoError(t.t, err)

	verifyResp, err = charlie.VerifyProof(ctxb, &taprpc.ProofFile{
		RawProofFile: modifiedBlob2,
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.NoError(t.t, err)
	require.False(t.t, verifyResp.Valid)
}

// sendProof manually exports a proof from the given source node and imports it
// using the development only ImportProof RPC on the destination node.
func sendProof(t *harnessTest, src, dst *tapdHarness,
	sendResp *taprpc.SendAssetResponse, scriptKey []byte,
	genInfo *taprpc.GenesisInfo) *tapdevrpc.ImportProofResponse {

	proofResp := exportProof(t, src, sendResp, scriptKey, genInfo)
	return importProof(t, dst, proofResp.RawProofFile, genInfo.GenesisPoint)
}

// exportProof manually exports a proof from the given source node for a
// specific asset of a transfer.
func exportProof(t *harnessTest, src *tapdHarness,
	sendResp *taprpc.SendAssetResponse, scriptKey []byte,
	genInfo *taprpc.GenesisInfo) *taprpc.ProofFile {

	ctxb := context.Background()

	// We need to find the outpoint of the asset we sent to the address.
	var outpoint *taprpc.OutPoint
	for _, out := range sendResp.Transfer.Outputs {
		if bytes.Equal(out.ScriptKey, scriptKey) {
			wireOutPoint, err := wire.NewOutPointFromString(
				out.Anchor.Outpoint,
			)
			require.NoError(t.t, err)

			outpoint = &taprpc.OutPoint{
				Txid:        wireOutPoint.Hash[:],
				OutputIndex: wireOutPoint.Index,
			}
		}
	}

	var proofResp *taprpc.ProofFile
	waitErr := wait.NoError(func() error {
		resp, err := src.ExportProof(ctxb, &taprpc.ExportProofRequest{
			AssetId:   genInfo.AssetId,
			ScriptKey: scriptKey,
			Outpoint:  outpoint,
		})
		if err != nil {
			return err
		}

		proofResp = resp
		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, waitErr)

	return proofResp
}

// importProof manually imports a proof using the development only ImportProof
// RPC.
func importProof(t *harnessTest, dst *tapdHarness, rawFile []byte,
	genesisPoint string) *tapdevrpc.ImportProofResponse {

	t.Logf("Importing proof %x", rawFile)

	ctxb := context.Background()
	importResp, err := dst.ImportProof(ctxb, &tapdevrpc.ImportProofRequest{
		ProofFile:    rawFile,
		GenesisPoint: genesisPoint,
	})
	require.NoError(t.t, err)

	return importResp
}

// sendUniProof manually exports a proof from the given source using the
// universe RPCs and then imports it into the destination node.
func sendUniProof(t *harnessTest, src, dst *tapdHarness, scriptKey []byte,
	genInfo *taprpc.GenesisInfo, group *taprpc.AssetGroup,
	outpoint string) *tapdevrpc.ImportProofResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	fetchUniProof := func(ctx context.Context,
		loc proof.Locator) (proof.Blob, error) {

		uniID := universe.Identifier{
			AssetID: *loc.AssetID,
		}
		if loc.GroupKey != nil {
			uniID.GroupKey = loc.GroupKey
		}

		rpcUniID, err := tap.MarshalUniID(uniID)
		require.NoError(t.t, err)

		op := &unirpc.Outpoint{
			HashStr: loc.OutPoint.Hash.String(),
			Index:   int32(loc.OutPoint.Index),
		}
		scriptKeyBytes := loc.ScriptKey.SerializeCompressed()

		uniProof, err := src.QueryProof(ctx, &unirpc.UniverseKey{
			Id: rpcUniID,
			LeafKey: &unirpc.AssetKey{
				Outpoint: &unirpc.AssetKey_Op{
					Op: op,
				},
				ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
					ScriptKeyBytes: scriptKeyBytes,
				},
			},
		})
		if err != nil {
			return nil, err
		}

		return uniProof.AssetLeaf.Proof, nil
	}

	var assetID asset.ID
	copy(assetID[:], genInfo.AssetId)

	scriptPubKey, err := btcec.ParsePubKey(scriptKey)
	require.NoError(t.t, err)

	op, err := wire.NewOutPointFromString(outpoint)
	require.NoError(t.t, err)

	loc := proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *scriptPubKey,
		OutPoint:  op,
	}

	if group != nil {
		groupKey, err := btcec.ParsePubKey(group.TweakedGroupKey)
		require.NoError(t.t, err)

		loc.GroupKey = groupKey
	}

	var proofFile *proof.File
	err = wait.NoError(func() error {
		proofFile, err = proof.FetchProofProvenance(
			ctxt, nil, loc, fetchUniProof,
		)
		return err
	}, defaultWaitTimeout)
	require.NoError(t.t, err)

	var buf bytes.Buffer
	err = proofFile.Encode(&buf)
	require.NoError(t.t, err)

	t.Logf("Importing proof %x", buf.Bytes())

	importResp, err := dst.ImportProof(ctxb, &tapdevrpc.ImportProofRequest{
		ProofFile:    buf.Bytes(),
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.NoError(t.t, err)

	return importResp
}

// sendProofUniRPC manually exports a proof from the given source node and
// imports it using the universe related InsertProof RPC on the destination
// node.
func sendProofUniRPC(t *harnessTest, src, dst *tapdHarness, scriptKey []byte,
	genInfo *taprpc.GenesisInfo) *unirpc.AssetProofResponse {

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

	t.Logf("Importing proof %x using InsertProof", proofResp.RawProofFile)

	f := proof.File{}
	err := f.Decode(bytes.NewReader(proofResp.RawProofFile))
	require.NoError(t.t, err)

	lastProof, err := f.LastProof()
	require.NoError(t.t, err)

	var lastProofBytes bytes.Buffer
	err = lastProof.Encode(&lastProofBytes)
	require.NoError(t.t, err)
	asset := lastProof.Asset

	proofType := universe.ProofTypeTransfer
	if asset.IsGenesisAsset() {
		proofType = universe.ProofTypeIssuance
	}

	uniID := universe.Identifier{
		AssetID:   asset.ID(),
		ProofType: proofType,
	}
	if asset.GroupKey != nil {
		uniID.GroupKey = &asset.GroupKey.GroupPubKey
	}

	rpcUniID, err := tap.MarshalUniID(uniID)
	require.NoError(t.t, err)

	outpoint := &unirpc.Outpoint{
		HashStr: lastProof.AnchorTx.TxHash().String(),
		Index:   int32(lastProof.InclusionProof.OutputIndex),
	}

	importResp, err := dst.InsertProof(ctxb, &unirpc.AssetProof{
		Key: &unirpc.UniverseKey{
			Id: rpcUniID,
			LeafKey: &unirpc.AssetKey{
				Outpoint: &unirpc.AssetKey_Op{
					Op: outpoint,
				},
				ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
					ScriptKeyBytes: scriptKey,
				},
			},
		},
		AssetLeaf: &unirpc.AssetLeaf{
			Proof: lastProofBytes.Bytes(),
		},
	})
	require.NoError(t.t, err)

	return importResp
}

// sendAssetsToAddr spends the given input asset and sends the amount specified
// in the address to the Taproot output derived from the address.
func sendAssetsToAddr(t *harnessTest, sender *tapdHarness,
	receiverAddrs ...*taprpc.Addr) (*taprpc.SendAssetResponse,
	*EventSubscription[*taprpc.SendEvent]) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	require.NotEmpty(t.t, receiverAddrs)
	scriptKey := receiverAddrs[0].ScriptKey

	encodedAddrs := make([]string, len(receiverAddrs))
	for i, addr := range receiverAddrs {
		encodedAddrs[i] = addr.Encoded
	}

	ctxc, streamCancel := context.WithCancel(ctxb)
	stream, err := sender.SubscribeSendEvents(
		ctxc, &taprpc.SubscribeSendEventsRequest{
			FilterScriptKey: scriptKey,
		},
	)
	require.NoError(t.t, err)
	sub := &EventSubscription[*taprpc.SendEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	resp, err := sender.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: encodedAddrs,
	})
	require.NoError(t.t, err)

	// We'll get events up to the point where we broadcast the transaction.
	AssertSendEvents(
		t.t, scriptKey, sub,
		tapfreighter.SendStateVirtualCommitmentSelect,
		tapfreighter.SendStateBroadcast,
	)

	return resp, sub
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

// fundPacket asks the wallet to fund the given virtual packet, and requires
// that funding succeed.
func fundPacket(t *harnessTest, tapd *tapdHarness,
	vPkg *tappsbt.VPacket) *wrpc.FundVirtualPsbtResponse {

	resp, err := maybeFundPacket(t, tapd, vPkg)
	require.NoError(t.t, err)

	return resp
}

// maybeFundPacket asks the wallet to fund the given virtual packet.
func maybeFundPacket(t *harnessTest, tapd *tapdHarness,
	vPkg *tappsbt.VPacket) (*wrpc.FundVirtualPsbtResponse, error) {

	var buf bytes.Buffer
	err := vPkg.Serialize(&buf)
	require.NoError(t.t, err)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	return tapd.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
		Template: &wrpc.FundVirtualPsbtRequest_Psbt{
			Psbt: buf.Bytes(),
		},
	})
}
