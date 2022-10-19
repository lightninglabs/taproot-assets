package itest

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

var (
	statusDetected  = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED
	statusConfirmed = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED
	statusCompleted = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED
)

func testAddresses(t *harnessTest) {
	// First, mint a few assets, so we have some to create addresses for.
	// We mint all of them in individual batches to avoid needing to sign
	// for multiple internal asset transfers when only sending one of them
	// to an external address.
	//
	// TODO(guggero): Update this test once we support pocket universes with
	// virtual TX outpoints in prevID so we don't have to sign for every
	// asset within a commitment if we only move one of them.
	var rpcAssets []*tarorpc.Asset
	rpcAssets = append(rpcAssets, mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)...)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var (
		addresses []*tarorpc.Addr
		events    []*tarorpc.AddrEvent
	)
	for _, a := range rpcAssets {
		var familyKey []byte
		if a.AssetFamily != nil {
			familyKey = a.AssetFamily.TweakedFamilyKey
		}

		// In order to force a split, we don't try to send the full
		// asset.
		addr, err := secondTarod.NewAddr(ctxt, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: a.AssetGenesis.GenesisBootstrapInfo,
			FamKey:               familyKey,
			Amt:                  a.Amount - 1,
		})
		require.NoError(t.t, err)
		addresses = append(addresses, addr)

		assertAddrCreated(t.t, secondTarod, a, addr)

		sendResp := sendAssetsToAddr(t, addr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)
		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Make sure that eventually we see a single event for the
		// address.
		err = wait.NoError(func() error {
			resp, err := secondTarod.AddrReceives(
				ctxt, &tarorpc.AddrReceivesRequest{
					FilterAddr: addr.Encoded,
				},
			)
			if err != nil {
				return err
			}

			if len(resp.Events) != 1 {
				return fmt.Errorf("got %d events, wanted 1",
					len(resp.Events))
			}

			if resp.Events[0].Status != statusDetected {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, statusDetected)
			}

			eventJSON, err := formatProtoJSON(resp.Events[0])
			require.NoError(t.t, err)
			t.Logf("Got address event %s", eventJSON)
			events = append(events, resp.Events[0])

			return nil
		}, defaultWaitTimeout/2)
		require.NoError(t.t, err)
	}

	// Mine a block to make sure the events are marked as confirmed.
	_ = mineBlocks(t, t.lndHarness, 1, len(rpcAssets))[0]

	// Eventually the events should be marked as confirmed.
	err := wait.NoError(func() error {
		resp, err := secondTarod.AddrReceives(
			ctxt, &tarorpc.AddrReceivesRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Events, len(rpcAssets))

		for _, event := range resp.Events {
			if event.Status != statusConfirmed {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, statusConfirmed)
			}
		}

		return nil
	}, defaultWaitTimeout/2)
	require.NoError(t.t, err)

	// To complete the transfer, we'll export the proof from the sender and
	// import it into the receiver for each asset set.
	for i, rpcAsset := range rpcAssets {
		receiverAddr := addresses[i]

		assetGen := rpcAsset.AssetGenesis

		var proofResp *tarorpc.ProofFile
		waitErr := wait.NoError(func() error {
			resp, err := t.tarod.ExportProof(
				ctxb,
				&tarorpc.ExportProofRequest{
					AssetId:   assetGen.AssetId,
					ScriptKey: receiverAddr.ScriptKey,
				},
			)
			if err != nil {
				return err
			}

			proofResp = resp
			return nil
		}, defaultWaitTimeout)
		require.NoError(t.t, waitErr)

		_, err = secondTarod.ImportProof(
			ctxb,
			&tarorpc.ImportProofRequest{
				ProofFile:    proofResp.RawProof,
				GenesisPoint: assetGen.GenesisPoint,
			},
		)
		require.NoError(t.t, err)
	}

	// And finally, they should be marked as completed with a proof
	// available.
	err = wait.NoError(func() error {
		resp, err := secondTarod.AddrReceives(
			ctxt, &tarorpc.AddrReceivesRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Events, len(rpcAssets))

		for _, event := range resp.Events {
			if event.Status != statusCompleted {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, statusCompleted)
			}

			if !event.HasProof {
				return fmt.Errorf("wanted proof, but was false")
			}
		}

		return nil
	}, defaultWaitTimeout/2)
	require.NoError(t.t, err)

	// Now sanity check that we can actually list the transfer.
	err = wait.NoError(func() error {
		resp, err := t.tarod.ListTransfers(
			ctxt, &tarorpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Transfers, len(rpcAssets))
		require.Len(t.t, resp.Transfers[0].AssetSpendDeltas, 1)
		delta := resp.Transfers[0].AssetSpendDeltas[0]
		require.Equal(t.t,
			rpcAssets[0].AssetGenesis.AssetId, delta.AssetId,
		)
		require.Equal(t.t, int64(1), delta.NewAmt)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)
}

// sendAssetsToAddr spends the given input asset and sends the amount specified
// in the address to the Taproot output derived from the address.
func sendAssetsToAddr(t *harnessTest,
	rpcAddr *tarorpc.Addr) *tarorpc.SendAssetResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := t.tarod.SendAsset(ctxt, &tarorpc.SendAssetRequest{
		TaroAddr: rpcAddr.Encoded,
	})
	require.NoError(t.t, err)

	return resp
}

func parseOutPoint(s string) (*wire.OutPoint, error) {
	split := strings.Split(s, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("expecting outpoint to be in format of: " +
			"txid:index")
	}

	index, err := strconv.ParseInt(split[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("unable to decode output index: %v", err)
	}

	txid, err := chainhash.NewHashFromStr(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse hex string: %v", err)
	}

	return &wire.OutPoint{
		Hash:  *txid,
		Index: uint32(index),
	}, nil
}
