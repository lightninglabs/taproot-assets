package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarorpc"
	unirpc "github.com/lightninglabs/taro/tarorpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

var (
	statusDetected  = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED
	statusConfirmed = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED
	statusCompleted = tarorpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED
)

// assetCheck is a function type that checks an RPC asset's property.
type assetCheck func(a *tarorpc.Asset) error

// assetAmountCheck returns a check function that tests an asset's amount.
func assetAmountCheck(amt uint64) assetCheck {
	return func(a *tarorpc.Asset) error {
		if a.Amount != amt {
			return fmt.Errorf("unexpected asset amount, got %d "+
				"wanted %d", a.Amount, amt)
		}

		return nil
	}
}

// assetTypeCheck returns a check function that tests an asset's type.
func assetTypeCheck(assetType tarorpc.AssetType) assetCheck {
	return func(a *tarorpc.Asset) error {
		if a.AssetType != assetType {
			return fmt.Errorf("unexpected asset type, got %v "+
				"wanted %v", a.AssetType, assetType)
		}

		return nil
	}
}

// assetAnchorCheck returns a check function that tests an asset's anchor.
func assetAnchorCheck(txid, blockHash chainhash.Hash) assetCheck {
	return func(a *tarorpc.Asset) error {
		if a.ChainAnchor == nil {
			return fmt.Errorf("asset is missing chain anchor field")
		}

		if a.ChainAnchor.AnchorTxid != txid.String() {
			return fmt.Errorf("unexpected asset anchor TXID, got "+
				"%x wanted %x", a.ChainAnchor.AnchorTxid,
				txid[:])
		}

		if !bytes.Equal(a.ChainAnchor.AnchorBlockHash, blockHash[:]) {
			return fmt.Errorf("unexpected asset anchor block "+
				"hash, got %x wanted %x",
				a.ChainAnchor.AnchorBlockHash, blockHash[:])
		}

		return nil
	}
}

// assetScriptKeyIsLocalCheck returns a check function that tests an asset's
// script key for being a local key.
func assetScriptKeyIsLocalCheck(isLocal bool) assetCheck {
	return func(a *tarorpc.Asset) error {
		if a.ScriptKeyIsLocal != isLocal {
			return fmt.Errorf("unexpected script key, wanted "+
				"local=%v but is local=%v", isLocal,
				a.ScriptKeyIsLocal)
		}

		return nil
	}
}

// assertAssetState makes sure that an asset with the given (possibly
// non-unique!) name exists in the list of assets and then performs the given
// additional checks on that asset.
func assertAssetState(t *harnessTest, tarod *tarodHarness, name string,
	metaHash []byte, assetChecks ...assetCheck) *tarorpc.Asset {

	t.t.Helper()

	ctxb := context.Background()

	var a *tarorpc.Asset
	err := wait.NoError(func() error {
		ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
		defer cancel()

		listResp, err := tarod.ListAssets(
			ctxt, &tarorpc.ListAssetRequest{},
		)
		if err != nil {
			return err
		}

		for _, rpcAsset := range listResp.Assets {
			rpcGen := rpcAsset.AssetGenesis
			if rpcGen.Name == name &&
				bytes.Equal(rpcGen.MetaHash, metaHash[:]) {

				a = rpcAsset

				for _, check := range assetChecks {
					if err := check(rpcAsset); err != nil {
						return err
					}
				}

				break
			}
		}

		if a == nil {
			return fmt.Errorf("asset with name %s not found in "+
				"asset list", name)
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, err)

	return a
}

// commitmentKey returns the asset's commitment key given an RPC asset
// representation.
func commitmentKey(t *testing.T, rpcAsset *tarorpc.Asset) [32]byte {
	t.Helper()

	var assetID asset.ID
	copy(assetID[:], rpcAsset.AssetGenesis.AssetId)

	scriptKey, err := btcec.ParsePubKey(rpcAsset.ScriptKey)
	require.NoError(t, err)

	var groupKey *btcec.PublicKey
	if rpcAsset.AssetGroup != nil &&
		len(rpcAsset.AssetGroup.TweakedGroupKey) > 0 {

		groupKey, err = btcec.ParsePubKey(
			rpcAsset.AssetGroup.TweakedGroupKey,
		)
		require.NoError(t, err)
	}

	return asset.AssetCommitmentKey(assetID, scriptKey, groupKey == nil)
}

// assertAssetProofs makes sure the proofs for the given asset can be retrieved
// from the given daemon and can be fully validated.
func assertAssetProofs(t *testing.T, tarod *tarodHarness,
	a *tarorpc.Asset) []byte {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	exportResp, err := tarod.ExportProof(ctxt, &tarorpc.ExportProofRequest{
		AssetId:   a.AssetGenesis.AssetId,
		ScriptKey: a.ScriptKey,
	})
	require.NoError(t, err)

	file, snapshot := verifyProofBlob(t, tarod, exportResp.RawProof)

	assetJSON, err := formatProtoJSON(a)
	require.NoError(t, err)
	t.Logf("Got proof file for asset %x that contains %d proof(s), full "+
		"asset: %s", a.AssetGenesis.AssetId, file.NumProofs(),
		assetJSON)

	require.Equal(
		t, commitmentKey(t, a), snapshot.Asset.AssetCommitmentKey(),
	)

	return exportResp.RawProof
}

// verifyProofBlob parses the given proof blob into a file, verifies it and
// returns the resulting last asset snapshot together with the parsed file.
func verifyProofBlob(t *testing.T, tarod *tarodHarness,
	blob proof.Blob) (*proof.File, *proof.AssetSnapshot) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	f := &proof.File{}
	require.NoError(t, f.Decode(bytes.NewReader(blob)))

	// Also make sure that the RPC can verify the proof as well.
	verifyResp, err := tarod.VerifyProof(ctxt, &tarorpc.ProofFile{
		RawProof: blob,
	})
	require.NoError(t, err)
	require.True(t, verifyResp.Valid)

	headerVerifier := func(blockHeader wire.BlockHeader) error {
		hash := blockHeader.BlockHash()
		req := &chainrpc.GetBlockRequest{
			BlockHash: hash.CloneBytes(),
		}
		_, err := tarod.cfg.LndNode.RPC.ChainKit.GetBlock(ctxb, req)
		return err
	}
	snapshot, err := f.Verify(ctxt, headerVerifier)
	require.NoError(t, err)

	return f, snapshot
}

// assertAddrCreated makes sure an address was created correctly for the given
// asset.
func assertAddrCreated(t *testing.T, tarod *tarodHarness,
	expected *tarorpc.Asset, actual *tarorpc.Addr) {

	// Was the address created correctly?
	assertAddr(t, expected, actual)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	decoded, err := tarod.DecodeAddr(ctxt, &tarorpc.DecodeAddrRequest{
		Addr: actual.Encoded,
	})
	require.NoError(t, err)

	decodedJSON, err := formatProtoJSON(decoded)
	require.NoError(t, err)
	t.Logf("Got address %s decoded as %v", actual.Encoded, decodedJSON)

	// Does the decoded address still show everything correctly?
	assertAddr(t, expected, decoded)

	allAddrs, err := tarod.QueryAddrs(ctxt, &tarorpc.QueryAddrRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, allAddrs.Addrs)

	// Can we find the address in the list of all addresses?
	var rpcAddr *tarorpc.Addr
	for idx := range allAddrs.Addrs {
		if allAddrs.Addrs[idx].Encoded == actual.Encoded {
			rpcAddr = allAddrs.Addrs[idx]
			break
		}
	}
	require.NotNil(t, rpcAddr)

	// Does the address in the list contain all information we expect?
	assertAddr(t, expected, rpcAddr)
}

// assertAddrEvent makes sure the given address was detected by the given
// daemon.
func assertAddrEvent(t *testing.T, tarod *tarodHarness, addr *tarorpc.Addr) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	err := wait.NoError(func() error {
		resp, err := tarod.AddrReceives(
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
		require.NoError(t, err)
		t.Logf("Got address event %s", eventJSON)

		return nil
	}, defaultWaitTimeout)
	require.NoError(t, err)
}

// assertAddrReceives makes sure the given number of events with the given
// status were received.
func assertAddrReceives(t *testing.T, tarod *tarodHarness, numEvents int,
	expectedStatus tarorpc.AddrEventStatus) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	err := wait.NoError(func() error {
		resp, err := tarod.AddrReceives(
			ctxt, &tarorpc.AddrReceivesRequest{},
		)
		require.NoError(t, err)
		require.Len(t, resp.Events, numEvents)

		for _, event := range resp.Events {
			if event.Status != expectedStatus {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, expectedStatus)
			}
		}

		return nil
	}, defaultWaitTimeout/2)
	require.NoError(t, err)
}

// confirmAndAssertOutboundTransfer makes sure the given outbound transfer has
// the correct state before confirming it and then asserting the confirmed state
// with the node.
func confirmAndAssertOutboundTransfer(t *harnessTest, sender *tarodHarness,
	sendResp *tarorpc.SendAssetResponse, assetID []byte,
	expectedAmounts []uint64, currentTransferIdx, numTransfers int) {

	confirmAndAssetOutboundTransferWithOutputs(
		t, sender, sendResp, assetID, expectedAmounts,
		currentTransferIdx, numTransfers, 2,
	)
}

// confirmAndAssetOutboundTransferWithOutputs makes sure the given outbound
// transfer has the correct state and number of outputs before confirming it and
// then asserting the confirmed state with the node.
func confirmAndAssetOutboundTransferWithOutputs(t *harnessTest,
	sender *tarodHarness, sendResp *tarorpc.SendAssetResponse,
	assetID []byte, expectedAmounts []uint64, currentTransferIdx,
	numTransfers, numOutputs int) {

	ctxb := context.Background()

	// Check that we now have two new outputs, and that they differ
	// in outpoints and scripts.
	outputs := sendResp.Transfer.Outputs
	require.Len(t.t, outputs, numOutputs)

	outpoints := make(map[string]struct{})
	scripts := make(map[string]struct{})
	for _, o := range outputs {
		_, ok := scripts[string(o.ScriptKey)]
		require.False(t.t, ok)

		outpoints[o.Anchor.Outpoint] = struct{}{}
		scripts[string(o.ScriptKey)] = struct{}{}
	}

	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	// Mine a block to force the send we created above to confirm.
	_ = mineBlocks(t, t.lndHarness, 1, 1)

	// Confirm that we can externally view the transfer.
	require.Eventually(t.t, func() bool {
		resp, err := sender.ListTransfers(
			ctxb, &tarorpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Transfers, numTransfers)

		// Assert the new outpoint, script and amount is in the
		// list.
		transfer := resp.Transfers[currentTransferIdx]
		require.Len(t.t, transfer.Outputs, numOutputs)
		require.Len(t.t, expectedAmounts, numOutputs)
		for idx := range transfer.Outputs {
			out := transfer.Outputs[idx]
			require.Contains(t.t, outpoints, out.Anchor.Outpoint)
			require.Contains(t.t, scripts, string(out.ScriptKey))
			require.Equal(t.t, expectedAmounts[idx], out.Amount)
		}

		firstIn := transfer.Inputs[0]
		return bytes.Equal(firstIn.AssetId, assetID)
	}, defaultTimeout, wait.PollInterval)
	require.NoError(t.t, err)

	transferResp, err := sender.ListTransfers(
		ctxb, &tarorpc.ListTransfersRequest{},
	)
	require.NoError(t.t, err)

	transferRespJSON, err := formatProtoJSON(transferResp)
	require.NoError(t.t, err)
	t.Logf("Got response from list transfers: %v", transferRespJSON)
}

// assertNonInteractiveRecvComplete makes sure the given receiver has the
// correct number of completed non-interactive inbound asset transfers in their
// list of events.
func assertNonInteractiveRecvComplete(t *harnessTest, receiver *tarodHarness,
	totalInboundTransfers int) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// And finally, they should be marked as completed with a proof
	// available.
	err := wait.NoError(func() error {
		resp, err := receiver.AddrReceives(
			ctxt, &tarorpc.AddrReceivesRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Events, totalInboundTransfers)

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
}

// assertAddr asserts that an address contains the correct information of an
// asset.
func assertAddr(t *testing.T, expected *tarorpc.Asset, actual *tarorpc.Addr) {
	require.Equal(t, expected.AssetGenesis.AssetId, actual.AssetId)
	require.Equal(t, expected.AssetType, actual.AssetType)

	if expected.AssetGroup == nil {
		require.Nil(t, actual.GroupKey)
	} else {
		// TODO(guggero): Address 33-byte vs. 32-byte issue in encoded
		// address vs. database.
		require.Equal(
			t, expected.AssetGroup.TweakedGroupKey[1:],
			actual.GroupKey[1:],
		)
	}

	// The script key must explicitly NOT be the same, as that would lead
	// to a collision with assets that have a group key.
	require.NotEqual(t, expected.ScriptKey, actual.ScriptKey)
}

// assertBalanceByID asserts that the balance of a single asset,
// specified by ID, on the given daemon is correct.
func assertBalanceByID(t *testing.T, tarod *tarodHarness, id []byte,
	amt uint64) {

	ctxb := context.Background()
	balancesResp, err := tarod.ListBalances(
		ctxb, &tarorpc.ListBalancesRequest{
			GroupBy: &tarorpc.ListBalancesRequest_AssetId{
				AssetId: true,
			},
			AssetFilter: id,
		},
	)
	require.NoError(t, err)

	balance, ok := balancesResp.AssetBalances[hex.EncodeToString(id)]
	if amt == 0 {
		require.False(t, ok)
		return
	}

	require.True(t, ok)
	require.Equal(t, uint64(amt), uint64(balance.Balance))
}

// assertBalanceByGroup asserts that the balance of a single asset group
// on the given daemon is correct.
func assertBalanceByGroup(t *testing.T, tarod *tarodHarness, hexGroupKey string,
	amt uint64) {

	t.Helper()

	groupKey, err := hex.DecodeString(hexGroupKey)
	require.NoError(t, err)

	ctxb := context.Background()
	balancesResp, err := tarod.ListBalances(
		ctxb, &tarorpc.ListBalancesRequest{
			GroupBy: &tarorpc.ListBalancesRequest_GroupKey{
				GroupKey: true,
			},
			GroupKeyFilter: groupKey,
		},
	)
	require.NoError(t, err)

	balance, ok := balancesResp.AssetGroupBalances[hexGroupKey]
	require.True(t, ok)
	require.Equal(t, amt, balance.Balance)
}

// assertTransfers asserts that the value of each transfer initiated on the
// given daemon is correct.
func assertTransfers(t *testing.T, tarod *tarodHarness, amts []uint64) {
	ctxb := context.Background()
	transferResp, err := tarod.ListTransfers(
		ctxb, &tarorpc.ListTransfersRequest{},
	)
	require.NoError(t, err)
	require.Len(t, transferResp.Transfers, len(amts))

	// TODO(jhb): Extend to support multi-asset transfers
	for i, transfer := range transferResp.Transfers {
		require.Len(t, transfer.Outputs, 2)
		require.Equal(t, amts[i], transfer.Outputs[0].Amount)
	}
}

// assertSplitTombstoneTransfer asserts that there is a transfer for the given
// asset ID that is a split that left over a tombstone output.
func assertSplitTombstoneTransfer(t *testing.T, tarod *tarodHarness,
	id []byte) {

	ctxb := context.Background()
	transferResp, err := tarod.ListTransfers(
		ctxb, &tarorpc.ListTransfersRequest{},
	)
	require.NoError(t, err)
	require.NotEmpty(t, transferResp.Transfers)

	tombstoneFound := false
	for _, transfer := range transferResp.Transfers {
		if !bytes.Equal(transfer.Inputs[0].AssetId, id) {
			continue
		}

		for _, out := range transfer.Outputs {
			if out.Amount != 0 {
				continue
			}

			// A zero amount output is a tombstone output.
			tombstoneFound = true
			require.Equal(t, asset.NUMSBytes, out.ScriptKey)
			require.False(t, out.ScriptKeyIsLocal)
			require.NotEmpty(t, out.SplitCommitRootHash)
		}
	}

	require.True(t, tombstoneFound, "no tombstone output found")
}

// assertNumGroups asserts that the number of groups the daemon is aware of
// is correct.
func assertNumGroups(t *testing.T, tarod *tarodHarness, num int) {
	ctxb := context.Background()
	groupResp, err := tarod.ListGroups(
		ctxb, &tarorpc.ListGroupsRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, num, len(groupResp.Groups))
}

// assertGroup asserts that an asset returned from the ListGroups call matches
// a specific asset and has the same group key.
func assertGroup(t *testing.T, a *tarorpc.Asset, b *tarorpc.AssetHumanReadable,
	groupKey []byte) {

	require.Equal(t, a.AssetGenesis.AssetId, b.Id)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.LockTime, b.LockTime)
	require.Equal(t, a.RelativeLockTime, b.RelativeLockTime)
	require.Equal(t, a.AssetGenesis.Name, b.Tag)
	require.Equal(t, a.AssetGenesis.MetaHash, b.MetaHash)
	require.Equal(t, a.AssetType, b.Type)
	require.Equal(t, a.AssetGroup.TweakedGroupKey, groupKey)
}

// MatchRpcAsset is a function that returns true if the given RPC asset is a
// match.
type MatchRpcAsset func(asset *tarorpc.Asset) bool

// assertListAssets checks that the assets returned by ListAssets match the
// expected assets.
func assertListAssets(t *harnessTest, ctx context.Context, tarod *tarodHarness,
	matchAssets []MatchRpcAsset) {

	resp, err := tarod.ListAssets(ctx, &tarorpc.ListAssetRequest{})
	require.NoError(t.t, err)

	// Ensure that the number of assets returned is correct.
	require.Equal(t.t, len(resp.Assets), len(matchAssets))

	// Match each asset returned by the daemon against the expected assets.
	for _, a := range resp.Assets {
		assetMatched := false
		for _, match := range matchAssets {
			if match(a) {
				assetMatched = true
				break
			}
		}
		require.True(t.t, assetMatched, "asset not matched: %v", a)
	}
}

func assertUniverseRootEqual(t *testing.T, a, b *unirpc.UniverseRoot) {
	// The ids should batch exactly.
	require.Equal(t, a.Id.Id, b.Id.Id)

	// The sum and root hash should also match for the SMT root itself.
	require.Equal(
		t, a.MssmtRoot.RootHash, b.MssmtRoot.RootHash,
	)
	require.Equal(
		t, a.MssmtRoot.RootSum, b.MssmtRoot.RootSum,
	)
}

func assertUniverseRootsEqual(t *testing.T, a, b *unirpc.AssetRootResponse) {
	// The set of keys in the maps should match exactly, as this means the
	// same set of asset IDs are being tracked.
	uniKeys := maps.Keys(a.UniverseRoots)
	require.Equal(t, len(a.UniverseRoots), len(b.UniverseRoots))
	require.True(t, chanutils.All(uniKeys, func(key string) bool {
		_, ok := b.UniverseRoots[key]
		return ok
	}))

	// Now that we know the same set of assets are being tracked, we'll
	// ensure that the root values are also the same.
	for uniID := range a.UniverseRoots {
		rootA, ok := a.UniverseRoots[uniID]
		require.True(t, ok)

		rootB, ok := b.UniverseRoots[uniID]
		require.True(t, ok)

		assertUniverseRootEqual(t, rootA, rootB)
	}
}

func assertUniverseLeavesEqual(t *testing.T, uniIDs []*unirpc.ID,
	a, b *tarodHarness) {

	for _, uniID := range uniIDs {
		aLeaves, err := a.AssetLeaves(context.Background(), uniID)
		require.NoError(t, err)

		bLeaves, err := b.AssetLeaves(context.Background(), uniID)
		require.NoError(t, err)

		require.Equal(t, len(aLeaves.Leaves), len(bLeaves.Leaves))

		for i := 0; i < len(aLeaves.Leaves); i++ {
			require.Equal(
				t, aLeaves.Leaves[i].Asset,
				bLeaves.Leaves[i].Asset,
			)

			require.Equal(
				t, aLeaves.Leaves[i].IssuanceProof,
				bLeaves.Leaves[i].IssuanceProof,
			)
		}
	}
}

func assertUniverseKeysEqual(t *testing.T, uniIDs []*unirpc.ID,
	a, b *tarodHarness) {

	for _, uniID := range uniIDs {
		aUniKeys, err := a.AssetLeafKeys(context.Background(), uniID)
		require.NoError(t, err)

		bUniKeys, err := b.AssetLeafKeys(context.Background(), uniID)
		require.NoError(t, err)

		require.Equal(
			t, len(aUniKeys.AssetKeys), len(bUniKeys.AssetKeys),
		)

		for i := 0; i < len(aUniKeys.AssetKeys); i++ {
			require.Equal(
				t, aUniKeys.AssetKeys[i], bUniKeys.AssetKeys[i],
			)
		}
	}
}
