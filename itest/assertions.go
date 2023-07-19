package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

var (
	statusDetected  = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED
	statusConfirmed = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_CONFIRMED
	statusCompleted = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED
)

// assetCheck is a function type that checks an RPC asset's property.
type assetCheck func(a *taprpc.Asset) error

// assetAmountCheck returns a check function that tests an asset's amount.
func assetAmountCheck(amt uint64) assetCheck {
	return func(a *taprpc.Asset) error {
		if a.Amount != amt {
			return fmt.Errorf("unexpected asset amount, got %d "+
				"wanted %d", a.Amount, amt)
		}

		return nil
	}
}

// assetTypeCheck returns a check function that tests an asset's type.
func assetTypeCheck(assetType taprpc.AssetType) assetCheck {
	return func(a *taprpc.Asset) error {
		if a.AssetType != assetType {
			return fmt.Errorf("unexpected asset type, got %v "+
				"wanted %v", a.AssetType, assetType)
		}

		return nil
	}
}

// assetAnchorCheck returns a check function that tests an asset's anchor.
func assetAnchorCheck(txid, blockHash chainhash.Hash) assetCheck {
	return func(a *taprpc.Asset) error {
		if a.ChainAnchor == nil {
			return fmt.Errorf("asset is missing chain anchor field")
		}

		if a.ChainAnchor.AnchorTxid != txid.String() {
			return fmt.Errorf("unexpected asset anchor TXID, got "+
				"%x wanted %x", a.ChainAnchor.AnchorTxid,
				txid[:])
		}

		if a.ChainAnchor.AnchorBlockHash != blockHash.String() {
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
	return func(a *taprpc.Asset) error {
		if a.ScriptKeyIsLocal != isLocal {
			return fmt.Errorf("unexpected script key, wanted "+
				"local=%v but is local=%v", isLocal,
				a.ScriptKeyIsLocal)
		}

		return nil
	}
}

// groupAssetsByName converts an unordered list of assets to a map of lists of
// assets, where all assets in a list have the same name.
func groupAssetsByName(assets []*taprpc.Asset) map[string][]*taprpc.Asset {
	assetLists := make(map[string][]*taprpc.Asset)
	for idx := range assets {
		a := assets[idx]
		assetLists[a.AssetGenesis.Name] = append(
			assetLists[a.AssetGenesis.Name], a,
		)
	}

	return assetLists
}

// assertAssetState makes sure that an asset with the given (possibly
// non-unique!) name exists in the list of assets and then performs the given
// additional checks on that asset.
func assertAssetState(t *harnessTest, assets map[string][]*taprpc.Asset,
	name string, metaHash []byte, assetChecks ...assetCheck) *taprpc.Asset {

	var a *taprpc.Asset

	require.Contains(t.t, assets, name)

	for _, rpcAsset := range assets[name] {
		rpcGen := rpcAsset.AssetGenesis
		if bytes.Equal(rpcGen.MetaHash, metaHash[:]) {
			a = rpcAsset

			for _, check := range assetChecks {
				err := check(rpcAsset)
				require.NoError(t.t, err)
			}

			break
		}
	}

	require.NotNil(t.t, a, fmt.Errorf("asset with matching metadata not"+
		"found in asset list"))

	return a
}

// waitForBatchState polls until the planter has reached the desired state with
// the current batch.
func waitForBatchState(t *harnessTest, ctx context.Context, tapd *tapdHarness,
	timeout time.Duration, targetState mintrpc.BatchState) bool {

	breakTimeout := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	isTargetState := func(b *mintrpc.MintingBatch) bool {
		return b.State == targetState
	}

	batchCount := func() int {
		batchResp, err := tapd.ListBatches(
			ctx, &mintrpc.ListBatchRequest{},
		)
		require.NoError(t.t, err)

		return fn.Count(batchResp.Batches, isTargetState)
	}

	initialBatchCount := batchCount()

	for {
		select {
		case <-breakTimeout:
			return false
		case <-ticker.C:
			currentBatchCount := batchCount()
			if currentBatchCount-initialBatchCount == 1 {
				return true
			}
		}
	}
}

// commitmentKey returns the asset's commitment key given an RPC asset
// representation.
func commitmentKey(t *testing.T, rpcAsset *taprpc.Asset) [32]byte {
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
func assertAssetProofs(t *testing.T, tapd *tapdHarness,
	a *taprpc.Asset) []byte {

	t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	exportResp, err := tapd.ExportProof(ctxt, &taprpc.ExportProofRequest{
		AssetId:   a.AssetGenesis.AssetId,
		ScriptKey: a.ScriptKey,
	})
	require.NoError(t, err)

	file, snapshot := verifyProofBlob(t, tapd, a, exportResp.RawProof)

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
func verifyProofBlob(t *testing.T, tapd *tapdHarness, a *taprpc.Asset,
	blob proof.Blob) (*proof.File, *proof.AssetSnapshot) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	f := &proof.File{}
	require.NoError(t, f.Decode(bytes.NewReader(blob)))

	// Also make sure that the RPC can verify the proof as well.
	verifyResp, err := tapd.VerifyProof(ctxt, &taprpc.ProofFile{
		RawProof: blob,
	})
	require.NoError(t, err)
	require.True(t, verifyResp.Valid)

	// Also make sure that the RPC can decode the proof as well.
	decodeResp, err := tapd.DecodeProof(ctxt, &taprpc.DecodeProofRequest{
		RawProof: blob,
	})
	require.NoError(t, err)

	require.NotNil(t, decodeResp.DecodedProof)
	assertAsset(t, a, decodeResp.DecodedProof.Asset)
	proofAsset := decodeResp.DecodedProof.Asset

	// Ensure anchor block height is set.
	anchorTxBlockHeight := proofAsset.ChainAnchor.BlockHeight
	require.Greater(t, anchorTxBlockHeight, uint32(0))

	headerVerifier := func(header wire.BlockHeader, height uint32) error {
		hash := header.BlockHash()

		// Ensure that the block hash matches the hash of the block
		// found at the given height.
		blockHashReq := &chainrpc.GetBlockHashRequest{
			BlockHeight: int64(height),
		}
		blockHashResp, err := tapd.cfg.LndNode.RPC.ChainKit.GetBlockHash(
			ctxb, blockHashReq,
		)
		if err != nil {
			return err
		}

		var heightHash chainhash.Hash
		copy(heightHash[:], blockHashResp.BlockHash)

		expectedHash := hash
		if heightHash != expectedHash {
			return fmt.Errorf("block hash and block height "+
				"mismatch; (height: %x, hashAtHeight: %s, "+
				"expectedHash: %s)", height, heightHash,
				expectedHash)
		}

		// Ensure that the block header corresponds to a block on-chain.
		req := &chainrpc.GetBlockRequest{
			BlockHash: hash.CloneBytes(),
		}
		_, err = tapd.cfg.LndNode.RPC.ChainKit.GetBlock(ctxb, req)
		return err
	}

	snapshot, err := f.Verify(ctxt, headerVerifier)
	require.NoError(t, err)

	return f, snapshot
}

// assertAddrCreated makes sure an address was created correctly for the given
// asset.
func assertAddrCreated(t *testing.T, tapd *tapdHarness,
	expected *taprpc.Asset, actual *taprpc.Addr) {

	// Was the address created correctly?
	assertAddr(t, expected, actual)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	decoded, err := tapd.DecodeAddr(ctxt, &taprpc.DecodeAddrRequest{
		Addr: actual.Encoded,
	})
	require.NoError(t, err)

	decodedJSON, err := formatProtoJSON(decoded)
	require.NoError(t, err)
	t.Logf("Got address %s decoded as %v", actual.Encoded, decodedJSON)

	// Does the decoded address still show everything correctly?
	assertAddr(t, expected, decoded)

	allAddrs, err := tapd.QueryAddrs(ctxt, &taprpc.QueryAddrRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, allAddrs.Addrs)

	// Can we find the address in the list of all addresses?
	var rpcAddr *taprpc.Addr
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
func assertAddrEvent(t *testing.T, tapd *tapdHarness, addr *taprpc.Addr,
	numEvents int, expectedStatus taprpc.AddrEventStatus) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	err := wait.NoError(func() error {
		resp, err := tapd.AddrReceives(
			ctxt, &taprpc.AddrReceivesRequest{
				FilterAddr: addr.Encoded,
			},
		)
		if err != nil {
			return err
		}

		if len(resp.Events) != numEvents {
			return fmt.Errorf("got %d events, wanted %d",
				len(resp.Events), numEvents)
		}

		if resp.Events[0].Status != expectedStatus {
			return fmt.Errorf("got status %v, wanted %v",
				resp.Events[0].Status, expectedStatus)
		}

		eventJSON, err := formatProtoJSON(resp.Events[0])
		require.NoError(t, err)
		t.Logf("Got address event %s", eventJSON)

		return nil
	}, defaultWaitTimeout)
	require.NoError(t, err)
}

// assertAddrEventByStatus makes sure the given number of events exist with the
// given status.
func assertAddrEventByStatus(t *testing.T, tapd *tapdHarness,
	filterStatus taprpc.AddrEventStatus, numEvents int) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	err := wait.NoError(func() error {
		resp, err := tapd.AddrReceives(
			ctxt, &taprpc.AddrReceivesRequest{
				FilterStatus: filterStatus,
			},
		)
		require.NoError(t, err)
		require.Len(t, resp.Events, numEvents)

		for _, event := range resp.Events {
			if event.Status != filterStatus {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, filterStatus)
			}
		}

		return nil
	}, defaultWaitTimeout/2)
	require.NoError(t, err)
}

// confirmAndAssertOutboundTransfer makes sure the given outbound transfer has
// the correct state before confirming it and then asserting the confirmed state
// with the node.
func confirmAndAssertOutboundTransfer(t *harnessTest, sender *tapdHarness,
	sendResp *taprpc.SendAssetResponse, assetID []byte,
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
	sender *tapdHarness, sendResp *taprpc.SendAssetResponse,
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

	// Mine a block to force the send event to complete (confirm on-chain).
	_ = mineBlocks(t, t.lndHarness, 1, 1)

	// Confirm that we can externally view the transfer.
	require.Eventually(t.t, func() bool {
		resp, err := sender.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{},
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
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t.t, err)

	transferRespJSON, err := formatProtoJSON(transferResp)
	require.NoError(t.t, err)
	t.Logf("Got response from list transfers: %v", transferRespJSON)
}

// assertNonInteractiveRecvComplete makes sure the given receiver has the
// correct number of completed non-interactive inbound asset transfers in their
// list of events.
func assertNonInteractiveRecvComplete(t *harnessTest, receiver *tapdHarness,
	totalInboundTransfers int) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// And finally, they should be marked as completed with a proof
	// available.
	err := wait.NoError(func() error {
		resp, err := receiver.AddrReceives(
			ctxt, &taprpc.AddrReceivesRequest{},
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
func assertAddr(t *testing.T, expected *taprpc.Asset, actual *taprpc.Addr) {
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

// assertEqualAsset asserts that two taprpc.Asset objects are equal, ignoring
// node-specific fields like if script keys are local, if the asset is spent,
// or if the anchor information is populated.
func assertAsset(t *testing.T, expected, actual *taprpc.Asset) {
	require.Equal(t, expected.Version, actual.Version)
	assertAssetGenesis(t, expected.AssetGenesis, actual.AssetGenesis)
	require.Equal(t, expected.AssetType, actual.AssetType)
	require.Equal(t, expected.Amount, actual.Amount)
	require.Equal(t, expected.LockTime, actual.LockTime)
	require.Equal(t, expected.RelativeLockTime, actual.RelativeLockTime)
	require.Equal(t, expected.ScriptVersion, actual.ScriptVersion)
	require.Equal(t, expected.ScriptKey, actual.ScriptKey)
	require.Equal(t, expected.AssetGroup == nil, actual.AssetGroup == nil)
	require.Equal(t, expected.PrevWitnesses, actual.PrevWitnesses)

	// The raw key isn't always set as that's not contained in proofs for
	// example.
	if expected.AssetGroup != nil {
		eg := expected.AssetGroup
		ag := actual.AssetGroup

		require.Equal(t, eg.AssetIdSig, ag.AssetIdSig)
		require.Equal(t, eg.TweakedGroupKey, ag.TweakedGroupKey)
	}
}

// assertAssetGenesis asserts that two taprpc.GenesisInfo objects are equal.
func assertAssetGenesis(t *testing.T, expected, actual *taprpc.GenesisInfo) {
	require.Equal(t, expected.GenesisPoint, actual.GenesisPoint)
	require.Equal(t, expected.Name, actual.Name)
	require.Equal(t, expected.MetaHash, actual.MetaHash)
	require.Equal(t, expected.AssetId, actual.AssetId)
	require.Equal(t, expected.OutputIndex, actual.OutputIndex)
	require.Equal(t, expected.Version, actual.Version)
}

// assertBalanceByID asserts that the balance of a single asset,
// specified by ID, on the given daemon is correct.
func assertBalanceByID(t *testing.T, tapd *tapdHarness, id []byte,
	amt uint64) {

	ctxb := context.Background()
	balancesResp, err := tapd.ListBalances(
		ctxb, &taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_AssetId{
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
func assertBalanceByGroup(t *testing.T, tapd *tapdHarness, hexGroupKey string,
	amt uint64) {

	t.Helper()

	groupKey, err := hex.DecodeString(hexGroupKey)
	require.NoError(t, err)

	ctxb := context.Background()
	balancesResp, err := tapd.ListBalances(
		ctxb, &taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_GroupKey{
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

// assertTransfer asserts that the value of each transfer initiated on the
// given daemon is correct.
func assertTransfer(t *testing.T, tapd *tapdHarness, transferIdx,
	numTransfers int, outputAmounts []uint64) {

	ctxb := context.Background()
	transferResp, err := tapd.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t, err)
	require.Len(t, transferResp.Transfers, numTransfers)

	transfer := transferResp.Transfers[transferIdx]
	require.Len(t, transfer.Outputs, len(outputAmounts))
	for i := range transfer.Outputs {
		require.Equal(t, outputAmounts[i], transfer.Outputs[i].Amount)
	}
}

// assertSplitTombstoneTransfer asserts that there is a transfer for the given
// asset ID that is a split that left over a tombstone output.
func assertSplitTombstoneTransfer(t *testing.T, tapd *tapdHarness,
	id []byte) {

	ctxb := context.Background()
	transferResp, err := tapd.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
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
func assertNumGroups(t *testing.T, tapd *tapdHarness, num int) {
	ctxb := context.Background()
	groupResp, err := tapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, num, len(groupResp.Groups))
}

// assertGroupSizes asserts that a set of groups the daemon is aware of contain
// the expected number of assets.
func assertGroupSizes(t *testing.T, tapd *tapdHarness, hexGroupKeys []string,
	sizes []int) {

	ctxb := context.Background()
	groupResp, err := tapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t, err)

	for i, key := range hexGroupKeys {
		groupAssets, ok := groupResp.Groups[key]
		require.True(t, ok)
		require.Equal(t, sizes[i], len(groupAssets.Assets))
	}
}

// assertGroup asserts that an asset returned from the ListGroups call matches
// a specific asset and has the same group key.
func assertGroup(t *testing.T, a *taprpc.Asset, b *taprpc.AssetHumanReadable,
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

// assertGroupAnchor asserts that a specific asset genesis was used to create
// a tweaked group key.
func assertGroupAnchor(t *testing.T, anchorGen *asset.Genesis,
	internalKey, tweakedKey []byte) {

	internalPubKey, err := btcec.ParsePubKey(internalKey)
	require.NoError(t, err)
	computedGroupPubKey := txscript.ComputeTaprootOutputKey(
		internalPubKey, anchorGen.GroupKeyTweak(),
	)
	computedGroupKey := computedGroupPubKey.SerializeCompressed()
	require.Equal(t, tweakedKey, computedGroupKey)
}

// MatchRpcAsset is a function that returns true if the given RPC asset is a
// match.
type MatchRpcAsset func(asset *taprpc.Asset) bool

// assertListAssets checks that the assets returned by ListAssets match the
// expected assets.
func assertListAssets(t *harnessTest, ctx context.Context, tapd *tapdHarness,
	matchAssets []MatchRpcAsset) {

	resp, err := tapd.ListAssets(ctx, &taprpc.ListAssetRequest{})
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

func assertUniverseRoot(t *testing.T, tapd *tapdHarness, sum int,
	assetID []byte, groupKey []byte) error {

	bothSet := assetID != nil && groupKey != nil
	neitherSet := assetID == nil && groupKey == nil
	if bothSet || neitherSet {
		return fmt.Errorf("only set one of assetID or groupKey")
	}

	// Re-parse and serialize the keys to account for the different
	// formats returned in RPC responses.
	matchingGroupKey := func(root *unirpc.UniverseRoot) bool {
		rootGroupKeyBytes := root.Id.GetGroupKey()
		require.NotNil(t, rootGroupKeyBytes)

		expectedGroupKey, err := btcec.ParsePubKey(groupKey)
		require.NoError(t, err)
		require.Equal(
			t, rootGroupKeyBytes,
			schnorr.SerializePubKey(expectedGroupKey),
		)

		return true
	}

	// Comparing the asset ID is always safe, even if nil.
	matchingRoot := func(root *unirpc.UniverseRoot) bool {
		require.Equal(t, root.MssmtRoot.RootSum, int64(sum))
		require.Equal(t, root.Id.GetAssetId(), assetID)
		if groupKey != nil {
			return matchingGroupKey(root)
		}

		return true
	}

	ctx := context.Background()

	uniRoots, err := tapd.AssetRoots(ctx, &unirpc.AssetRootRequest{})
	require.NoError(t, err)

	correctRoot := fn.Any(maps.Values(uniRoots.UniverseRoots), matchingRoot)
	require.True(t, correctRoot)

	return nil
}

func assertUniverseRootEqual(a, b *unirpc.UniverseRoot) bool {
	// The ids should batch exactly.
	if !reflect.DeepEqual(a.Id.Id, b.Id.Id) {
		return false
	}

	// The sum and root hash should also match for the SMT root itself.
	if !bytes.Equal(a.MssmtRoot.RootHash, b.MssmtRoot.RootHash) {
		return false
	}
	if a.MssmtRoot.RootSum != b.MssmtRoot.RootSum {
		return false
	}

	return true
}

func assertUniverseRootsEqual(a, b *unirpc.AssetRootResponse) bool {
	// The set of keys in the maps should match exactly, as this means the
	// same set of asset IDs are being tracked.
	uniKeys := maps.Keys(a.UniverseRoots)
	if len(a.UniverseRoots) != len(b.UniverseRoots) {
		return false
	}
	if !fn.All(uniKeys, func(key string) bool {
		_, ok := b.UniverseRoots[key]
		return ok
	}) {

		return false
	}

	// Now that we know the same set of assets are being tracked, we'll
	// ensure that the root values are also the same.
	for uniID := range a.UniverseRoots {
		rootA, ok := a.UniverseRoots[uniID]
		if !ok {
			return false
		}

		rootB, ok := b.UniverseRoots[uniID]
		if !ok {
			return false
		}

		return assertUniverseRootEqual(rootA, rootB)
	}

	return true
}

func assertUniverseStateEqual(t *testing.T, a, b *tapdHarness) bool {
	ctxb := context.Background()

	rootsA, err := a.AssetRoots(ctxb, &unirpc.AssetRootRequest{})
	require.NoError(t, err)

	rootsB, err := b.AssetRoots(ctxb, &unirpc.AssetRootRequest{})
	require.NoError(t, err)

	return assertUniverseRootsEqual(rootsA, rootsB)
}

func assertUniverseLeavesEqual(t *testing.T, uniIDs []*unirpc.ID,
	a, b *tapdHarness) {

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
	a, b *tapdHarness) {

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

func assertUniverseStats(t *testing.T, node *tapdHarness,
	numProofs, numSyncs, numAssets int) {

	err := wait.NoError(func() error {
		uniStats, err := node.UniverseStats(
			context.Background(), &unirpc.StatsRequest{},
		)
		if err != nil {
			return err
		}

		if numProofs != int(uniStats.NumTotalProofs) {
			return fmt.Errorf("expected %v proofs, got %v",
				numProofs, uniStats.NumTotalProofs)
		}
		if numSyncs != int(uniStats.NumTotalSyncs) {
			return fmt.Errorf("expected %v syncs, got %v",
				numSyncs, uniStats.NumTotalSyncs)
		}
		if numAssets != int(uniStats.NumTotalAssets) {
			return fmt.Errorf("expected %v assets, got %v",
				numAssets, uniStats.NumTotalAssets)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t, err)
}

func assertUniverseAssetStats(t *testing.T, node *tapdHarness,
	assets []*taprpc.Asset) {

	ctxb := context.Background()
	assetStats, err := node.QueryAssetStats(ctxb, &unirpc.AssetStatsQuery{})
	require.NoError(t, err)
	require.Len(t, assetStats.AssetStats, len(assets))

	for _, assetStat := range assetStats.AssetStats {
		found := fn.Any(
			assets, func(a *taprpc.Asset) bool {
				groupKeyEqual := true
				if a.AssetGroup != nil {
					groupKeyEqual = bytes.Equal(
						assetStat.GroupKey,
						a.AssetGroup.TweakedGroupKey,
					)
				}

				return groupKeyEqual && bytes.Equal(
					assetStat.AssetId,
					a.AssetGenesis.AssetId,
				)
			},
		)
		require.True(t, found)

		require.NotZero(t, assetStat.GenesisHeight)
		require.NotZero(t, assetStat.GenesisTimestamp)
		require.NotEmpty(t, assetStat.GenesisPoint)
	}

	eventStats, err := node.QueryEvents(ctxb, &unirpc.QueryEventsRequest{})
	require.NoError(t, err)

	todayStr := time.Now().Format("2006-01-02")
	require.Len(t, eventStats.Events, 1)

	s := eventStats.Events[0]
	require.Equal(t, todayStr, s.Date)
	require.EqualValues(t, len(assets), s.NewProofEvents)
}
