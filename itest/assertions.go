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
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// assetCheck is a function type that checks an RPC asset's property.
type assetCheck func(a *tarorpc.Asset) error

// assetAmountCheck returns a check function that tests an asset's amount.
func assetAmountCheck(amt int64) assetCheck {
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

		if !bytes.Equal(a.ChainAnchor.AnchorTxid, txid[:]) {
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

// assertAssetState makes sure that an asset with the given (possibly
// non-unique!) name exists in the list of assets and then performs the given
// additional checks on that asset.
func assertAssetState(t *harnessTest, tarod *tarodHarness, name string,
	meta []byte, assetChecks ...assetCheck) *tarorpc.Asset {

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
				bytes.Equal(rpcGen.Meta, meta) {

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
		_, err := tarod.cfg.LndNode.ChainKit.GetBlock(ctxb, req)
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

// assertBalance asserts that the balance of a given asset on the given daemon
// is correct.
func assertBalance(t *testing.T, tarod *tarodHarness, id []byte, amt int64) {
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
	require.Len(t, balancesResp.AssetBalances, 1)

	balance := balancesResp.AssetBalances[hex.EncodeToString(id)]
	require.Equal(t, balance.Balance, amt)
}

// assertTransfers asserts that the value of each transfer initiated on the
// given daemon is correct.
func assertTransfers(t *testing.T, tarod *tarodHarness, amts []int64) {
	ctxb := context.Background()
	transferResp, err := tarod.ListTransfers(
		ctxb, &tarorpc.ListTransfersRequest{},
	)
	require.NoError(t, err)
	require.Len(t, transferResp.Transfers, len(amts))

	// TODO(jhb): Extend to support multi-asset transfers
	for i, transfer := range transferResp.Transfers {
		require.Len(t, transfer.AssetSpendDeltas, 1)
		require.Equal(t, amts[i], transfer.AssetSpendDeltas[0].NewAmt)
	}
}
