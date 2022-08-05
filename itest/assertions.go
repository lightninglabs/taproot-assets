package itest

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarorpc"
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

	var familyKey *btcec.PublicKey
	if rpcAsset.AssetFamily != nil &&
		len(rpcAsset.AssetFamily.TweakedFamilyKey) > 0 {

		familyKey, err = btcec.ParsePubKey(
			rpcAsset.AssetFamily.TweakedFamilyKey,
		)
		require.NoError(t, err)
	}

	return asset.AssetCommitmentKey(assetID, scriptKey, familyKey == nil)
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

	f := &proof.File{}
	require.NoError(t, f.Decode(bytes.NewReader(exportResp.RawProof)))

	assetJSON, err := formatProtoJSON(a)
	require.NoError(t, err)
	t.Logf("Got proof file for asset %x that contains %d proof(s), full "+
		"asset: %s", a.AssetGenesis.AssetId, len(f.Proofs), assetJSON)

	snapshot, err := f.Verify(ctxt)
	require.NoError(t, err)
	require.Equal(
		t, commitmentKey(t, a), snapshot.Asset.AssetCommitmentKey(),
	)

	// Also make sure that the RPC can verify the proof as well.
	verifyResp, err := tarod.VerifyProof(ctxt, &tarorpc.ProofFile{
		RawProof: exportResp.RawProof,
	})
	require.NoError(t, err)
	require.True(t, verifyResp.Valid)

	return exportResp.RawProof
}
