package tapfreighter

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type mockAnchorLister struct {
	anchors []*ZeroValueAnchor
}

func (m *mockAnchorLister) ListZeroValueAnchors(context.Context) ([]*ZeroValueAnchor, error) {
	return m.anchors, nil
}

type mockCoinSelector struct {
	leased   []wire.OutPoint
	released []wire.OutPoint
}

func (m *mockCoinSelector) SelectCoins(context.Context, CommitmentConstraints,
	MultiCommitmentSelectStrategy, commitment.TapCommitmentVersion) (
	[]*AnchoredCommitment, error) {

	panic("not implemented")
}

func (m *mockCoinSelector) LeaseCoins(ctx context.Context, leaseOwner [32]byte,
	expiry time.Time, utxoOutpoints ...wire.OutPoint) error {

	m.leased = append(m.leased, utxoOutpoints...)
	return nil
}

func (m *mockCoinSelector) ReleaseCoins(ctx context.Context,
	utxoOutpoints ...wire.OutPoint) error {

	m.released = append(m.released, utxoOutpoints...)
	return nil
}

func TestZeroValueAnchorInputs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create a tombstone asset commitment for the zero-value anchor.
	tombstone := asset.RandAsset(t, asset.Normal)
	tombstone.Amount = 0
	tombstone.ScriptKey = asset.NUMSScriptKey

	commitmentTree, err := commitment.FromAssets(nil, tombstone)
	require.NoError(t, err)

	internalKey := keyDescriptorFromPubKey(test.RandPubKey(t))

	anchorOutpoint := wire.OutPoint{
		Hash:  test.RandHash(),
		Index: 1,
	}

	merkleRoot := commitmentTree.TapscriptRoot(nil)
	zeroAnchor := &ZeroValueAnchor{
		OutPoint:         anchorOutpoint,
		Value:            btcutil.Amount(1000),
		InternalKey:      internalKey,
		Commitment:       nil,
		TaprootAssetRoot: append([]byte(nil), merkleRoot[:]...),
		MerkleRoot:       append([]byte(nil), merkleRoot[:]...),
		TapscriptSibling: nil,
	}

	anchorLister := &mockAnchorLister{anchors: []*ZeroValueAnchor{zeroAnchor}}
	coinSelector := &mockCoinSelector{}

	wallet := NewAssetWallet(&WalletConfig{
		CoinSelector: coinSelector,
		AnchorLister: anchorLister,
		ChainParams:  &address.RegressionNetTap,
	})

	inputs, outpoints, err := wallet.zeroValueAnchorInputs(ctx, map[wire.OutPoint]struct{}{})
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Len(t, outpoints, 1)
	require.Equal(t, zeroAnchor.OutPoint, outpoints[0])
	require.Len(t, coinSelector.leased, 1)
	require.Equal(t, zeroAnchor.OutPoint, coinSelector.leased[0])

	psbtInput := inputs[0].input
	require.NotNil(t, psbtInput.WitnessUtxo)
	require.Equal(t, int64(zeroAnchor.Value), psbtInput.WitnessUtxo.Value)
	serializedInternal := schnorr.SerializePubKey(zeroAnchor.InternalKey.PubKey)
	require.Len(t, psbtInput.TaprootInternalKey, len(serializedInternal))
	require.Len(t, psbtInput.TaprootMerkleRoot, chainhash.HashSize)
	require.Equal(t, txscript.SigHashDefault, psbtInput.SighashType)

	var expectedMerkle chainhash.Hash
	copy(expectedMerkle[:], zeroAnchor.MerkleRoot)
	outputKey := txscript.ComputeTaprootOutputKey(
		zeroAnchor.InternalKey.PubKey, expectedMerkle[:],
	)
	expectedScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	require.Equal(t, expectedScript, psbtInput.WitnessUtxo.PkScript)

	// If the anchor is part of the skip set, no inputs should be returned
	// and no additional leases should be taken out.
	inputs, outpoints, err = wallet.zeroValueAnchorInputs(ctx, map[wire.OutPoint]struct{}{
		zeroAnchor.OutPoint: {},
	})
	require.NoError(t, err)
	require.Empty(t, inputs)
	require.Empty(t, outpoints)
	require.Len(t, coinSelector.leased, 1)
}

func keyDescriptorFromPubKey(pub *btcec.PublicKey) keychain.KeyDescriptor {
	return keychain.KeyDescriptor{
		PubKey: pub,
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(1),
			Index:  2,
		},
	}
}
