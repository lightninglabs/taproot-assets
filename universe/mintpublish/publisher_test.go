package mintpublish

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

// recordingRegistrar records every UpsertProofLeafBatch call and can
// return a scripted error per call.
type recordingRegistrar struct {
	universe.Registrar

	batches [][]*universe.Item

	// errs holds the error to return for the n-th batch call; calls
	// beyond the slice succeed.
	errs []error
}

func (r *recordingRegistrar) UpsertProofLeafBatch(_ context.Context,
	items []*universe.Item) error {

	callIdx := len(r.batches)
	r.batches = append(r.batches, items)

	if callIdx < len(r.errs) {
		return r.errs[callIdx]
	}

	return nil
}

// newPublishParams builds publish parameters for numAssets random
// assets, each with a valid minting proof.
func newPublishParams(t *testing.T,
	numAssets int) tapgarden.MintBatchPublishParams {

	t.Helper()

	dummyTx := wire.NewMsgTx(2)
	dummyTx.AddTxIn(&wire.TxIn{})
	dummyTx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte("dummy")})
	block := wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			Timestamp: time.Now(),
		},
		Transactions: []*wire.MsgTx{dummyTx},
	}

	assets := make([]*asset.Asset, numAssets)
	proofs := make(proof.AssetProofs, numAssets)
	for i := range assets {
		a := asset.RandAsset(t, asset.Normal)
		p := proof.RandProof(
			t, a.Genesis, a.ScriptKey.PubKey, block, 0, 0,
		)

		assets[i] = a
		proofs[asset.ToSerialized(a.ScriptKey.PubKey)] = &p
	}

	return tapgarden.MintBatchPublishParams{
		Assets:     assets,
		Proofs:     proofs,
		MintTxHash: dummyTx.TxHash(),
	}
}

// TestPublishMintBatchChunking asserts that the publisher splits a
// batch into batchSize-sized chunks and ships every asset exactly
// once, in order.
func TestPublishMintBatchChunking(t *testing.T) {
	t.Parallel()

	reg := &recordingRegistrar{}
	pub := NewPublisher(reg, 2)

	params := newPublishParams(t, 5)
	err := pub.PublishMintBatch(context.Background(), params)
	require.NoError(t, err)

	require.Len(t, reg.batches, 3)
	require.Len(t, reg.batches[0], 2)
	require.Len(t, reg.batches[1], 2)
	require.Len(t, reg.batches[2], 1)

	var got []*universe.Item
	for _, batch := range reg.batches {
		got = append(got, batch...)
	}
	for i, item := range got {
		require.Equal(t, params.Assets[i].ID(), item.ID.AssetID)
	}
}

// TestPublishMintBatchMissingProof asserts that an asset without a
// matching minting proof fails the publish before anything is sent.
func TestPublishMintBatchMissingProof(t *testing.T) {
	t.Parallel()

	reg := &recordingRegistrar{}
	pub := NewPublisher(reg, 10)

	params := newPublishParams(t, 2)
	delete(
		params.Proofs,
		asset.ToSerialized(params.Assets[1].ScriptKey.PubKey),
	)

	err := pub.PublishMintBatch(context.Background(), params)
	require.ErrorContains(t, err, "no minting proof")
	require.Empty(t, reg.batches)
}

// TestPublishMintBatchRegistrarError asserts that a hard registrar
// failure aborts the publish and surfaces the cause.
func TestPublishMintBatchRegistrarError(t *testing.T) {
	t.Parallel()

	reg := &recordingRegistrar{
		errs: []error{fmt.Errorf("registrar down")},
	}
	pub := NewPublisher(reg, 1)

	params := newPublishParams(t, 3)
	err := pub.PublishMintBatch(context.Background(), params)
	require.ErrorContains(t, err, "registrar down")

	// The failing chunk must have ended the run.
	require.Len(t, reg.batches, 1)
}

// TestPublishMintBatchMultiversePending asserts that a pending
// multiverse update is tolerated: the leaves are durably stored, so
// the publish continues and succeeds.
func TestPublishMintBatchMultiversePending(t *testing.T) {
	t.Parallel()

	reg := &recordingRegistrar{
		errs: []error{fmt.Errorf(
			"delayed: %w", universe.ErrMultiversePending,
		)},
	}
	pub := NewPublisher(reg, 2)

	params := newPublishParams(t, 4)
	err := pub.PublishMintBatch(context.Background(), params)
	require.NoError(t, err)
	require.Len(t, reg.batches, 2)
}

// TestNewPublisherZeroBatchSize asserts that a zero batch size is
// rejected at construction time.
func TestNewPublisherZeroBatchSize(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() {
		NewPublisher(&recordingRegistrar{}, 0)
	})
}
