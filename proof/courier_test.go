package proof_test

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	proofmock "github.com/lightninglabs/taproot-assets/internal/mock/proof"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

type mockProofArchive struct {
	proofs map[proof.Locator]proof.Blob
}

func newMockProofArchive() *mockProofArchive {
	return &mockProofArchive{
		proofs: make(map[proof.Locator]proof.Blob),
	}
}

func (m *mockProofArchive) FetchProof(ctx context.Context,
	id proof.Locator) (proof.Blob, error) {

	p, ok := m.proofs[id]
	if !ok {
		return nil, proof.ErrProofNotFound
	}

	return p, nil
}

func (m *mockProofArchive) HasProof(ctx context.Context,
	id proof.Locator) (bool, error) {

	_, ok := m.proofs[id]

	return ok, nil
}

func (m *mockProofArchive) FetchProofs(ctx context.Context,
	id asset.ID) ([]*proof.AnnotatedProof, error) {

	return nil, fmt.Errorf("not implemented")
}

func (m *mockProofArchive) ImportProofs(context.Context, proof.HeaderVerifier,
	proof.MerkleVerifier, proof.GroupVerifier, proof.ChainLookupGenerator,
	bool, ...*proof.AnnotatedProof) error {

	return fmt.Errorf("not implemented")
}

// TestUniverseRpcCourierLocalArchiveShortCut tests that the local archive is
// used as a shortcut to fetch a proof if it's available.
func TestUniverseRpcCourierLocalArchiveShortCut(t *testing.T) {
	localArchive := newMockProofArchive()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	genesis := assetmock.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	p := proofmock.RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)

	file, err := proof.NewFile(proof.V0, p, p)
	require.NoError(t, err)
	p.AdditionalInputs = []proof.File{*file, *file}

	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))
	proofBlob := proof.Blob(fileBuf.Bytes())

	locator := proof.Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *p.Asset.ScriptKey.PubKey,
		OutPoint:  fn.Ptr(p.OutPoint()),
	}
	localArchive.proofs[locator] = proofBlob

	cfg := &proof.CourierCfg{
		LocalArchive:   localArchive,
		UniverseRpcCfg: &proof.UniverseRpcCourierCfg{},
	}
	dispatch := proof.NewCourierDispatch(cfg)

	mockUrl, _ := url.Parse("universerpc://localhost")
	courier, err := dispatch.NewCourier(mockUrl, proof.Recipient{})
	require.NoError(t, err)

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	// If we attempt to receive a proof that the local archive has, we
	// expect to get it back.
	annotatedProof, err := courier.ReceiveProof(ctxt, locator)
	require.NoError(t, err)

	require.Equal(t, proofBlob, annotatedProof.Blob)

	// If we query for a proof that the local archive doesn't have, we
	// should end up in the code path that attempts to fetch the proof from
	// the universe. Since we don't want to set up a full universe server
	// in the test, we just make sure we get an error from that code path.
	_, err = courier.ReceiveProof(ctxt, proof.Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *p.Asset.ScriptKey.PubKey,
	})
	require.ErrorContains(t, err, "is missing outpoint")
}
