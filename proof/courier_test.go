package proof

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

type mockProofArchive struct {
	proofs map[Locator]Blob
}

func newMockProofArchive() *mockProofArchive {
	return &mockProofArchive{
		proofs: make(map[Locator]Blob),
	}
}

func (m *mockProofArchive) FetchProof(ctx context.Context,
	id Locator) (Blob, error) {

	proof, ok := m.proofs[id]
	if !ok {
		return nil, ErrProofNotFound
	}

	return proof, nil
}

func (m *mockProofArchive) HasProof(ctx context.Context,
	id Locator) (bool, error) {

	_, ok := m.proofs[id]

	return ok, nil
}

func (m *mockProofArchive) FetchProofs(ctx context.Context,
	id asset.ID) ([]*AnnotatedProof, error) {

	return nil, fmt.Errorf("not implemented")
}

func (m *mockProofArchive) ImportProofs(context.Context, HeaderVerifier,
	MerkleVerifier, GroupVerifier, bool, ...*AnnotatedProof) error {

	return fmt.Errorf("not implemented")
}

// TestUniverseRpcCourierLocalArchiveShortCut tests that the local archive is
// used as a shortcut to fetch a proof if it's available.
func TestUniverseRpcCourierLocalArchiveShortCut(t *testing.T) {
	localArchive := newMockProofArchive()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	proof := RandProof(t, genesis, scriptKey, oddTxBlock, 0, 1)

	file, err := NewFile(V0, proof, proof)
	require.NoError(t, err)
	proof.AdditionalInputs = []File{*file, *file}

	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))
	proofBlob := Blob(fileBuf.Bytes())

	locator := Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *proof.Asset.ScriptKey.PubKey,
		OutPoint:  fn.Ptr(proof.OutPoint()),
	}
	localArchive.proofs[locator] = proofBlob

	courier := &UniverseRpcCourier{
		recipient: Recipient{},
		client:    nil,
		cfg: &CourierCfg{
			LocalArchive: localArchive,
		},
		rawConn:       nil,
		backoffHandle: nil,
		subscribers:   nil,
	}

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
	_, err = courier.ReceiveProof(ctxt, Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *proof.Asset.ScriptKey.PubKey,
	})
	require.ErrorContains(t, err, "is missing outpoint")
}
