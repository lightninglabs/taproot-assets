package proof

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// TestUniverseRpcCourierLocalArchiveShortCut tests that the local archive is
// used as a shortcut to fetch a proof if it's available.
func TestUniverseRpcCourierLocalArchiveShortCut(t *testing.T) {
	localArchive := NewMockProofArchive()

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
	locHash, err := locator.Hash()
	require.NoError(t, err)

	localArchive.proofs.Store(locHash, proofBlob)

	recipient := Recipient{}
	courier := &UniverseRpcCourier{
		client:        nil,
		cfg:           &UniverseRpcCourierCfg{},
		localArchive:  localArchive,
		rawConn:       nil,
		backoffHandle: nil,
		subscribers:   nil,
	}

	var progressCount atomic.Uint32
	ctx := WithProgressCallback(context.Background(), func() {
		progressCount.Add(1)
	})
	ctxt, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	// If we attempt to receive a proof that the local archive has, we
	// expect to get it back.
	annotatedProof, err := courier.ReceiveProof(ctxt, recipient, locator)
	require.NoError(t, err)

	require.Equal(t, proofBlob, annotatedProof.Blob)
	require.Equal(t, uint32(1), progressCount.Load())

	// If we query for a proof that the local archive doesn't have, we
	// should end up in the code path that attempts to fetch the proof from
	// the universe. Since we don't want to set up a full universe server
	// in the test, we just make sure we get an error from that code path.
	_, err = courier.ReceiveProof(ctxt, recipient, Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *proof.Asset.ScriptKey.PubKey,
	})
	require.ErrorContains(t, err, "is missing outpoint")
}

// TestCheckUniverseRpcCourierConnection tests that we can connect to the
// universe rpc courier. We also test that we fail to connect to a
// universe rpc courier that is not listening on the given address.
func TestCheckUniverseRpcCourierConnection(t *testing.T) {
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	grpcServer := grpc.NewServer(serverOpts...)

	server := MockUniverseServer{}
	universerpc.RegisterUniverseServer(grpcServer, &server)

	// We also grab a port that is free to listen on for our negative test.
	// Since we know the port is free, and we don't listen on it, we expect
	// the connection to fail.
	noConnectPort := port.NextAvailablePort()
	noConnectAddr := fmt.Sprintf(test.ListenAddrTemplate, noConnectPort)

	mockServerAddr, cleanup, err := test.StartMockGRPCServer(
		t, grpcServer, true,
	)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	tests := []struct {
		name        string
		courierAddr *url.URL
		expectErr   string
	}{
		{
			name: "valid universe rpc courier",
			courierAddr: MockCourierURL(
				t, UniverseRpcCourierType, mockServerAddr,
			),
		},
		{
			name: "valid universe rpc courier, but can't connect",
			courierAddr: MockCourierURL(
				t, UniverseRpcCourierType, noConnectAddr,
			),
			expectErr: "unable to connect to courier service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We use a short timeout here, since we don't want to
			// wait for the full default timeout of the funding
			// controller
			ctxt, cancel := context.WithTimeout(
				context.Background(), test.StartupWaitTime*2,
			)
			defer cancel()

			err := CheckUniverseRpcCourierConnection(
				ctxt, test.StartupWaitTime, tt.courierAddr,
			)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// recordingCourierServer is a mock universe and auth mailbox server that
// records the order of the proof inserts and messages it receives.
type recordingCourierServer struct {
	MockUniverseServer

	mu               sync.Mutex
	calls            []string
	proofs           [][]byte
	leaves           map[string][]byte
	queries          []string
	missingProofCode codes.Code
}

// rpcUniverseKey returns the mock storage key for a Universe leaf.
func rpcUniverseKey(key *universerpc.UniverseKey) string {
	var namespace string
	switch {
	case key.GetId().GetAssetId() != nil:
		namespace = fmt.Sprintf(
			"asset:%x", key.GetId().GetAssetId(),
		)

	case key.GetId().GetGroupKey() != nil:
		namespace = fmt.Sprintf(
			"group:%x", key.GetId().GetGroupKey(),
		)
	}

	op := key.GetLeafKey().GetOp()
	return fmt.Sprintf(
		"%s:%s:%d:%x", namespace, op.GetHashStr(), op.GetIndex(),
		key.GetLeafKey().GetScriptKeyBytes(),
	)
}

// InsertProof records a proof insert.
func (s *recordingCourierServer) InsertProof(_ context.Context,
	assetProof *universerpc.AssetProof) (*universerpc.AssetProofResponse,
	error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "insert")
	s.proofs = append(s.proofs, bytes.Clone(assetProof.AssetLeaf.Proof))
	if s.leaves == nil {
		s.leaves = make(map[string][]byte)
	}

	key := rpcUniverseKey(assetProof.Key)
	storedProof, ok := s.leaves[key]
	if !ok {
		storedProof = bytes.Clone(assetProof.AssetLeaf.Proof)
		s.leaves[key] = storedProof
	}

	return &universerpc.AssetProofResponse{
		AssetLeaf: &universerpc.AssetLeaf{
			Proof: bytes.Clone(storedProof),
		},
	}, nil
}

// QueryProof returns the first proof stored for a Universe leaf.
func (s *recordingCourierServer) QueryProof(_ context.Context,
	key *universerpc.UniverseKey) (*universerpc.AssetProofResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	storageKey := rpcUniverseKey(key)
	s.queries = append(s.queries, storageKey)
	storedProof, ok := s.leaves[storageKey]
	if !ok {
		missingCode := s.missingProofCode
		if missingCode == codes.OK {
			missingCode = codes.NotFound
		}

		return nil, status.Error(missingCode, "proof not found")
	}

	return &universerpc.AssetProofResponse{
		AssetLeaf: &universerpc.AssetLeaf{
			Proof: bytes.Clone(storedProof),
		},
	}, nil
}

// SendMessage records a message.
func (s *recordingCourierServer) SendMessage(context.Context,
	*mboxrpc.SendMessageRequest) (*mboxrpc.SendMessageResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "send")

	return &mboxrpc.SendMessageResponse{MessageId: 1}, nil
}

// noopTransferLog is a TransferLog that records nothing.
type noopTransferLog struct{}

// LogProofTransferAttempt does nothing.
func (noopTransferLog) LogProofTransferAttempt(context.Context, Locator,
	TransferType) error {

	return nil
}

// QueryProofTransferLog returns no attempts.
func (noopTransferLog) QueryProofTransferLog(context.Context, Locator,
	TransferType) ([]time.Time, error) {

	return nil, nil
}

// TestUniverseRpcCourierDeliverFragmentOnce tests that delivering a proof
// file along with a send fragment inserts every proof of the file before
// sending the fragment, and sends it only once.
func TestUniverseRpcCourierDeliverFragmentOnce(t *testing.T) {
	grpcServer := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
	)
	server := &recordingCourierServer{}
	universerpc.RegisterUniverseServer(grpcServer, server)
	mboxrpc.RegisterMailboxServer(grpcServer, server)

	serverAddr, cleanup, err := test.StartMockGRPCServer(
		t, grpcServer, true,
	)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	courierAddr := MockCourierURL(
		t, AuthMailboxUniRpcCourierType, serverAddr,
	)
	courier, err := NewUniverseRpcCourier(
		ctx, &UniverseRpcCourierCfg{
			BackoffCfg: &BackoffCfg{
				SkipInitDelay: true,
				NumTries:      1,
			},
			ServiceRequestTimeout: testTimeout,
		}, noopTransferLog{}, nil, courierAddr, false,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, courier.Close())
	})

	// Build a proof DAG with three outer proofs. The middle outer proof
	// spends an additional input whose final proof references the same
	// deepest proof twice. The shared proof should only be inserted once.
	testBlocks := readTestData(t)
	genesis := asset.RandGenesis(t, asset.Normal)
	scriptKey := test.RandPubKey(t)
	randProof := func() Proof {
		return RandProof(t, genesis, scriptKey, testBlocks[0], 0, 1)
	}
	deepestProof := randProof()
	deepestFile, err := NewFile(V0, deepestProof)
	require.NoError(t, err)

	additionalProofs := []Proof{randProof(), randProof()}
	additionalProofs[1].AdditionalInputs = []File{
		*deepestFile, *deepestFile,
	}
	additionalFile, err := NewFile(V0, additionalProofs...)
	require.NoError(t, err)

	outerProofs := []Proof{randProof(), randProof(), randProof()}
	outerProofs[1].AdditionalInputs = []File{*additionalFile}
	file, err := NewFile(V0, outerProofs...)
	require.NoError(t, err)

	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))

	txProof := MockTxProof(t)
	txProof.BlockHeight = 100
	manifest := &SendManifest{
		TxProof:    *txProof,
		Receiver:   *test.RandPubKey(t),
		CourierURL: *courierAddr,
		Fragment: SendFragment{
			Version:     SendFragmentV1,
			BlockHeight: 100,
		},
	}

	err = courier.DeliverProof(
		ctx, Recipient{AssetID: genesis.ID()}, &AnnotatedProof{
			Blob: fileBuf.Bytes(),
		}, manifest,
	)
	require.NoError(t, err)

	// A locator uniquely identifies one Universe leaf, so reject a proof
	// DAG that assigns different proof bytes to the same locator.
	deepestVariant := deepestProof
	deepestVariant.BlockHeight++
	deepestVariantFile, err := NewFile(V0, deepestVariant)
	require.NoError(t, err)

	conflictingProof := randProof()
	conflictingProof.AdditionalInputs = []File{
		*deepestFile, *deepestVariantFile,
	}
	conflictingFile, err := NewFile(V0, conflictingProof)
	require.NoError(t, err)

	var conflictingFileBuf bytes.Buffer
	require.NoError(t, conflictingFile.Encode(&conflictingFileBuf))
	err = courier.DeliverProof(
		ctx, Recipient{AssetID: genesis.ID()}, &AnnotatedProof{
			Blob: conflictingFileBuf.Bytes(),
		}, nil,
	)
	require.ErrorContains(
		t, err, "conflicting proofs for Universe locator",
	)

	server.mu.Lock()
	defer server.mu.Unlock()
	require.Equal(
		t, []string{
			"insert", "insert", "insert", "insert", "insert",
			"insert", "insert", "insert", "insert", "insert",
			"insert", "insert", "send",
		},
		server.calls,
	)

	expectedOrder := []*Proof{
		&outerProofs[0], &additionalProofs[0], &deepestProof,
		&additionalProofs[1], &outerProofs[1], &outerProofs[2],
	}
	expectedProofs := make([][]byte, 0, len(expectedOrder)*2)
	for idx := range expectedOrder {
		proofBytes, err := expectedOrder[idx].Bytes()
		require.NoError(t, err)
		expectedProofs = append(expectedProofs, proofBytes, proofBytes)
	}
	require.Equal(t, expectedProofs, server.proofs)
}

// TestUniverseRpcCourierGroupedAssetFallback verifies that grouped assets with
// colliding or missing group leaves remain available through their asset-ID
// Universes.
func TestUniverseRpcCourierGroupedAssetFallback(t *testing.T) {
	grpcServer := grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
	)
	server := &recordingCourierServer{}
	universerpc.RegisterUniverseServer(grpcServer, server)

	serverAddr, cleanup, err := test.StartMockGRPCServer(
		t, grpcServer, true,
	)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	testCtx, cancel := context.WithTimeout(
		context.Background(), testTimeout,
	)
	defer cancel()

	courierAddr := MockCourierURL(
		t, UniverseRpcCourierType, serverAddr,
	)
	courier, err := NewUniverseRpcCourier(
		testCtx, &UniverseRpcCourierCfg{
			BackoffCfg: &BackoffCfg{
				SkipInitDelay: true,
				NumTries:      1,
			},
			ServiceRequestTimeout: testTimeout,
		}, noopTransferLog{}, NewMockProofArchive(), courierAddr, false,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, courier.Close())
	})

	testBlocks := readTestData(t)
	genesisA := asset.RandGenesis(t, asset.Normal)
	genesisB := asset.RandGenesis(t, asset.Normal)
	scriptKey := test.RandPubKey(t)
	proofA := RandProof(
		t, genesisA, scriptKey, testBlocks[0], 0, 1,
	)
	proofB := RandProof(
		t, genesisB, scriptKey, testBlocks[0], 0, 1,
	)

	// Use a common group, outpoint, and script key. The group Universe
	// therefore maps both assets to the same BaseLeafKey.
	groupKey := test.RandPubKey(t)
	proofA.Asset.GroupKey = &asset.GroupKey{
		GroupPubKey: *groupKey,
	}
	proofB.Asset.GroupKey = &asset.GroupKey{
		GroupPubKey: *groupKey,
	}
	proofB.AnchorTx = proofA.AnchorTx
	proofB.InclusionProof.OutputIndex = proofA.InclusionProof.OutputIndex
	proofB.Asset.ScriptKey = proofA.Asset.ScriptKey

	encodeFile := func(transitionProof Proof) []byte {
		proofFile, err := NewFile(V0, transitionProof)
		require.NoError(t, err)

		var fileBuf bytes.Buffer
		require.NoError(t, proofFile.Encode(&fileBuf))
		return fileBuf.Bytes()
	}

	deliver := func(transitionProof Proof) {
		err := courier.DeliverProof(
			testCtx, Recipient{AssetID: transitionProof.Asset.ID()},
			&AnnotatedProof{Blob: encodeFile(transitionProof)}, nil,
		)
		require.NoError(t, err)
	}
	deliver(proofA)
	deliver(proofB)

	assetIDB := proofB.Asset.ID()
	outPoint := proofB.OutPoint()
	locator := Locator{
		AssetID:   &assetIDB,
		GroupKey:  groupKey,
		ScriptKey: *proofB.Asset.ScriptKey.PubKey,
		OutPoint:  &outPoint,
	}
	receive := func() {
		received, err := courier.ReceiveProof(
			testCtx, Recipient{}, locator,
		)
		require.NoError(t, err)

		receivedFile := &File{}
		err = receivedFile.Decode(bytes.NewReader(received.Blob))
		require.NoError(t, err)
		receivedProof, err := receivedFile.LastProof()
		require.NoError(t, err)
		require.Equal(t, assetIDB, receivedProof.Asset.ID())
	}

	// The colliding group leaf holds asset A, so fetching asset B must fall
	// back to its asset-ID Universe.
	receive()

	server.mu.Lock()
	initialLeafCount := len(server.leaves)
	initialQueries := append([]string(nil), server.queries...)

	// Older servers report a missing proof as Unknown instead of NotFound.
	// Remove the group leaf to exercise that compatibility path.
	deletedGroupLeaf := false
	for key := range server.leaves {
		if strings.HasPrefix(key, "group:") {
			delete(server.leaves, key)
			deletedGroupLeaf = true
		}
	}
	server.missingProofCode = codes.Unknown
	server.mu.Unlock()

	require.Equal(t, 3, initialLeafCount)
	require.Len(t, initialQueries, 2)
	require.Contains(t, initialQueries[0], "group:")
	require.Contains(t, initialQueries[1], "asset:")
	require.True(t, deletedGroupLeaf)

	receive()

	server.mu.Lock()
	finalLeafCount := len(server.leaves)
	finalQueries := append([]string(nil), server.queries...)
	server.mu.Unlock()

	require.Equal(t, 2, finalLeafCount)
	require.Len(t, finalQueries, 4)
	require.Contains(t, finalQueries[2], "group:")
	require.Contains(t, finalQueries[3], "asset:")
}

// TestFetchProofProvenanceStopsOnContext tests that a provenance walk that
// never reaches a genesis proof ends once its context does.
func TestFetchProofProvenanceStopsOnContext(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	transfer := RandProof(t, genesis, scriptKey, testBlocks[0], 0, 1)

	// A transfer that names its own output as its input: following its
	// inputs back never arrives at a genesis proof.
	outPoint := transfer.OutPoint()
	transfer.Asset.PrevWitnesses = []asset.Witness{{
		PrevID: &asset.PrevID{
			OutPoint:  outPoint,
			ID:        genesis.ID(),
			ScriptKey: asset.ToSerialized(scriptKey),
		},
	}}
	transferBlob, err := transfer.Bytes()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const cancelAfter = 3
	var fetches int
	fetchSingleProof := func(context.Context, Locator) (Blob, error) {
		fetches++
		if fetches == cancelAfter {
			cancel()
		}

		return transferBlob, nil
	}

	_, err = FetchProofProvenance(ctx, nil, Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *scriptKey,
		OutPoint:  &outPoint,
	}, fetchSingleProof)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, cancelAfter, fetches)
}

// TestFetchProofProvenanceNoPrimaryInput tests that a provenance walk
// rejects a transfer proof whose primary witness names no input.
func TestFetchProofProvenanceNoPrimaryInput(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	genesis := asset.RandGenesis(t, asset.Collectible)
	scriptKey := test.RandPubKey(t)
	transfer := RandProof(t, genesis, scriptKey, testBlocks[0], 0, 1)
	transfer.Asset.PrevWitnesses = []asset.Witness{{
		TxWitness: [][]byte{{1}},
	}}
	transferBlob, err := transfer.Bytes()
	require.NoError(t, err)

	fetchSingleProof := func(context.Context, Locator) (Blob, error) {
		return transferBlob, nil
	}

	outPoint := transfer.OutPoint()
	_, err = FetchProofProvenance(t.Context(), nil, Locator{
		AssetID:   fn.Ptr(genesis.ID()),
		ScriptKey: *scriptKey,
		OutPoint:  &outPoint,
	}, fetchSingleProof)
	require.ErrorIs(t, err, ErrProofFileInvalid)
}
