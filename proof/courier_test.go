package proof

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
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
	"google.golang.org/grpc/credentials/insecure"
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
			// Allow a real connection time to complete under the
			// race detector. Only the unreachable-server case
			// needs a short deadline to keep the test fast.
			connectTimeout := testTimeout
			if tt.expectErr != "" {
				connectTimeout = test.StartupWaitTime
			}
			ctxt, cancel := context.WithTimeout(
				context.Background(), connectTimeout*2,
			)
			defer cancel()

			err := CheckUniverseRpcCourierConnection(
				ctxt, connectTimeout, tt.courierAddr,
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

	mu    sync.Mutex
	calls []string
}

// InsertProof records a proof insert.
func (s *recordingCourierServer) InsertProof(context.Context,
	*universerpc.AssetProof) (*universerpc.AssetProofResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "insert")

	return &universerpc.AssetProofResponse{}, nil
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

	// A proof file with three proofs, the last of which is the one being
	// delivered.
	testBlocks := readTestData(t)
	genesis := asset.RandGenesis(t, asset.Normal)
	scriptKey := test.RandPubKey(t)
	randProof := func() Proof {
		return RandProof(t, genesis, scriptKey, testBlocks[0], 0, 1)
	}
	file, err := NewFile(V0, randProof(), randProof(), randProof())
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

	server.mu.Lock()
	defer server.mu.Unlock()
	require.Equal(
		t, []string{"insert", "insert", "insert", "send"},
		server.calls,
	)
}
