package proof

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
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

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	// If we attempt to receive a proof that the local archive has, we
	// expect to get it back.
	annotatedProof, err := courier.ReceiveProof(ctxt, recipient, locator)
	require.NoError(t, err)

	require.Equal(t, proofBlob, annotatedProof.Blob)

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
