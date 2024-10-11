package rfq

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// testServiceAddress is the address of the mock RPC price oracle
	// service.
	testServiceAddress = "localhost:8095"

	// testRateTick is the rate tick used in the test cases.
	testRateTick uint64 = 42_000
)

// mockRpcPriceOracleServer is a mock implementation of the price oracle server.
type mockRpcPriceOracleServer struct {
	priceoraclerpc.UnimplementedPriceOracleServer
}

// QueryRateTick is a mock implementation of the QueryRateTick RPC endpoint.
func (p *mockRpcPriceOracleServer) QueryRateTick(_ context.Context,
	req *priceoraclerpc.QueryRateTickRequest) (
	*priceoraclerpc.QueryRateTickResponse, error) {

	// Specify a default rate tick in case a rate tick hint is not provided.
	expiry := time.Now().Add(5 * time.Minute).Unix()
	subjectAssetRate := rfqmsg.NewBigIntFixedPoint(testRateTick, 3)

	// Marshal the subject asset rate to a fixed point.
	subjectAssetFp, err := priceoraclerpc.MarshalBigIntFixedPoint(
		subjectAssetRate,
	)
	if err != nil {
		return nil, err
	}

	rateTick := priceoraclerpc.RateTick{
		SubjectAssetRate: subjectAssetFp,
		ExpiryTimestamp:  uint64(expiry),
	}

	err = validateRateTickRequest(req)
	if err != nil {
		return nil, err
	}

	// If a rate tick hint is provided, return it as the rate tick.
	if req.RateTickHint != nil {
		rateTick.SubjectAssetRate = req.RateTickHint.SubjectAssetRate
		rateTick.ExpiryTimestamp = req.RateTickHint.ExpiryTimestamp
	}

	return &priceoraclerpc.QueryRateTickResponse{
		Result: &priceoraclerpc.QueryRateTickResponse_Success{
			Success: &priceoraclerpc.QueryRateTickSuccessResponse{
				RateTick: &rateTick,
			},
		},
	}, nil
}

// validateRateTickRequest validates the given rate tick request.
func validateRateTickRequest(req *priceoraclerpc.QueryRateTickRequest) error {
	var zeroAssetID [32]byte
	if req.SubjectAsset == nil {
		return fmt.Errorf("subject asset must be specified")
	}
	if len(req.SubjectAsset.GetAssetId()) != 32 {
		return fmt.Errorf("invalid subject asset ID length")
	}
	if bytes.Equal(req.SubjectAsset.GetAssetId(), zeroAssetID[:]) {
		return fmt.Errorf("subject asset ID must NOT be all zero")
	}

	if req.PaymentAsset == nil {
		return fmt.Errorf("payment asset must be specified")
	}
	if len(req.PaymentAsset.GetAssetId()) != 32 {
		return fmt.Errorf("invalid payment asset ID length")
	}
	if !bytes.Equal(req.PaymentAsset.GetAssetId(), zeroAssetID[:]) {
		return fmt.Errorf("payment asset ID must be all zero")
	}

	return nil
}

// startBackendRPC starts the given RPC server and blocks until the server is
// shut down.
func startBackendRPC(grpcServer *grpc.Server) error {
	server := mockRpcPriceOracleServer{}
	priceoraclerpc.RegisterPriceOracleServer(grpcServer, &server)
	grpcListener, err := net.Listen("tcp", testServiceAddress)
	if err != nil {
		return fmt.Errorf("RPC server unable to listen on %s",
			testServiceAddress)
	}
	return grpcServer.Serve(grpcListener)
}

// testCaseQueryAskPrice is a test case for the RPC price oracle client
// QueryAskPrice function.
type testCaseQueryAskPrice struct {
	name string

	expectError bool

	assetId       *asset.ID
	assetGroupKey *btcec.PublicKey

	suggestedRateTick uint64
}

// runQueryAskPriceTest runs the RPC price oracle client QueryAskPrice test.
func runQueryAskPriceTest(t *testing.T, tc *testCaseQueryAskPrice) {
	// Start the mock RPC price oracle service.
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	backendService := grpc.NewServer(serverOpts...)
	go func() { _ = startBackendRPC(backendService) }()
	defer backendService.Stop()

	// Wait for the server to start.
	time.Sleep(200 * time.Millisecond)

	// Create a new RPC price oracle client and connect to the mock service.
	serviceAddr := fmt.Sprintf("rfqrpc://%s", testServiceAddress)
	client, err := NewRpcPriceOracle(serviceAddr, true)
	require.NoError(t, err)

	// Query for an ask price.
	ctx := context.Background()
	assetAmount := uint64(42)
	bidPrice := lnwire.MilliSatoshi(tc.suggestedRateTick)

	inAssetRate := rfqmsg.NewBigIntFixedPoint(
		tc.suggestedRateTick, 3,
	)

	resp, err := client.QueryAskPrice(
		ctx, tc.assetId, tc.assetGroupKey, assetAmount,
		fn.Some(inAssetRate),
	)

	// If we expect an error, ensure that it is returned.
	if tc.expectError {
		require.Error(t, err)
		return
	}

	// Otherwise, ensure that the response is valid.
	require.NoError(t, err)

	// The mock server should return the rate tick hint/bid.
	require.NotNil(t, resp.AssetRate)
	require.Equal(
		t, uint64(bidPrice), resp.AssetRate.Coefficient.ToUint64(),
	)

	// Ensure that the expiry timestamp is in the future.
	responseExpiry := time.Unix(int64(resp.Expiry), 0)
	require.True(t, responseExpiry.After(time.Now()))
}

// TestRpcPriceOracle tests the RPC price oracle client QueryAskPrice function.
func TestRpcPriceOracleQueryAskPrice(t *testing.T) {
	// Create a random asset ID and asset group key.
	var assetId asset.ID
	copy(assetId[:], test.RandBytes(32))

	assetGroupKey := test.RandPubKey(t)

	testCases := []*testCaseQueryAskPrice{
		{
			name:              "asset ID only",
			assetId:           &assetId,
			suggestedRateTick: 42_000,
		},
		{
			name: "asset group key only, expect " +
				"error: asset ID must be specified",
			expectError:       true,
			assetGroupKey:     assetGroupKey,
			suggestedRateTick: 42_000,
		},
		{
			name: "asset ID and asset group key " +
				"missing",
			expectError:       true,
			suggestedRateTick: 42_000,
		},
		{
			name: "asset ID only; suggested rate " +
				"tick 0",
			assetId:           &assetId,
			suggestedRateTick: 0,
		},
	}

	for _, tc := range testCases {
		runQueryAskPriceTest(t, tc)
	}
}

// testCaseQueryBidPrice is a test case for the RPC price oracle client
// QueryBidPrice function.
type testCaseQueryBidPrice struct {
	name string

	expectError bool

	assetId       *asset.ID
	assetGroupKey *btcec.PublicKey
}

// runQueryBidPriceTest runs the RPC price oracle client QueryBidPrice test.
func runQueryBidPriceTest(t *testing.T, tc *testCaseQueryBidPrice) {
	// Start the mock RPC price oracle service.
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	backendService := grpc.NewServer(serverOpts...)
	go func() { _ = startBackendRPC(backendService) }()
	defer backendService.Stop()

	// Wait for the server to start.
	time.Sleep(2 * time.Second)

	// Create a new RPC price oracle client and connect to the mock service.
	serviceAddr := fmt.Sprintf("rfqrpc://%s", testServiceAddress)
	client, err := NewRpcPriceOracle(serviceAddr, true)
	require.NoError(t, err)

	// Query for an ask price.
	ctx := context.Background()
	assetAmount := uint64(42)

	resp, err := client.QueryBidPrice(
		ctx, tc.assetId, tc.assetGroupKey, assetAmount,
	)

	// If we expect an error, ensure that it is returned.
	if tc.expectError {
		require.Error(t, err)
		return
	}

	// Otherwise, ensure that the response is valid.
	require.NoError(t, err)

	// The mock server should return the rate tick hint/ask.
	require.NotNil(t, resp.AssetRate)
	require.Equal(t, testRateTick, resp.AssetRate.Coefficient.ToUint64())

	// Ensure that the expiry timestamp is in the future.
	responseExpiry := time.Unix(int64(resp.Expiry), 0)
	require.True(t, responseExpiry.After(time.Now()))
}

// TestRpcPriceOracle tests the RPC price oracle client QueryBidPrice function.
func TestRpcPriceOracleQueryBidPrice(t *testing.T) {
	// Create a random asset ID and asset group key.
	var assetId asset.ID
	copy(assetId[:], test.RandBytes(32))

	assetGroupKey := test.RandPubKey(t)

	testCases := []*testCaseQueryBidPrice{
		{
			name:    "asset ID only",
			assetId: &assetId,
		},
		{
			name: "asset group key only, expect " +
				"error: asset ID must be specified",
			expectError:   true,
			assetGroupKey: assetGroupKey,
		},
		{
			name: "asset ID and asset group key " +
				"missing",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		runQueryBidPriceTest(t, tc)
	}
}
