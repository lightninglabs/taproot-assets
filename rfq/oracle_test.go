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
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
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

var (
	// priceMilliSatPerBtc is the static price of 1 BTC expressed in
	// milli-satoshi (10^11) and represented as a fixed point number.
	priceMilliSatPerBtc = &rfqrpc.FixedPoint{
		Value: 1,
		Scale: 11,
	}

	// testPrice is a static price quote used in the test cases.
	testPrice = &rfqrpc.FixedPoint{
		Value: 5_578_020,
		Scale: 2,
	}
)

// mockRpcPriceOracleServer is a mock implementation of the price oracle server.
type mockRpcPriceOracleServer struct {
	priceoraclerpc.UnimplementedPriceOracleServer
}

// QueryRateTick is a mock implementation of the QueryPrice RPC endpoint.
func (p *mockRpcPriceOracleServer) QueryPrice(_ context.Context,
	req *priceoraclerpc.QueryPriceRequest) (
	*priceoraclerpc.QueryPriceResponse, error) {

	expiry := uint64(time.Now().Add(5 * time.Minute).Unix())
	priceQuote := &priceoraclerpc.PriceQuote{
		ExpiryTimestamp: expiry,
	}
	if req.TransactionType == priceoraclerpc.TransactionType_PURCHASE {
		priceQuote.InAssetPrice = testPrice
		priceQuote.OutAssetPrice = priceMilliSatPerBtc
	} else {
		priceQuote.InAssetPrice = priceMilliSatPerBtc
		priceQuote.OutAssetPrice = testPrice
	}

	err := validateRateTickRequest(req)
	if err != nil {
		return nil, err
	}

	// If a rate tick hint is provided, return it as the rate tick.
	if req.PriceHint != nil {
		priceQuote.InAssetPrice = req.PriceHint.InAssetPrice
		priceQuote.OutAssetPrice = req.PriceHint.OutAssetPrice
		priceQuote.ExpiryTimestamp = req.PriceHint.ExpiryTimestamp
	}

	return &priceoraclerpc.QueryPriceResponse{
		Result: &priceoraclerpc.QueryPriceResponse_Success{
			Success: priceQuote,
		},
	}, nil
}

// validateRateTickRequest validates the given price query request.
func validateRateTickRequest(req *priceoraclerpc.QueryPriceRequest) error {
	var zeroAssetID [32]byte
	if req.InAsset == nil {
		return fmt.Errorf("in asset must be specified")
	}
	if len(req.InAsset.GetAssetId()) != 32 {
		return fmt.Errorf("invalid in asset ID length")
	}

	if req.OutAsset == nil {
		return fmt.Errorf("out asset must be specified")
	}
	if len(req.OutAsset.GetAssetId()) != 32 {
		return fmt.Errorf("out payment asset ID length")
	}

	// Depending on the transaction type, one of the assets must be the zero
	// asset and the other one must not.
	switch req.TransactionType {
	case priceoraclerpc.TransactionType_SALE:
		if !bytes.Equal(req.InAsset.GetAssetId(), zeroAssetID[:]) {
			return fmt.Errorf("in asset ID must be all zero")
		}
		if bytes.Equal(req.OutAsset.GetAssetId(), zeroAssetID[:]) {
			return fmt.Errorf("out asset ID must NOT be all zero")
		}
	case priceoraclerpc.TransactionType_PURCHASE:
		if bytes.Equal(req.InAsset.GetAssetId(), zeroAssetID[:]) {
			return fmt.Errorf("in asset ID must NOT be all zero")
		}
		if !bytes.Equal(req.OutAsset.GetAssetId(), zeroAssetID[:]) {
			return fmt.Errorf("out asset ID must be all zero")
		}

	default:
		return fmt.Errorf("unsupported transaction type: %d",
			req.TransactionType)
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
// QuerySellPrice function.
type testCaseQueryAskPrice struct {
	name string

	expectError bool

	assetId       *asset.ID
	assetGroupKey *btcec.PublicKey

	suggestedRateTick uint64
}

// runQueryAskPriceTest runs the RPC price oracle client QuerySellPrice test.
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

	resp, err := client.QuerySellPrice(
		ctx, tc.assetId, tc.assetGroupKey, assetAmount, &bidPrice,
	)

	// If we expect an error, ensure that it is returned.
	if tc.expectError {
		require.Error(t, err)
		return
	}

	// Otherwise, ensure that the response is valid.
	require.NoError(t, err)

	// The mock server should return the rate tick hint/bid.
	require.NotNil(t, resp.AskPrice)
	require.Equal(t, uint64(bidPrice), uint64(*resp.AskPrice))

	// Ensure that the expiry timestamp is in the future.
	responseExpiry := time.Unix(int64(resp.Expiry), 0)
	require.True(t, responseExpiry.After(time.Now()))
}

// TestRpcPriceOracle tests the RPC price oracle client QuerySellPrice function.
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
// QueryBuyPrice function.
type testCaseQueryBidPrice struct {
	name string

	expectError bool

	assetId       *asset.ID
	assetGroupKey *btcec.PublicKey
}

// runQueryBidPriceTest runs the RPC price oracle client QueryBuyPrice test.
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

	resp, err := client.QueryBuyPrice(
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
	require.NotNil(t, resp.BidPrice)
	require.Equal(t, testRateTick, uint64(*resp.BidPrice))

	// Ensure that the expiry timestamp is in the future.
	responseExpiry := time.Unix(int64(resp.Expiry), 0)
	require.True(t, responseExpiry.After(time.Now()))
}

// TestRpcPriceOracle tests the RPC price oracle client QueryBuyPrice function.
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
