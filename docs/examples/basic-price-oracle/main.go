// This example demonstrates a basic RPC price oracle server that implements the
// QueryRateTick RPC method. The server listens on localhost:8095 and returns a
// rate tick for a given transaction type, subject asset, and payment asset. The
// rate tick is the exchange rate between the subject asset and the payment
// asset.
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lightninglabs/taproot-assets/rpcutils"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// serviceListenAddress is the listening address of the service.
	serviceListenAddress = "localhost:8095"
)

// RpcPriceOracleServer is a basic example RPC price oracle server.
type RpcPriceOracleServer struct {
	oraclerpc.UnimplementedPriceOracleServer
}

// isSupportedSubjectAsset returns true if the given subject asset is supported
// by the price oracle, and false otherwise.
func isSupportedSubjectAsset(subjectAsset *oraclerpc.AssetSpecifier) bool {
	// Ensure that the subject asset is set.
	if subjectAsset == nil {
		return false
	}

	// In this example we'll only support a single asset.
	assetIdStr := subjectAsset.GetAssetIdStr()
	supportedAssetId := "7b4336d33b019df9438e586f83c587ca00fa65602497b9" +
		"3ace193e9ce53b1a67"

	return assetIdStr == supportedAssetId
}

// getRateTick returns a rate tick for a given transaction type and subject
// asset max amount.
func getRateTick(transactionType oraclerpc.TransactionType,
	subjectAssetMaxAmount uint64) oraclerpc.RateTick {

	// Determine the rate based on the transaction type.
	var rate uint64
	if transactionType == oraclerpc.TransactionType_PURCHASE {
		// The rate for a purchase transaction is 42,000 asset units per
		// mSAT.
		rate = 42_000
	} else {
		// The rate for a sale transaction is 40,000 asset units per
		// mSAT.
		rate = 40_000
	}

	// Set the rate expiry to 5 minutes by default.
	expiry := time.Now().Add(5 * time.Minute).Unix()

	// If the subject asset max amount is greater than 100,000, set the rate
	// expiry to 1 minute.
	if subjectAssetMaxAmount > 100_000 {
		expiry = time.Now().Add(1 * time.Minute).Unix()
	}

	return oraclerpc.RateTick{
		Rate:            rate,
		ExpiryTimestamp: uint64(expiry),
	}
}

// QueryRateTick queries the rate tick for a given transaction type, subject
// asset, and payment asset. The rate tick is the exchange rate between the
// subject asset and the payment asset.
//
// Example use case:
//
// Alice is trying to pay an invoice by spending an asset. Alice therefore
// requests that Bob (her asset channel counterparty) purchase the asset from
// her. Bob's payment, in BTC, will pay the invoice.
//
// Alice requests a bid quote from Bob. Her request includes a rate tick
// hint (ask). Alice get the rate tick hint by calling this endpoint. She sets:
// - `SubjectAsset` to the asset she is trying to sell.
// - `SubjectAssetMaxAmount` to the max channel asset outbound.
// - `PaymentAsset` to BTC.
// - `TransactionType` to SALE.
// - `RateTickHint` to nil.
//
// Bob calls this endpoint to get the bid quote rate tick that he will send as a
// response to Alice's request. He sets:
// - `SubjectAsset` to the asset that Alice is trying to sell.
// - `SubjectAssetMaxAmount` to the value given in Alice's quote request.
// - `PaymentAsset` to BTC.
// - `TransactionType` to PURCHASE.
// - `RateTickHint` to the value given in Alice's quote request.
func (p *RpcPriceOracleServer) QueryRateTick(_ context.Context,
	req *oraclerpc.QueryRateTickRequest) (
	*oraclerpc.QueryRateTickResponse, error) {

	// Ensure that the payment asset is BTC. We only support BTC as the
	// payment asset in this example.
	if !rpcutils.IsAssetBtc(req.PaymentAsset) {
		return &oraclerpc.QueryRateTickResponse{
			Result: &oraclerpc.QueryRateTickResponse_Error{
				Error: &oraclerpc.QueryRateTickErrResponse{
					Message: "unsupported payment asset, " +
						"only BTC is supported",
				},
			},
		}, nil
	}

	// Ensure that the subject asset is set.
	if req.SubjectAsset == nil {
		return nil, fmt.Errorf("subject asset is not set")
	}

	// Ensure that the subject asset is supported.
	if !isSupportedSubjectAsset(req.SubjectAsset) {
		return &oraclerpc.QueryRateTickResponse{
			Result: &oraclerpc.QueryRateTickResponse_Error{
				Error: &oraclerpc.QueryRateTickErrResponse{
					Message: "unsupported subject asset",
				},
			},
		}, nil
	}

	// Determine which rate tick to return.
	var rateTick oraclerpc.RateTick

	if req.RateTickHint != nil {
		// If a rate tick hint is provided, return it as the rate tick.
		// In doing so, we effectively accept the rate tick proposed by
		// our peer.
		rateTick.Rate = req.RateTickHint.Rate
		rateTick.ExpiryTimestamp = req.RateTickHint.ExpiryTimestamp
	} else {
		// If a rate tick hint is not provided, fetch a rate tick from
		// our internal system.
		rateTick = getRateTick(
			req.TransactionType, req.SubjectAssetMaxAmount,
		)
	}

	return &oraclerpc.QueryRateTickResponse{
		Result: &oraclerpc.QueryRateTickResponse_Success{
			Success: &oraclerpc.QueryRateTickSuccessResponse{
				RateTick: &rateTick,
			},
		},
	}, nil
}

// startService starts the given RPC server and blocks until the server is
// shut down.
func startService(grpcServer *grpc.Server) error {
	serviceAddr := fmt.Sprintf("rfqrpc://%s", serviceListenAddress)
	println("Starting RPC price oracle service at address: ", serviceAddr)

	server := RpcPriceOracleServer{}
	oraclerpc.RegisterPriceOracleServer(grpcServer, &server)
	grpcListener, err := net.Listen("tcp", serviceListenAddress)
	if err != nil {
		return fmt.Errorf("RPC server unable to listen on %s",
			serviceListenAddress)
	}
	return grpcServer.Serve(grpcListener)
}

func main() {
	// Start the mock RPC price oracle service.
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	backendService := grpc.NewServer(serverOpts...)
	_ = startService(backendService)
	backendService.Stop()
}
