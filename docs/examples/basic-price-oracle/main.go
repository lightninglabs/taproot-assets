// This example demonstrates a basic RPC price oracle server that implements the
// QueryPrice RPC method. The server listens on localhost:8095 and returns a
// price for a given transaction type, input asset, and output asset. The
// price is the exchange rate between the input asset and BTC and between the
// output asset and BTC.
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// serviceListenAddress is the listening address of the service.
	serviceListenAddress = "localhost:8095"
)

var (
	// priceMilliSatPerBtc is the static price of 1 BTC expressed in
	// milli-satoshi (10^11) and represented as a fixed point number.
	priceMilliSatPerBtc = &rfqrpc.FixedPoint{
		Value: 1,
		Scale: 11,
	}
)

// RpcPriceOracleServer is a basic example RPC price oracle server.
type RpcPriceOracleServer struct {
	oraclerpc.UnimplementedPriceOracleServer
}

// isSupportedSubjectAsset returns true if the given subject asset is supported
// by the price oracle, and false otherwise.
func isSupportedSubjectAsset(subjectAsset *rfqrpc.AssetSpecifier) bool {
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

// getPrice returns a rate tick for a given transaction type and subject
// asset max amount.
func getPrice(transactionType oraclerpc.TransactionType,
	inAssetMaxAmount uint64) *oraclerpc.PriceQuote {

	// Determine the price based on the transaction type.
	var quote *oraclerpc.PriceQuote
	if transactionType == oraclerpc.TransactionType_PURCHASE {
		// The price for a purchase transaction is 5_578_020 asset units
		// per BTC (with a scale of 2 decimal places, which results in
		// an exchange rate of $55,780.20 USD per BTC).
		quote = &oraclerpc.PriceQuote{
			InAssetPrice: &rfqrpc.FixedPoint{
				Value: 5_578_020,
				Scale: 2,
			},
			OutAssetPrice: priceMilliSatPerBtc,
		}
	} else {
		// The price for a sale transaction is 5_580_930 asset units
		// per BTC (with a scale of 2 decimal places, which results in
		// an exchange rate of $55,809.30 USD per BTC).
		quote = &oraclerpc.PriceQuote{
			InAssetPrice: priceMilliSatPerBtc,
			OutAssetPrice: &rfqrpc.FixedPoint{
				Value: 5_580_930,
				Scale: 2,
			},
		}
	}

	// Set the rate expiry to 5 minutes by default.
	timeout := 5 * time.Minute

	// If the subject asset max amount is greater than 100,000, set the rate
	// expiry to 1 minute.
	if inAssetMaxAmount > 100_000 {
		timeout = 1 * time.Minute
	}

	quote.ExpiryTimestamp = uint64(time.Now().Add(timeout).Unix())
	return quote
}

// QueryPrice queries the price for a given transaction type, input asset, and
// output asset. The price is the exchange rate between the input asset and BTC
// and between the output asset and BTC.
//
// Example use case:
//
// Alice is trying to pay an invoice by spending an asset. Alice therefore
// requests that Bob (her asset channel counterparty and edge node) purchase the
// asset from her. Bob's payment, in BTC, will pay the invoice by forwarding the
// BTC to the wider network.
//
// Alice requests a price quote from Bob. Her request includes a price hint.
// Alice get the price hint by calling this endpoint. She sets:
// - `InAsset` to BTC.
// - `InAssetMaxAmount` to the invoice amount + max routing fee.
// - `OutAsset` to the asset she is trying to sell.
// - `TransactionType` to SALE.
// - `InAssetPriceHint` to nil.
// - `OutAssetPriceHint` to nil.
//
// Bob calls this endpoint to get the sell quote price that he will send as a
// response to Alice's request. He sets:
// - `InAsset` to BTC.
// - `InAssetMaxAmount` to the value given in Alice's quote request.
// - `OutAsset` to the asset that Alice is trying to sell.
// - `TransactionType` to SALE.
// - `InAssetPriceHint` to the value given in Alice's quote request.
// - `OutAssetPriceHint` to the value given in Alice's quote request.
func (p *RpcPriceOracleServer) QueryPrice(_ context.Context,
	req *oraclerpc.QueryPriceRequest) (*oraclerpc.QueryPriceResponse,
	error) {

	// Depending on the transaction type, either the input or output asset
	// needs to be BTC, as we currently only support BTC as the secondary
	// asset.
	switch req.TransactionType {
	case oraclerpc.TransactionType_SALE:
		// A sell order (paying an invoice) means the input asset is
		// BTC.
		if !oraclerpc.IsAssetBtc(req.InAsset) {
			return &oraclerpc.QueryPriceResponse{
				Result: &oraclerpc.QueryPriceResponse_Error{
					Error: &oraclerpc.QueryPriceError{
						Message: "unsupported input " +
							"asset, only BTC is " +
							"supported",
					},
				},
			}, nil
		}

		// We make sure the other asset is set.
		if req.OutAsset == nil {
			return nil, fmt.Errorf("output asset is not set")
		}

	case oraclerpc.TransactionType_PURCHASE:
		// A buy order (receiving via an invoice) means the output asset
		// is BTC.
		if !oraclerpc.IsAssetBtc(req.OutAsset) {
			return &oraclerpc.QueryPriceResponse{
				Result: &oraclerpc.QueryPriceResponse_Error{
					Error: &oraclerpc.QueryPriceError{
						Message: "unsupported output " +
							"asset, only BTC is " +
							"supported",
					},
				},
			}, nil
		}

		// We make sure the other asset is set.
		if req.InAsset == nil {
			return nil, fmt.Errorf("input asset is not set")
		}

	default:
		return nil, fmt.Errorf("unsupported transaction type: %d",
			req.TransactionType)
	}

	// Determine which price quote to return.
	var priceQuote *oraclerpc.PriceQuote
	if req.PriceHint != nil {
		// We make sure the price hint hasn't expired yet.
		if req.PriceHint.ExpiryTimestamp < uint64(time.Now().Unix()) {
			return &oraclerpc.QueryPriceResponse{
				Result: &oraclerpc.QueryPriceResponse_Error{
					Error: &oraclerpc.QueryPriceError{
						Message: "price hint has " +
							"expired",
					},
				},
			}, nil
		}

		// If a rate tick hint is provided, return it as the rate tick.
		// In doing so, we effectively accept the rate tick proposed by
		// our peer.
		priceQuote = &oraclerpc.PriceQuote{
			InAssetPrice:  req.PriceHint.InAssetPrice,
			OutAssetPrice: req.PriceHint.OutAssetPrice,
			// We now make our own offer, so a new expiry should
			// start ticking.
			ExpiryTimestamp: uint64(
				time.Now().Add(5 * time.Minute).Unix(),
			),
		}
	} else {
		// If a rate tick hint is not provided, fetch a rate tick from
		// our internal system.
		priceQuote = getPrice(req.TransactionType, req.InAssetMaxAmount)
	}

	return &oraclerpc.QueryPriceResponse{
		Result: &oraclerpc.QueryPriceResponse_Success{
			Success: priceQuote,
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
