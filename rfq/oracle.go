package rfq

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/lnwire"
)

// OracleError is a struct that holds an error returned by the price oracle
// service.
type OracleError struct {
	// Code is a code which uniquely identifies the error type.
	Code uint8

	// Msg is a human-readable error message.
	Msg string
}

// Error returns a human-readable string representation of the error.
func (o *OracleError) Error() string {
	// Sanitise price oracle error message by truncating to 255 characters.
	// The price oracle service might be a third-party service and could
	// return an error message that is too long.
	errMsg := o.Msg
	if len(errMsg) > 255 {
		errMsg = errMsg[:255]
	}

	return fmt.Sprintf("OracleError(code=%d, msg=%s)", o.Code, errMsg)
}

// OracleAskResponse is a struct that holds the price oracle's suggested ask
// price for an asset.
type OracleAskResponse struct {
	// AskPrice is the asking price of the quote.
	AskPrice *lnwire.MilliSatoshi

	// Expiry is the price expiryDelay lifetime unix timestamp.
	Expiry uint64

	// Err is an optional error returned by the price oracle service.
	Err *OracleError
}

// OracleBidResponse is a struct that holds the price oracle's suggested bid
// price for an asset.
type OracleBidResponse struct {
	// BidPrice is the suggested bid price for the asset amount.
	BidPrice *lnwire.MilliSatoshi

	// Expiry is the price expiryDelay lifetime unix timestamp.
	Expiry uint64

	// Err is an optional error returned by the price oracle service.
	Err *OracleError
}

// PriceOracle is an interface that provides exchange rate information for
// assets.
type PriceOracle interface {
	// QueryAskPrice returns an asking price for the given asset amount.
	QueryAskPrice(ctx context.Context, assetId *asset.ID,
		assetGroupKey *btcec.PublicKey, assetAmount uint64,
		suggestedBidPrice *lnwire.MilliSatoshi) (*OracleAskResponse,
		error)

	// QueryBidPrice returns a bid price for the given asset amount.
	QueryBidPrice(ctx context.Context, assetId *asset.ID,
		assetGroupKey *btcec.PublicKey,
		assetAmount uint64) (*OracleBidResponse, error)
}

//// RpcPriceOracle is a price oracle that uses an external RPC server to get
//// exchange rate information.
//type RpcPriceOracle struct {
//}
//
//// serverDialOpts returns the set of server options needed to connect to the
//// price oracle RPC server using a TLS connection.
//func serverDialOpts() ([]grpc.DialOption, error) {
//	var opts []grpc.DialOption
//
//	// Skip TLS certificate verification.
//	tlsConfig := tls.Config{InsecureSkipVerify: true}
//	transportCredentials := credentials.NewTLS(&tlsConfig)
//	opts = append(opts, grpc.WithTransportCredentials(transportCredentials))
//
//	return opts, nil
//}
//
//// NewRpcPriceOracle creates a new RPC price oracle handle given the address
//// of the price oracle RPC server.
//func NewRpcPriceOracle(addr url.URL) (*RpcPriceOracle, error) {
//	//// Connect to the RPC server.
//	//dialOpts, err := serverDialOpts()
//	//if err != nil {
//	//	return nil, err
//	//}
//	//
//	//serverAddr := fmt.Sprintf("%s:%s", addr.Hostname(), addr.Port())
//	//conn, err := grpc.Dial(serverAddr, dialOpts...)
//	//if err != nil {
//	//	return nil, err
//	//}
//
//	return &RpcPriceOracle{}, nil
//}
//
//// QueryAskingPrice returns the asking price for the given asset amount.
//func (r *RpcPriceOracle) QueryAskingPrice(ctx context.Context,
//	assetId *asset.ID, assetGroupKey *btcec.PublicKey, assetAmount uint64,
//	bidPrice *lnwire.MilliSatoshi) (*OracleAskResponse, error) {
//
//	//// Call the external oracle service to get the exchange rate.
//	//conn := getClientConn(ctx, false)
//
//	return nil, nil
//}
//
//// Ensure that RpcPriceOracle implements the PriceOracle interface.
//var _ PriceOracle = (*RpcPriceOracle)(nil)

// MockPriceOracle is a mock implementation of the PriceOracle interface.
// It returns the suggested rate as the exchange rate.
type MockPriceOracle struct {
	expiryDelay uint64
}

// NewMockPriceOracle creates a new mock price oracle.
func NewMockPriceOracle(expiryDelay uint64) *MockPriceOracle {
	return &MockPriceOracle{
		expiryDelay: expiryDelay,
	}
}

// QueryAskPrice returns the ask price for the given asset amount.
func (m *MockPriceOracle) QueryAskPrice(_ context.Context,
	_ *asset.ID, _ *btcec.PublicKey, _ uint64,
	suggestedBidPrice *lnwire.MilliSatoshi) (*OracleAskResponse, error) {

	// Calculate the rate expiryDelay lifetime.
	expiry := uint64(time.Now().Unix()) + m.expiryDelay

	return &OracleAskResponse{
		AskPrice: suggestedBidPrice,
		Expiry:   expiry,
	}, nil
}

// QueryBidPrice returns a bid price for the given asset amount.
func (m *MockPriceOracle) QueryBidPrice(_ context.Context, _ *asset.ID,
	_ *btcec.PublicKey, _ uint64) (*OracleBidResponse, error) {

	// Calculate the rate expiryDelay lifetime.
	expiry := uint64(time.Now().Unix()) + m.expiryDelay

	bidPrice := lnwire.MilliSatoshi(42000)

	return &OracleBidResponse{
		BidPrice: &bidPrice,
		Expiry:   expiry,
	}, nil
}

// Ensure that MockPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*MockPriceOracle)(nil)
