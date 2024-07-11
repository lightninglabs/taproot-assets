package rfq

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightninglabs/taproot-assets/asset"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// defaultRateTickExpirySeconds is the default rate tick expiry lifetime
	// in seconds. 600s = 10 minutes.
	//
	// TODO(ffranr): This const is currently used in conjunction with the
	//  AcceptSuggestedPrices flag. It is used to set the expiry time of the
	//  rate tick in the accept message. This is a temporary solution and
	//  should be replaced with an expiry time provided by the peer in the
	//  quote request message.
	defaultRateTickExpirySeconds = 600
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

	// Expiry is the price expiry lifetime unix timestamp in seconds.
	Expiry uint64

	// Err is an optional error returned by the price oracle service.
	Err *OracleError
}

// OracleAddr is a type alias for a URL type that represents a price oracle
// service address.
type OracleAddr = url.URL

const (
	// RfqRpcOracleAddrScheme is the URL address scheme used by an RPC price
	// oracle service.
	RfqRpcOracleAddrScheme string = "rfqrpc"
)

// ParsePriceOracleAddress parses a price oracle service address string and
// returns a URL type instance.
func ParsePriceOracleAddress(addrStr string) (*OracleAddr, error) {
	// Basic sanity check to ensure the address is not empty.
	if addrStr == "" {
		return nil, fmt.Errorf("price oracle " +
			"address is an empty string")
	}

	// Parse the price oracle address.
	addr, err := url.ParseRequestURI(addrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid price oracle service URI "+
			"address: %w", err)
	}

	// Ensure that the price oracle address scheme is valid.
	if addr.Scheme != RfqRpcOracleAddrScheme {
		return nil, fmt.Errorf("unknown price oracle protocol "+
			"(consider updating tapd): %v", addr.Scheme)
	}

	return addr, nil
}

// PriceOracle is an interface that provides exchange rate information for
// assets.
type PriceOracle interface {
	// QueryAskPrice returns the ask price for a given asset amount.
	// The ask price is the amount the oracle suggests a peer should accept
	// from another peer to provide the specified asset amount.
	QueryAskPrice(ctx context.Context, assetId *asset.ID,
		assetGroupKey *btcec.PublicKey, assetAmount uint64,
		suggestedBidPrice *lnwire.MilliSatoshi) (*OracleAskResponse,
		error)

	// QueryBidPrice returns the bid price for a given asset amount.
	// The bid price is the amount the oracle suggests a peer should pay
	// to another peer to receive the specified asset amount.
	QueryBidPrice(ctx context.Context, assetId *asset.ID,
		assetGroupKey *btcec.PublicKey,
		assetAmount uint64) (*OracleBidResponse, error)
}

// RpcPriceOracle is a price oracle that uses an external RPC server to get
// exchange rate information.
type RpcPriceOracle struct {
	// client is the RPC client that this instance will use to interact with
	// the price oracle RPC server.
	client oraclerpc.PriceOracleClient

	// rawConn is the raw connection to the remote gRPC service.
	rawConn *grpc.ClientConn
}

// serverDialOpts returns the set of server options needed to connect to the
// price oracle RPC server using a TLS connection.
func serverDialOpts() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	// Skip TLS certificate verification.
	tlsConfig := tls.Config{InsecureSkipVerify: true}
	transportCredentials := credentials.NewTLS(&tlsConfig)
	opts = append(opts, grpc.WithTransportCredentials(transportCredentials))

	return opts, nil
}

// insecureServerDialOpts returns the set of server options needed to connect to
// the price oracle RPC server using a TLS connection.
func insecureServerDialOpts() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	// Skip TLS certificate verification.
	opts = append(opts, grpc.WithTransportCredentials(
		insecure.NewCredentials(),
	))

	return opts, nil
}

// NewRpcPriceOracle creates a new RPC price oracle handle given the address
// of the price oracle RPC server.
func NewRpcPriceOracle(addrStr string, dialInsecure bool) (*RpcPriceOracle,
	error) {

	addr, err := ParsePriceOracleAddress(addrStr)
	if err != nil {
		return nil, err
	}

	// Connect to the RPC server.
	dialOpts, err := serverDialOpts()
	if err != nil {
		return nil, err
	}

	// Allow connecting to a non-TLS (h2c, http over cleartext) gRPC server,
	// should be used for testing only.
	if dialInsecure {
		dialOpts, err = insecureServerDialOpts()
		if err != nil {
			return nil, err
		}
	}

	// Formulate the server address dial string.
	serverAddr := fmt.Sprintf("%s:%s", addr.Hostname(), addr.Port())

	conn, err := grpc.Dial(serverAddr, dialOpts...)
	if err != nil {
		return nil, err
	}

	// Create a new price oracle client from the active connection.
	client := oraclerpc.NewPriceOracleClient(conn)

	return &RpcPriceOracle{
		client:  client,
		rawConn: conn,
	}, nil
}

// QueryAskPrice returns the ask price for the given asset amount.
func (r *RpcPriceOracle) QueryAskPrice(ctx context.Context,
	assetId *asset.ID, assetGroupKey *btcec.PublicKey, assetAmount uint64,
	bidPrice *lnwire.MilliSatoshi) (*OracleAskResponse, error) {

	// For now, we only support querying the ask price with an asset ID.
	if assetId == nil {
		return nil, fmt.Errorf("asset ID is nil")
	}

	// Construct query request.
	var subjectAssetId []byte
	copy(subjectAssetId, assetId[:])

	paymentAssetId := make([]byte, 32)

	// Construct the RPC rate tick hint.
	var rateTickHint *oraclerpc.RateTick
	if bidPrice != nil {
		// Compute an expiry time using the default expiry delay.
		expiryTimestamp := uint64(time.Now().Unix()) +
			defaultRateTickExpirySeconds

		rateTickHint = &oraclerpc.RateTick{
			Rate:            uint64(*bidPrice),
			ExpiryTimestamp: expiryTimestamp,
		}
	}

	req := &oraclerpc.QueryRateTickRequest{
		TransactionType: oraclerpc.TransactionType_SALE,
		SubjectAsset: &oraclerpc.AssetSpecifier{
			Id: &oraclerpc.AssetSpecifier_AssetId{
				AssetId: subjectAssetId,
			},
		},
		SubjectAssetMaxAmount: assetAmount,
		PaymentAsset: &oraclerpc.AssetSpecifier{
			Id: &oraclerpc.AssetSpecifier_AssetId{
				AssetId: paymentAssetId,
			},
		},
		RateTickHint: rateTickHint,
	}

	// Perform query.
	resp, err := r.client.QueryRateTick(ctx, req)
	if err != nil {
		return nil, err
	}

	// Parse the response.
	switch result := resp.GetResult().(type) {
	case *oraclerpc.QueryRateTickResponse_Success:
		if result.Success.RateTick == nil {
			return nil, fmt.Errorf("QueryRateTick response is " +
				"successful but rate tick is nil")
		}

		rate := lnwire.MilliSatoshi(result.Success.RateTick.Rate)
		return &OracleAskResponse{
			AskPrice: &rate,
			Expiry:   result.Success.RateTick.ExpiryTimestamp,
		}, nil

	case *oraclerpc.QueryRateTickResponse_Error:
		if result.Error == nil {
			return nil, fmt.Errorf("QueryRateTick response is " +
				"an error but error is nil")
		}

		return &OracleAskResponse{
			Err: &OracleError{
				Msg: result.Error.Message,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}
}

// QueryBidPrice returns a bid price for the given asset amount.
func (r *RpcPriceOracle) QueryBidPrice(ctx context.Context, assetId *asset.ID,
	assetGroupKey *btcec.PublicKey,
	maxAssetAmount uint64) (*OracleBidResponse, error) {

	// For now, we only support querying the ask price with an asset ID.
	if assetId == nil {
		return nil, fmt.Errorf("asset ID is nil")
	}

	// Construct query request.
	var subjectAssetId []byte
	copy(subjectAssetId, assetId[:])

	paymentAssetId := make([]byte, 32)

	req := &oraclerpc.QueryRateTickRequest{
		TransactionType: oraclerpc.TransactionType_PURCHASE,
		SubjectAsset: &oraclerpc.AssetSpecifier{
			Id: &oraclerpc.AssetSpecifier_AssetId{
				AssetId: subjectAssetId,
			},
		},
		SubjectAssetMaxAmount: maxAssetAmount,
		PaymentAsset: &oraclerpc.AssetSpecifier{
			Id: &oraclerpc.AssetSpecifier_AssetId{
				AssetId: paymentAssetId,
			},
		},
		RateTickHint: nil,
	}

	// Perform query.
	resp, err := r.client.QueryRateTick(ctx, req)
	if err != nil {
		return nil, err
	}

	// Parse the response.
	switch result := resp.GetResult().(type) {
	case *oraclerpc.QueryRateTickResponse_Success:
		if result.Success.RateTick == nil {
			return nil, fmt.Errorf("QueryRateTick response is " +
				"successful but rate tick is nil")
		}

		rate := lnwire.MilliSatoshi(result.Success.RateTick.Rate)
		return &OracleBidResponse{
			BidPrice: &rate,
			Expiry:   result.Success.RateTick.ExpiryTimestamp,
		}, nil

	case *oraclerpc.QueryRateTickResponse_Error:
		if result.Error == nil {
			return nil, fmt.Errorf("QueryRateTick response is " +
				"an error but error is nil")
		}

		return &OracleBidResponse{
			Err: &OracleError{
				Msg: result.Error.Message,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}
}

// Ensure that RpcPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*RpcPriceOracle)(nil)

// MockPriceOracle is a mock implementation of the PriceOracle interface.
// It returns the suggested rate as the exchange rate.
type MockPriceOracle struct {
	expiryDelay  uint64
	mSatPerAsset lnwire.MilliSatoshi
}

// NewMockPriceOracle creates a new mock price oracle.
func NewMockPriceOracle(expiryDelay, assetsPerBTC uint64) *MockPriceOracle {
	mSatPerAsset := lnwire.NewMSatFromSatoshis(btcutil.SatoshiPerBitcoin) /
		lnwire.MilliSatoshi(assetsPerBTC)

	return &MockPriceOracle{
		expiryDelay:  expiryDelay,
		mSatPerAsset: mSatPerAsset,
	}
}

// QueryAskPrice returns the ask price for the given asset amount.
func (m *MockPriceOracle) QueryAskPrice(_ context.Context,
	_ *asset.ID, _ *btcec.PublicKey, _ uint64,
	_ *lnwire.MilliSatoshi) (*OracleAskResponse, error) {

	// Calculate the rate expiryDelay lifetime.
	expiry := uint64(time.Now().Unix()) + m.expiryDelay

	return &OracleAskResponse{
		AskPrice: &m.mSatPerAsset,
		Expiry:   expiry,
	}, nil
}

// QueryBidPrice returns a bid price for the given asset amount.
func (m *MockPriceOracle) QueryBidPrice(_ context.Context, _ *asset.ID,
	_ *btcec.PublicKey, _ uint64) (*OracleBidResponse, error) {

	// Calculate the rate expiryDelay lifetime.
	expiry := uint64(time.Now().Unix()) + m.expiryDelay

	return &OracleBidResponse{
		BidPrice: &m.mSatPerAsset,
		Expiry:   expiry,
	}, nil
}

// Ensure that MockPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*MockPriceOracle)(nil)
