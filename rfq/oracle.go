package rfq

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// defaultAssetRateExpirySeconds is the default asset units to BTC rate
	// expiry lifetime in seconds. 600s = 10 minutes.
	//
	// TODO(ffranr): This const is currently used in conjunction with the
	//  AcceptSuggestedPrices flag. It is used to set the expiry time of the
	//  asset units to BTC rate in the accept message. This is a temporary
	//  solution and should be replaced with an expiry time provided by the
	//  peer in the quote request message.
	defaultAssetRateExpirySeconds = 600
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

// OracleResponse is a struct that holds the price oracle's suggested buy or
// sell price for an asset swap.
type OracleResponse struct {
	// AssetRate is the asset to BTC rate. Other asset in the transfer is
	// assumed to be BTC and therefore not included in the response.
	AssetRate rfqmath.BigIntFixedPoint

	// Expiry is the asset to BTC rate expiry lifetime unix timestamp. The
	// rate is only valid until this time.
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
		assetRateHint fn.Option[rfqmath.BigIntFixedPoint]) (
		*OracleResponse, error)

	// QueryBidPrice returns the bid price for a given asset amount.
	// The bid price is the amount the oracle suggests a peer should pay
	// to another peer to receive the specified asset amount.
	QueryBidPrice(ctx context.Context, assetId *asset.ID,
		assetGroupKey *btcec.PublicKey,
		assetAmount uint64) (*OracleResponse, error)
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
	assetRateHint fn.Option[rfqmath.BigIntFixedPoint]) (*OracleResponse,
	error) {

	// For now, we only support querying the ask price with an asset ID.
	if assetId == nil {
		return nil, fmt.Errorf("asset ID is nil")
	}

	var (
		subjectAssetId = make([]byte, 32)
		paymentAssetId = make([]byte, 32)
	)

	// The payment asset ID is BTC, so we leave it at all zeroes. We only
	// set the subject asset ID.
	copy(subjectAssetId, assetId[:])

	// Construct the RPC asset rates hint.
	var (
		rpcAssetRatesHint *oraclerpc.AssetRates
		err               error
	)
	assetRateHint.WhenSome(func(rate rfqmath.BigIntFixedPoint) {
		// Compute an expiry time using the default expiry delay.
		expiryTimestamp := uint64(time.Now().Unix()) +
			defaultAssetRateExpirySeconds

		// Marshal the subject asset rate.
		subjectAssetRate, err := oraclerpc.MarshalBigIntFixedPoint(
			rate,
		)
		if err != nil {
			return
		}

		// Marshal the payment asset rate. For now, we only support BTC
		// as the payment asset.
		paymentAssetRate, err := oraclerpc.MarshalBigIntFixedPoint(
			rfqmsg.MilliSatPerBtc,
		)
		if err != nil {
			return
		}

		rpcAssetRatesHint = &oraclerpc.AssetRates{
			SubjectAssetRate: subjectAssetRate,
			PaymentAssetRate: paymentAssetRate,
			ExpiryTimestamp:  expiryTimestamp,
		}
	})
	if err != nil {
		return nil, err
	}

	req := &oraclerpc.QueryAssetRatesRequest{
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
		AssetRatesHint: rpcAssetRatesHint,
	}

	// Perform query.
	resp, err := r.client.QueryAssetRates(ctx, req)
	if err != nil {
		return nil, err
	}

	// Parse the response.
	switch result := resp.GetResult().(type) {
	case *oraclerpc.QueryAssetRatesResponse_Ok:
		if result.Ok.AssetRates == nil {
			return nil, fmt.Errorf("QueryAssetRates response is " +
				"successful but asset rates is nil")
		}

		// Unmarshal the subject asset to BTC rate.
		rate, err := oraclerpc.UnmarshalFixedPoint(
			result.Ok.AssetRates.SubjectAssetRate,
		)
		if err != nil {
			return nil, err
		}

		return &OracleResponse{
			AssetRate: *rate,
			Expiry:    result.Ok.AssetRates.ExpiryTimestamp,
		}, nil

	case *oraclerpc.QueryAssetRatesResponse_Error:
		if result.Error == nil {
			return nil, fmt.Errorf("QueryAssetRates response is " +
				"an error but error is nil")
		}

		return &OracleResponse{
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
	maxAssetAmount uint64) (*OracleResponse, error) {

	// For now, we only support querying the ask price with an asset ID.
	if assetId == nil {
		return nil, fmt.Errorf("asset ID is nil")
	}

	var (
		subjectAssetId = make([]byte, 32)
		paymentAssetId = make([]byte, 32)
	)

	// The payment asset ID is BTC, so we leave it at all zeroes. We only
	// set the subject asset ID.
	copy(subjectAssetId, assetId[:])

	req := &oraclerpc.QueryAssetRatesRequest{
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
		AssetRatesHint: nil,
	}

	// Perform query.
	resp, err := r.client.QueryAssetRates(ctx, req)
	if err != nil {
		return nil, err
	}

	// Parse the response.
	switch result := resp.GetResult().(type) {
	case *oraclerpc.QueryAssetRatesResponse_Ok:
		if result.Ok.AssetRates == nil {
			return nil, fmt.Errorf("QueryAssetRates response is " +
				"successful but asset rates is nil")
		}

		// Unmarshal the subject asset to BTC rate.
		rate, err := oraclerpc.UnmarshalFixedPoint(
			result.Ok.AssetRates.SubjectAssetRate,
		)
		if err != nil {
			return nil, err
		}

		return &OracleResponse{
			AssetRate: *rate,
			Expiry:    result.Ok.AssetRates.ExpiryTimestamp,
		}, nil

	case *oraclerpc.QueryAssetRatesResponse_Error:
		if result.Error == nil {
			return nil, fmt.Errorf("QueryAssetRates response is " +
				"an error but error is nil")
		}

		return &OracleResponse{
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
	expiryDelay    uint64
	assetToBtcRate rfqmath.BigIntFixedPoint
}

// NewMockPriceOracle creates a new mock price oracle.
func NewMockPriceOracle(expiryDelay,
	assetRateCoefficient uint64) *MockPriceOracle {

	return &MockPriceOracle{
		expiryDelay: expiryDelay,
		assetToBtcRate: rfqmath.NewBigIntFixedPoint(
			assetRateCoefficient, 0,
		),
	}
}

// NewMockPriceOracleSatPerAsset creates a new mock price oracle with a
// specified satoshis per asset rate.
//
// TODO(ffranr): Remove in favour of NewMockPriceOracle.
func NewMockPriceOracleSatPerAsset(expiryDelay uint64,
	assetRateCoefficient uint64) *MockPriceOracle {

	return &MockPriceOracle{
		expiryDelay: expiryDelay,
		assetToBtcRate: rfqmath.NewBigIntFixedPoint(
			assetRateCoefficient, 0,
		),
	}
}

// QueryAskPrice returns the ask price for the given asset amount.
func (m *MockPriceOracle) QueryAskPrice(_ context.Context,
	_ *asset.ID, _ *btcec.PublicKey, _ uint64,
	_ fn.Option[rfqmath.BigIntFixedPoint]) (*OracleResponse, error) {

	// Calculate the rate expiryDelay lifetime.
	expiry := uint64(time.Now().Unix()) + m.expiryDelay

	return &OracleResponse{
		AssetRate: m.assetToBtcRate,
		Expiry:    expiry,
	}, nil
}

// QueryBidPrice returns a bid price for the given asset amount.
func (m *MockPriceOracle) QueryBidPrice(_ context.Context, _ *asset.ID,
	_ *btcec.PublicKey, _ uint64) (*OracleResponse, error) {

	// Calculate the rate expiryDelay lifetime.
	expiry := uint64(time.Now().Unix()) + m.expiryDelay

	return &OracleResponse{
		AssetRate: m.assetToBtcRate,
		Expiry:    expiry,
	}, nil
}

// Ensure that MockPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*MockPriceOracle)(nil)
