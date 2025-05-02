package rfq

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	AssetRate rfqmsg.AssetRate

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
	QueryAskPrice(ctx context.Context, assetSpecifier asset.Specifier,
		assetMaxAmt fn.Option[uint64],
		paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
		assetRateHint fn.Option[rfqmsg.AssetRate]) (
		*OracleResponse, error)

	// QueryBidPrice returns the bid price for a given asset amount.
	// The bid price is the amount the oracle suggests a peer should pay
	// to another peer to receive the specified asset amount.
	QueryBidPrice(ctx context.Context, assetSpecifier asset.Specifier,
		assetMaxAmt fn.Option[uint64],
		paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
		assetRateHint fn.Option[rfqmsg.AssetRate]) (
		*OracleResponse, error)
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
	assetSpecifier asset.Specifier, assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate]) (*OracleResponse,
	error) {

	// The payment asset ID is BTC, so we leave it at all zeroes.
	var paymentAssetId = make([]byte, 32)

	// Marshal asset max amount.
	assetMaxAmount := assetMaxAmt.UnwrapOr(0)

	// Construct the RPC asset rates hint.
	rpcAssetRatesHint, err := fn.MapOptionZ(
		assetRateHint, rpcutils.MarshalAssetRates,
	).Unpack()
	if err != nil {
		return nil, err
	}

	// Marshal payment asset max amount.
	paymentAssetMaxAmount := uint64(
		paymentMaxAmt.UnwrapOr(lnwire.MilliSatoshi(0)),
	)

	req := &oraclerpc.QueryAssetRatesRequest{
		TransactionType:       oraclerpc.TransactionType_SALE,
		SubjectAsset:          rpcMarshalAssetSpecifier(assetSpecifier),
		SubjectAssetMaxAmount: assetMaxAmount,
		PaymentAsset: &oraclerpc.AssetSpecifier{
			Id: &oraclerpc.AssetSpecifier_AssetId{
				AssetId: paymentAssetId,
			},
		},
		PaymentAssetMaxAmount: paymentAssetMaxAmount,
		AssetRatesHint:        rpcAssetRatesHint,
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
		rate, err := rpcutils.UnmarshalFixedPoint(
			result.Ok.AssetRates.SubjectAssetRate,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal the expiry timestamp.
		if result.Ok.AssetRates.ExpiryTimestamp > math.MaxInt64 {
			return nil, fmt.Errorf("expiry timestamp exceeds " +
				"int64 max")
		}
		expiry := time.Unix(int64(
			result.Ok.AssetRates.ExpiryTimestamp,
		), 0).UTC()

		return &OracleResponse{
			AssetRate: rfqmsg.NewAssetRate(*rate, expiry),
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
func (r *RpcPriceOracle) QueryBidPrice(ctx context.Context,
	assetSpecifier asset.Specifier, assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate]) (*OracleResponse,
	error) {

	// The payment asset ID is BTC, so we leave it at all zeroes.
	var paymentAssetId = make([]byte, 32)

	// Marshal asset max amount.
	assetMaxAmount := assetMaxAmt.UnwrapOr(0)

	// Marshal payment asset max amount.
	paymentAssetMaxAmount := uint64(
		paymentMaxAmt.UnwrapOr(lnwire.MilliSatoshi(0)),
	)

	// Construct the RPC asset rates hint.
	rpcAssetRatesHint, err := fn.MapOptionZ(
		assetRateHint, rpcutils.MarshalAssetRates,
	).Unpack()
	if err != nil {
		return nil, err
	}

	req := &oraclerpc.QueryAssetRatesRequest{
		TransactionType:       oraclerpc.TransactionType_PURCHASE,
		SubjectAsset:          rpcMarshalAssetSpecifier(assetSpecifier),
		SubjectAssetMaxAmount: assetMaxAmount,
		PaymentAsset: &oraclerpc.AssetSpecifier{
			Id: &oraclerpc.AssetSpecifier_AssetId{
				AssetId: paymentAssetId,
			},
		},
		PaymentAssetMaxAmount: paymentAssetMaxAmount,
		AssetRatesHint:        rpcAssetRatesHint,
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
		rate, err := rpcutils.UnmarshalFixedPoint(
			result.Ok.AssetRates.SubjectAssetRate,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal the expiry timestamp.
		if result.Ok.AssetRates.ExpiryTimestamp > math.MaxInt64 {
			return nil, fmt.Errorf("expiry timestamp exceeds " +
				"int64 max")
		}
		expiry := time.Unix(int64(
			result.Ok.AssetRates.ExpiryTimestamp,
		), 0).UTC()

		return &OracleResponse{
			AssetRate: rfqmsg.NewAssetRate(*rate, expiry),
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

// rpcMarshalAssetSpecifier is a helper method that converts an asset specifier
// to the oraclerpc representation of the specifier.
func rpcMarshalAssetSpecifier(
	assetSpecifier asset.Specifier) *oraclerpc.AssetSpecifier {

	var subjectSpecifier oraclerpc.AssetSpecifier

	switch {
	case assetSpecifier.HasId():
		assetID := assetSpecifier.UnwrapIdToPtr()
		subjectSpecifier.Id = &oraclerpc.AssetSpecifier_AssetId{
			AssetId: assetID[:],
		}

	case assetSpecifier.HasGroupPubKey():
		groupKey := assetSpecifier.UnwrapGroupKeyToPtr()
		subjectSpecifier.Id = &oraclerpc.AssetSpecifier_GroupKey{
			GroupKey: groupKey.SerializeCompressed(),
		}
	}

	return &subjectSpecifier
}
