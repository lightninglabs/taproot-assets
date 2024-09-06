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
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
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
	// Price is the buy or sell price of the swap quote.
	Price *rfqmsg.PriceQuote

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
	// QuerySellPrice returns the price for selling output assets up to
	// the specified amount of input assets (BTC). The suggestedPrice is an
	// optional price hint that tells the oracle the price the requesting
	// party is willing to pay for the asset swap.
	QuerySellPrice(ctx context.Context, outAssetId *asset.ID,
		outAssetGroupKey *btcec.PublicKey, inAssetMaxAmount uint64,
		suggestedPrice *rfqmsg.PriceQuote) (*OracleResponse, error)

	// QueryBuyPrice returns the price for buying an input asset up to the
	// specified amount and receiving output assets (BTC) in return. The
	// suggestedPrice is an optional price hint that tells the oracle the
	// price the requesting party is willing to pay for the asset swap.
	QueryBuyPrice(ctx context.Context, inAssetId *asset.ID,
		inAssetGroupKey *btcec.PublicKey, inAssetMaxAmount uint64,
		suggestedPrice *rfqmsg.PriceQuote) (*OracleResponse, error)
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

// QuerySellPrice returns the price for selling output assets up to the
// specified amount of input assets (BTC). The suggestedPrice is an optional
// price hint that tells the oracle the price the requesting party is willing to
// pay for the asset swap.
func (r *RpcPriceOracle) QuerySellPrice(ctx context.Context,
	outAssetId *asset.ID, _ *btcec.PublicKey, inAssetMaxAmount uint64,
	suggestedPrice *rfqmsg.PriceQuote) (*OracleResponse, error) {

	// For now, we only support querying the sell price with an asset ID.
	if outAssetId == nil {
		return nil, fmt.Errorf("asset ID is nil")
	}

	var (
		// For a sell request the input asset is BTC, so we leave it at
		// all zeroes.
		inAssetID  = make([]byte, 32)
		outAssetID = outAssetId[:]
	)

	var priceHint *oraclerpc.PriceQuote
	if suggestedPrice != nil {
		priceHint = marshalQuote(suggestedPrice)
	}

	req := &oraclerpc.QueryPriceRequest{
		TransactionType: oraclerpc.TransactionType_SALE,
		InAsset: &rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: inAssetID,
			},
		},
		InAssetMaxAmount: inAssetMaxAmount,
		OutAsset: &rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: outAssetID,
			},
		},
		PriceHint: priceHint,
	}

	resp, err := r.client.QueryPrice(ctx, req)
	if err != nil {
		return nil, err
	}

	return parseOracleResponse(resp)
}

// QueryBuyPrice returns the price for buying an input asset up to the
// specified amount and receiving output assets (BTC) in return. The
// suggestedPrice is an optional price hint that tells the oracle the
// price the requesting party is willing to pay for the asset swap.
func (r *RpcPriceOracle) QueryBuyPrice(ctx context.Context, inAssetId *asset.ID,
	_ *btcec.PublicKey, inAssetMaxAmount uint64,
	suggestedPrice *rfqmsg.PriceQuote) (*OracleResponse, error) {

	// For now, we only support querying the buy price with an asset ID.
	if inAssetId == nil {
		return nil, fmt.Errorf("asset ID is nil")
	}

	var (
		// For a buy request the output asset is BTC, so we leave it at
		// all zeroes.
		outAssetID = make([]byte, 32)
		inAssetID  = inAssetId[:]
	)

	var priceHint *oraclerpc.PriceQuote
	if suggestedPrice != nil {
		priceHint = marshalQuote(suggestedPrice)
	}

	req := &oraclerpc.QueryPriceRequest{
		TransactionType: oraclerpc.TransactionType_PURCHASE,
		InAsset: &rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: inAssetID,
			},
		},
		InAssetMaxAmount: inAssetMaxAmount,
		OutAsset: &rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: outAssetID,
			},
		},
		PriceHint: priceHint,
	}

	resp, err := r.client.QueryPrice(ctx, req)
	if err != nil {
		return nil, err
	}

	return parseOracleResponse(resp)
}

// parseOracleResponse parses the response from the price oracle service and
// returns an OracleResponse instance.
func parseOracleResponse(resp *oraclerpc.QueryPriceResponse) (*OracleResponse,
	error) {

	// Parse the response.
	switch result := resp.GetResult().(type) {
	case *oraclerpc.QueryPriceResponse_Success:
		quote, err := unmarshalPriceQuote(result.Success)
		if err != nil {
			return nil, fmt.Errorf("QueryPrice response is "+
				"successful but price quote is invalid: %w",
				err)
		}

		return &OracleResponse{
			Price: quote,
		}, nil

	case *oraclerpc.QueryPriceResponse_Error:
		if result.Error == nil {
			return nil, fmt.Errorf("QueryRateTick response is " +
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

// NewMockPriceOracleSatPerAsset creates a new mock price oracle with a
// specified satoshis per asset rate.
func NewMockPriceOracleSatPerAsset(expiryDelay uint64,
	satPerAsset btcutil.Amount) *MockPriceOracle {

	return &MockPriceOracle{
		expiryDelay:  expiryDelay,
		mSatPerAsset: lnwire.NewMSatFromSatoshis(satPerAsset),
	}
}

// QuerySellPrice returns the sell price for the given asset amount.
func (m *MockPriceOracle) QuerySellPrice(_ context.Context,
	_ *asset.ID, _ *btcec.PublicKey, _ uint64,
	_ *rfqmsg.PriceQuote) (*OracleResponse, error) {

	return &OracleResponse{
		// TODO(guggero): Fix mock oracle response.
	}, nil
}

// QueryBuyPrice returns a buy price for the given asset amount.
func (m *MockPriceOracle) QueryBuyPrice(_ context.Context, _ *asset.ID,
	_ *btcec.PublicKey, _ uint64, _ *rfqmsg.PriceQuote) (*OracleResponse, error) {

	return &OracleResponse{
		// TODO(guggero): Fix mock oracle response.
	}, nil
}

// Ensure that MockPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*MockPriceOracle)(nil)

// marshalQuote marshals a PriceQuote to the RPC price quote type. If the given
// quote is nil, nil is returned.
func marshalQuote(q *rfqmsg.PriceQuote) *oraclerpc.PriceQuote {
	if q == nil {
		return nil
	}

	return &oraclerpc.PriceQuote{
		InAssetPrice:    marshalFixedPoint(&q.InAssetPrice),
		OutAssetPrice:   marshalFixedPoint(&q.OutAssetPrice),
		ExpiryTimestamp: uint64(q.Expiry.Unix()),
	}
}

// unmarshalPriceQuote unmarshals a PriceQuote from the RPC price quote type.
func unmarshalPriceQuote(q *oraclerpc.PriceQuote) (*rfqmsg.PriceQuote, error) {
	if q == nil {
		return nil, fmt.Errorf("quote is nil")
	}

	if q.InAssetPrice == nil {
		return nil, fmt.Errorf("in asset price is nil")
	}

	if q.OutAssetPrice == nil {
		return nil, fmt.Errorf("out asset price is nil")
	}

	return &rfqmsg.PriceQuote{
		InAssetPrice:  *unmarshalFixedPoint(q.InAssetPrice),
		OutAssetPrice: *unmarshalFixedPoint(q.OutAssetPrice),
		Expiry:        time.Unix(int64(q.ExpiryTimestamp), 0),
	}, nil
}

// marshalFixedPoint marshals a Uint64FixedPoint to the RPC fixed point type.
// If the given fixed point is nil, nil is returned.
func marshalFixedPoint(q *rfqmsg.Uint64FixedPoint) *rfqrpc.FixedPoint {
	if q == nil {
		return nil
	}

	return &rfqrpc.FixedPoint{
		Value: q.Value.ToUint64(),
		Scale: uint32(q.Scale),
	}
}

// unmarshalFixedPoint unmarshals a Uint64FixedPoint from the RPC fixed point
// type.
func unmarshalFixedPoint(q *rfqrpc.FixedPoint) *rfqmsg.Uint64FixedPoint {
	if q == nil {
		return nil
	}

	return &rfqmsg.Uint64FixedPoint{
		Value: rfqmath.NewGoInt(q.Value),
		Scale: int(q.Scale),
	}
}
