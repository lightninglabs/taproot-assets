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
	"github.com/lightningnetwork/lnd/routing/route"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// PriceQueryIntent is an enum that represents the intent of a price rate
// query. It is used to indicate the purpose of the price rate request, such as
// whether the user is requesting a hint for paying an invoice, or if they are
// qualifying a rate for an invoice payment. This information is used by the
// price oracle service to provide the appropriate asset rate for the requested
// intent.
type PriceQueryIntent uint8

const (
	// IntentUnspecified is used to indicate that the intent of the price
	// rate query is not specified. This is the fallback default value and
	// should not be used in production code. It is primarily used for
	// backward compatibility with older versions of the protocol that did
	// not include intent information.
	IntentUnspecified PriceQueryIntent = 0

	// IntentPayInvoiceHint is used to indicate that the user is requesting
	// a price rate hint for paying an invoice. This is typically used by
	// the payer of an invoice to provide a suggestion of the expected asset
	// rate to the RFQ peer (edge node) that will determine the actual rate
	// for the payment.
	IntentPayInvoiceHint PriceQueryIntent = 1

	// IntentPayInvoice is used to indicate that a peer wants to pay an
	// invoice with assets. This is typically used by the edge node that
	// facilitates the swap from assets to BTC for the payer of an invoice.
	// This intent is used to provide the actual asset rate for the payment,
	// which may differ from the hint provided by the payer.
	IntentPayInvoice PriceQueryIntent = 2

	// IntentPayInvoiceQualify is used to indicate that the payer of an
	// invoice has received an asset rate from their RFQ peer (edge node)
	// and is qualifying the rate for the payment. This is typically used by
	// the payer of an invoice to ensure that the asset rate provided by
	// their peer (edge node) is acceptable before proceeding with the
	// payment.
	IntentPayInvoiceQualify PriceQueryIntent = 3

	// IntentRecvPaymentHint is used to indicate that the user is requesting
	// a price rate hint for receiving a payment through an invoice. This is
	// typically used by the creator of an invoice to provide a suggestion
	// of the expected asset rate to the RFQ peer (edge node) that will
	// determine the actual rate used for creating an invoice.
	IntentRecvPaymentHint PriceQueryIntent = 4

	// IntentRecvPayment is used to indicate that a peer wants to create an
	// invoice to receive a payment with assets. This is typically used by
	// the edge node that facilitates the swap from BTC to assets for the
	// receiver of a payment. This intent is used to provide the actual
	// asset rate for the invoice creation, which may differ from the hint
	// provided by the receiver.
	IntentRecvPayment PriceQueryIntent = 5

	// IntentRecvPaymentQualify is used to indicate that the creator of an
	// invoice received an asset rate from their RFQ peer (edge node) and is
	// qualifying the rate for the creation of the invoice. This is
	// typically used by the creator of an invoice to ensure that the asset
	// rate provided by their peer (edge node) is acceptable before
	// proceeding with creating the invoice.
	IntentRecvPaymentQualify PriceQueryIntent = 6
)

// OracleError is a struct that holds an error returned by the price oracle
// service.
type OracleError struct {
	// Code is a code which uniquely identifies the error type.
	Code OracleErrorCode

	// Msg is a human-readable error message.
	Msg string
}

// OracleErrorCode uniquely identifies the kinds of error an oracle may
// return.
type OracleErrorCode uint8

const (
	// UnspecifiedOracleErrorCode represents the case where the oracle has
	// declined to give a more specific reason for the error.
	UnspecifiedOracleErrorCode OracleErrorCode = 0

	// UnsupportedAssetOracleErrorCode represents the case in which an
	// oracle does not provide quotes for the requested asset.
	UnsupportedAssetOracleErrorCode OracleErrorCode = 1
)

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
	// QuerySellPrice returns the sell price for a given asset amount. The
	// sell price is the amount the oracle suggests a peer should accept
	// from another peer to provide the specified asset amount.
	QuerySellPrice(ctx context.Context, assetSpecifier asset.Specifier,
		assetMaxAmt fn.Option[uint64],
		paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
		assetRateHint fn.Option[rfqmsg.AssetRate],
		counterparty fn.Option[route.Vertex], metadata string,
		intent PriceQueryIntent) (*OracleResponse, error)

	// QueryBuyPrice returns the buy price for a given asset amount. The buy
	// price is the amount the oracle suggests a peer should pay to another
	// peer to receive the specified asset amount.
	QueryBuyPrice(ctx context.Context, assetSpecifier asset.Specifier,
		assetMaxAmt fn.Option[uint64],
		paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
		assetRateHint fn.Option[rfqmsg.AssetRate],
		counterparty fn.Option[route.Vertex], metadata string,
		intent PriceQueryIntent) (*OracleResponse, error)
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

// clientKeepaliveDialOption configures bidirectional health probing to prevent
// idle RFQ connections from being silently terminated by network intermediaries
// (NATs, load balancers) or aggressive server timeouts. Without active
// keepalive, the first price query after an idle period would fail with
// "connection reset by peer" and require a retry.
var clientKeepaliveDialOption = grpc.WithKeepaliveParams(
	keepalive.ClientParameters{
		// Ping server after 30 seconds of inactivity.
		Time: 30 * time.Second,

		// Wait 20 seconds for ping response.
		Timeout: 20 * time.Second,

		// Permit keepalive pings even when there are no active
		// streams. This is critical for long-lived connections with
		// infrequent RFQ requests.
		PermitWithoutStream: true,
	},
)

// serverDialOpts returns the set of server options needed to connect to the
// price oracle RPC server using a TLS connection.
func serverDialOpts() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	tlsConfig := tls.Config{InsecureSkipVerify: true}
	transportCredentials := credentials.NewTLS(&tlsConfig)

	opts = append(opts, grpc.WithTransportCredentials(transportCredentials))

	opts = append(opts, clientKeepaliveDialOption)

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

	opts = append(opts, clientKeepaliveDialOption)

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

// QuerySellPrice returns the sell price for the given asset amount.
func (r *RpcPriceOracle) QuerySellPrice(ctx context.Context,
	assetSpecifier asset.Specifier, assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate],
	counterparty fn.Option[route.Vertex], metadata string,
	intent PriceQueryIntent) (*OracleResponse, error) {

	if len(metadata) > rfqmsg.MaxOracleMetadataLength {
		return nil, fmt.Errorf("metadata exceeds maximum length of %d "+
			"bytes: %d bytes", rfqmsg.MaxOracleMetadataLength,
			len(metadata))
	}

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

	rpcIntent, err := rpcMarshalIntent(intent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal intent: %w", err)
	}

	var counterpartyBytes []byte
	counterparty.WhenSome(func(c route.Vertex) {
		counterpartyBytes = c[:]
	})

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
		Intent:                rpcIntent,
		CounterpartyId:        counterpartyBytes,
		Metadata:              metadata,
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

// QueryBuyPrice returns a buy price for the given asset amount.
func (r *RpcPriceOracle) QueryBuyPrice(ctx context.Context,
	assetSpecifier asset.Specifier, assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate],
	counterparty fn.Option[route.Vertex], metadata string,
	intent PriceQueryIntent) (*OracleResponse, error) {

	if len(metadata) > rfqmsg.MaxOracleMetadataLength {
		return nil, fmt.Errorf("metadata exceeds maximum length of %d "+
			"bytes: %d bytes", rfqmsg.MaxOracleMetadataLength,
			len(metadata))
	}

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

	rpcIntent, err := rpcMarshalIntent(intent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal intent: %w", err)
	}

	var counterpartyBytes []byte
	counterparty.WhenSome(func(c route.Vertex) {
		counterpartyBytes = c[:]
	})

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
		Intent:                rpcIntent,
		CounterpartyId:        counterpartyBytes,
		Metadata:              metadata,
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

// rpcMarshalIntent converts a PriceQueryIntent to the corresponding
// oraclerpc.Intent type. It returns an error if the intent is unknown.
func rpcMarshalIntent(intent PriceQueryIntent) (oraclerpc.Intent,
	error) {

	switch intent {
	case IntentUnspecified:
		return oraclerpc.Intent_INTENT_UNSPECIFIED, nil
	case IntentPayInvoiceHint:
		return oraclerpc.Intent_INTENT_PAY_INVOICE_HINT, nil
	case IntentPayInvoice:
		return oraclerpc.Intent_INTENT_PAY_INVOICE, nil
	case IntentPayInvoiceQualify:
		return oraclerpc.Intent_INTENT_PAY_INVOICE_QUALIFY, nil
	case IntentRecvPaymentHint:
		return oraclerpc.Intent_INTENT_RECV_PAYMENT_HINT, nil
	case IntentRecvPayment:
		return oraclerpc.Intent_INTENT_RECV_PAYMENT, nil
	case IntentRecvPaymentQualify:
		return oraclerpc.Intent_INTENT_RECV_PAYMENT_QUALIFY, nil
	default:
		return 0, fmt.Errorf("unknown price query intent: %d", intent)
	}
}
