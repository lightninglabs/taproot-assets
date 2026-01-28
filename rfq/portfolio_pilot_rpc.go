package rfq

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	//nolint:lll
	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightningnetwork/lnd/routing/route"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// PortfolioPilotAddr is a type alias for a URL type that represents a
// portfolio pilot service address.
type PortfolioPilotAddr = url.URL

const (
	// PortfolioPilotRpcAddrScheme is the URL address scheme used by an RPC
	// portfolio pilot service.
	PortfolioPilotRpcAddrScheme string = "portfoliopilotrpc"
)

// ParsePortfolioPilotAddress parses a portfolio pilot service address string
// and returns a URL type instance.
func ParsePortfolioPilotAddress(addrStr string) (*PortfolioPilotAddr, error) {
	// Basic sanity check to ensure the address is not empty.
	if addrStr == "" {
		return nil, fmt.Errorf("portfolio pilot address is an " +
			"empty string")
	}

	// Parse the portfolio pilot address.
	addr, err := url.ParseRequestURI(addrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid portfolio pilot service "+
			"URI address: %w", err)
	}

	// Ensure that the portfolio pilot address scheme is valid.
	if addr.Scheme != PortfolioPilotRpcAddrScheme {
		return nil, fmt.Errorf("unknown portfolio pilot protocol "+
			"(consider updating tapd): %v", addr.Scheme)
	}

	return addr, nil
}

// RpcPortfolioPilot is a portfolio pilot that uses an external RPC server to
// evaluate RFQ requests and asset rates.
type RpcPortfolioPilot struct {
	// client is the RPC client that this instance will use to interact with
	// the portfolio pilot RPC server.
	client pilotrpc.PortfolioPilotClient

	// rawConn is the raw connection to the remote gRPC service.
	rawConn *grpc.ClientConn
}

// portfolioPilotDialOpts returns gRPC dial options for the portfolio pilot.
func portfolioPilotDialOpts(insecureDial bool) []grpc.DialOption {
	var creds credentials.TransportCredentials
	if insecureDial {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		})
	}

	return []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	}
}

// NewRpcPortfolioPilot creates a new RPC portfolio pilot handle given the
// address of the portfolio pilot RPC server.
func NewRpcPortfolioPilot(addrStr string, dialInsecure bool) (
	*RpcPortfolioPilot, error) {

	addr, err := ParsePortfolioPilotAddress(addrStr)
	if err != nil {
		return nil, fmt.Errorf("parse portfolio pilot address: %w",
			err)
	}

	dialOpts := portfolioPilotDialOpts(dialInsecure)

	// Formulate the server address dial string.
	serverAddr := fmt.Sprintf("%s:%s", addr.Hostname(), addr.Port())

	conn, err := grpc.NewClient(serverAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial portfolio pilot RPC: %w", err)
	}

	// Create a new portfolio pilot client from the active connection.
	client := pilotrpc.NewPortfolioPilotClient(conn)

	return &RpcPortfolioPilot{
		client:  client,
		rawConn: conn,
	}, nil
}

// ResolveRequest resolves a quote request by calling the portfolio pilot RPC
// server.
func (r *RpcPortfolioPilot) ResolveRequest(ctx context.Context,
	request rfqmsg.Request) (ResolveResp, error) {

	var zero ResolveResp

	if request == nil {
		return zero, fmt.Errorf("request is nil")
	}

	rpcReq, err := rpcMarshalResolveRequest(request)
	if err != nil {
		return zero, fmt.Errorf("marshal resolve request: %w", err)
	}

	resp, err := r.client.ResolveRequest(ctx, rpcReq)
	if err != nil {
		return zero, fmt.Errorf("resolve request RPC: %w", err)
	}

	switch result := resp.GetResult().(type) {
	case *pilotrpc.ResolveRequestResponse_Accept:
		if result.Accept == nil {
			return zero, fmt.Errorf("ResolveRequest response " +
				"is successful but asset rate is nil")
		}

		assetRate, err := rpcutils.UnmarshalPortfolioAssetRate(
			result.Accept,
		)
		if err != nil {
			return zero, fmt.Errorf("unmarshal accept rate: %w",
				err)
		}

		return NewAcceptResolveResp(*assetRate), nil

	case *pilotrpc.ResolveRequestResponse_Reject:
		if result.Reject == nil {
			return zero, fmt.Errorf("ResolveRequest response " +
				"is reject but reject is nil")
		}

		rejectErr := rfqmsg.RejectErr{
			Code: rpcUnmarshalRejectCode(result.Reject.Code),
			Msg:  result.Reject.Message,
		}

		return NewRejectResolveResp(rejectErr), nil

	default:
		return zero, fmt.Errorf("unexpected response type: %T",
			result)
	}
}

// VerifyAcceptQuote verifies an accepted quote by calling the portfolio pilot
// RPC server.
func (r *RpcPortfolioPilot) VerifyAcceptQuote(ctx context.Context,
	accept rfqmsg.Accept) (QuoteRespStatus, error) {

	if accept == nil {
		return PortfolioPilotErrQuoteRespStatus,
			fmt.Errorf("accept message is nil")
	}

	rpcReq, err := rpcMarshalVerifyAcceptQuoteRequest(accept)
	if err != nil {
		return PortfolioPilotErrQuoteRespStatus,
			fmt.Errorf("marshal verify accept request: %w", err)
	}

	resp, err := r.client.VerifyAcceptQuote(ctx, rpcReq)
	if err != nil {
		return PortfolioPilotErrQuoteRespStatus,
			fmt.Errorf("verify accept quote RPC: %w", err)
	}

	status, err := rpcUnmarshalQuoteRespStatus(resp.Status)
	if err != nil {
		return PortfolioPilotErrQuoteRespStatus,
			fmt.Errorf("unmarshal quote status: %w", err)
	}

	return status, nil
}

// QueryAssetRates returns current asset rate information by calling the
// portfolio pilot RPC server.
func (r *RpcPortfolioPilot) QueryAssetRates(ctx context.Context,
	query AssetRateQuery) (rfqmsg.AssetRate, error) {

	var zero rfqmsg.AssetRate

	rpcReq, err := rpcMarshalQueryAssetRatesRequest(query)
	if err != nil {
		return zero, fmt.Errorf("marshal asset rate query: %w", err)
	}

	resp, err := r.client.QueryAssetRates(ctx, rpcReq)
	if err != nil {
		return zero, fmt.Errorf("query asset rates RPC: %w", err)
	}

	if resp.AssetRate == nil {
		return zero, fmt.Errorf("QueryAssetRates response " +
			"asset rate is nil")
	}

	assetRate, err := rpcutils.UnmarshalPortfolioAssetRate(
		resp.AssetRate,
	)
	if err != nil {
		return zero, fmt.Errorf("unmarshal asset rate: %w", err)
	}

	return *assetRate, nil
}

// Ensure that RpcPortfolioPilot implements the PortfolioPilot interface.
var _ PortfolioPilot = (*RpcPortfolioPilot)(nil)

// rpcMarshalResolveRequest converts a typed RFQ request to its RPC form.
func rpcMarshalResolveRequest(
	request rfqmsg.Request) (*pilotrpc.ResolveRequestRequest,
	error) {

	switch req := request.(type) {
	case *rfqmsg.BuyRequest:
		rpcBuyRequest, err := rpcMarshalBuyRequest(req)
		if err != nil {
			return nil, fmt.Errorf("marshal buy request: %w", err)
		}

		rpcReq := &pilotrpc.ResolveRequestRequest_BuyRequest{
			BuyRequest: rpcBuyRequest,
		}
		return &pilotrpc.ResolveRequestRequest{
			Request: rpcReq,
		}, nil

	case *rfqmsg.SellRequest:
		rpcSellRequest, err := rpcMarshalSellRequest(req)
		if err != nil {
			return nil, fmt.Errorf("marshal sell request: %w", err)
		}

		rpcReq := &pilotrpc.ResolveRequestRequest_SellRequest{
			SellRequest: rpcSellRequest,
		}
		return &pilotrpc.ResolveRequestRequest{
			Request: rpcReq,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported request type %T", req)
	}
}

// rpcMarshalVerifyAcceptQuoteRequest converts an accept message to RPC.
func rpcMarshalVerifyAcceptQuoteRequest(
	accept rfqmsg.Accept) (*pilotrpc.VerifyAcceptQuoteRequest,
	error) {

	switch msg := accept.(type) {
	case *rfqmsg.BuyAccept:
		rpcRequest, err := rpcMarshalBuyRequest(&msg.Request)
		if err != nil {
			return nil, fmt.Errorf("marshal buy request: %w", err)
		}

		rpcAcceptedRate, err := rpcutils.MarshalPortfolioAssetRate(
			msg.AcceptedRate(),
		)
		if err != nil {
			return nil, fmt.Errorf("marshal accepted rate: %w", err)
		}

		peer := msg.MsgPeer()
		requestWrapper := &pilotrpc.AcceptedQuote_BuyRequest{
			BuyRequest: rpcRequest,
		}
		return &pilotrpc.VerifyAcceptQuoteRequest{
			Accept: &pilotrpc.AcceptedQuote{
				PeerId:       peer[:],
				AcceptedRate: rpcAcceptedRate,
				Request:      requestWrapper,
			},
		}, nil

	case *rfqmsg.SellAccept:
		rpcRequest, err := rpcMarshalSellRequest(&msg.Request)
		if err != nil {
			return nil, fmt.Errorf("marshal sell request: %w", err)
		}

		rpcAcceptedRate, err := rpcutils.MarshalPortfolioAssetRate(
			msg.AcceptedRate(),
		)
		if err != nil {
			return nil, fmt.Errorf("marshal accepted rate: %w", err)
		}

		peer := msg.MsgPeer()
		requestWrapper := &pilotrpc.AcceptedQuote_SellRequest{
			SellRequest: rpcRequest,
		}
		return &pilotrpc.VerifyAcceptQuoteRequest{
			Accept: &pilotrpc.AcceptedQuote{
				PeerId:       peer[:],
				AcceptedRate: rpcAcceptedRate,
				Request:      requestWrapper,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported accept type %T", msg)
	}
}

// rpcMarshalQueryAssetRatesRequest converts an asset rate query to RPC.
func rpcMarshalQueryAssetRatesRequest(query AssetRateQuery) (
	*pilotrpc.QueryAssetRatesRequest, error) {

	if len(query.OracleMetadata.UnwrapOr("")) >
		rfqmsg.MaxOracleMetadataLength {

		return nil, fmt.Errorf("metadata exceeds maximum length of %d "+
			"bytes: %d bytes", rfqmsg.MaxOracleMetadataLength,
			len(query.OracleMetadata.UnwrapOr("")))
	}

	rpcDirection, err := rpcMarshalAssetTransferDirection(
		query.Direction,
	)
	if err != nil {
		return nil, fmt.Errorf("marshal transfer direction: %w",
			err)
	}

	rpcIntent, err := rpcMarshalPortfolioIntent(query.Intent)
	if err != nil {
		return nil, fmt.Errorf("marshal intent: %w", err)
	}

	var rpcRateHint *pilotrpc.AssetRate
	var rateHintErr error
	query.RateHint.WhenSome(func(rate rfqmsg.AssetRate) {
		rpcRateHint, rateHintErr =
			rpcutils.MarshalPortfolioAssetRate(rate)
	})
	if rateHintErr != nil {
		return nil, fmt.Errorf("marshal rate hint: %w", rateHintErr)
	}

	var peerID []byte
	query.PeerID.WhenSome(func(peer route.Vertex) {
		peerID = peer[:]
	})

	var expiryTimestamp uint64
	var expiryErr error
	query.Expiry.WhenSome(func(expiry time.Time) {
		if expiry.Unix() < 0 {
			expiryErr = fmt.Errorf(
				"expiry timestamp before unix epoch",
			)
			return
		}
		expiryTimestamp = uint64(expiry.Unix())
	})
	if expiryErr != nil {
		return nil, fmt.Errorf("marshal expiry timestamp: %w",
			expiryErr)
	}

	rpcSpecifier :=
		rpcMarshalPortfolioAssetSpecifier(query.AssetSpecifier)
	return &pilotrpc.QueryAssetRatesRequest{
		AssetSpecifier:      rpcSpecifier,
		Direction:           rpcDirection,
		Intent:              rpcIntent,
		AssetAmount:         query.AssetAmount.UnwrapOr(0),
		PaymentAmount:       uint64(query.PaymentAmount.UnwrapOr(0)),
		AssetRateHint:       rpcRateHint,
		PriceOracleMetadata: query.OracleMetadata.UnwrapOr(""),
		PeerId:              peerID,
		ExpiryTimestamp:     expiryTimestamp,
	}, nil
}

// rpcMarshalBuyRequest converts a buy request to its RPC form.
func rpcMarshalBuyRequest(
	req *rfqmsg.BuyRequest) (*pilotrpc.BuyRequest, error) {

	if req == nil {
		return nil, fmt.Errorf("buy request is nil")
	}

	if len(req.PriceOracleMetadata) > rfqmsg.MaxOracleMetadataLength {
		return nil, fmt.Errorf("metadata exceeds maximum length of %d "+
			"bytes: %d bytes", rfqmsg.MaxOracleMetadataLength,
			len(req.PriceOracleMetadata))
	}

	var rpcRateHint *pilotrpc.AssetRate
	var err error
	req.AssetRateHint.WhenSome(func(rate rfqmsg.AssetRate) {
		rpcRateHint, err = rpcutils.MarshalPortfolioAssetRate(rate)
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rate hint: %w", err)
	}

	peer := req.MsgPeer()
	rpcSpecifier := rpcMarshalPortfolioAssetSpecifier(req.AssetSpecifier)
	return &pilotrpc.BuyRequest{
		AssetSpecifier:      rpcSpecifier,
		AssetMaxAmount:      req.AssetMaxAmt,
		AssetRateHint:       rpcRateHint,
		PriceOracleMetadata: req.PriceOracleMetadata,
		PeerId:              peer[:],
	}, nil
}

// rpcMarshalSellRequest converts a sell request to its RPC form.
func rpcMarshalSellRequest(
	req *rfqmsg.SellRequest) (*pilotrpc.SellRequest, error) {

	if req == nil {
		return nil, fmt.Errorf("sell request is nil")
	}

	if len(req.PriceOracleMetadata) > rfqmsg.MaxOracleMetadataLength {
		return nil, fmt.Errorf("metadata exceeds maximum length of %d "+
			"bytes: %d bytes", rfqmsg.MaxOracleMetadataLength,
			len(req.PriceOracleMetadata))
	}

	var rpcRateHint *pilotrpc.AssetRate
	var err error
	req.AssetRateHint.WhenSome(func(rate rfqmsg.AssetRate) {
		rpcRateHint, err = rpcutils.MarshalPortfolioAssetRate(rate)
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rate hint: %w", err)
	}

	peer := req.MsgPeer()
	rpcSpecifier := rpcMarshalPortfolioAssetSpecifier(req.AssetSpecifier)
	return &pilotrpc.SellRequest{
		AssetSpecifier:      rpcSpecifier,
		PaymentMaxAmount:    uint64(req.PaymentMaxAmt),
		AssetRateHint:       rpcRateHint,
		PriceOracleMetadata: req.PriceOracleMetadata,
		PeerId:              peer[:],
	}, nil
}

// rpcMarshalPortfolioAssetSpecifier converts a specifier to its RPC form.
func rpcMarshalPortfolioAssetSpecifier(
	assetSpecifier asset.Specifier) *pilotrpc.AssetSpecifier {

	var rpcSpecifier pilotrpc.AssetSpecifier

	switch {
	case assetSpecifier.HasId():
		assetID := assetSpecifier.UnwrapIdToPtr()
		rpcSpecifier.Id = &pilotrpc.AssetSpecifier_AssetId{
			AssetId: assetID[:],
		}

	case assetSpecifier.HasGroupPubKey():
		groupKey := assetSpecifier.UnwrapGroupKeyToPtr()
		rpcSpecifier.Id = &pilotrpc.AssetSpecifier_GroupKey{
			GroupKey: groupKey.SerializeCompressed(),
		}
	}

	return &rpcSpecifier
}

// rpcMarshalPortfolioIntent converts a query intent to its RPC enum.
func rpcMarshalPortfolioIntent(
	intent PriceQueryIntent) (pilotrpc.Intent, error) {

	switch intent {
	case IntentUnspecified:
		return pilotrpc.Intent_INTENT_UNSPECIFIED, nil
	case IntentPayInvoiceHint:
		return pilotrpc.Intent_INTENT_PAY_INVOICE_HINT, nil
	case IntentPayInvoice:
		return pilotrpc.Intent_INTENT_PAY_INVOICE, nil
	case IntentPayInvoiceQualify:
		return pilotrpc.Intent_INTENT_PAY_INVOICE_QUALIFY, nil
	case IntentRecvPaymentHint:
		return pilotrpc.Intent_INTENT_RECV_PAYMENT_HINT, nil
	case IntentRecvPayment:
		return pilotrpc.Intent_INTENT_RECV_PAYMENT, nil
	case IntentRecvPaymentQualify:
		return pilotrpc.Intent_INTENT_RECV_PAYMENT_QUALIFY, nil
	default:
		return 0, fmt.Errorf("unknown price query intent: %d", intent)
	}
}

// rpcMarshalAssetTransferDirection converts a transfer direction to its RPC
// enum.
func rpcMarshalAssetTransferDirection(
	direction AssetTransferDirection) (
	pilotrpc.AssetTransferDirection, error) {

	const (
		assetDirUnspecified = pilotrpc.AssetTransferDirection(0)
		assetDirBuy         = pilotrpc.AssetTransferDirection(1)
		assetDirSell        = pilotrpc.AssetTransferDirection(2)
	)

	switch direction {
	case AssetTransferUndefined:
		return assetDirUnspecified, nil
	case AssetTransferBuy:
		return assetDirBuy, nil
	case AssetTransferSell:
		return assetDirSell, nil
	default:
		return 0, fmt.Errorf("unknown asset transfer direction: %d",
			direction)
	}
}

// rpcUnmarshalQuoteRespStatus converts an RPC quote status to the local enum.
func rpcUnmarshalQuoteRespStatus(
	status pilotrpc.QuoteRespStatus) (QuoteRespStatus, error) {

	switch status {
	case pilotrpc.QuoteRespStatus_INVALID_ASSET_RATES:
		return InvalidAssetRatesQuoteRespStatus, nil
	case pilotrpc.QuoteRespStatus_INVALID_EXPIRY:
		return InvalidExpiryQuoteRespStatus, nil
	case pilotrpc.QuoteRespStatus_PRICE_ORACLE_QUERY_ERR:
		return PriceOracleQueryErrQuoteRespStatus, nil
	case pilotrpc.QuoteRespStatus_PORTFOLIO_PILOT_ERR:
		return PortfolioPilotErrQuoteRespStatus, nil
	case pilotrpc.QuoteRespStatus_VALID_ACCEPT_QUOTE:
		return ValidAcceptQuoteRespStatus, nil
	default:
		return 0, fmt.Errorf("unknown quote response status: %v",
			status)
	}
}

// rpcUnmarshalRejectCode converts an RPC reject code to the local enum.
func rpcUnmarshalRejectCode(
	code pilotrpc.RejectCode) rfqmsg.RejectCode {

	switch code {
	case pilotrpc.RejectCode_REJECT_CODE_UNSPECIFIED:
		return rfqmsg.PriceOracleUnspecifiedRejectCode
	case pilotrpc.RejectCode_REJECT_CODE_PRICE_ORACLE_UNAVAILABLE:
		return rfqmsg.PriceOracleUnavailableRejectCode
	default:
		return rfqmsg.PriceOracleUnspecifiedRejectCode
	}
}
