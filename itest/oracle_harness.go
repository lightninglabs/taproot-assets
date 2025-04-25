package itest

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// oracleHarness is a basic integration test RPC price oracle server harness.
type oracleHarness struct {
	oraclerpc.UnimplementedPriceOracleServer

	listenAddr string

	grpcListener net.Listener
	grpcServer   *grpc.Server

	// bidPrices is a map used internally by the oracle harness to store bid
	// prices for certain assets. We use the asset specifier string as a
	// unique identifier, since it will either contain an asset ID or a
	// group key.
	bidPrices map[string]rfqmath.BigIntFixedPoint

	// askPrices is a map used internally by the oracle harness to store ask
	// prices for certain assets. We use the asset specifier string as a
	// unique identifier, since it will either contain an asset ID or a
	// group key.
	askPrices map[string]rfqmath.BigIntFixedPoint
}

// newOracleHarness returns a new oracle harness instance that is set to listen
// on the provided address.
func newOracleHarness(listenAddr string) *oracleHarness {
	return &oracleHarness{
		listenAddr: listenAddr,
		bidPrices:  make(map[string]rfqmath.BigIntFixedPoint),
		askPrices:  make(map[string]rfqmath.BigIntFixedPoint),
	}
}

// setPrice sets the target bid and ask price for the provided specifier.
func (o *oracleHarness) setPrice(specifier asset.Specifier, bidPrice,
	askPrice rfqmath.BigIntFixedPoint) {

	o.bidPrices[specifier.String()] = bidPrice
	o.askPrices[specifier.String()] = askPrice
}

// start runs the oracle harness.
func (o *oracleHarness) start(t *testing.T) {
	// Start the mock RPC price oracle service.
	//
	// Generate self-signed certificate. This allows us to use TLS for the
	// gRPC server.
	tlsCert, err := generateSelfSignedCert()
	require.NoError(t, err)

	// Create the gRPC server with TLS
	transportCredentials := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	o.grpcServer = grpc.NewServer(grpc.Creds(transportCredentials))

	serviceAddr := fmt.Sprintf("rfqrpc://%s", o.listenAddr)
	log.Infof("Starting RPC price oracle service at address: %s\n",
		serviceAddr)

	oraclerpc.RegisterPriceOracleServer(o.grpcServer, o)

	go func() {
		var err error
		o.grpcListener, err = net.Listen("tcp", o.listenAddr)
		if err != nil {
			log.Errorf("Error oracle listening: %v", err)
			return
		}
		if err := o.grpcServer.Serve(o.grpcListener); err != nil {
			log.Errorf("Error oracle serving: %v", err)
		}
	}()
}

// stop terminates the oracle harness.
func (o *oracleHarness) stop() {
	if o.grpcServer != nil {
		o.grpcServer.Stop()
	}
	if o.grpcListener != nil {
		_ = o.grpcListener.Close()
	}
}

// getAssetRates returns the asset rates for a given transaction type.
func (o *oracleHarness) getAssetRates(specifier asset.Specifier,
	transactionType oraclerpc.TransactionType) (oraclerpc.AssetRates,
	error) {

	// Determine the rate based on the transaction type.
	var subjectAssetRate rfqmath.BigIntFixedPoint
	if transactionType == oraclerpc.TransactionType_PURCHASE {
		rate, ok := o.bidPrices[specifier.String()]
		if !ok {
			return oraclerpc.AssetRates{}, fmt.Errorf("purchase "+
				"price not found for %s", specifier.String())
		}
		subjectAssetRate = rate
	} else {
		rate, ok := o.askPrices[specifier.String()]
		if !ok {
			return oraclerpc.AssetRates{}, fmt.Errorf("sale "+
				"price not found for %s", specifier.String())
		}
		subjectAssetRate = rate
	}

	// Marshal subject asset rate to RPC format.
	rpcSubjectAssetToBtcRate, err := rpcutils.MarshalBigIntFixedPoint(
		subjectAssetRate,
	)
	if err != nil {
		return oraclerpc.AssetRates{}, err
	}

	// Marshal payment asset rate to RPC format.
	rpcPaymentAssetToBtcRate, err := rpcutils.MarshalBigIntFixedPoint(
		rfqmsg.MilliSatPerBtc,
	)
	if err != nil {
		return oraclerpc.AssetRates{}, err
	}

	expiry := time.Now().Add(5 * time.Minute).Unix()
	return oraclerpc.AssetRates{
		SubjectAssetRate: rpcSubjectAssetToBtcRate,
		PaymentAssetRate: rpcPaymentAssetToBtcRate,
		ExpiryTimestamp:  uint64(expiry),
	}, nil
}

// QueryAssetRates queries the asset rates for a given transaction type, subject
// asset, and payment asset. An asset rate is the number of asset units per
// BTC.
//
// Example use case:
//
// Alice is trying to pay an invoice by spending an asset. Alice therefore
// requests that Bob (her asset channel counterparty) purchase the asset from
// her. Bob's payment, in BTC, will pay the invoice.
//
// Alice requests a bid quote from Bob. Her request includes an asset rates hint
// (ask). Alice obtains the asset rates hint by calling this endpoint. She sets:
// - `SubjectAsset` to the asset she is trying to sell.
// - `SubjectAssetMaxAmount` to the max channel asset outbound.
// - `PaymentAsset` to BTC.
// - `TransactionType` to SALE.
// - `AssetRateHint` to nil.
//
// Bob calls this endpoint to get the bid quote asset rates that he will send as
// a response to Alice's request. He sets:
// - `SubjectAsset` to the asset that Alice is trying to sell.
// - `SubjectAssetMaxAmount` to the value given in Alice's quote request.
// - `PaymentAsset` to BTC.
// - `TransactionType` to PURCHASE.
// - `AssetRateHint` to the value given in Alice's quote request.
func (o *oracleHarness) QueryAssetRates(_ context.Context,
	req *oraclerpc.QueryAssetRatesRequest) (
	*oraclerpc.QueryAssetRatesResponse, error) {

	// Ensure that the payment asset is BTC. We only support BTC as the
	// payment asset in this example.
	if !rpcutils.IsAssetBtc(req.PaymentAsset) {
		log.Infof("Payment asset is not BTC: %v", req.PaymentAsset)

		return &oraclerpc.QueryAssetRatesResponse{
			Result: &oraclerpc.QueryAssetRatesResponse_Error{
				Error: &oraclerpc.QueryAssetRatesErrResponse{
					Message: "unsupported payment asset, " +
						"only BTC is supported",
				},
			},
		}, nil
	}

	// Ensure that the subject asset is set correctly.
	specifier, err := parseSubjectAsset(req.SubjectAsset)
	if err != nil {
		log.Errorf("Error parsing subject asset: %v", err)
		return nil, fmt.Errorf("error parsing subject asset: %w", err)
	}

	_, hasPurchase := o.bidPrices[specifier.String()]
	_, hasSale := o.askPrices[specifier.String()]

	log.Infof("Have for %s, purchase=%v, sale=%v", specifier.String(),
		hasPurchase, hasSale)

	// Ensure that the subject asset is supported.
	if !hasPurchase || !hasSale {
		log.Infof("Unsupported subject specifier: %v\n",
			req.SubjectAsset)

		return &oraclerpc.QueryAssetRatesResponse{
			Result: &oraclerpc.QueryAssetRatesResponse_Error{
				Error: &oraclerpc.QueryAssetRatesErrResponse{
					Message: "unsupported subject asset",
				},
			},
		}, nil
	}

	assetRates, err := o.getAssetRates(specifier, req.TransactionType)
	if err != nil {
		return nil, err
	}

	log.Infof("QueryAssetRates returning rates (subject_asset_rate=%v, "+
		"payment_asset_rate=%v)", assetRates.SubjectAssetRate,
		assetRates.PaymentAssetRate)

	return &oraclerpc.QueryAssetRatesResponse{
		Result: &oraclerpc.QueryAssetRatesResponse_Ok{
			Ok: &oraclerpc.QueryAssetRatesOkResponse{
				AssetRates: &assetRates,
			},
		},
	}, nil
}

// parseSubjectAsset parses the subject asset from the given asset specifier.
func parseSubjectAsset(subjectAsset *oraclerpc.AssetSpecifier) (asset.Specifier,
	error) {

	// Ensure that the subject asset is set.
	if subjectAsset == nil {
		return asset.Specifier{}, fmt.Errorf("subject asset is not " +
			"set (nil)")
	}

	// Check the subject asset bytes if set.
	var specifier asset.Specifier
	switch {
	case len(subjectAsset.GetAssetId()) > 0:
		var assetID asset.ID
		copy(assetID[:], subjectAsset.GetAssetId())
		specifier = asset.NewSpecifierFromId(assetID)

	case len(subjectAsset.GetAssetIdStr()) > 0:
		assetIDBytes, err := hex.DecodeString(
			subjectAsset.GetAssetIdStr(),
		)
		if err != nil {
			return asset.Specifier{}, fmt.Errorf("error decoding "+
				"asset ID hex string: %w", err)
		}

		var assetID asset.ID
		copy(assetID[:], assetIDBytes)
		specifier = asset.NewSpecifierFromId(assetID)

	case len(subjectAsset.GetGroupKey()) > 0:
		groupKeyBytes := subjectAsset.GetGroupKey()
		groupKey, err := btcec.ParsePubKey(groupKeyBytes)
		if err != nil {
			return asset.Specifier{}, fmt.Errorf("error decoding "+
				"asset group key: %w", err)
		}

		specifier = asset.NewSpecifierFromGroupKey(*groupKey)

	case len(subjectAsset.GetGroupKeyStr()) > 0:
		groupKeyBytes, err := hex.DecodeString(
			subjectAsset.GetGroupKeyStr(),
		)
		if err != nil {
			return asset.Specifier{}, fmt.Errorf("error decoding "+
				" asset group key string: %w", err)
		}

		groupKey, err := btcec.ParsePubKey(groupKeyBytes)
		if err != nil {
			return asset.Specifier{}, fmt.Errorf("error decoding "+
				"asset group key: %w", err)
		}

		specifier = asset.NewSpecifierFromGroupKey(*groupKey)

	default:
		return asset.Specifier{}, fmt.Errorf("subject asset " +
			"specifier is empty")
	}

	return specifier, nil
}

// generateSelfSignedCert generates a self-signed TLS certificate and private
// key.
func generateSelfSignedCert() (tls.Certificate, error) {
	certBytes, keyBytes, err := cert.GenCertPair(
		"itest price oracle", nil, nil, false, 24*time.Hour,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}
