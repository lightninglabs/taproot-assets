package tapdb

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// rfqPolicy is the database model for an RFQ policy. It contains all the
// necessary fields to reconstruct a BuyAccept or SellAccept message.
type rfqPolicy struct {
	// PolicyType denotes the type of the policy (buy or sell).
	PolicyType rfq.RfqPolicyType

	// Scid is the short channel ID associated with the policy.
	Scid uint64

	// RfqID is the unique identifier for the RFQ session.
	RfqID [32]byte

	// Peer is the public key of the peer node.
	Peer [33]byte

	// AssetID is the optional specific asset ID.
	AssetID *[32]byte

	// AssetGroupKey is the optional asset group key.
	AssetGroupKey *[33]byte

	// RateCoefficient is the coefficient of the exchange rate.
	RateCoefficient []byte

	// RateScale is the scale of the exchange rate.
	RateScale uint8

	// ExpiryUnix is the expiration timestamp of the policy.
	ExpiryUnix uint64

	// MaxOutAssetAmt is the maximum asset amount for sale policies.
	MaxOutAssetAmt *uint64

	// PaymentMaxMsat is the maximum payment amount for purchase policies.
	PaymentMaxMsat *int64

	// RequestAssetMaxAmt is the requested maximum asset amount.
	RequestAssetMaxAmt *uint64

	// RequestPaymentMaxMsat is the requested maximum payment amount.
	RequestPaymentMaxMsat *int64

	// PriceOracleMetadata contains metadata about the price oracle.
	PriceOracleMetadata string

	// RequestVersion is the version of the RFQ request.
	RequestVersion *uint32

	// AgreedAt is the timestamp when the policy was agreed upon.
	AgreedAt time.Time
}

// RfqPolicyStore is the database interface for RFQ policies.
type RfqPolicyStore interface {
	// InsertRfqPolicy inserts a new RFQ policy into the database.
	InsertRfqPolicy(context.Context,
		sqlc.InsertRfqPolicyParams) (int64, error)

	// FetchActiveRfqPolicies retrieves all active RFQ policies from the
	// database.
	FetchActiveRfqPolicies(context.Context, int64) ([]sqlc.RfqPolicy, error)
}

// BatchedRfqPolicyStore supports batched database operations.
type BatchedRfqPolicyStore interface {
	RfqPolicyStore
	BatchedTx[RfqPolicyStore]
}

// PersistedPolicyStore offers helpers to persist and load RFQ policies.
type PersistedPolicyStore struct {
	db BatchedRfqPolicyStore
}

// NewPersistedPolicyStore creates a new policy persistence helper.
func NewPersistedPolicyStore(db BatchedRfqPolicyStore) *PersistedPolicyStore {
	return &PersistedPolicyStore{
		db: db,
	}
}

// StoreSalePolicy persists a buy-accept policy.
func (s *PersistedPolicyStore) StoreSalePolicy(ctx context.Context,
	acpt rfqmsg.BuyAccept) error {

	assetID, groupKey := specifierPointers(acpt.Request.AssetSpecifier)
	rateBytes := coefficientBytes(acpt.AssetRate.Rate)
	expiry := acpt.AssetRate.Expiry.UTC()

	record := rfqPolicy{
		PolicyType:          rfq.RfqPolicyTypeAssetSale,
		Scid:                uint64(acpt.ShortChannelId()),
		RfqID:               rfqIDArray(acpt.ID),
		Peer:                serializePeer(acpt.Peer),
		AssetID:             assetID,
		AssetGroupKey:       groupKey,
		RateCoefficient:     rateBytes,
		RateScale:           acpt.AssetRate.Rate.Scale,
		ExpiryUnix:          uint64(expiry.Unix()),
		MaxOutAssetAmt:      fn.Ptr(acpt.Request.AssetMaxAmt),
		RequestAssetMaxAmt:  fn.Ptr(acpt.Request.AssetMaxAmt),
		PriceOracleMetadata: acpt.Request.PriceOracleMetadata,
		RequestVersion:      fn.Ptr(uint32(acpt.Request.Version)),
		AgreedAt:            acpt.AgreedAt.UTC(),
	}

	return s.storePolicy(ctx, record)
}

// StorePurchasePolicy persists a sell-accept policy.
func (s *PersistedPolicyStore) StorePurchasePolicy(ctx context.Context,
	acpt rfqmsg.SellAccept) error {

	assetID, groupKey := specifierPointers(acpt.Request.AssetSpecifier)
	rateBytes := coefficientBytes(acpt.AssetRate.Rate)
	expiry := acpt.AssetRate.Expiry.UTC()
	paymentMax := int64(acpt.Request.PaymentMaxAmt)

	record := rfqPolicy{
		PolicyType:            rfq.RfqPolicyTypeAssetPurchase,
		Scid:                  uint64(acpt.ShortChannelId()),
		RfqID:                 rfqIDArray(acpt.ID),
		Peer:                  serializePeer(acpt.Peer),
		AssetID:               assetID,
		AssetGroupKey:         groupKey,
		RateCoefficient:       rateBytes,
		RateScale:             acpt.AssetRate.Rate.Scale,
		ExpiryUnix:            uint64(expiry.Unix()),
		PaymentMaxMsat:        fn.Ptr(paymentMax),
		RequestPaymentMaxMsat: fn.Ptr(paymentMax),
		PriceOracleMetadata:   acpt.Request.PriceOracleMetadata,
		RequestVersion:        fn.Ptr(uint32(acpt.Request.Version)),
		AgreedAt:              acpt.AgreedAt.UTC(),
	}

	return s.storePolicy(ctx, record)
}

func (s *PersistedPolicyStore) storePolicy(ctx context.Context,
	policy rfqPolicy) error {

	writeOpts := WriteTxOption()
	return s.db.ExecTx(ctx, writeOpts, func(q RfqPolicyStore) error {
		_, err := q.InsertRfqPolicy(ctx, newInsertParams(policy))
		if err != nil {
			return fmt.Errorf("error inserting RFQ policy: %w", err)
		}

		return nil
	})
}

// FetchAcceptedQuotes retrieves all non-expired policies from the database and
// returns them as buy and sell accepts.
func (s *PersistedPolicyStore) FetchAcceptedQuotes(ctx context.Context) (
	[]rfqmsg.BuyAccept, []rfqmsg.SellAccept, error) {

	readOpts := ReadTxOption()
	var (
		buyAccepts  []rfqmsg.BuyAccept
		sellAccepts []rfqmsg.SellAccept
	)
	now := time.Now().UTC()

	err := s.db.ExecTx(ctx, readOpts, func(q RfqPolicyStore) error {
		rows, err := q.FetchActiveRfqPolicies(ctx, now.Unix())
		if err != nil {
			return fmt.Errorf("error fetching policies: %w", err)
		}

		for _, row := range rows {
			policy := policyFromRow(row)

			switch policy.PolicyType {
			case rfq.RfqPolicyTypeAssetSale:
				accept, err := buyAcceptFromStored(policy)
				if err != nil {
					return fmt.Errorf("error restoring "+
						"sale policy: %w", err)
				}
				buyAccepts = append(buyAccepts, accept)

			case rfq.RfqPolicyTypeAssetPurchase:
				accept, err := sellAcceptFromStored(policy)
				if err != nil {
					return fmt.Errorf("error restoring "+
						"purchase policy: %w", err)
				}
				sellAccepts = append(sellAccepts, accept)

			default:
				// This should never happen by assertion.
				return fmt.Errorf("unknown policy type: %s",
					policy.PolicyType)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return buyAccepts, sellAccepts, nil
}

// newInsertParams creates the parameters for inserting an RFQ policy into the
// database.
func newInsertParams(policy rfqPolicy) sqlc.InsertRfqPolicyParams {
	params := sqlc.InsertRfqPolicyParams{
		PolicyType:      policy.PolicyType.String(),
		Scid:            int64(policy.Scid),
		RfqID:           policy.RfqID[:],
		Peer:            policy.Peer[:],
		RateCoefficient: append([]byte(nil), policy.RateCoefficient...),
		RateScale:       int32(policy.RateScale),
		Expiry:          int64(policy.ExpiryUnix),
		AgreedAt:        policy.AgreedAt.Unix(),
	}

	if policy.AssetID != nil {
		params.AssetID = policy.AssetID[:]
	}

	if policy.AssetGroupKey != nil {
		params.AssetGroupKey = policy.AssetGroupKey[:]
	}

	if policy.MaxOutAssetAmt != nil {
		params.MaxOutAssetAmt = sqlPtrInt64(policy.MaxOutAssetAmt)
		params.RequestAssetMaxAmt = sqlPtrInt64(policy.MaxOutAssetAmt)
	}

	if policy.PaymentMaxMsat != nil {
		params.PaymentMaxMsat = sqlPtrInt64(policy.PaymentMaxMsat)
		params.RequestPaymentMaxMsat = sqlPtrInt64(
			policy.PaymentMaxMsat,
		)
	}

	if policy.RequestAssetMaxAmt != nil {
		params.RequestAssetMaxAmt = sqlPtrInt64(
			policy.RequestAssetMaxAmt,
		)
	}

	if policy.RequestPaymentMaxMsat != nil {
		params.RequestPaymentMaxMsat = sqlPtrInt64(
			policy.RequestPaymentMaxMsat,
		)
	}

	params.PriceOracleMetadata = sqlStr(policy.PriceOracleMetadata)
	params.RequestVersion = sqlPtrInt32(policy.RequestVersion)

	return params
}

// policyFromRow converts a database row to an rfqPolicy struct.
func policyFromRow(row sqlc.RfqPolicy) rfqPolicy {
	var (
		rfqID [32]byte
		peer  [33]byte
	)
	copy(rfqID[:], row.RfqID)
	copy(peer[:], row.Peer)

	var assetIDPtr *[32]byte
	if len(row.AssetID) > 0 {
		var id [32]byte
		copy(id[:], row.AssetID)
		assetIDPtr = &id
	}

	var groupKeyPtr *[33]byte
	if len(row.AssetGroupKey) > 0 {
		var key [33]byte
		copy(key[:], row.AssetGroupKey)
		groupKeyPtr = &key
	}

	policy := rfqPolicy{
		PolicyType:      rfq.RfqPolicyType(row.PolicyType),
		Scid:            uint64(row.Scid),
		RfqID:           rfqID,
		Peer:            peer,
		AssetID:         assetIDPtr,
		AssetGroupKey:   groupKeyPtr,
		RateCoefficient: append([]byte(nil), row.RateCoefficient...),
		RateScale:       uint8(row.RateScale),
		ExpiryUnix:      uint64(row.Expiry),
		AgreedAt:        time.Unix(row.AgreedAt, 0).UTC(),
	}

	if row.PriceOracleMetadata.Valid {
		policy.PriceOracleMetadata = row.PriceOracleMetadata.String
	}

	policy.RequestVersion = extractSqlInt32Ptr[uint32](row.RequestVersion)
	policy.MaxOutAssetAmt = extractSqlInt64Ptr[uint64](row.MaxOutAssetAmt)
	policy.PaymentMaxMsat = extractSqlInt64Ptr[int64](row.PaymentMaxMsat)
	policy.RequestAssetMaxAmt = extractSqlInt64Ptr[uint64](
		row.RequestAssetMaxAmt,
	)
	policy.RequestPaymentMaxMsat = extractSqlInt64Ptr[int64](
		row.RequestPaymentMaxMsat,
	)

	return policy
}

// specifierPointers extracts pointers to asset ID and group key from a
// specifier.
func specifierPointers(spec asset.Specifier) (*[32]byte, *[33]byte) {
	var assetIDPtr *[32]byte
	if id := spec.UnwrapIdToPtr(); id != nil {
		assetID := new([32]byte)
		copy(assetID[:], id[:])
		assetIDPtr = assetID
	}

	var groupKeyPtr *[33]byte
	if key := spec.UnwrapGroupKeyToPtr(); key != nil {
		groupKey := new([33]byte)
		copy(groupKey[:], key.SerializeCompressed())
		groupKeyPtr = groupKey
	}

	return assetIDPtr, groupKeyPtr
}

// coefficientBytes returns the bytes of the rate coefficient.
func coefficientBytes(rate rfqmath.BigIntFixedPoint) []byte {
	coeff := rate.Coefficient.Bytes()
	if len(coeff) == 0 {
		return []byte{0}
	}

	return append([]byte(nil), coeff...)
}

// serializePeer serializes the peer public key.
func serializePeer(peer route.Vertex) [33]byte {
	var peerBytes [33]byte
	copy(peerBytes[:], peer[:])
	return peerBytes
}

// rfqIDArray converts an RFQ ID to a byte array.
func rfqIDArray(id rfqmsg.ID) [32]byte {
	var idBytes [32]byte
	copy(idBytes[:], id[:])
	return idBytes
}

// buyAcceptFromStored reconstructs a BuyAccept message from a stored policy.
func buyAcceptFromStored(row rfqPolicy) (rfqmsg.BuyAccept, error) {
	spec, err := assetSpecifierFromStored(row)
	if err != nil {
		return rfqmsg.BuyAccept{}, err
	}

	rate := rateFromStored(row)

	vertex := vertexFromBytes(row.Peer)
	id := rfqIDFromBytes(row.RfqID)

	version := rfqmsg.V1
	if row.RequestVersion != nil {
		version = rfqmsg.WireMsgDataVersion(*row.RequestVersion)
	}

	assetMax := row.RequestAssetMaxAmt
	if assetMax == nil {
		assetMax = row.MaxOutAssetAmt
	}

	expiry := time.Unix(int64(row.ExpiryUnix), 0).UTC()

	request := rfqmsg.BuyRequest{
		Peer:                vertex,
		Version:             version,
		ID:                  id,
		AssetSpecifier:      spec,
		AssetMaxAmt:         *assetMax,
		AssetRateHint:       fn.None[rfqmsg.AssetRate](),
		PriceOracleMetadata: row.PriceOracleMetadata,
	}

	return rfqmsg.BuyAccept{
		Peer:      vertex,
		Request:   request,
		Version:   rfqmsg.V1,
		ID:        id,
		AssetRate: rfqmsg.NewAssetRate(rate, expiry),
		AgreedAt:  row.AgreedAt,
	}, nil
}

// sellAcceptFromStored reconstructs a SellAccept message from a stored policy.
func sellAcceptFromStored(row rfqPolicy) (rfqmsg.SellAccept, error) {
	spec, err := assetSpecifierFromStored(row)
	if err != nil {
		return rfqmsg.SellAccept{}, err
	}

	rate := rateFromStored(row)

	vertex := vertexFromBytes(row.Peer)
	id := rfqIDFromBytes(row.RfqID)

	version := rfqmsg.V1
	if row.RequestVersion != nil {
		version = rfqmsg.WireMsgDataVersion(*row.RequestVersion)
	}

	paymentPtr := row.RequestPaymentMaxMsat
	if paymentPtr == nil {
		paymentPtr = row.PaymentMaxMsat
	}

	expiry := time.Unix(int64(row.ExpiryUnix), 0).UTC()

	request := rfqmsg.SellRequest{
		Peer:                vertex,
		Version:             version,
		ID:                  id,
		AssetSpecifier:      spec,
		PaymentMaxAmt:       lnwire.MilliSatoshi(*paymentPtr),
		AssetRateHint:       fn.None[rfqmsg.AssetRate](),
		PriceOracleMetadata: row.PriceOracleMetadata,
	}

	return rfqmsg.SellAccept{
		Peer:      vertex,
		Request:   request,
		Version:   rfqmsg.V1,
		ID:        id,
		AssetRate: rfqmsg.NewAssetRate(rate, expiry),
		AgreedAt:  row.AgreedAt,
	}, nil
}

// assetSpecifierFromStored reconstructs an asset specifier from a stored
// policy.
func assetSpecifierFromStored(row rfqPolicy) (asset.Specifier, error) {
	var idPtr *asset.ID
	if row.AssetID != nil {
		var id asset.ID
		copy(id[:], row.AssetID[:])
		idPtr = &id
	}

	var groupKey *btcec.PublicKey
	if row.AssetGroupKey != nil {
		key, err := btcec.ParsePubKey(row.AssetGroupKey[:])
		if err != nil {
			return asset.Specifier{}, fmt.Errorf("error parsing "+
				"group key: %w", err)
		}
		groupKey = key
	}

	return asset.NewSpecifier(idPtr, groupKey, nil, true)
}

// rateFromStored reconstructs the asset rate from a stored policy.
func rateFromStored(row rfqPolicy) rfqmath.BigIntFixedPoint {
	coeff := rfqmath.BigInt{}.FromBytes(row.RateCoefficient)
	return rfqmath.BigIntFixedPoint{
		Coefficient: coeff,
		Scale:       row.RateScale,
	}
}

// vertexFromBytes converts a byte array to a route.Vertex.
func vertexFromBytes(raw [33]byte) route.Vertex {
	var vertex route.Vertex
	copy(vertex[:], raw[:])
	return vertex
}

// rfqIDFromBytes converts a byte array to an RFQ ID.
func rfqIDFromBytes(raw [32]byte) rfqmsg.ID {
	var id rfqmsg.ID
	copy(id[:], raw[:])
	return id
}
