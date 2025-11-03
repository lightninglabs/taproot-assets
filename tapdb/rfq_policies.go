package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// RfqPolicyType denotes the type of a persisted RFQ policy.
type RfqPolicyType string

const (
	// RfqPolicyTypeAssetSale identifies an asset sale policy.
	RfqPolicyTypeAssetSale RfqPolicyType = "asset_sale"

	// RfqPolicyTypeAssetPurchase identifies an asset purchase policy.
	RfqPolicyTypeAssetPurchase RfqPolicyType = "asset_purchase"
)

// String converts the policy type to its string representation.
func (t RfqPolicyType) String() string {
	return string(t)
}

// rfqPolicy is the database model for an RFQ policy.
type rfqPolicy struct {
	PolicyType            RfqPolicyType
	Scid                  uint64
	RfqID                 [32]byte
	Peer                  [33]byte
	AssetID               *[32]byte
	AssetGroupKey         *[33]byte
	RateCoefficient       []byte
	RateScale             uint8
	ExpiryUnix            uint64
	MaxOutAssetAmt        *uint64
	PaymentMaxMsat        *int64
	RequestAssetMaxAmt    *uint64
	RequestPaymentMaxMsat *int64
	PriceOracleMetadata   string
	RequestVersion        *uint32
	AgreedAt              time.Time
}

// RfqPolicyStore is the database interface for RFQ policies.
type RfqPolicyStore interface {
	InsertRfqPolicy(context.Context,
		sqlc.InsertRfqPolicyParams) (int64, error)

	FetchActiveRfqPolicies(context.Context) (
		[]sqlc.RfqPolicy, error)
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
	accept rfqmsg.BuyAccept) error {

	assetID, groupKey := specifierPointers(accept.Request.AssetSpecifier)
	rateBytes := coefficientBytes(accept.AssetRate.Rate)
	expiry := accept.AssetRate.Expiry.UTC()

	record := rfqPolicy{
		PolicyType:          RfqPolicyTypeAssetSale,
		Scid:                uint64(accept.ShortChannelId()),
		RfqID:               rfqIDArray(accept.ID),
		Peer:                serializePeer(accept.Peer),
		AssetID:             assetID,
		AssetGroupKey:       groupKey,
		RateCoefficient:     rateBytes,
		RateScale:           accept.AssetRate.Rate.Scale,
		ExpiryUnix:          uint64(expiry.Unix()),
		MaxOutAssetAmt:      ptrUint64(accept.Request.AssetMaxAmt),
		RequestAssetMaxAmt:  ptrUint64(accept.Request.AssetMaxAmt),
		PriceOracleMetadata: accept.Request.PriceOracleMetadata,
		RequestVersion:      ptrUint32(uint32(accept.Request.Version)),
		AgreedAt:            time.Now().UTC(),
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
		PolicyType:            RfqPolicyTypeAssetPurchase,
		Scid:                  uint64(acpt.ShortChannelId()),
		RfqID:                 rfqIDArray(acpt.ID),
		Peer:                  serializePeer(acpt.Peer),
		AssetID:               assetID,
		AssetGroupKey:         groupKey,
		RateCoefficient:       rateBytes,
		RateScale:             acpt.AssetRate.Rate.Scale,
		ExpiryUnix:            uint64(expiry.Unix()),
		PaymentMaxMsat:        ptrInt64(paymentMax),
		RequestPaymentMaxMsat: ptrInt64(paymentMax),
		PriceOracleMetadata:   acpt.Request.PriceOracleMetadata,
		RequestVersion:        ptrUint32(uint32(acpt.Request.Version)),
		AgreedAt:              time.Now().UTC(),
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
		rows, err := q.FetchActiveRfqPolicies(ctx)
		if err != nil {
			return fmt.Errorf("error fetching policies: %w", err)
		}

		for _, row := range rows {
			policy := policyFromRow(row)

			// Skip expired entries.
			expiry := time.Unix(int64(policy.ExpiryUnix), 0).UTC()
			if now.After(expiry) {
				continue
			}

			switch policy.PolicyType {
			case RfqPolicyTypeAssetSale:
				accept, err := buyAcceptFromStored(policy)
				if err != nil {
					return fmt.Errorf("error restoring "+
						"sale policy: %w", err)
				}
				buyAccepts = append(buyAccepts, accept)

			case RfqPolicyTypeAssetPurchase:
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
		params.MaxOutAssetAmt = sql.NullInt64{
			Int64: int64(*policy.MaxOutAssetAmt),
			Valid: true,
		}
		params.RequestAssetMaxAmt = sql.NullInt64{
			Int64: int64(*policy.MaxOutAssetAmt),
			Valid: true,
		}
	}

	if policy.PaymentMaxMsat != nil {
		params.PaymentMaxMsat = sql.NullInt64{
			Int64: *policy.PaymentMaxMsat,
			Valid: true,
		}
		params.RequestPaymentMaxMsat = sql.NullInt64{
			Int64: *policy.PaymentMaxMsat,
			Valid: true,
		}
	}

	if policy.RequestAssetMaxAmt != nil {
		params.RequestAssetMaxAmt = sql.NullInt64{
			Int64: int64(*policy.RequestAssetMaxAmt),
			Valid: true,
		}
	}

	if policy.RequestPaymentMaxMsat != nil {
		params.RequestPaymentMaxMsat = sql.NullInt64{
			Int64: *policy.RequestPaymentMaxMsat,
			Valid: true,
		}
	}

	if policy.PriceOracleMetadata != "" {
		params.PriceOracleMetadata = sql.NullString{
			String: policy.PriceOracleMetadata,
			Valid:  true,
		}
	}

	if policy.RequestVersion != nil {
		params.RequestVersion = sql.NullInt32{
			Int32: int32(*policy.RequestVersion),
			Valid: true,
		}
	}

	return params
}

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
		PolicyType:      RfqPolicyType(row.PolicyType),
		Scid:            uint64(row.Scid),
		RfqID:           rfqID,
		Peer:            peer,
		AssetID:         assetIDPtr,
		AssetGroupKey:   groupKeyPtr,
		RateCoefficient: append([]byte(nil), row.RateCoefficient...),
		RateScale:       uint8(row.RateScale),
		ExpiryUnix:      uint64(row.Expiry),
		PriceOracleMetadata: func() string {
			if row.PriceOracleMetadata.Valid {
				return row.PriceOracleMetadata.String
			}
			return ""
		}(),
		RequestVersion: func() *uint32 {
			if row.RequestVersion.Valid {
				val := uint32(row.RequestVersion.Int32)
				return &val
			}
			return nil
		}(),
		AgreedAt: time.Unix(row.AgreedAt, 0).UTC(),
	}

	if row.MaxOutAssetAmt.Valid {
		amt := uint64(row.MaxOutAssetAmt.Int64)
		policy.MaxOutAssetAmt = &amt
	}

	if row.PaymentMaxMsat.Valid {
		val := row.PaymentMaxMsat.Int64
		policy.PaymentMaxMsat = &val
	}

	if row.RequestAssetMaxAmt.Valid {
		amt := uint64(row.RequestAssetMaxAmt.Int64)
		policy.RequestAssetMaxAmt = &amt
	}

	if row.RequestPaymentMaxMsat.Valid {
		val := row.RequestPaymentMaxMsat.Int64
		policy.RequestPaymentMaxMsat = &val
	}

	return policy
}

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

func coefficientBytes(rate rfqmath.BigIntFixedPoint) []byte {
	coeff := rate.Coefficient.Bytes()
	if len(coeff) == 0 {
		return []byte{0}
	}

	return append([]byte(nil), coeff...)
}

func serializePeer(peer route.Vertex) [33]byte {
	var peerBytes [33]byte
	copy(peerBytes[:], peer[:])
	return peerBytes
}

func rfqIDArray(id rfqmsg.ID) [32]byte {
	var idBytes [32]byte
	copy(idBytes[:], id[:])
	return idBytes
}

func ptrUint64(v uint64) *uint64 {
	val := v
	return &val
}

func ptrInt64(v int64) *int64 {
	val := v
	return &val
}

func ptrUint32(v uint32) *uint32 {
	val := v
	return &val
}

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
	}, nil
}

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
	}, nil
}

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

func rateFromStored(row rfqPolicy) rfqmath.BigIntFixedPoint {
	coeff := rfqmath.BigInt{}.FromBytes(row.RateCoefficient)
	return rfqmath.BigIntFixedPoint{
		Coefficient: coeff,
		Scale:       row.RateScale,
	}
}

func vertexFromBytes(raw [33]byte) route.Vertex {
	var vertex route.Vertex
	copy(vertex[:], raw[:])
	return vertex
}

func rfqIDFromBytes(raw [32]byte) rfqmsg.ID {
	var id rfqmsg.ID
	copy(id[:], raw[:])
	return id
}
