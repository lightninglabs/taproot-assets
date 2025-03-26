package rfq

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// parseHtlcCustomRecords parses a HTLC custom record to extract any data which
// is relevant to the RFQ service. If the custom records map is nil or a
// relevant record was not found, false is returned.
func parseHtlcCustomRecords(customRecords map[uint64][]byte) (*rfqmsg.Htlc,
	error) {

	if len(customRecords) == 0 {
		return nil, fmt.Errorf("missing custom records")
	}

	// Re-encode the custom records map as a TLV stream.
	records := tlv.MapToRecords(customRecords)
	stream, err := tlv.NewStream(records...)
	if err != nil {
		return nil, fmt.Errorf("error creating stream: %w", err)
	}

	var buf bytes.Buffer
	if err := stream.Encode(&buf); err != nil {
		return nil, fmt.Errorf("error encoding stream: %w", err)
	}

	htlc, err := rfqmsg.DecodeHtlc(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error decoding HTLC: %w", err)
	}

	return htlc, nil
}

// SerialisedScid is a serialised short channel id (SCID).
type SerialisedScid = rfqmsg.SerialisedScid

// Policy is an interface that abstracts the terms which determine whether an
// asset sale/purchase channel HTLC is accepted or rejected.
type Policy interface {
	// CheckHtlcCompliance returns an error if the given HTLC intercept
	// descriptor does not satisfy the subject policy.
	CheckHtlcCompliance(ctx context.Context, htlc lndclient.InterceptedHtlc,
		specifierChecker rfqmsg.SpecifierChecker) error

	// Expiry returns the policy's expiry time as a unix timestamp.
	Expiry() uint64

	// HasExpired returns true if the policy has expired.
	HasExpired() bool

	// Scid returns the serialised short channel ID (SCID) of the channel to
	// which the policy applies.
	Scid() uint64

	// TrackAcceptedHtlc makes the policy aware of this new accepted HTLC.
	// This is important in cases where the set of existing HTLCs may affect
	// whether the next compliance check passes.
	TrackAcceptedHtlc(circuitKey models.CircuitKey, amt lnwire.MilliSatoshi)

	// UntrackHtlc stops tracking the uniquely identified HTLC.
	UntrackHtlc(circuitKey models.CircuitKey)

	// GenerateInterceptorResponse generates an interceptor response for the
	// HTLC interceptor from the policy.
	GenerateInterceptorResponse(
		lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
		error)
}

// AssetSalePolicy is a struct that holds the terms which determine whether an
// asset sale channel HTLC is accepted or rejected.
type AssetSalePolicy struct {
	// AssetSpecifier is the identifier for the specific asset or asset
	// group to which this policy applies.
	AssetSpecifier asset.Specifier

	// AcceptedQuoteId is the unique identifier of the RFQ session quote
	// accept message that the policy is associated with.
	AcceptedQuoteId rfqmsg.ID

	// MaxOutboundAssetAmount represents the maximum asset amount permitted
	// by policy for outbound transactions. It sets an upper limit on the
	// amount of assets this node is willing to divest within the remit of
	// the policy.
	MaxOutboundAssetAmount uint64

	// CurrentAssetAmountMsat is the total amount that is held currently in
	// accepted HTLCs.
	CurrentAmountMsat lnwire.MilliSatoshi

	// stateMutex is a mutex that locks access to this policy's internal
	// state. This is needed as state is updated asynchronously by each
	// routine that handles an intercepted HTLC.
	stateMutex sync.RWMutex

	// AskAssetRate is the quote's asking asset unit to BTC conversion rate.
	AskAssetRate rfqmath.BigIntFixedPoint

	// htlcToAmt maps the unique HTLC identifiers to the effective amount
	// that they carry.
	htlcToAmt map[models.CircuitKey]lnwire.MilliSatoshi

	// expiry is the policy's expiry unix timestamp after which the policy
	// is no longer valid.
	expiry uint64
}

// NewAssetSalePolicy creates a new asset sale policy.
func NewAssetSalePolicy(quote rfqmsg.BuyAccept) *AssetSalePolicy {
	htlcToAmtMap := make(map[models.CircuitKey]lnwire.MilliSatoshi)

	return &AssetSalePolicy{
		AssetSpecifier:         quote.Request.AssetSpecifier,
		AcceptedQuoteId:        quote.ID,
		MaxOutboundAssetAmount: quote.Request.AssetMaxAmt,
		AskAssetRate:           quote.AssetRate.Rate,
		expiry:                 uint64(quote.AssetRate.Expiry.Unix()),
		htlcToAmt:              htlcToAmtMap,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
//
// The HTLC examined by this function was likely created by a peer unaware of
// the RFQ agreement (i.e., they are simply paying an invoice), with the SCID
// included as a hop hint within the invoice. The SCID is the only piece of
// information used to determine the policy applicable to the HTLC. As a result,
// HTLC custom records are not expected to be present.
func (c *AssetSalePolicy) CheckHtlcCompliance(_ context.Context,
	htlc lndclient.InterceptedHtlc, _ rfqmsg.SpecifierChecker) error {

	// Since we will be reading CurrentAmountMsat value we acquire a read
	// lock.
	c.stateMutex.RLock()
	defer c.stateMutex.RUnlock()

	// Check that the channel SCID is as expected.
	htlcScid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
	if htlcScid != c.AcceptedQuoteId.Scid() {
		return fmt.Errorf("HTLC outgoing channel ID does not match "+
			"policy's SCID (htlc_scid=%d, policy_scid=%d)",
			htlcScid, c.AcceptedQuoteId.Scid())
	}

	// The RFQ quote sets an upper limit on the amount of assets this node
	// is willing to sell. We need to ensure that the HTLC outbound amount
	// does not correspond to an asset amount exceeding this agreed maximum.
	//
	// In other words, this check ensures our peer isn't trying to obtain
	// more assets than we are willing to sell.
	//
	// Verify that the HTLC outbound amount (msat) does not exceed the
	// maximum asset amount (converted to msat) as specified in the quote.
	// Convert the maximum asset amount to msat using the asset-to-BTC rate
	// from the quote, and ensure it is less than the HTLC outbound amount
	// (msat).
	maxAssetAmount := rfqmath.NewBigIntFixedPoint(
		c.MaxOutboundAssetAmount, 0,
	)
	policyMaxOutMsat := rfqmath.UnitsToMilliSatoshi(
		maxAssetAmount, c.AskAssetRate,
	)

	if (c.CurrentAmountMsat + htlc.AmountOutMsat) > policyMaxOutMsat {
		return fmt.Errorf("HTLC out amount is greater than the policy "+
			"maximum (htlc_out_msat=%d, policy_max_out_msat=%d)",
			htlc.AmountOutMsat, policyMaxOutMsat)
	}

	// Lastly, check to ensure that the policy has not expired.
	if time.Now().Unix() > int64(c.expiry) {
		return fmt.Errorf("policy has expired (expiry_unix_ts=%d)",
			c.expiry)
	}

	return nil
}

// TrackAcceptedHtlc accounts for the newly accepted HTLC. This may affect the
// acceptance of future HTLCs.
func (c *AssetSalePolicy) TrackAcceptedHtlc(circuitKey models.CircuitKey,
	amt lnwire.MilliSatoshi) {

	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	c.CurrentAmountMsat += amt

	c.htlcToAmt[circuitKey] = amt
}

// UntrackHtlc stops tracking the uniquely identified HTLC.
func (c *AssetSalePolicy) UntrackHtlc(circuitKey models.CircuitKey) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	amt, found := c.htlcToAmt[circuitKey]
	if !found {
		return
	}

	delete(c.htlcToAmt, circuitKey)

	c.CurrentAmountMsat -= amt
}

// Expiry returns the policy's expiry time as a unix timestamp.
func (c *AssetSalePolicy) Expiry() uint64 {
	return c.expiry
}

// HasExpired returns true if the policy has expired.
func (c *AssetSalePolicy) HasExpired() bool {
	expireTime := time.Unix(int64(c.expiry), 0).UTC()

	return time.Now().UTC().After(expireTime)
}

// Scid returns the serialised short channel ID (SCID) of the channel to which
// the policy applies.
func (c *AssetSalePolicy) Scid() uint64 {
	return uint64(c.AcceptedQuoteId.Scid())
}

// GenerateInterceptorResponse generates an interceptor response for the policy.
func (c *AssetSalePolicy) GenerateInterceptorResponse(
	htlc lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
	error) {

	outgoingAmt := rfqmath.DefaultOnChainHtlcMSat

	var assetID asset.ID

	// We have performed checks for the asset IDs inside the HTLC against
	// the specifier's group key in a previous step. Here we just need to
	// provide a dummy value as the asset ID. The real asset IDs will be
	// carefully picked in a later step in the process. What really matters
	// now is the total amount.
	switch {
	case c.AssetSpecifier.HasGroupPubKey():
		groupKey := c.AssetSpecifier.UnwrapGroupKeyToPtr()
		groupKeyX := schnorr.SerializePubKey(groupKey)

		assetID = asset.ID(groupKeyX)

	case c.AssetSpecifier.HasId():
		specifierID := *c.AssetSpecifier.UnwrapIdToPtr()
		copy(assetID[:], specifierID[:])
	}

	// Compute the outgoing asset amount given the msat outgoing amount and
	// the asset to BTC rate.
	outgoingAssetAmount := rfqmath.MilliSatoshiToUnits(
		htlc.AmountOutMsat, c.AskAssetRate,
	)
	amt := outgoingAssetAmount.ScaleTo(0).ToUint64()

	// Include the asset balance in the HTLC record.
	htlcBalance := rfqmsg.NewAssetBalance(assetID, amt)
	htlcRecord := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{htlcBalance}, fn.Some(c.AcceptedQuoteId),
	)

	customRecords, err := lnwire.ParseCustomRecords(htlcRecord.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error parsing custom records: %w", err)
	}

	return &lndclient.InterceptedHtlcResponse{
		Action:         lndclient.InterceptorActionResumeModified,
		OutgoingAmount: outgoingAmt,
		CustomRecords:  customRecords,
	}, nil
}

// Ensure that AssetSalePolicy implements the Policy interface.
var _ Policy = (*AssetSalePolicy)(nil)

// AssetPurchasePolicy is a struct that holds the terms which determine whether
// an asset purchase channel HTLC is accepted or rejected.
type AssetPurchasePolicy struct {
	// scid is the serialised short channel ID (SCID) of the channel to
	// which the policy applies.
	//
	// TODO(ffranr): Remove this field. It can be derived from
	//  AcceptedQuoteId.
	scid SerialisedScid

	// AssetSpecifier is the identifier for the specific asset or asset
	// group to which this policy applies.
	AssetSpecifier asset.Specifier

	// AcceptedQuoteId is the ID of the accepted quote.
	AcceptedQuoteId rfqmsg.ID

	// CurrentAssetAmountMsat is the total amount that is held currently in
	// accepted HTLCs.
	CurrentAmountMsat lnwire.MilliSatoshi

	// stateMutex is a mutex that locks access to this policy's internal
	// state. This is needed as state is updated asynchronously by each
	// routine that handles an intercepted HTLC.
	stateMutex sync.RWMutex

	// BidAssetRate is the quote's asset to BTC conversion rate.
	BidAssetRate rfqmath.BigIntFixedPoint

	// PaymentMaxAmt is the maximum agreed BTC payment.
	PaymentMaxAmt lnwire.MilliSatoshi

	// htlcToAmt maps the unique HTLC identifiers to the effective amount
	// that they carry.
	htlcToAmt map[models.CircuitKey]lnwire.MilliSatoshi

	// expiry is the policy's expiry unix timestamp in seconds after which
	// the policy is no longer valid.
	expiry uint64
}

// NewAssetPurchasePolicy creates a new asset purchase policy.
func NewAssetPurchasePolicy(quote rfqmsg.SellAccept) *AssetPurchasePolicy {
	htlcToAmtMap := make(map[models.CircuitKey]lnwire.MilliSatoshi)

	return &AssetPurchasePolicy{
		scid:            quote.ShortChannelId(),
		AssetSpecifier:  quote.Request.AssetSpecifier,
		AcceptedQuoteId: quote.ID,
		BidAssetRate:    quote.AssetRate.Rate,
		PaymentMaxAmt:   quote.Request.PaymentMaxAmt,
		expiry:          uint64(quote.AssetRate.Expiry.Unix()),
		htlcToAmt:       htlcToAmtMap,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
func (c *AssetPurchasePolicy) CheckHtlcCompliance(ctx context.Context,
	htlc lndclient.InterceptedHtlc,
	specifierChecker rfqmsg.SpecifierChecker) error {

	// Since we will be reading CurrentAmountMsat value we acquire a read
	// lock.
	c.stateMutex.RLock()
	defer c.stateMutex.RUnlock()

	// Check that the HTLC contains the accepted quote ID.
	htlcRecord, err := parseHtlcCustomRecords(htlc.InWireCustomRecords)
	if err != nil {
		return fmt.Errorf("parsing HTLC custom records failed: %w", err)
	}

	if htlcRecord.RfqID.ValOpt().IsNone() {
		return fmt.Errorf("incoming HTLC does not contain an RFQ ID")
	}

	rfqID := htlcRecord.RfqID.ValOpt().UnsafeFromSome()

	if rfqID != c.AcceptedQuoteId {
		return fmt.Errorf("HTLC contains a custom record, but it does "+
			"not contain the accepted quote ID (HTLC=%v, "+
			"accepted_quote_id=%v)", htlc, c.AcceptedQuoteId)
	}

	// Sum the asset balance in the HTLC record.
	assetAmt, err := htlcRecord.SumAssetBalance(
		ctx, c.AssetSpecifier, specifierChecker,
	)
	if err != nil {
		return fmt.Errorf("error summing asset balance: %w", err)
	}

	// Due to rounding errors, we may slightly underreport the incoming
	// value of the asset. So we increase it by exactly one asset unit to
	// ensure that we do not reject the HTLC in the "inbound amount cannot
	// be less than outbound amount" check below.
	roundingCorrection := rfqmath.NewBigIntFromUint64(1)
	assetAmt = assetAmt.Add(roundingCorrection)

	// Convert the inbound asset amount to millisatoshis and ensure that the
	// outgoing HTLC amount is not more than the inbound asset amount.
	assetAmtFp := new(rfqmath.BigIntFixedPoint).SetIntValue(assetAmt)
	inboundAmountMSat := rfqmath.UnitsToMilliSatoshi(
		assetAmtFp, c.BidAssetRate,
	)

	if inboundAmountMSat < htlc.AmountOutMsat {
		return fmt.Errorf("HTLC out amount is more than inbound "+
			"asset amount in millisatoshis (htlc_out_msat=%d, "+
			"inbound_asset_amount=%s, "+
			"inbound_asset_amount_msat=%v)", htlc.AmountOutMsat,
			assetAmt.String(), inboundAmountMSat)
	}

	// Ensure that the outbound HTLC amount is less than the maximum agreed
	// BTC payment.
	if (c.CurrentAmountMsat + htlc.AmountOutMsat) > c.PaymentMaxAmt {
		return fmt.Errorf("HTLC out amount is more than the maximum "+
			"agreed BTC payment (htlc_out_msat=%d, "+
			"payment_max_amt=%d)", htlc.AmountOutMsat,
			c.PaymentMaxAmt)
	}

	// Lastly, check to ensure that the policy has not expired.
	if time.Now().Unix() > int64(c.expiry) {
		return fmt.Errorf("policy has expired (expiry_unix_ts=%d)",
			c.expiry)
	}

	return nil
}

// TrackAcceptedHtlc accounts for the newly accepted HTLC. This may affect the
// acceptance of future HTLCs.
func (c *AssetPurchasePolicy) TrackAcceptedHtlc(circuitKey models.CircuitKey,
	amt lnwire.MilliSatoshi) {

	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	c.CurrentAmountMsat += amt

	c.htlcToAmt[circuitKey] = amt
}

// UntrackHtlc stops tracking the uniquely identified HTLC.
func (c *AssetPurchasePolicy) UntrackHtlc(circuitKey models.CircuitKey) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	amt, found := c.htlcToAmt[circuitKey]
	if !found {
		return
	}

	delete(c.htlcToAmt, circuitKey)

	c.CurrentAmountMsat -= amt
}

// Expiry returns the policy's expiry time as a unix timestamp in seconds.
func (c *AssetPurchasePolicy) Expiry() uint64 {
	return c.expiry
}

// HasExpired returns true if the policy has expired.
func (c *AssetPurchasePolicy) HasExpired() bool {
	expireTime := time.Unix(int64(c.expiry), 0).UTC()

	return time.Now().UTC().After(expireTime)
}

// Scid returns the serialised short channel ID (SCID) of the channel to which
// the policy applies.
func (c *AssetPurchasePolicy) Scid() uint64 {
	return uint64(c.scid)
}

// GenerateInterceptorResponse generates an interceptor response for the policy.
func (c *AssetPurchasePolicy) GenerateInterceptorResponse(
	htlc lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
	error) {

	htlcRecord, err := parseHtlcCustomRecords(htlc.InWireCustomRecords)
	if err != nil {
		return nil, fmt.Errorf("parsing HTLC custom records failed: %w",
			err)
	}

	// The incoming amount is just to signal to the fee logic in lnd that
	// we have received enough to pay for the routing fees and the asset
	// amount. Due to rounding errors, we may slightly underreport the
	// incoming value of the asset. So we increase it by exactly one asset
	// unit to ensure that the fee logic in lnd does not reject the HTLC.
	const roundingCorrection = 1
	htlcAssetAmount := htlcRecord.Amounts.Val.Sum() + roundingCorrection

	assetAmt := rfqmath.NewBigIntFixedPoint(htlcAssetAmount, 0)
	incomingHtlcMsats := rfqmath.UnitsToMilliSatoshi(
		assetAmt, c.BidAssetRate,
	)

	return &lndclient.InterceptedHtlcResponse{
		Action:         lndclient.InterceptorActionResumeModified,
		IncomingAmount: incomingHtlcMsats,
	}, nil
}

// Ensure that AssetPurchasePolicy implements the Policy interface.
var _ Policy = (*AssetPurchasePolicy)(nil)

// AssetForwardPolicy is a struct that holds the terms which determine whether a
// channel HTLC for an asset-to-asset forward is accepted or rejected.
type AssetForwardPolicy struct {
	incomingPolicy *AssetPurchasePolicy
	outgoingPolicy *AssetSalePolicy
}

// NewAssetForwardPolicy creates a new asset forward policy.
func NewAssetForwardPolicy(incoming, outgoing Policy) (*AssetForwardPolicy,
	error) {

	incomingPolicy, ok := incoming.(*AssetPurchasePolicy)
	if !ok {
		return nil, fmt.Errorf("incoming policy is not an asset "+
			"purchase policy, but %T", incoming)
	}

	outgoingPolicy, ok := outgoing.(*AssetSalePolicy)
	if !ok {
		return nil, fmt.Errorf("outgoing policy is not an asset "+
			"sale policy, but %T", outgoing)
	}

	return &AssetForwardPolicy{
		incomingPolicy: incomingPolicy,
		outgoingPolicy: outgoingPolicy,
	}, nil
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
func (a *AssetForwardPolicy) CheckHtlcCompliance(ctx context.Context,
	htlc lndclient.InterceptedHtlc, sChk rfqmsg.SpecifierChecker) error {

	if err := a.incomingPolicy.CheckHtlcCompliance(
		ctx, htlc, sChk,
	); err != nil {
		return fmt.Errorf("error checking forward policy, inbound "+
			"HTLC does not comply with policy: %w", err)
	}

	if err := a.outgoingPolicy.CheckHtlcCompliance(
		ctx, htlc, sChk,
	); err != nil {
		return fmt.Errorf("error checking forward policy, outbound "+
			"HTLC does not comply with policy: %w", err)
	}

	return nil
}

// TrackAcceptedHtlc accounts for the newly accepted HTLC. This may affect the
// acceptance of future HTLCs.
func (a *AssetForwardPolicy) TrackAcceptedHtlc(circuitKey models.CircuitKey,
	amt lnwire.MilliSatoshi) {

	// Track accepted HTLC in the incoming policy.
	a.incomingPolicy.TrackAcceptedHtlc(circuitKey, amt)

	// Track accepted HTLC in the outgoing policy.
	a.outgoingPolicy.TrackAcceptedHtlc(circuitKey, amt)
}

// UntrackHtlc stops tracking the uniquely identified HTLC.
func (a *AssetForwardPolicy) UntrackHtlc(circuitKey models.CircuitKey) {
	// Untrack HTLC in the incoming policy.
	a.incomingPolicy.UntrackHtlc(circuitKey)

	// Untrack HTLC in the outgoing policy.
	a.outgoingPolicy.UntrackHtlc(circuitKey)
}

// Expiry returns the policy's expiry time as a unix timestamp in seconds. The
// returned expiry time is the earliest expiry time of the incoming and outgoing
// policies.
func (a *AssetForwardPolicy) Expiry() uint64 {
	if a.incomingPolicy.Expiry() < a.outgoingPolicy.Expiry() {
		return a.incomingPolicy.Expiry()
	}

	return a.outgoingPolicy.Expiry()
}

// HasExpired returns true if the policy has expired.
func (a *AssetForwardPolicy) HasExpired() bool {
	expireTime := time.Unix(int64(a.Expiry()), 0).UTC()

	return time.Now().UTC().After(expireTime)
}

// Scid returns the serialised short channel ID (SCID) of the channel to which
// the policy applies. This is the SCID of the incoming policy.
func (a *AssetForwardPolicy) Scid() uint64 {
	return a.incomingPolicy.Scid()
}

// GenerateInterceptorResponse generates an interceptor response for the policy.
func (a *AssetForwardPolicy) GenerateInterceptorResponse(
	htlc lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
	error) {

	incomingResponse, err := a.incomingPolicy.GenerateInterceptorResponse(
		htlc,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating incoming interceptor "+
			"response: %w", err)
	}

	outgoingResponse, err := a.outgoingPolicy.GenerateInterceptorResponse(
		htlc,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating outgoing interceptor "+
			"response: %w", err)
	}

	return &lndclient.InterceptedHtlcResponse{
		// Both incoming and outgoing policies will resume with
		// modifications.
		Action: lndclient.InterceptorActionResumeModified,

		// The incoming policy will modify the incoming amount in order
		// to satisfy the fee check in `lnd`.
		IncomingAmount: incomingResponse.IncomingAmount,

		// The outgoing policy will modify the outgoing amount and add
		// custom records in order to satisfy the terms of the receiving
		// node.
		OutgoingAmount: outgoingResponse.OutgoingAmount,
		CustomRecords:  outgoingResponse.CustomRecords,
	}, nil
}

// Ensure that AssetForwardPolicy implements the Policy interface.
var _ Policy = (*AssetForwardPolicy)(nil)

// OrderHandlerCfg is a struct that holds the configuration parameters for the
// order handler service.
type OrderHandlerCfg struct {
	// CleanupInterval is the interval at which the order handler cleans up
	// expired accepted quotes from its local cache.
	CleanupInterval time.Duration

	// HtlcInterceptor is the HTLC interceptor. This component is used to
	// intercept and accept/reject HTLCs.
	HtlcInterceptor HtlcInterceptor

	// AcceptHtlcEvents is a channel that receives accepted HTLCs.
	AcceptHtlcEvents chan<- *AcceptHtlcEvent

	// HtlcSubscriber is a subscriber that is used to retrieve live HTLC
	// event updates.
	HtlcSubscriber HtlcSubscriber

	// SpecifierChecker is an interface that contains methods for
	// checking certain properties related to asset specifiers.
	SpecifierChecker rfqmsg.SpecifierChecker
}

// OrderHandler orchestrates management of accepted quote bundles. It monitors
// HTLCs (Hash Time Locked Contracts), and determines acceptance/rejection based
// on the terms of the associated accepted quote.
type OrderHandler struct {
	startOnce sync.Once
	stopOnce  sync.Once

	// cfg holds the configuration parameters for the RFQ order handler.
	cfg OrderHandlerCfg

	// policies is a map of serialised short channel IDs (SCIDs) to
	// associated asset transaction policies.
	policies lnutils.SyncMap[SerialisedScid, Policy]

	// htlcToPolicy maps an HTLC circuit key to the policy that applies to
	// it. We need this map because for failed HTLCs we don't have the RFQ
	// data available, so we need to cache this info.
	htlcToPolicy lnutils.SyncMap[models.CircuitKey, Policy]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewOrderHandler creates a new struct instance.
func NewOrderHandler(cfg OrderHandlerCfg) (*OrderHandler, error) {
	return &OrderHandler{
		cfg:      cfg,
		policies: lnutils.SyncMap[SerialisedScid, Policy]{},
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}, nil
}

// handleIncomingHtlc handles an incoming HTLC.
//
// NOTE: This function must be thread safe. It is used by an external
// interceptor service.
func (h *OrderHandler) handleIncomingHtlc(ctx context.Context,
	htlc lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
	error) {

	log.Debugf("Handling incoming HTLC, incoming channel ID: %v, "+
		"outgoing channel ID: %v (incoming amount: %v, outgoing "+
		"amount: %v)", htlc.IncomingCircuitKey.ChanID.ToUint64(),
		htlc.OutgoingChannelID.ToUint64(), htlc.AmountInMsat,
		htlc.AmountOutMsat)

	// Look up a policy for the HTLC. If a policy does not exist, we resume
	// the HTLC. This is because the HTLC may be relevant to another
	// interceptor service. We only reject HTLCs that are relevant to the
	// RFQ service and do not comply with a known policy.
	policy, ok, err := h.fetchPolicy(htlc)
	if err != nil {
		return nil, fmt.Errorf("error fetching policy: %w", err)
	}

	if !ok {
		log.Debug("Failed to find a policy for the HTLC. Resuming.")
		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionResume,
		}, nil
	}

	log.Debugf("Fetched policy with SCID %v of type %T", policy.Scid(),
		policy)

	// At this point, we know that a policy exists and has not expired
	// whilst sitting in the local cache. We can now check that the HTLC
	// complies with the policy.
	err = policy.CheckHtlcCompliance(ctx, htlc, h.cfg.SpecifierChecker)
	if err != nil {
		log.Warnf("HTLC does not comply with policy: %v "+
			"(HTLC=%v, policy=%v)", err, htlc, policy)

		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionFail,
		}, nil
	}

	h.htlcToPolicy.Store(htlc.IncomingCircuitKey, policy)

	// The HTLC passed the compliance checks, so now we keep track of the
	// accepted HTLC.
	policy.TrackAcceptedHtlc(htlc.IncomingCircuitKey, htlc.AmountOutMsat)

	log.Debug("HTLC complies with policy. Broadcasting accept event.")
	h.cfg.AcceptHtlcEvents <- NewAcceptHtlcEvent(htlc, policy)

	return policy.GenerateInterceptorResponse(htlc)
}

// setupHtlcIntercept sets up HTLC interception.
func (h *OrderHandler) setupHtlcIntercept(ctx context.Context) error {
	// Intercept incoming HTLCs. This call passes the handleIncomingHtlc
	// function to the interceptor. The interceptor will call this function
	// in a separate goroutine.
	err := h.cfg.HtlcInterceptor.InterceptHtlcs(ctx, h.handleIncomingHtlc)
	if err != nil {
		if fn.IsCanceled(err) {
			return nil
		}

		return fmt.Errorf("unable to setup incoming HTLC "+
			"interceptor: %w", err)
	}

	return nil
}

// mainEventLoop executes the main event handling loop.
func (h *OrderHandler) mainEventLoop() {
	log.Debug("Starting main event loop for order handler")

	cleanupTicker := time.NewTicker(h.cfg.CleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		// Periodically clean up expired policies from our local cache.
		case <-cleanupTicker.C:
			log.Debug("Cleaning up any stale policy from the " +
				"order handler")
			h.cleanupStalePolicies()

		case <-h.Quit:
			log.Debug("Received quit signal. Stopping negotiator " +
				"event loop")
			return
		}
	}
}

// subscribeHtlcs subscribes the OrderHandler to HTLC events provided by the lnd
// RPC interface. We use this subscription to track HTLC forwarding failures,
// which we use to perform a live update of our policies.
func (h *OrderHandler) subscribeHtlcs(ctx context.Context) error {
	events, chErr, err := h.cfg.HtlcSubscriber.SubscribeHtlcEvents(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case event := <-events:
			// We only care about forwarding events.
			if event.GetEventType() != routerrpc.HtlcEvent_FORWARD {
				continue
			}

			// Retrieve the two instances that may be relevant.
			failEvent := event.GetForwardFailEvent()
			linkFail := event.GetLinkFailEvent()

			// Craft the circuit key that identifies this HTLC.
			circuitKey := models.CircuitKey{
				ChanID: lnwire.NewShortChanIDFromInt(
					event.IncomingChannelId,
				),
				HtlcID: event.IncomingHtlcId,
			}

			switch {
			case failEvent != nil:
				fallthrough
			case linkFail != nil:
				// Fetch the policy that is related to this
				// HTLC.
				policy, found := h.htlcToPolicy.LoadAndDelete(
					circuitKey,
				)

				if !found {
					continue
				}

				// Stop tracking this HTLC as it failed.
				policy.UntrackHtlc(circuitKey)
			}

		case err := <-chErr:
			return err

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Start starts the service.
func (h *OrderHandler) Start() error {
	var startErr error
	h.startOnce.Do(func() {
		// Start the main event loop in a separate goroutine.
		h.Wg.Add(1)
		go func() {
			defer h.Wg.Done()

			ctx, cancel := h.WithCtxQuitNoTimeout()
			defer cancel()

			startErr = h.setupHtlcIntercept(ctx)
			if startErr != nil {
				log.Errorf("Error setting up HTLC "+
					"interception: %v", startErr)
				return
			}

			h.mainEventLoop()
		}()

		// Start the HTLC event subscription loop.
		h.Wg.Add(1)
		go func() {
			defer h.Wg.Done()

			ctx, cancel := h.WithCtxQuitNoTimeout()
			defer cancel()

			err := h.subscribeHtlcs(ctx)
			if err != nil {
				log.Errorf("HTLC subscriber error: %v", err)
			}
		}()
	})

	return startErr
}

// RegisterAssetSalePolicy generates and registers an asset sale policy with the
// order handler. This function takes an outgoing buy accept message as an
// argument.
func (h *OrderHandler) RegisterAssetSalePolicy(buyAccept rfqmsg.BuyAccept) {
	log.Debugf("Order handler is registering an asset sale policy given a "+
		"buy accept message: %s", buyAccept.String())

	policy := NewAssetSalePolicy(buyAccept)
	h.policies.Store(policy.AcceptedQuoteId.Scid(), policy)
}

// RegisterAssetPurchasePolicy generates and registers an asset buy policy with the
// order handler. This function takes an incoming sell accept message as an
// argument.
func (h *OrderHandler) RegisterAssetPurchasePolicy(
	sellAccept rfqmsg.SellAccept) {

	log.Debugf("Order handler is registering an asset buy policy given a "+
		"sell accept message: %s", sellAccept.String())

	policy := NewAssetPurchasePolicy(sellAccept)
	h.policies.Store(policy.scid, policy)
}

// fetchPolicy fetches a policy which is relevant to a given HTLC. If a policy
// is not found, false is returned. Expired policies are not returned and are
// removed from the cache.
func (h *OrderHandler) fetchPolicy(htlc lndclient.InterceptedHtlc) (Policy,
	bool, error) {

	outScid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
	outPolicy, haveOutPolicy := h.policies.Load(outScid)

	inScid := SerialisedScid(htlc.IncomingCircuitKey.ChanID.ToUint64())
	inPolicy, haveInPolicy := h.policies.Load(inScid)

	log.Tracef("Have inbound policy: %v: %v", haveInPolicy,
		lnutils.LogClosure(func() string {
			if inPolicy == nil {
				return "<nil>"
			}

			return fmt.Sprintf("%d", inPolicy.Scid())
		}))
	log.Tracef("Have outbound policy: %v: scid %v", haveOutPolicy,
		lnutils.LogClosure(func() string {
			if outPolicy == nil {
				return "<nil>"
			}

			return fmt.Sprintf("%d", outPolicy.Scid())
		}))

	var (
		foundPolicy *Policy
		foundScid   *SerialisedScid
	)

	// If the HTLC has a custom record, we check if it is relevant to the
	// RFQ service.
	if len(htlc.InWireCustomRecords) > 0 {
		log.Debug("HTLC has custom records, parsing them")
		htlcRecords, err := parseHtlcCustomRecords(
			htlc.InWireCustomRecords,
		)
		if err != nil {
			return nil, false, fmt.Errorf("parsing HTLC custom "+
				"records failed: %w", err)
		}

		log.Debugf("Parsed HTLC custom records: %v",
			spew.Sdump(htlcRecords))

		htlcRecords.RfqID.ValOpt().WhenSome(func(quoteId rfqmsg.ID) {
			scid := quoteId.Scid()
			log.Debugf("Looking up policy by SCID: %d", scid)

			policy, ok := h.policies.Load(scid)
			if ok {
				foundPolicy = &policy
				foundScid = &scid
			}
		})
	}

	// Here we handle a special case where we both have an incoming and
	// outgoing policy. In this case, we need to create a forward policy.
	if foundPolicy != nil && haveOutPolicy {
		incomingPolicy := *foundPolicy
		outgoingPolicy := outPolicy

		if incomingPolicy.HasExpired() {
			scid := incomingPolicy.Scid()
			h.policies.Delete(SerialisedScid(scid))
		}
		if outgoingPolicy.HasExpired() {
			scid := outgoingPolicy.Scid()
			h.policies.Delete(SerialisedScid(scid))
		}

		// If either the incoming or outgoing policy has expired, we
		// return false, as if we didn't find a policy.
		if incomingPolicy.HasExpired() || outgoingPolicy.HasExpired() {
			return nil, false, nil
		}

		forwardPolicy, err := NewAssetForwardPolicy(
			incomingPolicy, outgoingPolicy,
		)
		if err != nil {
			return nil, false, fmt.Errorf("error creating forward "+
				"policy: %w", err)
		}

		return forwardPolicy, true, nil

	}

	// If no policy has been found so far, we attempt to look up a policy by
	// the outgoing channel SCID.
	if foundPolicy == nil && haveOutPolicy {
		foundPolicy = &outPolicy
		foundScid = &outScid
	}

	// If no policy has been found so far, we attempt to look up a policy by
	// the incoming channel SCID.
	if foundPolicy == nil && haveInPolicy {
		foundPolicy = &inPolicy
		foundScid = &inScid
	}

	// If no policy has been found, we return false.
	if foundPolicy == nil {
		return nil, false, nil
	}

	policy := *foundPolicy
	scid := *foundScid

	if policy.HasExpired() {
		h.policies.Delete(scid)
		return nil, false, nil
	}

	return policy, true, nil
}

// cleanupStalePolicies removes expired policies from the local cache.
func (h *OrderHandler) cleanupStalePolicies() {
	// Iterate over policies and remove any that have expired.
	staleCounter := 0

	h.policies.ForEach(
		func(scid SerialisedScid, policy Policy) error {
			if policy.HasExpired() {
				staleCounter++
				h.policies.Delete(scid)
			}

			return nil
		},
	)

	if staleCounter > 0 {
		log.Tracef("Removed stale policies from the order handler: "+
			"(count=%d)", staleCounter)
	}
}

// Stop stops the handler.
func (h *OrderHandler) Stop() error {
	h.stopOnce.Do(func() {
		log.Info("Stopping subsystem: order handler")

		// Stop the main event loop.
		close(h.Quit)
	})
	return nil
}

// HtlcInterceptor is an interface that abstracts the hash time locked contract
// (HTLC) intercept functionality.
type HtlcInterceptor interface {
	// InterceptHtlcs intercepts HTLCs, using the handling function provided
	// to respond to HTLCs.
	InterceptHtlcs(context.Context, lndclient.HtlcInterceptHandler) error
}

// HtlcSubscriber is an interface that contains the function necessary for
// retrieving live HTLC event updates.
type HtlcSubscriber interface {
	// SubscribeHtlcEvents subscribes to a stream of events related to
	// HTLC updates.
	SubscribeHtlcEvents(ctx context.Context) (<-chan *routerrpc.HtlcEvent,
		<-chan error, error)
}
