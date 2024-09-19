package rfq

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwallet"
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
	CheckHtlcCompliance(htlc lndclient.InterceptedHtlc) error

	// Expiry returns the policy's expiry time as a unix timestamp.
	Expiry() uint64

	// HasExpired returns true if the policy has expired.
	HasExpired() bool

	// Scid returns the serialised short channel ID (SCID) of the channel to
	// which the policy applies.
	Scid() uint64

	// GenerateInterceptorResponse generates an interceptor response for the
	// HTLC interceptor from the policy.
	GenerateInterceptorResponse(
		lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
		error)
}

// AssetSalePolicy is a struct that holds the terms which determine whether an
// asset sale channel HTLC is accepted or rejected.
type AssetSalePolicy struct {
	ID rfqmsg.ID

	// MaxAssetAmount is the maximum amount of the asset that is being
	// requested.
	MaxAssetAmount uint64

	// AskPrice is the asking price of the quote in milli-satoshis per asset
	// unit.
	AskPrice lnwire.MilliSatoshi

	// expiry is the policy's expiry unix timestamp after which the policy
	// is no longer valid.
	expiry uint64

	// assetID is the asset ID of the asset that the accept message is for.
	assetID *asset.ID
}

// NewAssetSalePolicy creates a new asset sale policy.
func NewAssetSalePolicy(quote rfqmsg.BuyAccept) *AssetSalePolicy {
	return &AssetSalePolicy{
		ID:             quote.ID,
		MaxAssetAmount: quote.Request.AssetAmount,
		AskPrice:       quote.AskPrice,
		expiry:         quote.Expiry,
		assetID:        quote.Request.AssetID,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
func (c *AssetSalePolicy) CheckHtlcCompliance(
	htlc lndclient.InterceptedHtlc) error {

	// Check that the channel SCID is as expected.
	htlcScid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
	if htlcScid != c.ID.Scid() {
		return fmt.Errorf("htlc outgoing channel ID does not match "+
			"policy's SCID (htlc_scid=%d, policy_scid=%d)",
			htlcScid, c.ID.Scid())
	}

	// Check that the HTLC amount is not greater than the negotiated maximum
	// amount.
	maxOutboundAmount := lnwire.MilliSatoshi(c.MaxAssetAmount) * c.AskPrice
	if htlc.AmountOutMsat > maxOutboundAmount {
		return fmt.Errorf("htlc out amount is greater than the policy "+
			"maximum (htlc_out_msat=%d, policy_max_out_msat=%d)",
			htlc.AmountOutMsat, maxOutboundAmount)
	}

	// Lastly, check to ensure that the policy has not expired.
	if time.Now().Unix() > int64(c.expiry) {
		return fmt.Errorf("policy has expired (expiry_unix_ts=%d)",
			c.expiry)
	}

	return nil
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
	return uint64(c.ID.Scid())
}

// GenerateInterceptorResponse generates an interceptor response for the policy.
func (c *AssetSalePolicy) GenerateInterceptorResponse(
	htlc lndclient.InterceptedHtlc) (*lndclient.InterceptedHtlcResponse,
	error) {

	outgoingAmt := lnwire.NewMSatFromSatoshis(lnwallet.DustLimitForSize(
		input.UnknownWitnessSize,
	))

	if c.assetID == nil {
		return nil, fmt.Errorf("policy has no asset ID")
	}

	outgoingAssetAmount := uint64(htlc.AmountOutMsat / c.AskPrice)
	htlcBalance := rfqmsg.NewAssetBalance(*c.assetID, outgoingAssetAmount)
	htlcRecord := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{htlcBalance}, fn.Some(c.ID),
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
	scid SerialisedScid

	// AcceptedQuoteId is the ID of the accepted quote.
	AcceptedQuoteId rfqmsg.ID

	// AssetAmount is the amount of the tap asset that is being requested.
	AssetAmount uint64

	// BidPrice is the milli-satoshi per asset unit price that was
	// negotiated.
	BidPrice lnwire.MilliSatoshi

	// expiry is the policy's expiry unix timestamp in seconds after which
	// the policy is no longer valid.
	expiry uint64
}

// NewAssetPurchasePolicy creates a new asset purchase policy.
func NewAssetPurchasePolicy(quote rfqmsg.SellAccept) *AssetPurchasePolicy {
	return &AssetPurchasePolicy{
		scid:            quote.ShortChannelId(),
		AcceptedQuoteId: quote.ID,
		AssetAmount:     quote.Request.AssetAmount,
		BidPrice:        quote.BidPrice,
		expiry:          quote.Expiry,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
func (c *AssetPurchasePolicy) CheckHtlcCompliance(
	htlc lndclient.InterceptedHtlc) error {

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
			"not contain the accepted quote ID (htlc=%v, "+
			"accepted_quote_id=%v)", htlc, c.AcceptedQuoteId)
	}

	inboundAmountMSat := lnwire.MilliSatoshi(c.AssetAmount) * c.BidPrice
	if inboundAmountMSat < htlc.AmountOutMsat {
		return fmt.Errorf("htlc out amount is more than inbound "+
			"asset amount in millisatoshis (htlc_out_msat=%d, "+
			"inbound_asset_amount=%d, "+
			"inbound_asset_amount_msat=%v)", htlc.AmountOutMsat,
			c.AssetAmount, inboundAmountMSat)
	}

	// Lastly, check to ensure that the policy has not expired.
	if time.Now().Unix() > int64(c.expiry) {
		return fmt.Errorf("policy has expired (expiry_unix_ts=%d)",
			c.expiry)
	}

	return nil
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
	incomingValue := lnwire.MilliSatoshi(htlcAssetAmount) * c.BidPrice

	return &lndclient.InterceptedHtlcResponse{
		Action:         lndclient.InterceptorActionResumeModified,
		IncomingAmount: incomingValue,
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
func (a *AssetForwardPolicy) CheckHtlcCompliance(
	htlc lndclient.InterceptedHtlc) error {

	if err := a.incomingPolicy.CheckHtlcCompliance(htlc); err != nil {
		return fmt.Errorf("error checking forward policy, inbound "+
			"HTLC does not comply with policy: %w", err)
	}

	if err := a.outgoingPolicy.CheckHtlcCompliance(htlc); err != nil {
		return fmt.Errorf("error checking forward policy, outbound "+
			"HTLC does not comply with policy: %w", err)
	}

	return nil
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
func (h *OrderHandler) handleIncomingHtlc(_ context.Context,
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
	err = policy.CheckHtlcCompliance(htlc)
	if err != nil {
		log.Warnf("HTLC does not comply with policy: %v "+
			"(htlc=%v, policy=%v)", err, htlc, policy)

		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionFail,
		}, nil
	}

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

// Start starts the service.
func (h *OrderHandler) Start() error {
	var startErr error
	h.startOnce.Do(func() {
		log.Info("Starting subsystem: order handler")

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
	h.policies.Store(policy.ID.Scid(), policy)
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
		spew.Sdump(inPolicy))
	log.Tracef("Have outbound policy: %v: %v", haveOutPolicy,
		spew.Sdump(outPolicy))

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
