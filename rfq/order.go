package rfq

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	// LnCustomRecordType is a taproot-assets specific lightning payment hop
	// custom record K-V value.
	LnCustomRecordType = 65536 + uint64(rfqmsg.TapMessageTypeBaseOffset)
)

// parseHtlcCustomRecords parses a HTLC custom record to extract any data which
// is relevant to the RFQ service. If the custom records map is nil or a
// relevant record was not found, false is returned.
func parseHtlcCustomRecords(customRecords map[uint64][]byte) (*rfqmsg.ID,
	bool) {

	// If the given custom records map is nil, we return false.
	if customRecords == nil {
		return nil, false
	}

	// Check for the RFQ custom record key in the custom records map.
	val, ok := customRecords[LnCustomRecordType]
	if !ok {
		return nil, false
	}

	// TODO(ffranr): val here should be a TLV.
	var quoteId rfqmsg.ID
	copy(quoteId[:], val)
	return &quoteId, true
}

// SerialisedScid is a serialised short channel id (SCID).
type SerialisedScid uint64

// Policy is an interface that abstracts the terms which determine whether an
// asset sale/purchase channel HTLC is accepted or rejected.
type Policy interface {
	// CheckHtlcCompliance returns an error if the given HTLC intercept
	// descriptor does not satisfy the subject policy.
	CheckHtlcCompliance(htlc lndclient.InterceptedHtlc) error

	// Expiry returns the policy's expiry time as a unix timestamp.
	Expiry() uint64

	// Scid returns the serialised short channel ID (SCID) of the channel to
	// which the policy applies.
	Scid() uint64
}

// AssetSalePolicy is a struct that holds the terms which determine whether an
// asset sale channel HTLC is accepted or rejected.
type AssetSalePolicy struct {
	// scid is the serialised short channel ID (SCID) of the channel to
	// which the policy applies.
	scid SerialisedScid

	// AssetAmount is the amount of the tap asset that is being requested.
	AssetAmount uint64

	// MinimumChannelPayment is the minimum number of millisatoshis that
	// must be sent in the HTLC.
	MinimumChannelPayment lnwire.MilliSatoshi

	// expiry is the policy's expiry unix timestamp after which the policy
	// is no longer valid.
	expiry uint64
}

// NewAssetSalePolicy creates a new asset sale policy.
func NewAssetSalePolicy(quote rfqmsg.BuyAccept) *AssetSalePolicy {
	// Compute the serialised short channel ID (SCID) for the channel.
	scid := SerialisedScid(quote.ShortChannelId())

	return &AssetSalePolicy{
		scid:                  scid,
		AssetAmount:           quote.AssetAmount,
		MinimumChannelPayment: quote.AskPrice,
		expiry:                quote.Expiry,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
func (c *AssetSalePolicy) CheckHtlcCompliance(
	htlc lndclient.InterceptedHtlc) error {

	// Check that the channel SCID is as expected.
	htlcScid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
	if htlcScid != c.scid {
		return fmt.Errorf("htlc outgoing channel ID does not match "+
			"policy's SCID (htlc_scid=%d, policy_scid=%d)",
			htlcScid, c.scid)
	}

	// Check that the HTLC amount is at least the minimum acceptable amount.
	if htlc.AmountOutMsat < c.MinimumChannelPayment {
		return fmt.Errorf("htlc out amount is less than the policy "+
			"minimum (htlc_out_msat=%d, policy_min_msat=%d)",
			htlc.AmountOutMsat, c.MinimumChannelPayment)
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

// Scid returns the serialised short channel ID (SCID) of the channel to which
// the policy applies.
func (c *AssetSalePolicy) Scid() uint64 {
	return uint64(c.scid)
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

	// MinimumChannelPayment is the minimum number of millisatoshis that
	// must be sent in the HTLC.
	MinimumChannelPayment lnwire.MilliSatoshi

	// expiry is the policy's expiry unix timestamp in seconds after which
	// the policy is no longer valid.
	expiry uint64
}

// NewAssetPurchasePolicy creates a new asset purchase policy.
func NewAssetPurchasePolicy(quote rfqmsg.SellAccept) *AssetPurchasePolicy {
	// Compute the serialised short channel ID (SCID) for the channel.
	scid := SerialisedScid(quote.ShortChannelId())

	return &AssetPurchasePolicy{
		scid:                  scid,
		AcceptedQuoteId:       quote.ID,
		AssetAmount:           quote.AssetAmount,
		MinimumChannelPayment: quote.BidPrice,
		expiry:                quote.Expiry,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject policy.
func (c *AssetPurchasePolicy) CheckHtlcCompliance(
	htlc lndclient.InterceptedHtlc) error {

	// Check that the HTLC contains the accepted quote ID.
	quoteId, ok := parseHtlcCustomRecords(htlc.CustomRecords)
	if !ok {
		return fmt.Errorf("HTLC does not contain a relevant custom "+
			"record (htlc=%v)", htlc)
	}

	if *quoteId != c.AcceptedQuoteId {
		return fmt.Errorf("HTLC contains a custom record, but it does "+
			"not contain the accepted quote ID (htlc=%v, "+
			"accepted_quote_id=%v)", htlc, c.AcceptedQuoteId)
	}

	// Check that the HTLC amount is at least the minimum acceptable amount.
	if htlc.AmountOutMsat < c.MinimumChannelPayment {
		return fmt.Errorf("htlc out amount is less than the policy "+
			"minimum (htlc_out_msat=%d, policy_min_msat=%d)",
			htlc.AmountOutMsat, c.MinimumChannelPayment)
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

// Scid returns the serialised short channel ID (SCID) of the channel to which
// the policy applies.
func (c *AssetPurchasePolicy) Scid() uint64 {
	return uint64(c.scid)
}

// Ensure that AssetPurchasePolicy implements the Policy interface.
var _ Policy = (*AssetPurchasePolicy)(nil)

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

	log.Debug("Handling incoming HTLC")

	// Look up a policy for the HTLC. If a policy does not exist, we resume
	// the HTLC. This is because the HTLC may be relevant to another
	// interceptor service. We only reject HTLCs that are relevant to the
	// RFQ service and do not comply with a known policy.
	policy, ok := h.fetchPolicy(htlc)
	if !ok {
		log.Debug("Failed to find a policy for the HTLC. Resuming.")
		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionResume,
		}, nil
	}

	// At this point, we know that a policy exists and has not expired
	// whilst sitting in the local cache. We can now check that the HTLC
	// complies with the policy.
	err := policy.CheckHtlcCompliance(htlc)
	if err != nil {
		log.Warnf("HTLC does not comply with policy: %v "+
			"(htlc=%v, policy=%v)", err, htlc, policy)

		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionFail,
		}, nil
	}

	log.Debug("HTLC complies with policy. Broadcasting accept event.")
	acceptHtlcEvent := NewAcceptHtlcEvent(htlc, policy)
	h.cfg.AcceptHtlcEvents <- acceptHtlcEvent

	return &lndclient.InterceptedHtlcResponse{
		Action: lndclient.InterceptorActionResume,
	}, nil
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
	h.policies.Store(policy.scid, policy)
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
	bool) {

	var (
		foundPolicy *Policy
		foundScid   *SerialisedScid
	)

	// If the HTLC has a custom record, we check if it is relevant to the
	// RFQ service.
	quoteId, ok := parseHtlcCustomRecords(htlc.CustomRecords)
	if ok {
		scid := SerialisedScid(quoteId.Scid())
		policy, ok := h.policies.Load(scid)
		if ok {
			foundPolicy = &policy
			foundScid = &scid
		}
	}

	// If no policy has been found so far, we attempt to look up a policy by
	// the outgoing channel SCID.
	if foundPolicy == nil {
		scid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
		policy, ok := h.policies.Load(scid)
		if ok {
			foundPolicy = &policy
			foundScid = &scid
		}
	}

	// If no policy has been found so far, we attempt to look up a policy by
	// the incoming channel SCID.
	if foundPolicy == nil {
		scid := SerialisedScid(htlc.IncomingCircuitKey.ChanID.ToUint64())
		policy, ok := h.policies.Load(scid)
		if ok {
			foundPolicy = &policy
			foundScid = &scid
		}
	}

	// If no policy has been found, we return false.
	if foundPolicy == nil {
		return nil, false
	}

	policy := *foundPolicy
	scid := *foundScid

	// If the policy has expired, return false and clear it from the cache.
	expireTime := time.Unix(int64(policy.Expiry()), 0).UTC()
	currentTime := time.Now().UTC()

	if currentTime.After(expireTime) {
		h.policies.Delete(scid)
		return nil, false
	}

	return policy, true
}

// cleanupStalePolicies removes expired policies from the local cache.
func (h *OrderHandler) cleanupStalePolicies() {
	// Iterate over policies and remove any that have expired.
	staleCounter := 0

	h.policies.ForEach(
		func(scid SerialisedScid, policy Policy) error {
			expireTime := time.Unix(int64(policy.Expiry()), 0).UTC()
			currentTime := time.Now().UTC()

			if currentTime.After(expireTime) {
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
