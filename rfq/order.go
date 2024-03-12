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

// SerialisedScid is a serialised short channel id (SCID).
type SerialisedScid uint64

// ChannelRemit is a struct that holds the terms which determine whether a
// channel HTLC is accepted or rejected.
type ChannelRemit struct {
	// Scid is the serialised short channel ID (SCID) of the channel to
	// which the remit applies.
	Scid SerialisedScid

	// AssetAmount is the amount of the tap asset that is being requested.
	AssetAmount uint64

	// MinimumChannelPayment is the minimum number of millisatoshis that
	// must be sent in the HTLC.
	MinimumChannelPayment lnwire.MilliSatoshi

	// Expiry is the asking price expiryDelay lifetime unix timestamp.
	Expiry uint64
}

// NewChannelRemit creates a new channel remit.
func NewChannelRemit(quoteAccept rfqmsg.BuyAccept) *ChannelRemit {
	// Compute the serialised short channel ID (SCID) for the channel.
	scid := SerialisedScid(quoteAccept.ShortChannelId())

	return &ChannelRemit{
		Scid:                  scid,
		AssetAmount:           quoteAccept.AssetAmount,
		MinimumChannelPayment: quoteAccept.AskPrice,
		Expiry:                quoteAccept.Expiry,
	}
}

// CheckHtlcCompliance returns an error if the given HTLC intercept descriptor
// does not satisfy the subject channel remit.
func (c *ChannelRemit) CheckHtlcCompliance(
	htlc lndclient.InterceptedHtlc) error {

	// Check that the channel SCID is as expected.
	htlcScid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
	if htlcScid != c.Scid {
		return fmt.Errorf("htlc outgoing channel ID does not match "+
			"remit's SCID (htlc_scid=%d, remit_scid=%d)", htlcScid,
			c.Scid)
	}

	// Check that the HTLC amount is at least the minimum acceptable amount.
	if htlc.AmountOutMsat < c.MinimumChannelPayment {
		return fmt.Errorf("htlc out amount is less than the remit's "+
			"minimum (htlc_out_msat=%d, remit_min_msat=%d)",
			htlc.AmountOutMsat, c.MinimumChannelPayment)
	}

	// Lastly, check to ensure that the channel remit has not expired.
	if time.Now().Unix() > int64(c.Expiry) {
		return fmt.Errorf("channel remit has expired "+
			"(expiry_unix_ts=%d)", c.Expiry)
	}

	return nil
}

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

	// channelRemits is a map of serialised short channel IDs (SCIDs) to
	// associated active channel remits.
	channelRemits lnutils.SyncMap[SerialisedScid, *ChannelRemit]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewOrderHandler creates a new struct instance.
func NewOrderHandler(cfg OrderHandlerCfg) (*OrderHandler, error) {
	return &OrderHandler{
		cfg:           cfg,
		channelRemits: lnutils.SyncMap[SerialisedScid, *ChannelRemit]{},
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

	scid := SerialisedScid(htlc.OutgoingChannelID.ToUint64())
	channelRemit, ok := h.fetchChannelRemit(scid)

	// If a channel remit does not exist for the channel SCID, we resume the
	// HTLC. This is because the HTLC may be relevant to another interceptor
	// service. We only reject HTLCs that are relevant to the RFQ service
	// and do not comply with a known channel remit.
	if !ok {
		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionResume,
		}, nil
	}

	// At this point, we know that the channel remit exists and has not
	// expired whilst sitting in the local cache. We can now check that the
	// HTLC complies with the channel remit.
	err := channelRemit.CheckHtlcCompliance(htlc)
	if err != nil {
		log.Warnf("HTLC does not comply with channel remit: %v "+
			"(htlc=%v, channel_remit=%v)", err, htlc, channelRemit)

		return &lndclient.InterceptedHtlcResponse{
			Action: lndclient.InterceptorActionFail,
		}, nil
	}

	log.Debug("HTLC complies with channel remit. Broadcasting accept " +
		"event.")
	acceptHtlcEvent := NewAcceptHtlcEvent(htlc, *channelRemit)
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
		// Periodically clean up expired channel remits from our local
		// cache.
		case <-cleanupTicker.C:
			log.Debug("Cleaning up any stale channel remits from " +
				"the order handler")
			h.cleanupStaleChannelRemits()

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

	channelRemit := NewChannelRemit(buyAccept)
	h.channelRemits.Store(channelRemit.Scid, channelRemit)
}

// fetchChannelRemit fetches a channel remit given a serialised SCID. If a
// channel remit is not found, false is returned. Expired channel remits are
// not returned and are removed from the cache.
func (h *OrderHandler) fetchChannelRemit(scid SerialisedScid) (*ChannelRemit,
	bool) {

	remit, ok := h.channelRemits.Load(scid)
	if !ok {
		return nil, false
	}

	// If the remit has expired, return false and clear it from the cache.
	expireTime := time.Unix(int64(remit.Expiry), 0).UTC()
	currentTime := time.Now().UTC()

	if currentTime.After(expireTime) {
		h.channelRemits.Delete(scid)
		return nil, false
	}

	return remit, true
}

// cleanupStaleChannelRemits removes expired channel remits from the local
// cache.
func (h *OrderHandler) cleanupStaleChannelRemits() {
	// Iterate over the channel remits and remove any that have expired.
	staleCounter := 0

	h.channelRemits.ForEach(
		func(scid SerialisedScid, remit *ChannelRemit) error {
			expireTime := time.Unix(int64(remit.Expiry), 0).UTC()
			currentTime := time.Now().UTC()

			if currentTime.After(expireTime) {
				staleCounter++
				h.channelRemits.Delete(scid)
			}

			return nil
		},
	)

	if staleCounter > 0 {
		log.Tracef("Removed stale channel remits from the order "+
			"handler: (count=%d)", staleCounter)
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
