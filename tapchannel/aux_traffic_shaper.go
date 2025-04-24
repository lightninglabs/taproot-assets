package tapchannel

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// TrafficShaperConfig defines the configuration for the auxiliary traffic
// shaper.
type TrafficShaperConfig struct {
	ChainParams *address.ChainParams

	RfqManager *rfq.Manager
}

// AuxTrafficShaper is a Taproot Asset auxiliary traffic shaper that can be used
// to make routing decisions for Taproot Asset channels.
type AuxTrafficShaper struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *TrafficShaperConfig

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxTrafficShaper creates a new Taproot Asset auxiliary traffic shaper
// based on the passed config.
func NewAuxTrafficShaper(cfg *TrafficShaperConfig) *AuxTrafficShaper {
	return &AuxTrafficShaper{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new aux traffic shaper.
func (s *AuxTrafficShaper) Start() error {
	var startErr error
	s.startOnce.Do(func() {
		log.Info("Starting aux traffic shaper")
	})
	return startErr
}

// Stop signals for an aux traffic shaper to gracefully exit.
func (s *AuxTrafficShaper) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		log.Info("Stopping aux traffic shaper")

		close(s.Quit)
		s.Wg.Wait()
	})

	return stopErr
}

// ShouldHandleTraffic is called in order to check if the channel identified by
// the provided channel ID is handled by the traffic shaper implementation. If
// it is handled by the traffic shaper, then the normal bandwidth calculation
// can be skipped and the bandwidth returned by PaymentBandwidth should be used
// instead.
func (s *AuxTrafficShaper) ShouldHandleTraffic(cid lnwire.ShortChannelID,
	_, htlcBlob lfn.Option[tlv.Blob]) (bool, error) {

	// The rule here is simple: If the HTLC is an asset HTLC, we _need_ to
	// handle the bandwidth. Because of non-strict forwarding in lnd, it
	// could otherwise be the case that we forward an asset HTLC on a
	// non-asset channel, which would be a problem.
	htlcBytes := htlcBlob.UnwrapOr(nil)
	if len(htlcBytes) == 0 {
		log.Tracef("Empty HTLC blob, not handling traffic for %v", cid)
		return false, nil
	}

	// If there are no asset HTLC custom records, we don't need to do
	// anything as this is a regular payment.
	if !rfqmsg.HasAssetHTLCEntries(htlcBytes) {
		log.Tracef("No asset HTLC custom records, not handling "+
			"traffic for %v", cid)
		return false, nil
	}

	// If this _is_ an asset HTLC, we definitely want to handle the
	// bandwidth for this channel, so we can deny forwarding asset HTLCs
	// over non-asset channels.
	return true, nil
}

// PaymentBandwidth returns the available bandwidth for a custom channel decided
// by the given channel aux blob and HTLC blob. A return value of 0 means there
// is no bandwidth available. To find out if a channel is a custom channel that
// should be handled by the traffic shaper, the HandleTraffic method should be
// called first.
func (s *AuxTrafficShaper) PaymentBandwidth(fundingBlob, htlcBlob,
	commitmentBlob lfn.Option[tlv.Blob], linkBandwidth,
	htlcAmt lnwire.MilliSatoshi,
	htlcView lnwallet.AuxHtlcView) (lnwire.MilliSatoshi, error) {

	fundingBlobBytes := fundingBlob.UnwrapOr(nil)
	htlcBytes := htlcBlob.UnwrapOr(nil)
	commitmentBytes := commitmentBlob.UnwrapOr(nil)

	// If the HTLC is not an asset HTLC, we can just return the normal link
	// bandwidth, as we don't need to do any special math. We shouldn't even
	// get here in the first place, since the ShouldHandleTraffic function
	// should return false in this case.
	if len(htlcBytes) == 0 || !rfqmsg.HasAssetHTLCEntries(htlcBytes) {
		log.Tracef("Empty HTLC blob or no asset HTLC custom records, "+
			"returning link bandwidth %v", linkBandwidth)
		return linkBandwidth, nil
	}

	// If this is an asset HTLC but the channel is not an asset channel, we
	// MUST deny forwarding the HTLC.
	if len(commitmentBytes) == 0 || len(fundingBlobBytes) == 0 {
		log.Tracef("Empty commitment or funding blob, cannot forward" +
			"asset HTLC over non-asset channel, returning 0 " +
			"bandwidth")
		return 0, nil
	}

	fundingChan, err := cmsg.DecodeOpenChannel(fundingBlobBytes)
	if err != nil {
		return 0, fmt.Errorf("error decoding funding blob: %w", err)
	}

	commitment, err := cmsg.DecodeCommitment(commitmentBytes)
	if err != nil {
		return 0, fmt.Errorf("error decoding commitment blob: %w", err)
	}

	htlc, err := rfqmsg.DecodeHtlc(htlcBytes)
	if err != nil {
		return 0, fmt.Errorf("error decoding HTLC blob: %w", err)
	}

	// Before we do any further checks, we actually need to make sure that
	// the HTLC is compatible with this channel. Because of `lnd`'s
	// non-strict forwarding, if there are multiple asset channels, the
	// wrong one could be chosen if we signal there's bandwidth. So we need
	// to tell `lnd` it can't use this channel if the assets aren't
	// compatible.
	htlcAssetIDs := fn.NewSet[asset.ID](fn.Map(
		htlc.Balances(), func(b *rfqmsg.AssetBalance) asset.ID {
			return b.AssetID.Val
		})...,
	)
	if !fundingChan.HasAllAssetIDs(htlcAssetIDs) {
		log.Tracef("HTLC asset IDs %v not compatible with asset IDs "+
			"of channel, returning 0 bandwidth", htlcAssetIDs)
		return 0, nil
	}

	// With the help of the latest HtlcView, let's calculate a more precise
	// local balance. This is useful in order to not forward HTLCs that may
	// never be settled. Other HTLCs that may also call into this method are
	// not yet registered to the commitment, so we need to account for them
	// manually.
	computedLocal, decodedView, err := ComputeLocalBalance(
		*commitment, htlcView,
	)
	if err != nil {
		return 0, err
	}

	log.Tracef("Computed asset HTLC View: commitmentLocal=%v, "+
		"computedLocal=%v, nextHeight=%v, thisHtlc=%v, newView=%v",
		cmsg.OutputSum(commitment.LocalOutputs()), computedLocal,
		htlcView.NextHeight, htlc.Amounts.Val.Sum(),
		lnutils.NewLogClosure(func() string {
			return prettyPrintLocalView(*decodedView)
		}))

	// Get the minimum HTLC amount, which is just above dust.
	minHtlcAmt := rfqmath.DefaultOnChainHtlcMSat

	// LND calls this hook twice. Once to see if the overall budget of the
	// node is enough, and then during pathfinding to actually see if
	// there's enough balance in the channel to make the payment attempt.
	//
	// When doing the overall balance check, we don't know what the actual
	// htlcAmt is in satoshis, so a value of 0 will be passed here. Let's at
	// least check if we can afford the min amount above dust. If the actual
	// htlc amount ends up being greater when calling this method during
	// pathfinding, we will still check it below.

	// If the passed htlcAmt is below dust, then assume the dust amount. At
	// this point we know we are sending assets, so we cannot anchor them to
	// dust amounts. Dust HTLCs are added to the fees and aren't
	// materialized in an on-chain output, so we wouldn't have anything
	// to anchor the asset commitment to.
	if htlcAmt < minHtlcAmt {
		htlcAmt = minHtlcAmt
	}

	// If the HTLC carries asset units (keysend, forwarding), then there's
	// no need to do any RFQ related math. We can directly compare the asset
	// units of the HTLC with those in our local balance.
	htlcAssetAmount := htlc.Amounts.Val.Sum()
	if htlcAssetAmount != 0 {
		return paymentBandwidthAssetUnits(
			htlcAssetAmount, computedLocal, linkBandwidth, htlcAmt,
		)
	}

	// Otherwise, we derive the available bandwidth from the HTLC's RFQ and
	// the asset units in our local balance.
	return s.paymentBandwidth(
		htlc, computedLocal, linkBandwidth, minHtlcAmt,
	)
}

// paymentBandwidthAssetUnits includes the asset unit related checks between the
// HTLC carrying the units and the asset balance of our channel. The response
// will either be infinite or zero bandwidth, as we can't really map the amount
// to msats without an RFQ, and it's also not needed.
func paymentBandwidthAssetUnits(htlcAssetAmount, computedLocal uint64,
	linkBandwidth,
	htlcAmt lnwire.MilliSatoshi) (lnwire.MilliSatoshi, error) {

	switch {
	case htlcAssetAmount <= computedLocal:
		// Check if the current link bandwidth can afford sending out
		// the htlc amount without dipping into the channel reserve. If
		// it goes below the reserve, we report zero bandwidth as we
		// cannot push the HTLC amount.
		if linkBandwidth < htlcAmt {
			log.Tracef("Link bandwidth %v smaller than HTLC "+
				"amount %d, returning 0 as we'd dip below "+
				"reserver otherwise", linkBandwidth, htlcAmt)
			return 0, nil
		}

		// We signal "infinite" bandwidth by returning a very high
		// value (number of Satoshis ever in existence), since we might
		// not have a quote available to know what the asset amount
		// means in terms of satoshis. But the satoshi amount doesn't
		// matter too much here, we just want to signal that this
		// channel _does_ have available bandwidth.
		return lnwire.NewMSatFromSatoshis(btcutil.MaxSatoshi), nil

	case htlcAssetAmount > computedLocal:
		// The asset balance of the channel is simply not enough to
		// route the asset units, we report 0 bandwidth in order for the
		// HTLC to fail back.
		return 0, nil

	default:
		// We shouldn't reach this case, we add it only for the function
		// to always return something and the compiler to be happy.
		return 0, fmt.Errorf("should not reach this, invalid htlc " +
			"asset amount or computed local balance")
	}
}

// paymentBandwidth returns the available payment bandwidth of the channel based
// on the asset rate of the RFQ quote that is included in the HTLC and the asset
// units of the local balance.
func (s *AuxTrafficShaper) paymentBandwidth(htlc *rfqmsg.Htlc,
	localBalance uint64, linkBandwidth,
	minHtlcAmt lnwire.MilliSatoshi) (lnwire.MilliSatoshi, error) {

	// If the HTLC doesn't have an RFQ ID, it's incomplete, and we cannot
	// determine the bandwidth.
	if htlc.RfqID.ValOpt().IsNone() {
		log.Tracef("No RFQ ID in HTLC, cannot determine matching " +
			"outgoing channel")
		return 0, nil
	}

	// For every other use case (i.e. a normal payment with a negotiated
	// quote or a multi-hop keysend that also uses a quote), we need to look
	// up the accepted quote and determine the outgoing bandwidth in
	// satoshis based on the local asset balance.
	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()
	acceptedSellQuotes := s.cfg.RfqManager.PeerAcceptedSellQuotes()
	acceptedBuyQuotes := s.cfg.RfqManager.LocalAcceptedBuyQuotes()

	sellQuote, isSellQuote := acceptedSellQuotes[rfqID.Scid()]
	buyQuote, isBuyQuote := acceptedBuyQuotes[rfqID.Scid()]

	var rate rfqmsg.AssetRate
	switch {
	case isSellQuote:
		rate = sellQuote.AssetRate

	case isBuyQuote:
		rate = buyQuote.AssetRate

	default:
		return 0, fmt.Errorf("no accepted quote found for RFQ ID "+
			"%x (SCID %d)", rfqID[:], rfqID.Scid())
	}

	// Calculate the local available balance in the local asset unit,
	// expressed in milli-satoshis.
	localBalanceFp := rfqmath.NewBigIntFixedPoint(localBalance, 0)
	availableBalanceMsat := rfqmath.UnitsToMilliSatoshi(
		localBalanceFp, rate.Rate,
	)

	// At this point we have acquired what we need to express the asset
	// bandwidth expressed in satoshis. Before we return the result, we need
	// to check if the link bandwidth can afford sending a non-dust htlc to
	// the other side.
	if linkBandwidth < minHtlcAmt {
		log.Tracef("Link bandwidth %v smaller than HTLC min amount "+
			"%d, returning 0 as we'd dip below reserver otherwise",
			linkBandwidth, minHtlcAmt)
		return 0, nil
	}

	// The available balance is the local asset unit expressed in
	// milli-satoshis.
	return availableBalanceMsat, nil
}

// ComputeLocalBalance combines the given commitment state with the HtlcView to
// produce the available local balance with accuracy.
func ComputeLocalBalance(commitment cmsg.Commitment,
	htlcView lnwallet.AuxHtlcView) (uint64, *DecodedView, error) {

	// Set the htlcView next height to 0. This is needed because the
	// following helper `ComputeLocalBalance` will use that height to add or
	// remove HTLCs that have a matching addHeight. The HTLCs that are not
	// yet part of the commitment have an addHeight of 0, so that's the
	// height we want to filter by here.
	htlcView.NextHeight = 0

	// Let's get the current local and remote asset balances of the channel
	// as reported by the latest commitment.
	localBalance := cmsg.OutputSum(commitment.LocalOutputs())
	remoteBalance := cmsg.OutputSum(commitment.RemoteOutputs())

	// With the help of the latest HtlcView, let's calculate a more precise
	// local balance. This is useful in order to not forward HTLCs that may
	// never be settled. Other HTLCs that may also call into this method are
	// not yet registered to the commitment, so we need to account for them
	// manually.
	computedLocal, _, decodedView, _, err := ComputeView(
		localBalance, remoteBalance, lntypes.Local, htlcView,
	)
	if err != nil {
		return 0, nil, err
	}

	return computedLocal, decodedView, nil
}

// ProduceHtlcExtraData is a function that, based on the previous custom record
// blob of an HTLC, may produce a different blob or modify the amount of bitcoin
// this HTLC should carry.
func (s *AuxTrafficShaper) ProduceHtlcExtraData(totalAmount lnwire.MilliSatoshi,
	htlcCustomRecords lnwire.CustomRecords) (lnwire.MilliSatoshi,
	lnwire.CustomRecords, error) {

	if !rfqmsg.HasAssetHTLCCustomRecords(htlcCustomRecords) {
		log.Tracef("No asset HTLC custom records, not producing " +
			"extra data")
		return totalAmount, nil, nil
	}

	// We need to do a round trip to convert the custom records to a blob
	// that we can then parse into the correct struct again.
	htlc, err := rfqmsg.HtlcFromCustomRecords(htlcCustomRecords)
	if err != nil {
		return 0, nil, fmt.Errorf("error decoding HTLC blob: %w", err)
	}

	// If we already have an asset amount in the HTLC, we assume this is a
	// keysend payment and don't need to do anything. We even return the
	// original on-chain amount as we don't want to change it.
	if htlc.Amounts.Val.Sum() > 0 {
		log.Tracef("Already have asset amount (sum %d) in HTLC, not "+
			"producing extra data", htlc.Amounts.Val.Sum())
		return totalAmount, htlcCustomRecords, nil
	}

	if htlc.RfqID.ValOpt().IsNone() {
		return 0, nil, fmt.Errorf("no RFQ ID present in HTLC blob")
	}

	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()
	acceptedQuotes := s.cfg.RfqManager.PeerAcceptedSellQuotes()
	quote, ok := acceptedQuotes[rfqID.Scid()]
	if !ok {
		return 0, nil, fmt.Errorf("no accepted quote found for RFQ ID "+
			"%x (SCID %d)", rfqID[:], rfqID.Scid())
	}

	// Now that we've queried the accepted quote, we know how many asset
	// units we need to send. This is the main purpose of this method: We
	// convert the BTC amount originally intended to be sent out into the
	// corresponding number of assets, then reduce the number of satoshis of
	// the HTLC to the bare minimum that can be materialized on chain.
	numAssetUnitsFp := rfqmath.MilliSatoshiToUnits(
		totalAmount, quote.AssetRate.Rate,
	)
	numAssetUnits := numAssetUnitsFp.ScaleTo(0).ToUint64()

	var assetId asset.ID

	switch {
	case quote.Request.AssetSpecifier.HasId():
		assetId = *quote.Request.AssetSpecifier.UnwrapIdToPtr()

	case quote.Request.AssetSpecifier.HasGroupPubKey():
		// If a group key is defined in the quote we place the X
		// coordinate of the group key as the dummy asset ID in the
		// HTLC. This asset balance in the HTLC is just a hint and the
		// actual asset IDs will be picked later in the process.
		groupKey := quote.Request.AssetSpecifier.UnwrapGroupKeyToPtr()
		groupKeyX := schnorr.SerializePubKey(groupKey)
		assetId = asset.ID(groupKeyX)
	}

	// If the number of asset units to send is zero due to integer division
	// and insufficient asset unit precision vs. satoshis, we cannot send
	// this payment. This should only happen if the amount to pay is very
	// small (small satoshi or sub satoshi total value) or the price oracle
	// has given a very high price for the asset.
	if numAssetUnits == 0 {
		return 0, nil, fmt.Errorf("asset unit price (%v asset per "+
			"BTC) too high to represent HTLC value of %v",
			quote.AssetRate, totalAmount)
	}

	log.Debugf("Producing HTLC extra data for RFQ ID %x (SCID %d): "+
		"asset_specifier=%s, btc_amt=%v, asset_amount %d", rfqID[:],
		rfqID.Scid(), quote.Request.AssetSpecifier.String(),
		totalAmount, numAssetUnits)

	htlc.Amounts.Val.Balances = []*rfqmsg.AssetBalance{
		rfqmsg.NewAssetBalance(assetId, numAssetUnits),
	}

	// Encode the updated HTLC TLV back into a blob and return it with the
	// amount that should be sent on-chain, which is a value in satoshi that
	// is just above the dust limit.
	htlcAmountMSat := rfqmath.DefaultOnChainHtlcMSat
	updatedRecords, err := htlc.ToCustomRecords()
	if err != nil {
		return 0, nil, fmt.Errorf("error encoding HTLC blob: %w", err)
	}

	return htlcAmountMSat, updatedRecords, nil
}

// prettyPrintLocalView returns a string that pretty-prints the local update log
// of an HTLC view.
func prettyPrintLocalView(view DecodedView) string {
	var res string
	res = "\nHtlcView Local Updates:\n"
	for _, v := range view.OurUpdates {
		assetAmt := uint64(0)
		if rfqmsg.HasAssetHTLCCustomRecords(v.CustomRecords) {
			assetHtlc, err := rfqmsg.HtlcFromCustomRecords(
				v.CustomRecords,
			)
			if err != nil {
				res = fmt.Sprintf("%s\terror: could not "+
					"decode htlc custom records\n", res)
				continue
			}

			assetAmt = rfqmsg.Sum(assetHtlc.Balances())
		}

		res = fmt.Sprintf("%s\thtlcIndex=%v: amt=%v, assets=%v, "+
			"addHeight=%v\n", res, v.HtlcIndex, v.Amount, assetAmt,
			v.AddHeight(lntypes.Local))
	}

	return res
}
