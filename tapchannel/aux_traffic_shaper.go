package tapchannel

import (
	"context"
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
	"github.com/lightningnetwork/lnd/routing/route"
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
	htlcAmt lnwire.MilliSatoshi, htlcView lnwallet.AuxHtlcView,
	peer route.Vertex) (lnwire.MilliSatoshi, error) {

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
		htlc, computedLocal, linkBandwidth, minHtlcAmt, fundingChan,
		peer,
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
// on the list of available RFQ IDs. If any of those IDs matches the channel, we
// calculate the bandwidth based on its asset rate.
func (s *AuxTrafficShaper) paymentBandwidth(htlc *rfqmsg.Htlc,
	localBalance uint64, linkBandwidth, minHtlcAmt lnwire.MilliSatoshi,
	fundingChan *cmsg.OpenChannel,
	peer route.Vertex) (lnwire.MilliSatoshi, error) {

	// If the HTLC doesn't have any available RFQ IDs, it's incomplete, and
	// we cannot determine the bandwidth. The available RFQ IDs is the list
	// of RFQ IDs that may be used for the HTLCs of a payment. If they are
	// missing something is wrong.
	if htlc.AvailableRfqIDs.IsNone() {
		log.Tracef("No available RFQ IDs in HTLC, cannot determine " +
			"matching outgoing channel")
		return 0, nil
	}

	// Retrieve the available RFQ IDs.
	availableIDs := htlc.AvailableRfqIDs.UnsafeFromSome().Val.IDs

	acceptedSellQuotes := s.cfg.RfqManager.PeerAcceptedSellQuotes()
	acceptedBuyQuotes := s.cfg.RfqManager.LocalAcceptedBuyQuotes()

	// Now we'll go over our available RFQ IDs and try to find one that can
	// produce bandwidth over the channel.
	for _, rfqID := range availableIDs {
		// For this rfqID we'll fetch the corresponding quote and rate.
		sellQuote, isSellQuote := acceptedSellQuotes[rfqID.Scid()]
		buyQuote, isBuyQuote := acceptedBuyQuotes[rfqID.Scid()]

		var (
			rate      rfqmsg.AssetRate
			specifier asset.Specifier
			quotePeer route.Vertex
		)
		switch {
		case isSellQuote:
			quotePeer = sellQuote.Peer
			rate = sellQuote.AssetRate
			specifier = sellQuote.Request.AssetSpecifier

		case isBuyQuote:
			quotePeer = buyQuote.Peer
			rate = buyQuote.AssetRate
			specifier = buyQuote.Request.AssetSpecifier

		default:
			return 0, fmt.Errorf("no accepted quote found for RFQ "+
				"ID %x (SCID %d)", rfqID[:], rfqID.Scid())
		}

		// If the channel peer does not match the quote peer, continue
		// to the next available quote.
		if peer != quotePeer {
			continue
		}

		bandwidth, err := s.paymentBandwidthRFQ(
			rfqID, rate, specifier, localBalance, linkBandwidth,
			minHtlcAmt, fundingChan,
		)
		if err != nil {
			return 0, err
		}

		// We know that we establish 1 quote per peer in the scope of
		// each payment. This means that the first quote that produces
		// bandwidth is the only quote that can produce bandwidth, so
		// we immediately return it.
		if bandwidth > 0 {
			return bandwidth, nil
		}
	}

	return 0, nil
}

// paymentBandwidthRFQ retrieves the bandwidth for a specific channel and quote.
func (s *AuxTrafficShaper) paymentBandwidthRFQ(rfqID rfqmsg.ID,
	rate rfqmsg.AssetRate, specifier asset.Specifier, localBalance uint64,
	linkBandwidth, minHtlcAmt lnwire.MilliSatoshi,
	fundingChan *cmsg.OpenChannel) (lnwire.MilliSatoshi, error) {

	// Now that we have the quote, we can determine if this quote is even
	// compatible with this channel. If not, we cannot forward the HTLC
	// and should return 0 bandwidth.
	for _, b := range fundingChan.FundedAssets.Val.Outputs {
		// We define compatibility by making sure that each asset in the
		// channel matches the specifier of the RFQ quote. This means
		// if the quote was created for a single asset in a grouped
		// asset channel with multiple tranches, then the check will
		// return false, because the group key needs to be used in that
		// case. But this matches the behavior in other areas, where we
		// also use AssetMatchesSpecifier.
		match, err := s.cfg.RfqManager.AssetMatchesSpecifier(
			context.Background(), specifier, b.AssetID.Val,
		)
		if err != nil {
			return 0, fmt.Errorf("error checking if asset ID %x "+
				"matches specifier %s: %w", b.AssetID.Val[:],
				specifier.String(), err)
		}

		// One of the asset IDs in the channel does not match the quote,
		// we don't want to route this HTLC over this channel.
		if !match {
			log.Tracef("Quote with ID %x (SCID %d) not compatible "+
				"with channel assets, returning 0 bandwidth",
				rfqID[:], rfqID.Scid())
			return 0, nil
		}
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
	htlcCustomRecords lnwire.CustomRecords,
	peer route.Vertex) (lnwire.MilliSatoshi, lnwire.CustomRecords, error) {

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

	// Within the context of a payment we may negotiate multiple quotes. All
	// of the quotes that may be used for a payment are encoded in the
	// following field. If we don't have any available quotes then we can't
	// proceed.
	if htlc.AvailableRfqIDs.IsNone() {
		return 0, nil, fmt.Errorf("no available RFQ IDs present in " +
			"HTLC blob")
	}

	acceptedQuotes := s.cfg.RfqManager.PeerAcceptedSellQuotes()
	availableIDs := htlc.AvailableRfqIDs.UnsafeFromSome().Val.IDs

	var (
		rfqID rfqmsg.ID
		quote rfqmsg.SellAccept
	)

	// Let's find the quote that matches this peer. This will be the quote
	// that we'll use to calculate the asset units. Given that we may only
	// establish a maximum of 1 quote per peer per payment, this check is
	// safe to perform as there are no competing quotes for a certain peer.
	for _, id := range availableIDs {
		q, ok := acceptedQuotes[id.Scid()]
		if !ok {
			continue
		}

		// We found the quote to use, now let's set the related fields.
		if q.Peer == peer {
			// This is the actual RFQ ID that our peer will use to
			// perform checks on their end.
			rfqID = id
			htlc.RfqID = rfqmsg.SomeRfqIDRecord(rfqID)
			quote = q
			break
		}
	}

	if htlc.RfqID.IsNone() {
		return 0, nil, fmt.Errorf("none of the available RFQ IDs "+
			"match our peer=%s", peer)
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
