package tapchannel

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// DefaultOnChainHtlcAmount is the default amount that we consider
	// as the smallest HTLC amount that can be sent on-chain. This needs to
	// be greater than the dust limit for an HTLC.
	DefaultOnChainHtlcAmount = lnwallet.DustLimitForSize(
		input.UnknownWitnessSize,
	)
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

// A compile-time check to ensure that AuxTrafficShaper fully implements the
// routing.TlvTrafficShaper interface.
var _ routing.TlvTrafficShaper = (*AuxTrafficShaper)(nil)

// ShouldHandleTraffic is called in order to check if the channel identified by
// the provided channel ID is handled by the traffic shaper implementation. If
// it is handled by the traffic shaper, then the normal bandwidth calculation
// can be skipped and the bandwidth returned by PaymentBandwidth should be used
// instead.
func (s *AuxTrafficShaper) ShouldHandleTraffic(_ lnwire.ShortChannelID,
	fundingBlob lfn.Option[tlv.Blob]) (bool, error) {

	// If there is no auxiliary blob in the channel, it's not a custom
	// channel, and we don't need to handle it.
	if fundingBlob.IsNone() {
		return false, nil
	}

	// If we can successfully decode the channel blob as a channel capacity
	// information, we know that this is a custom channel.
	err := lfn.MapOptionZ(fundingBlob, func(blob tlv.Blob) error {
		_, err := cmsg.DecodeOpenChannel(blob)
		return err
	})
	if err != nil {
		return false, err
	}

	// No error, so this is a custom channel, we'll want to decide.
	return true, nil
}

// PaymentBandwidth returns the available bandwidth for a custom channel decided
// by the given channel aux blob and HTLC blob. A return value of 0 means there
// is no bandwidth available. To find out if a channel is a custom channel that
// should be handled by the traffic shaper, the HandleTraffic method should be
// called first.
func (s *AuxTrafficShaper) PaymentBandwidth(htlcBlob,
	commitmentBlob lfn.Option[tlv.Blob], linkBandwidth,
	htlcAmt lnwire.MilliSatoshi) (lnwire.MilliSatoshi, error) {

	// If the commitment or HTLC blob is not set, we don't have any
	// information about the channel and cannot determine the available
	// bandwidth from a taproot asset perspective. We return the link
	// bandwidth as a fallback.
	if commitmentBlob.IsNone() || htlcBlob.IsNone() {
		return linkBandwidth, nil
	}

	commitmentBytes := commitmentBlob.UnsafeFromSome()
	htlcBytes := htlcBlob.UnsafeFromSome()

	// Sometimes the blob is set but actually empty, in which case we also
	// don't have any information about the channel.
	if len(commitmentBytes) == 0 || len(htlcBytes) == 0 {
		return linkBandwidth, nil
	}

	// Get the minimum HTLC amount, which is just above dust.
	minHtlcAmt := lnwire.NewMSatFromSatoshis(DefaultOnChainHtlcAmount)

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

	commitment, err := cmsg.DecodeCommitment(commitmentBytes)
	if err != nil {
		return 0, fmt.Errorf("error decoding commitment blob: %w", err)
	}

	htlc, err := rfqmsg.DecodeHtlc(htlcBytes)
	if err != nil {
		return 0, fmt.Errorf("error decoding HTLC blob: %w", err)
	}

	localBalance := cmsg.OutputSum(commitment.LocalOutputs())

	// There either already is an amount set in the HTLC (which would
	// indicate it to be a direct-channel keysend payment that just sends
	// assets to the direct peer with no conversion), in which case we don't
	// need an RFQ ID as we can just compare the local balance and the
	// required HTLC amount. If there is no amount set, we need to look up
	// the RFQ ID in the HTLC blob and use the accepted quote to determine
	// the amount.
	htlcAssetAmount := htlc.Amounts.Val.Sum()
	if htlcAssetAmount != 0 && htlcAssetAmount <= localBalance {
		// Check if the current link bandwidth can afford sending out
		// the htlc amount without dipping into the channel reserve. If
		// it goes below the reserve, we report zero bandwdith as we
		// cannot push the htlc amount.
		if linkBandwidth < htlcAmt {
			return 0, nil
		}

		// We signal "infinite" bandwidth by returning a very high
		// value (number of Satoshis ever in existence), since we might
		// not have a quote available to know what the asset amount
		// means in terms of satoshis. But the satoshi amount doesn't
		// matter too much here, we just want to signal that this
		// channel _does_ have available bandwidth.
		return lnwire.NewMSatFromSatoshis(btcutil.MaxSatoshi), nil
	}

	// If the HTLC doesn't have an asset amount and RFQ ID, it's incomplete,
	// and we cannot determine what channel to use.
	if htlc.RfqID.ValOpt().IsNone() {
		return 0, nil
	}

	// For every other use case (i.e. a normal payment with a negotiated
	// quote or a multi-hop keysend that also uses a quote), we need to look
	// up the accepted quote and determine the outgoing bandwidth in
	// satoshis based on the local asset balance.
	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()
	acceptedQuotes := s.cfg.RfqManager.PeerAcceptedSellQuotes()
	quote, ok := acceptedQuotes[rfqID.Scid()]
	if !ok {
		return 0, fmt.Errorf("no accepted quote found for RFQ ID "+
			"%x (SCID %d)", rfqID[:], rfqID.Scid())
	}

	mSatPerAssetUnit := quote.BidPrice

	// At this point we have acquired what we need to express the asset
	// bandwidth expressed in satoshis. Before we return the result, we need
	// to check if the link bandwidth can afford sending a non-dust htlc to
	// the other side.
	if linkBandwidth < minHtlcAmt {
		return 0, nil
	}

	// The available balance is the local asset unit expressed in
	// milli-satoshis.
	return lnwire.MilliSatoshi(localBalance) * mSatPerAssetUnit, nil
}

// ProduceHtlcExtraData is a function that, based on the previous custom record
// blob of an HTLC, may produce a different blob or modify the amount of bitcoin
// this HTLC should carry.
func (s *AuxTrafficShaper) ProduceHtlcExtraData(totalAmount lnwire.MilliSatoshi,
	htlcCustomRecords lnwire.CustomRecords) (lnwire.MilliSatoshi,
	lnwire.CustomRecords, error) {

	if len(htlcCustomRecords) == 0 {
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
	// The bid price is in milli-satoshis per asset unit. We round to the
	// nearest 10 units to avoid more than half an asset unit of rounding
	// error that we would get if we did normal integer division (rounding
	// down).
	mSatPerAssetUnit := quote.BidPrice
	numAssetUnits := uint64(totalAmount*10/mSatPerAssetUnit) / 10

	// We now know how many units we need. We take the asset ID from the
	// RFQ so the recipient can match it back to the quote.
	if quote.Request.AssetID == nil {
		return 0, nil, fmt.Errorf("quote has no asset ID")
	}

	// If the number of asset units to send is zero due to integer division
	// and insufficient asset unit precision vs. satoshis, we cannot send
	// this payment. This should only happen if the amount to pay is very
	// small (small satoshi or sub satoshi total value) or the price oracle
	// has given a very high price for the asset.
	if numAssetUnits == 0 {
		return 0, nil, fmt.Errorf("asset unit price (%d mSat per "+
			"asset unit) too high to represent HTLC value of %v",
			mSatPerAssetUnit, totalAmount)
	}

	log.Debugf("Producing HTLC extra data for RFQ ID %x (SCID %d): "+
		"asset ID %x, btc_amt=%v, asset amount %d", rfqID[:],
		rfqID.Scid(), quote.Request.AssetID[:], totalAmount,
		numAssetUnits)

	htlc.Amounts.Val.Balances = []*rfqmsg.AssetBalance{
		rfqmsg.NewAssetBalance(*quote.Request.AssetID, numAssetUnits),
	}

	// Encode the updated HTLC TLV back into a blob and return it with the
	// amount that should be sent on-chain, which is a value in satoshi that
	// is just above the dust limit.
	htlcAmountMSat := lnwire.NewMSatFromSatoshis(DefaultOnChainHtlcAmount)
	updatedRecords, err := htlc.ToCustomRecords()
	if err != nil {
		return 0, nil, fmt.Errorf("error encoding HTLC blob: %w", err)
	}

	return htlcAmountMSat, updatedRecords, nil
}
