package tapchannel

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestIssue121CarrierDustEvaluation documents the corrected behavior behind
// issue #121: the fixed on-chain HTLC carrier does NOT become dust at
// elevated feerates for real tapd channels, because they are taproot
// channels and lnd's second-level HTLC fee functions return zero for
// taproot channel types, making lnwallet.HtlcIsDust feerate-independent.
// The originally reported mechanism (a feerate spike wedging every asset
// commitment) therefore does not reproduce.
//
// The residual that is real: the carrier can fall below a negotiated dust
// limit, which tapd's commitment assembly does reject channel-fatally.
func TestIssue121CarrierDustEvaluation(t *testing.T) {
	t.Parallel()

	channel := newOneSidedChannel(t)
	fundedAsset := channel.fundingProof.Asset.ID()

	prevState := tapchannelmsg.NewCommitment(
		nil, []*tapchannelmsg.AssetOutput{channel.assetOutput}, nil,
		nil, lnwallet.CommitAuxLeaves{}, false, false,
	)
	chanAssetState := tapchannelmsg.NewOpenChannel(
		[]*tapchannelmsg.AssetOutput{channel.assetOutput}, 0, nil,
	)

	// The channel type of a real tapd channel: taproot with a tapscript
	// root and anchors.
	taprootChanType := channeldb.SingleFunderTweaklessBit |
		channeldb.AnchorOutputsBit | channeldb.ScidAliasChanBit |
		channeldb.SimpleTaprootFeatureBit | channeldb.TapscriptRootBit
	taprootChanState := lnwallet.AuxChanState{
		ChanType: taprootChanType,
	}

	// The fixed carrier of an asset HTLC, as the traffic shaper sets it.
	carrierSat := rfqmath.DefaultOnChainHtlcSat

	// Feerate-independence of the dust evaluation for taproot channels:
	// at a low and at a very high feerate, the carrier is not dust, and
	// commitment generation with an in-flight asset HTLC succeeds at both.
	feerates := []chainfee.SatPerKWeight{
		chainfee.FeePerKwFloor, 25_000,
	}
	for _, feePerKw := range feerates {
		require.False(t, lnwallet.HtlcIsDust(
			taprootChanType, false, lntypes.Remote, feePerKw,
			carrierSat, 0,
		), "carrier must not be dust for taproot channels at "+
			"feePerKw=%v", feePerKw)

		htlcRecord := rfqmsg.NewHtlc(
			[]*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(
					fundedAsset,
					channel.fundingProof.Asset.Amount,
				),
			},
			fn.None[rfqmsg.ID](), fn.None[[]rfqmsg.ID](),
		)
		records, err := lnwire.ParseCustomRecords(htlcRecord.Bytes())
		require.NoError(t, err)

		desc := lnwallet.NewTestAuxHtlcDescriptor(
			lnwire.ChannelID{}, lnwallet.PaymentHash{1},
			uint32(carrierSat),
			lnwire.MilliSatoshi(carrierSat)*1000,
			0, 0, uint8(lnwallet.Add), records,
			1, 0, 0, 0,
		)
		view := lnwallet.AuxHtlcView{
			NextHeight: 1,
			FeePerKw:   feePerKw,
			Updates: lntypes.Dual[[]lnwallet.AuxHtlcDescriptor]{
				Remote: []lnwallet.AuxHtlcDescriptor{desc},
			},
		}

		_, _, err = GenerateCommitmentAllocations(
			prevState, taprootChanState, chanAssetState,
			lntypes.Local,
			lnwire.MilliSatoshi(1_000_000_000),
			lnwire.MilliSatoshi(1_000_000_000), view,
			testChainParams, test.RandCommitmentKeyRing(t),
			STXOFeatures{},
		)
		require.NoError(t, err,
			"asset commitment must assemble at feePerKw=%v for a "+
				"taproot channel: the feerate wedge of issue "+
				"#121 does not reproduce", feePerKw)
	}

	// The residual: a negotiated dust limit above the fixed carrier is
	// still rejected channel-fatally by the commitment assembly, which is
	// the fail-closed behavior for an asset-carrying dust output.
	highDustChanState := taprootChanState
	highDustChanState.LocalChanCfg.DustLimit = carrierSat * 10

	htlcRecord := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{
			rfqmsg.NewAssetBalance(
				fundedAsset, channel.fundingProof.Asset.Amount,
			),
		},
		fn.None[rfqmsg.ID](), fn.None[[]rfqmsg.ID](),
	)
	records, err := lnwire.ParseCustomRecords(htlcRecord.Bytes())
	require.NoError(t, err)
	desc := lnwallet.NewTestAuxHtlcDescriptor(
		lnwire.ChannelID{}, lnwallet.PaymentHash{1},
		uint32(carrierSat), lnwire.MilliSatoshi(carrierSat)*1000,
		0, 0, uint8(lnwallet.Add), records,
		1, 0, 0, 0,
	)
	view := lnwallet.AuxHtlcView{
		NextHeight: 1,
		FeePerKw:   chainfee.FeePerKwFloor,
		Updates: lntypes.Dual[[]lnwallet.AuxHtlcDescriptor]{
			Remote: []lnwallet.AuxHtlcDescriptor{desc},
		},
	}

	_, _, err = GenerateCommitmentAllocations(
		prevState, highDustChanState, chanAssetState, lntypes.Local,
		lnwire.MilliSatoshi(1_000_000_000),
		lnwire.MilliSatoshi(1_000_000_000), view,
		testChainParams, test.RandCommitmentKeyRing(t), STXOFeatures{},
	)
	require.Error(t, err,
		"a carrier below the negotiated dust limit must still be "+
			"rejected channel-fatally")
}
