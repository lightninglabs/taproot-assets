package tapchannel

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestIssue115ForeignAssetIdRejected asserts that an HTLC declaring an asset
// ID the channel was not funded with is rejected during commitment
// generation, on both our own and the remote's commitment. The commitment
// math is sum-only, so without this check a routing node could be made to
// forward a valuable asset over an outgoing channel while the incoming
// channel only ever held a cheap one (issue #115).
func TestIssue115ForeignAssetIdRejected(t *testing.T) {
	t.Parallel()

	channel := newOneSidedChannel(t)
	fundedAsset := channel.fundingProof.Asset.ID()

	// The channel is funded with 1000 units on the remote side only; the
	// peer holds all assets and pays from their balance.
	prevState := tapchannelmsg.NewCommitment(
		nil, []*tapchannelmsg.AssetOutput{channel.assetOutput}, nil,
		nil, lnwallet.CommitAuxLeaves{}, false, false,
	)
	chanAssetState := tapchannelmsg.NewOpenChannel(
		[]*tapchannelmsg.AssetOutput{channel.assetOutput}, 0, nil,
	)

	makeView := func(declared asset.ID) lnwallet.AuxHtlcView {
		htlcRecord := rfqmsg.NewHtlc(
			[]*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(
					declared,
					channel.fundingProof.Asset.Amount,
				),
			},
			fn.None[rfqmsg.ID](), fn.None[[]rfqmsg.ID](),
		)
		records, err := lnwire.ParseCustomRecords(htlcRecord.Bytes())
		require.NoError(t, err)

		desc := lnwallet.NewTestAuxHtlcDescriptor(
			lnwire.ChannelID{}, lnwallet.PaymentHash{1},
			100, lnwire.MilliSatoshi(10000000),
			0, 0, uint8(lnwallet.Add), records,
			1, 0, 0, 0,
		)
		return lnwallet.AuxHtlcView{
			NextHeight: 1,
			FeePerKw:   1000,
			Updates: lntypes.Dual[[]lnwallet.AuxHtlcDescriptor]{
				Remote: []lnwallet.AuxHtlcDescriptor{desc},
			},
		}
	}

	// Control: an incoming HTLC declaring the funded asset is accepted.
	_, _, err := GenerateCommitmentAllocations(
		prevState, chanState, chanAssetState, lntypes.Local,
		lnwire.MilliSatoshi(1_000_000_000),
		lnwire.MilliSatoshi(1_000_000_000), makeView(fundedAsset),
		testChainParams, test.RandCommitmentKeyRing(t), STXOFeatures{},
	)
	require.NoError(t, err, "HTLC declaring the funded asset must pass")

	// Regression: an incoming HTLC declaring an asset the channel does
	// not hold must be rejected, on our commitment and on the remote's.
	foreignAsset := asset.ID{9, 9, 9, 9}
	for _, whoseCommit := range []lntypes.ChannelParty{
		lntypes.Local, lntypes.Remote,
	} {
		_, _, err := GenerateCommitmentAllocations(
			prevState, chanState, chanAssetState, whoseCommit,
			lnwire.MilliSatoshi(1_000_000_000),
			lnwire.MilliSatoshi(1_000_000_000),
			makeView(foreignAsset), testChainParams,
			test.RandCommitmentKeyRing(t), STXOFeatures{},
		)
		require.Error(t, err,
			"whoseCommit=%v: HTLC declaring an asset the channel "+
				"does not hold must be rejected", whoseCommit)
	}

	// Group-specified quotes carry a placeholder asset ID (the serialized
	// group key) in their HTLC records, so the placeholder of the channel's
	// own funding group must be accepted...
	groupKey := test.RandPubKey(t)
	groupedChanAssetState := tapchannelmsg.NewOpenChannel(
		[]*tapchannelmsg.AssetOutput{channel.assetOutput}, 0, groupKey,
	)
	groupPlaceholder := asset.ID(schnorr.SerializePubKey(groupKey))
	_, _, err = GenerateCommitmentAllocations(
		prevState, chanState, groupedChanAssetState, lntypes.Local,
		lnwire.MilliSatoshi(1_000_000_000),
		lnwire.MilliSatoshi(1_000_000_000), makeView(groupPlaceholder),
		testChainParams, test.RandCommitmentKeyRing(t), STXOFeatures{},
	)
	require.NoError(t, err,
		"the funding group's placeholder ID must be accepted")

	// ...while the placeholder of a foreign group is still rejected, so a
	// channel cannot be made to accept assets of a group it never held.
	foreignGroup := test.RandPubKey(t)
	foreignPlaceholder := asset.ID(schnorr.SerializePubKey(foreignGroup))
	_, _, err = GenerateCommitmentAllocations(
		prevState, chanState, groupedChanAssetState, lntypes.Local,
		lnwire.MilliSatoshi(1_000_000_000),
		lnwire.MilliSatoshi(1_000_000_000),
		makeView(foreignPlaceholder),
		testChainParams, test.RandCommitmentKeyRing(t), STXOFeatures{},
	)
	require.Error(t, err,
		"a foreign group's placeholder ID must be rejected")
}
