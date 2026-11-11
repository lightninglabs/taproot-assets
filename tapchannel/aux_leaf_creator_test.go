package tapchannel

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/internal/test/lndmock"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestPopulateSecondLevelLeaves asserts that second-level HTLC aux leaves are
// derived from a revocation log for exactly the HTLCs that carry assets: an
// incoming asset HTLC gets a second-level leaf with a CLTV timeout, an
// outgoing asset HTLC gets one without, HTLCs without asset outputs are
// skipped, and revocation log entries without an HTLC index are ignored.
func TestPopulateSecondLevelLeaves(t *testing.T) {
	t.Parallel()

	commitTx := randProof(t).AnchorTx
	keyRing := lndmock.RandCommitmentKeyRing(t)

	groupKey := &asset.GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}

	newHtlcOutputs := func() []*cmsg.AssetOutput {
		assetID, p := htlcGroupProof(t, groupKey, commitTx)
		return []*cmsg.AssetOutput{
			cmsg.NewAssetOutput(assetID, p.Asset.Amount, *p),
		}
	}

	const (
		incomingIdx = uint64(1)
		outgoingIdx = uint64(2)
		btcOnlyIdx  = uint64(3)
	)

	incomingHtlcs := map[input.HtlcIndex][]*cmsg.AssetOutput{
		incomingIdx: newHtlcOutputs(),
	}
	outgoingHtlcs := map[input.HtlcIndex][]*cmsg.AssetOutput{
		outgoingIdx: newHtlcOutputs(),
	}

	commitment := cmsg.NewCommitment(
		nil, nil, outgoingHtlcs, incomingHtlcs,
		lnwallet.CommitAuxLeaves{}, false, false, cmsg.SigHashAll,
	)

	newEntry := func(idx uint64, incoming bool) *channeldb.HTLCEntry {
		entry, err := channeldb.NewHTLCEntryFromHTLC(channeldb.HTLC{
			RHash:         [32]byte{byte(idx)},
			RefundTimeout: 800_000 + uint32(idx),
			Incoming:      incoming,
			Amt: lnwire.NewMSatFromSatoshis(
				354,
			),
			HtlcIndex: idx,
		})
		require.NoError(t, err)

		return entry
	}

	revLog := &channeldb.RevocationLog{
		HTLCEntries: []*channeldb.HTLCEntry{
			newEntry(incomingIdx, true),
			newEntry(outgoingIdx, false),
			// A BTC-only HTLC: present in the log, but carries no
			// asset outputs in the commitment.
			newEntry(btcOnlyIdx, true),
			// An entry without an HTLC index must be skipped.
			{},
		},
	}

	leaves := lnwallet.CommitAuxLeaves{
		IncomingHtlcLeaves: make(input.HtlcAuxLeaves),
		OutgoingHtlcLeaves: make(input.HtlcAuxLeaves),
	}

	err := populateSecondLevelLeaves(
		revLog, commitment, chanState, keyRing, &commitTx,
		testChainParams, &leaves,
	)
	require.NoError(t, err)

	// The incoming asset HTLC must have produced a second-level leaf.
	incomingLeaf, ok := leaves.IncomingHtlcLeaves[incomingIdx]
	require.True(t, ok, "incoming asset HTLC missing second-level leaf")
	require.True(t, incomingLeaf.SecondLevelLeaf.IsSome())

	// Same for the outgoing asset HTLC.
	outgoingLeaf, ok := leaves.OutgoingHtlcLeaves[outgoingIdx]
	require.True(t, ok, "outgoing asset HTLC missing second-level leaf")
	require.True(t, outgoingLeaf.SecondLevelLeaf.IsSome())

	// The incoming and outgoing leaves must differ: the incoming path
	// commits to a CLTV timeout while the outgoing one does not.
	require.NotEqual(
		t,
		incomingLeaf.SecondLevelLeaf.UnwrapOrFail(t).Script,
		outgoingLeaf.SecondLevelLeaf.UnwrapOrFail(t).Script,
	)

	// The BTC-only HTLC and the index-less entry must not have produced
	// any leaves.
	require.NotContains(t, leaves.IncomingHtlcLeaves, btcOnlyIdx)
	require.Len(t, leaves.IncomingHtlcLeaves, 1)
	require.Len(t, leaves.OutgoingHtlcLeaves, 1)
}

// fixedFeatures is a FeatureBitFetcher that reports the same features for
// every channel.
type fixedFeatures struct {
	bits []lnwire.FeatureBit
}

// GetChannelFeatures returns the configured features.
func (f fixedFeatures) GetChannelFeatures(
	_ lnwire.ChannelID) lnwire.FeatureVector {

	return *lnwire.NewFeatureVector(
		lnwire.NewRawFeatureVector(f.bits...), nil,
	)
}

// TestLeafStoreSigHashModeFromRequest asserts that the sighash mode of a
// commitment being built is the one lnd states in the request, for the leaves
// and for the blob alike, whatever the live feature negotiation and the
// previous commitment say.
//
// The signer of a commitment decides its mode and states it on the
// commitment_signed. That message can be retransmitted after both peers
// upgraded, so the receiver has to build a legacy commitment while the
// feature is already negotiated. Deriving the mode here would record
// SigHashDefault for a commitment that was signed as legacy.
func TestLeafStoreSigHashModeFromRequest(t *testing.T) {
	t.Parallel()

	channel := newOneSidedChannel(t)
	fundedAsset := channel.fundingProof.Asset.ID()
	chanAssetState := cmsg.NewOpenChannel(
		[]*cmsg.AssetOutput{channel.assetOutput}, 0, nil,
	)

	chanType := channeldb.SingleFunderTweaklessBit |
		channeldb.AnchorOutputsBit | channeldb.ScidAliasChanBit |
		channeldb.SimpleTaprootFeatureBit | channeldb.TapscriptRootBit
	chanState := lnwallet.AuxChanState{
		ChanType:   chanType,
		CustomBlob: lfn.Some[tlv.Blob](chanAssetState.Bytes()),
	}
	dustLimit := rfqmath.LegacyOnChainHtlcSat
	chanState.LocalChanCfg.DustLimit = dustLimit

	// The legacy carrier of an asset HTLC has an output on a legacy
	// commitment and is dust on a SigHashDefault one, where it must also
	// pay for the fee and the anchor of the second-level transaction. A
	// commitment that would trim an asset HTLC is refused, which makes
	// the mode the allocations were generated with observable.
	legacyCarrier := rfqmath.LegacyOnChainHtlcSat
	feePerKw := chainfee.FeePerKwFloor
	require.False(t, lnwallet.HtlcIsDust(
		chanType, true, lntypes.Local, feePerKw, legacyCarrier,
		dustLimit, false,
	))
	require.True(t, lnwallet.HtlcIsDust(
		chanType, true, lntypes.Local, feePerKw, legacyCarrier,
		dustLimit, true,
	))

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

	newInput := func(prevDefault, sigHashDefault bool,
		carrier btcutil.Amount) lnwallet.CommitDiffAuxInput {

		prevState := cmsg.NewCommitment(
			nil, []*cmsg.AssetOutput{channel.assetOutput}, nil,
			nil, lnwallet.CommitAuxLeaves{}, false, false,
			cmsg.SigHashTypeFromBool(prevDefault),
		)
		desc := lnwallet.NewTestAuxHtlcDescriptor(
			lnwire.ChannelID{}, lnwallet.PaymentHash{1},
			uint32(carrier), lnwire.NewMSatFromSatoshis(carrier),
			0, 0, uint8(lnwallet.Add), records, 1, 0, 0, 0,
		)

		var view lnwallet.AuxHtlcView
		view.NextHeight = 1
		view.FeePerKw = feePerKw
		view.Updates.Remote = []lnwallet.AuxHtlcDescriptor{desc}

		return lnwallet.CommitDiffAuxInput{
			ChannelState:   chanState,
			PrevBlob:       prevState.Bytes(),
			UnfilteredView: view,
			WhoseCommit:    lntypes.Local,
			OurBalance:     lnwire.MilliSatoshi(1_000_000_000),
			TheirBalance:   lnwire.MilliSatoshi(1_000_000_000),
			KeyRing:        lndmock.RandCommitmentKeyRing(t),
			SigHashDefault: sigHashDefault,
		}
	}

	negotiated := fixedFeatures{
		bits: []lnwire.FeatureBit{
			tapfeatures.DeterministicHTLCsOptional,
		},
	}

	for _, features := range []fixedFeatures{{}, negotiated} {
		for _, prevDefault := range []bool{false, true} {
			name := fmt.Sprintf("negotiated=%v prev_default=%v",
				len(features.bits) > 0, prevDefault)

			// The blob records the mode of the request.
			for _, mode := range []bool{false, true} {
				in := newInput(
					prevDefault, mode,
					rfqmath.DefaultOnChainHtlcSat,
				)
				blob, err := ApplyHtlcView(
					testChainParams, in, features,
				).Unpack()
				require.NoError(t, err, name)

				commit, err := cmsg.DecodeCommitment(
					blob.UnwrapOr(nil),
				)
				require.NoError(t, err, name)
				recorded := commit.SigHashDefault.Val
				require.Equal(t, mode, recorded, name)

				_, err = FetchLeavesFromView(
					testChainParams, in, features,
				).Unpack()
				require.NoError(t, err, name)
			}

			// The allocations behind the leaves and the blob are
			// generated with that mode as well: the legacy carrier
			// passes as legacy and is refused as SigHashDefault.
			legacy := newInput(prevDefault, false, legacyCarrier)
			_, err := FetchLeavesFromView(
				testChainParams, legacy, features,
			).Unpack()
			require.NoError(t, err, name)
			_, err = ApplyHtlcView(
				testChainParams, legacy, features,
			).Unpack()
			require.NoError(t, err, name)

			deterministic := newInput(
				prevDefault, true, legacyCarrier,
			)
			_, err = FetchLeavesFromView(
				testChainParams, deterministic, features,
			).Unpack()
			require.Error(t, err, name)
			_, err = ApplyHtlcView(
				testChainParams, deterministic, features,
			).Unpack()
			require.Error(t, err, name)
		}
	}
}
