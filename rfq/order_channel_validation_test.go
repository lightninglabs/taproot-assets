package rfq

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

type orderChannelLister struct {
	channels []lndclient.ChannelInfo
	err      error
}

func (l *orderChannelLister) ListChannels(_ context.Context, _, _ bool,
	_ ...lndclient.ListChannelsOption) ([]lndclient.ChannelInfo, error) {

	return l.channels, l.err
}

func testChannelData(t *testing.T, ids ...asset.ID) []byte {
	t.Helper()

	fundingAssets := make([]rfqmsg.JsonAssetUtxo, len(ids))
	for idx := range ids {
		fundingAssets[idx].AssetGenesis.AssetID = ids[idx].String()
	}

	data, err := json.Marshal(rfqmsg.JsonAssetChannel{
		FundingAssets: fundingAssets,
	})
	require.NoError(t, err)

	return data
}

func testPurchasePolicy(t *testing.T, assetID asset.ID) *AssetPurchasePolicy {
	t.Helper()

	id, err := rfqmsg.NewID()
	require.NoError(t, err)

	peer := route.Vertex{0x02}
	request := rfqmsg.SellRequest{
		Peer:           peer,
		AssetSpecifier: asset.NewSpecifierFromId(assetID),
		PaymentMaxAmt:  10_000_000_000,
	}
	accept := rfqmsg.SellAccept{
		Peer:    peer,
		Request: request,
		AssetRate: rfqmsg.NewAssetRate(
			rfqmath.NewBigIntFixedPoint(100, 0),
			time.Now().Add(time.Hour),
		),
		ID: id,
	}

	return NewAssetPurchasePolicy(accept)
}

func testPurchaseHtlc(t *testing.T, policy *AssetPurchasePolicy,
	incomingScid uint64, balances ...*rfqmsg.AssetBalance) lndclient.InterceptedHtlc {

	t.Helper()

	record := rfqmsg.NewHtlc(
		balances, fn.Some(policy.AcceptedQuoteId),
		fn.None[[]rfqmsg.ID](),
	)
	customRecords, err := record.ToCustomRecords()
	require.NoError(t, err)

	return lndclient.InterceptedHtlc{
		IncomingCircuitKey: models.CircuitKey{
			ChanID: lnwire.NewShortChanIDFromInt(incomingScid),
			HtlcID: 1,
		},
		OutgoingChannelID:   lnwire.NewShortChanIDFromInt(9999),
		AmountInMsat:        500_000,
		AmountOutMsat:       1_000_000,
		InWireCustomRecords: customRecords,
	}
}

// TestResolveIncomingHtlcValidatesAssetChannel ensures an RFQ policy cannot
// replace an HTLC's incoming wire amount unless the actual incoming channel is
// funded by every asset claimed by the HTLC.
func TestResolveIncomingHtlcValidatesAssetChannel(t *testing.T) {
	t.Parallel()

	var (
		assetID      = asset.ID{0x01}
		otherAssetID = asset.ID{0x02}
		incomingScid = uint64(1234)
	)

	testCases := []struct {
		name       string
		channels   []lndclient.ChannelInfo
		balances   []*rfqmsg.AssetBalance
		listErr    error
		wantAction lndclient.InterceptorAction
	}{
		{
			name: "matching channel id",
			channels: []lndclient.ChannelInfo{{
				ChannelID:         incomingScid,
				CustomChannelData: testChannelData(t, assetID),
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionResumeModified,
		},
		{
			name: "matching zero conf primary channel id",
			channels: []lndclient.ChannelInfo{{
				ChannelID:         incomingScid,
				ZeroConf:          true,
				ZeroConfScid:      5678,
				CustomChannelData: testChannelData(t, assetID),
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionResumeModified,
		},
		{
			name: "alias is not the incoming link id",
			channels: []lndclient.ChannelInfo{{
				ChannelID:         4321,
				AliasScids:        []uint64{incomingScid},
				CustomChannelData: testChannelData(t, assetID),
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "confirmed zero conf scid is not the incoming link id",
			channels: []lndclient.ChannelInfo{{
				ChannelID:         4321,
				ZeroConfScid:      incomingScid,
				CustomChannelData: testChannelData(t, assetID),
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "plain btc channel",
			channels: []lndclient.ChannelInfo{{
				ChannelID: incomingScid,
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "channel missing claimed asset",
			channels: []lndclient.ChannelInfo{{
				ChannelID:         incomingScid,
				CustomChannelData: testChannelData(t, otherAssetID),
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "unmatched asset cannot inflate incoming amount",
			channels: []lndclient.ChannelInfo{{
				ChannelID: incomingScid,
				CustomChannelData: testChannelData(
					t, assetID, otherAssetID,
				),
			}},
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
				rfqmsg.NewAssetBalance(otherAssetID, 10_000),
			},
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "incoming channel not found",
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "channel lookup failure",
			balances: []*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(assetID, 1),
			},
			listErr:    errors.New("list channels failed"),
			wantAction: lndclient.InterceptorActionFail,
		},
		{
			name: "asset htlc has no balances",
			channels: []lndclient.ChannelInfo{{
				ChannelID:         incomingScid,
				CustomChannelData: testChannelData(t, assetID),
			}},
			wantAction: lndclient.InterceptorActionFail,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			policy := testPurchasePolicy(t, assetID)
			htlc := testPurchaseHtlc(
				t, policy, incomingScid, testCase.balances...,
			)
			events := make(chan *AcceptHtlcEvent, 1)
			handler, err := NewOrderHandler(OrderHandlerCfg{
				ChannelLister: &orderChannelLister{
					channels: testCase.channels,
					err:      testCase.listErr,
				},
				SpecifierChecker: func(_ context.Context,
					_ asset.Specifier, id asset.ID) (bool, error) {

					return id == assetID, nil
				},
				AcceptHtlcEvents: events,
			})
			require.NoError(t, err)
			handler.policies.Store(policy.scid, policy)

			response, err := handler.resolveIncomingHtlc(
				context.Background(), htlc,
			)
			require.NoError(t, err)
			require.Equal(t, testCase.wantAction, response.Action)

			if testCase.wantAction ==
				lndclient.InterceptorActionResumeModified {

				require.Greater(t, response.IncomingAmount,
					htlc.AmountInMsat)
				require.Len(t, events, 1)
			} else {
				require.Zero(t, policy.CurrentAmountMsat)
				require.Empty(t, events)
			}
		})
	}
}

// TestResolveIncomingHtlcAcceptsGroupKeyXCoordinate verifies that a grouped
// asset HTLC can identify its group by the x-coordinate carried as an asset ID.
func TestResolveIncomingHtlcAcceptsGroupKeyXCoordinate(t *testing.T) {
	t.Parallel()

	groupKey := test.RandPubKey(t)
	var groupKeyID asset.ID
	copy(groupKeyID[:], schnorr.SerializePubKey(groupKey))

	policy := testPurchasePolicy(t, groupKeyID)
	policy.AssetSpecifier = asset.NewSpecifierFromGroupKey(*groupKey)

	channelData, err := json.Marshal(rfqmsg.JsonAssetChannel{
		FundingAssets: []rfqmsg.JsonAssetUtxo{{
			AssetGenesis: rfqmsg.JsonAssetGenesis{
				AssetID: asset.ID{0x02}.String(),
			},
		}},
		GroupKey: hex.EncodeToString(groupKey.SerializeCompressed()),
	})
	require.NoError(t, err)

	const incomingScid = uint64(1234)
	handler, err := NewOrderHandler(OrderHandlerCfg{
		ChannelLister: &orderChannelLister{
			channels: []lndclient.ChannelInfo{{
				ChannelID:         incomingScid,
				CustomChannelData: channelData,
			}},
		},
		SpecifierChecker: func(_ context.Context, specifier asset.Specifier,
			id asset.ID) (bool, error) {

			require.Equal(t, policy.AssetSpecifier, specifier)
			return id == groupKeyID, nil
		},
		AcceptHtlcEvents: make(chan *AcceptHtlcEvent, 1),
	})
	require.NoError(t, err)
	handler.policies.Store(policy.scid, policy)

	htlc := testPurchaseHtlc(
		t, policy, incomingScid, rfqmsg.NewAssetBalance(groupKeyID, 1),
	)
	response, err := handler.resolveIncomingHtlc(
		context.Background(), htlc,
	)
	require.NoError(t, err)
	require.Equal(
		t, lndclient.InterceptorActionResumeModified, response.Action,
	)
}

// TestIncomingChannelAssetDataRevalidatesScid verifies that funding data is
// looked up on every use. A zero-conf primary SCID can be reassigned after its
// original channel closes, so funding data must not outlive the active channel.
func TestIncomingChannelAssetDataRevalidatesScid(t *testing.T) {
	t.Parallel()

	var (
		assetID      = asset.ID{0x01}
		recycledScid = lnwire.ShortChannelID{
			BlockHeight: 16_000_001,
		}.ToUint64()
	)

	lister := &orderChannelLister{
		channels: []lndclient.ChannelInfo{{
			ChannelID:         recycledScid,
			CustomChannelData: testChannelData(t, assetID),
		}},
	}
	handler, err := NewOrderHandler(OrderHandlerCfg{
		ChannelLister: lister,
	})
	require.NoError(t, err)

	_, err = handler.incomingChannelAssetData(
		context.Background(), recycledScid,
	)
	require.NoError(t, err)

	// Simulate the asset channel closing and lnd assigning its primary
	// zero-conf SCID to a new plain channel.
	lister.channels = []lndclient.ChannelInfo{{
		ChannelID: recycledScid,
	}}
	_, err = handler.incomingChannelAssetData(
		context.Background(), recycledScid,
	)
	require.ErrorContains(t, err, "has no asset funding data")
}

// TestValidateIncomingAssetChannelChecksForwardPolicy verifies that an
// asset-to-asset forward also requires asset funding on its incoming channel.
func TestValidateIncomingAssetChannelChecksForwardPolicy(t *testing.T) {
	t.Parallel()

	var (
		assetID      = asset.ID{0x01}
		incomingScid = uint64(1234)
		incoming     = testPurchasePolicy(t, assetID)
	)

	id, err := rfqmsg.NewID()
	require.NoError(t, err)

	peer := route.Vertex{0x02}
	outgoing := NewAssetSalePolicy(rfqmsg.BuyAccept{
		Peer: peer,
		Request: rfqmsg.BuyRequest{
			Peer:           peer,
			AssetSpecifier: asset.NewSpecifierFromId(assetID),
			AssetMaxAmt:    1,
		},
		AssetRate: rfqmsg.NewAssetRate(
			rfqmath.NewBigIntFixedPoint(100, 0),
			time.Now().Add(time.Hour),
		),
		ID: id,
	}, false, nil)
	forward, err := NewAssetForwardPolicy(incoming, outgoing)
	require.NoError(t, err)

	handler, err := NewOrderHandler(OrderHandlerCfg{
		ChannelLister: &orderChannelLister{
			channels: []lndclient.ChannelInfo{{
				ChannelID: incomingScid,
			}},
		},
		SpecifierChecker: func(context.Context, asset.Specifier, asset.ID) (
			bool, error) {

			return true, nil
		},
	})
	require.NoError(t, err)

	htlc := testPurchaseHtlc(
		t, incoming, incomingScid, rfqmsg.NewAssetBalance(assetID, 1),
	)
	err = handler.validateIncomingAssetChannel(
		context.Background(), htlc, forward,
	)
	require.ErrorContains(t, err, "has no asset funding data")
}

// TestValidateIncomingAssetChannelSkipsSalePolicy confirms that BTC-to-asset
// forwards, whose incoming amount remains the real wire amount, do not require
// an asset-funded incoming channel.
func TestValidateIncomingAssetChannelSkipsSalePolicy(t *testing.T) {
	t.Parallel()

	assetID := asset.ID{0x01}
	id, err := rfqmsg.NewID()
	require.NoError(t, err)

	peer := route.Vertex{0x02}
	policy := NewAssetSalePolicy(rfqmsg.BuyAccept{
		Peer: peer,
		Request: rfqmsg.BuyRequest{
			Peer:           peer,
			AssetSpecifier: asset.NewSpecifierFromId(assetID),
			AssetMaxAmt:    1,
		},
		AssetRate: rfqmsg.NewAssetRate(
			rfqmath.NewBigIntFixedPoint(100, 0),
			time.Now().Add(time.Hour),
		),
		ID: id,
	}, false, nil)

	handler, err := NewOrderHandler(OrderHandlerCfg{})
	require.NoError(t, err)
	require.NoError(t, handler.validateIncomingAssetChannel(
		context.Background(), lndclient.InterceptedHtlc{}, policy,
	))
}
