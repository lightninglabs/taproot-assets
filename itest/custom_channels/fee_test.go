//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsFee tests that funding a custom channel with an invalid
// fee rate (zero or below the relay fee) is properly rejected.
func testCustomChannelsFee(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Charlie as the proof courier. But in order for Charlie to
	// also use itself, we need to define its port upfront.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))

	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint an asset on Charlie and sync Dave to Charlie as the universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// Fund a channel with a fee rate of zero.
	zeroFeeRate := uint32(0)

	_, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        cents.Amount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: zeroFeeRate,
			PushSat:            0,
		},
	)

	errSpecifyFeerate := "fee rate must be specified"
	require.ErrorContains(t.t, err, errSpecifyFeerate)

	net.FeeService.SetMinRelayFeerate(
		chainfee.SatPerVByte(2).FeePerKVByte(),
	)

	// Fund a channel with a fee rate that is too low.
	tooLowFeeRate := uint32(1)
	tooLowFeeRateAmount := chainfee.SatPerVByte(tooLowFeeRate)

	_, err = asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        cents.Amount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: tooLowFeeRate,
			PushSat:            0,
		},
	)

	errFeeRateTooLow := fmt.Sprintf("fee rate %s too low, "+
		"min_relay_fee: ", tooLowFeeRateAmount.FeePerKWeight())
	require.ErrorContains(t.t, err, errFeeRateTooLow)
}
