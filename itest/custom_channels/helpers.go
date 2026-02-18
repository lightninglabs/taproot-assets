package custom_channels

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	mintrpc "github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	rfqrpc "github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// tapdAdapter wraps the tapd-specific RPC clients from an
// itest.IntegratedNode to satisfy interfaces like
// commands.RpcClientsBundle, tapClient, and
// taprpc.TaprootAssetsClient without the ambiguous selector
// issues that arise from IntegratedNode embedding both lnd and
// tapd clients.
type tapdAdapter struct {
	taprpc.TaprootAssetsClient
	wrpc.AssetWalletClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	tchrpc.TaprootAssetChannelsClient
	unirpc.UniverseClient
	tapdevrpc.TapDevClient
	authmailboxrpc.MailboxClient
}

// asTapd extracts just the tapd RPC clients from an
// itest.IntegratedNode, returning a type that satisfies
// commands.RpcClientsBundle and tapClient without ambiguity.
func asTapd(n *itest.IntegratedNode) *tapdAdapter {
	return &tapdAdapter{
		TaprootAssetsClient:        n.TaprootAssetsClient,
		AssetWalletClient:          n.AssetWalletClient,
		MintClient:                 n.MintClient,
		RfqClient:                  n.RfqClient,
		TaprootAssetChannelsClient: n.TaprootAssetChannelsClient,
		UniverseClient:             n.UniverseClient,
		TapDevClient:               n.TapDevClient,
		MailboxClient:              n.MailboxClient,
	}
}

// ---------------------------------------------------------------------------
// Type aliases and definitions
// ---------------------------------------------------------------------------

// pendingChan is a type alias for the pending channel proto message.
type pendingChan = lnrpc.PendingChannelsResponse_PendingChannel

// coOpCloseBalanceCheck is a function type that can be passed into
// closeAssetChannelAndAssert to assert the final balance of the closing
// transaction.
type coOpCloseBalanceCheck func(t *testing.T,
	local, remote *itest.IntegratedNode,
	closeTx *wire.MsgTx, closeUpdate *lnrpc.ChannelCloseUpdate,
	assetIDs [][]byte, groupKey []byte, universeTap *itest.IntegratedNode)

// TapPayment encapsulates the outcome of a tap asset payment.
type TapPayment struct {
	lndPayment *lnrpc.Payment
	assetRate  rfqmath.FixedPoint[rfqmath.BigInt]
}

// ---------------------------------------------------------------------------
// Payment config and options
// ---------------------------------------------------------------------------

type payConfig struct {
	smallShards       bool
	maxShards         uint32
	errSubStr         string
	allowOverpay      bool
	feeLimit          lnwire.MilliSatoshi
	destCustomRecords map[uint64][]byte
	payStatus         lnrpc.Payment_PaymentStatus
	failureReason     lnrpc.PaymentFailureReason
	rfq               fn.Option[rfqmsg.ID]
	groupKey          []byte
	outgoingChanIDs   []uint64
	allowSelfPayment  bool
	routeHints        []*lnrpc.RouteHint
}

func defaultPayConfig() *payConfig {
	return &payConfig{
		smallShards:   false,
		errSubStr:     "",
		feeLimit:      1_000_000,
		payStatus:     lnrpc.Payment_SUCCEEDED,
		failureReason: lnrpc.PaymentFailureReason_FAILURE_REASON_NONE,
	}
}

type payOpt func(*payConfig)

func withSmallShards() payOpt {
	return func(c *payConfig) {
		c.smallShards = true
	}
}

func withMaxShards(maxShards uint32) payOpt {
	return func(c *payConfig) {
		c.maxShards = maxShards
	}
}

func withPayErrSubStr(errSubStr string) payOpt {
	return func(c *payConfig) {
		c.errSubStr = errSubStr
	}
}

func withFailure(status lnrpc.Payment_PaymentStatus,
	reason lnrpc.PaymentFailureReason) payOpt {

	return func(c *payConfig) {
		c.payStatus = status
		c.failureReason = reason
	}
}

func withRFQ(rfqID rfqmsg.ID) payOpt {
	return func(c *payConfig) {
		c.rfq = fn.Some(rfqID)
	}
}

func withFeeLimit(limit lnwire.MilliSatoshi) payOpt {
	return func(c *payConfig) {
		c.feeLimit = limit
	}
}

func withDestCustomRecords(records map[uint64][]byte) payOpt {
	return func(c *payConfig) {
		c.destCustomRecords = records
	}
}

func withAllowOverpay() payOpt {
	return func(c *payConfig) {
		c.allowOverpay = true
	}
}

func withGroupKey(groupKey []byte) payOpt {
	return func(c *payConfig) {
		c.groupKey = groupKey
	}
}

func withOutgoingChanIDs(ids []uint64) payOpt {
	return func(c *payConfig) {
		c.outgoingChanIDs = ids
	}
}

func withAllowSelfPayment() payOpt {
	return func(c *payConfig) {
		c.allowSelfPayment = true
	}
}

func withPayRouteHints(hints []*lnrpc.RouteHint) payOpt {
	return func(c *payConfig) {
		c.routeHints = hints
	}
}

// ---------------------------------------------------------------------------
// Invoice config and options
// ---------------------------------------------------------------------------

type invoiceConfig struct {
	errSubStr  string
	groupKey   []byte
	msats      lnwire.MilliSatoshi
	routeHints []*lnrpc.RouteHint
}

func defaultInvoiceConfig() *invoiceConfig {
	return &invoiceConfig{
		errSubStr: "",
	}
}

type invoiceOpt func(*invoiceConfig)

func withInvoiceErrSubStr(errSubStr string) invoiceOpt {
	return func(c *invoiceConfig) {
		c.errSubStr = errSubStr
	}
}

func withInvGroupKey(groupKey []byte) invoiceOpt {
	return func(c *invoiceConfig) {
		c.groupKey = groupKey
	}
}

func withMsatAmount(amt uint64) invoiceOpt {
	return func(c *invoiceConfig) {
		c.msats = lnwire.MilliSatoshi(amt)
	}
}

func withRouteHints(hints []*lnrpc.RouteHint) invoiceOpt {
	return func(c *invoiceConfig) {
		c.routeHints = hints
	}
}

// ---------------------------------------------------------------------------
// Network setup helpers
// ---------------------------------------------------------------------------

// connectAllNodes connects all nodes pairwise.
func connectAllNodes(t *testing.T, net *itest.IntegratedNetworkHarness,
	nodes []*itest.IntegratedNode) {

	for i, node := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			peer := nodes[j]
			net.EnsureConnected(t, node, peer)
		}
	}
}

// fundAllNodes sends 1 BTC from the miner to each node.
func fundAllNodes(t *testing.T, net *itest.IntegratedNetworkHarness,
	nodes []*itest.IntegratedNode) {

	for _, node := range nodes {
		net.SendCoins(t, btcutil.SatoshiPerBitcoin, node)
	}
}

// syncUniverses syncs each node's universe with the given universe host.
func syncUniverses(t *testing.T, universe *itest.IntegratedNode,
	nodes ...*itest.IntegratedNode) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	for _, node := range nodes {
		universeHostAddr := universe.RPCAddr()
		t.Logf("Syncing node %v with universe %v", node.Cfg.Name,
			universeHostAddr)

		itest.SyncUniverses(
			ctxt, t, asTapd(node), asTapd(universe),
			universeHostAddr, wait.DefaultTimeout,
		)
	}
}

// ---------------------------------------------------------------------------
// Channel data and balance helpers
// ---------------------------------------------------------------------------

// parseChannelData unmarshals raw custom channel data into the JSON asset
// channel struct.
func parseChannelData(
	data []byte) (*rfqmsg.JsonAssetChannel, error) {

	var closeData rfqmsg.JsonAssetChannel
	err := json.Unmarshal(data, &closeData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling channel data: %w",
			err)
	}

	return &closeData, nil
}

// getChannelCustomData returns the custom channel data for the asset channel
// between src and dst.
func getChannelCustomData(src, dst *itest.IntegratedNode) (
	*rfqmsg.JsonAssetChannel, error) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	srcDestChannels, err := src.ListChannels(
		ctxt, &lnrpc.ListChannelsRequest{
			Peer: dst.PubKey[:],
		},
	)
	if err != nil {
		return nil, err
	}

	assetChannels := fn.Filter(srcDestChannels.Channels,
		func(c *lnrpc.Channel) bool {
			return len(c.CustomChannelData) > 0
		})

	if len(assetChannels) != 1 {
		return nil, fmt.Errorf("expected 1 asset channel, got %d",
			len(assetChannels))
	}

	targetChan := assetChannels[0]

	assetData, err := parseChannelData(targetChan.CustomChannelData)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal asset data: %w",
			err)
	}

	if len(assetData.FundingAssets) == 0 {
		return nil, fmt.Errorf("expected at least 1 asset, got %d",
			len(assetData.FundingAssets))
	}

	return assetData, nil
}

// getAssetChannelBalance returns the asset channel balances for the node,
// filtered by the given asset IDs.
func getAssetChannelBalance(t *testing.T, node *itest.IntegratedNode,
	assetIDs [][]byte, pending bool) (uint64, uint64, uint64, uint64) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	balance, err := node.ChannelBalance(
		ctxt, &lnrpc.ChannelBalanceRequest{},
	)
	require.NoError(t, err)

	if len(balance.CustomChannelData) == 0 {
		return 0, 0, 0, 0
	}

	var assetBalance rfqmsg.JsonAssetChannelBalances
	err = json.Unmarshal(balance.CustomChannelData, &assetBalance)
	require.NoErrorf(t, err, "json: '%x'", balance.CustomChannelData)

	balances := assetBalance.OpenChannels
	if pending {
		balances = assetBalance.PendingChannels
	}

	idMatch := func(assetIDString string) bool {
		for _, groupedID := range assetIDs {
			if assetIDString == hex.EncodeToString(groupedID) {
				return true
			}
		}

		return false
	}

	var localSum, remoteSum uint64
	for assetIDString := range balances {
		if !idMatch(assetIDString) {
			continue
		}

		localSum += balances[assetIDString].LocalBalance
		remoteSum += balances[assetIDString].RemoteBalance
	}

	return localSum, remoteSum, balance.LocalBalance.Sat,
		balance.RemoteBalance.Sat
}

// fetchChannel returns the channel between node and the given channel point.
func fetchChannel(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint) *lnrpc.Channel {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	channelResp, err := node.ListChannels(ctxt, &lnrpc.ListChannelsRequest{
		ActiveOnly: true,
	})
	require.NoError(t, err)

	txid, err := lnrpc.GetChanPointFundingTxid(chanPoint)
	require.NoError(t, err)
	targetChanPoint := fmt.Sprintf(
		"%v:%v", txid.String(), chanPoint.OutputIndex,
	)

	for _, channel := range channelResp.Channels {
		if channel.ChannelPoint == targetChanPoint {
			return channel
		}
	}

	t.Fatalf("channel %v not found", targetChanPoint)

	return nil
}

// logBalance logs the asset and sat balances for all given nodes.
func logBalance(t *testing.T, nodes []*itest.IntegratedNode, assetID []byte,
	occasion string) {

	t.Helper()

	time.Sleep(time.Millisecond * 250)

	for _, node := range nodes {
		local, remote, localSat, remoteSat := getAssetChannelBalance(
			t, node, [][]byte{assetID}, false,
		)

		t.Logf("%-7s balance: local=%-9d remote=%-9d, localSat=%-9d, "+
			"remoteSat=%-9d (%v)", node.Cfg.Name, local, remote,
			localSat, remoteSat, occasion)
	}
}

// logBalanceGroup logs balances for nodes with grouped asset IDs.
func logBalanceGroup(t *testing.T, nodes []*itest.IntegratedNode,
	assetIDs [][]byte, occasion string) {

	t.Helper()

	time.Sleep(time.Millisecond * 250)

	for _, node := range nodes {
		local, remote, localSat, remoteSat := getAssetChannelBalance(
			t, node, assetIDs, false,
		)

		t.Logf("%-7s balance: local=%-9d remote=%-9d, localSat=%-9d, "+
			"remoteSat=%-9d (%v)", node.Cfg.Name, local, remote,
			localSat, remoteSat, occasion)
	}
}

// haveFundingAsset returns true if the asset channel has a funding asset with
// the given asset ID.
func haveFundingAsset(assetChannel *rfqmsg.JsonAssetChannel,
	assetID []byte) bool {

	assetIDStr := hex.EncodeToString(assetID)
	for _, fundingAsset := range assetChannel.FundingAssets {
		if fundingAsset.AssetGenesis.AssetID == assetIDStr {
			return true
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

// assertBalance asserts the asset balance of the given node.
func assertBalance(t *testing.T, client *itest.IntegratedNode, balance uint64,
	opts ...itest.BalanceOption) {

	itest.AssertBalances(t, asTapd(client), balance, opts...)
}

// assertUniverseProofExists asserts that a proof for the given asset exists in
// the universe.
func assertUniverseProofExists(t *testing.T, universe *itest.IntegratedNode,
	assetID, groupKey, scriptKey []byte,
	outpoint string) *taprpc.Asset {

	t.Logf("Asserting proof outpoint=%v, script_key=%x, asset_id=%x, "+
		"group_key=%x", outpoint, scriptKey, assetID, groupKey)

	req := &unirpc.UniverseKey{
		Id: &unirpc.ID{
			ProofType: unirpc.ProofType_PROOF_TYPE_TRANSFER,
		},
		LeafKey: &unirpc.AssetKey{
			Outpoint: &unirpc.AssetKey_OpStr{
				OpStr: outpoint,
			},
			ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
				ScriptKeyBytes: scriptKey,
			},
		},
	}

	switch {
	case len(groupKey) > 0:
		req.Id.Id = &unirpc.ID_GroupKey{
			GroupKey: groupKey,
		}

	case len(assetID) > 0:
		req.Id.Id = &unirpc.ID_AssetId{
			AssetId: assetID,
		}

	default:
		t.Fatalf("Need either asset ID or group key")
	}

	ctxb := context.Background()
	var proofResp *unirpc.AssetProofResponse
	err := wait.NoError(func() error {
		var pErr error
		proofResp, pErr = universe.QueryProof(ctxb, req)
		return pErr
	}, wait.DefaultTimeout)
	require.NoError(
		t, err, "%v: outpoint=%v, script_key=%x", err, outpoint,
		scriptKey,
	)

	if len(groupKey) > 0 {
		require.NotNil(t, proofResp.AssetLeaf.Asset.AssetGroup)
		require.Equal(
			t, proofResp.AssetLeaf.Asset.AssetGroup.TweakedGroupKey,
			groupKey,
		)
	} else {
		require.Equal(
			t, proofResp.AssetLeaf.Asset.AssetGenesis.AssetId,
			assetID,
		)
	}

	a := proofResp.AssetLeaf.Asset
	t.Logf("Proof found for scriptKey=%x, amount=%d", a.ScriptKey,
		a.Amount)

	return a
}

// assertPendingChannels asserts that the node has the expected number of
// pending channels with the expected balances.
func assertPendingChannels(t *testing.T, node *itest.IntegratedNode,
	mintedAsset *taprpc.Asset, numChannels int, localSum,
	remoteSum uint64) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	pendingChannelsResp, err := node.PendingChannels(
		ctxt, &lnrpc.PendingChannelsRequest{},
	)
	require.NoError(t, err)
	require.Len(t, pendingChannelsResp.PendingOpenChannels, numChannels)

	pendingCh := pendingChannelsResp.PendingOpenChannels[0]
	pendingJSON, err := parseChannelData(
		pendingCh.Channel.CustomChannelData,
	)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(pendingJSON.FundingAssets), 1)
	require.NotZero(t, pendingJSON.Capacity)

	var expectedDecimalDisplay uint8
	if mintedAsset.DecimalDisplay != nil {
		expectedDecimalDisplay = uint8(
			mintedAsset.DecimalDisplay.DecimalDisplay,
		)
	}

	require.Equal(
		t, expectedDecimalDisplay,
		pendingJSON.FundingAssets[0].DecimalDisplay,
	)

	assetID := mintedAsset.AssetGenesis.AssetId
	pendingLocalBalance, pendingRemoteBalance, _, _ :=
		getAssetChannelBalance(t, node, [][]byte{assetID}, true)
	require.EqualValues(t, localSum, pendingLocalBalance)
	require.EqualValues(t, remoteSum, pendingRemoteBalance)
}

// assertInvoiceHtlcAssets looks up the invoice on the receiver and asserts the
// total asset amount across all HTLCs matches (within rounding tolerance).
func assertInvoiceHtlcAssets(t *testing.T, node *itest.IntegratedNode,
	addedInvoice *lnrpc.AddInvoiceResponse, assetID []byte,
	groupID []byte, assetAmount uint64) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	invoice, err := node.InvoicesClient.LookupInvoiceV2(
		ctxt, &invoicesrpc.LookupInvoiceMsg{
			InvoiceRef: &invoicesrpc.LookupInvoiceMsg_PaymentAddr{
				PaymentAddr: addedInvoice.PaymentAddr,
			},
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, invoice.Htlcs)

	var targetID string
	switch {
	case len(groupID) > 0:
		targetID = hex.EncodeToString(groupID)

	case len(assetID) > 0:
		targetID = hex.EncodeToString(assetID)
	}

	var totalAssetAmount uint64
	for _, htlc := range invoice.Htlcs {
		require.NotEmpty(t, htlc.CustomChannelData)

		jsonHtlc := &rfqmsg.JsonHtlc{}
		err := json.Unmarshal(htlc.CustomChannelData, jsonHtlc)
		require.NoError(t, err)

		for _, balance := range jsonHtlc.Balances {
			if balance.AssetID != targetID {
				continue
			}

			totalAssetAmount += balance.Amount
		}
	}

	// Due to rounding we allow up to 1 unit of error.
	require.InDelta(t, assetAmount, totalAssetAmount, 1)
}

// assertPaymentHtlcAssets tracks the payment on the sender and asserts the
// total asset amount across all HTLCs matches (within rounding tolerance).
func assertPaymentHtlcAssets(t *testing.T, node *itest.IntegratedNode,
	payHash []byte, assetID []byte, groupID []byte,
	assetAmount uint64) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	stream, err := node.RouterClient.TrackPaymentV2(
		ctxt, &routerrpc.TrackPaymentRequest{
			PaymentHash:       payHash,
			NoInflightUpdates: true,
		},
	)
	require.NoError(t, err)

	payment, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, payment)
	require.NotEmpty(t, payment.Htlcs)

	var targetID string
	switch {
	case len(groupID) > 0:
		targetID = hex.EncodeToString(groupID)

	case len(assetID) > 0:
		targetID = hex.EncodeToString(assetID)
	}

	var totalAssetAmount uint64
	for _, htlc := range payment.Htlcs {
		require.NotNil(t, htlc.Route)
		require.NotEmpty(t, htlc.Route.CustomChannelData)

		jsonHtlc := &rfqmsg.JsonHtlc{}
		err := json.Unmarshal(
			htlc.Route.CustomChannelData, jsonHtlc,
		)
		require.NoError(t, err)

		for _, balance := range jsonHtlc.Balances {
			if balance.AssetID != targetID {
				continue
			}

			totalAssetAmount += balance.Amount
		}
	}

	// Due to rounding we allow up to 1 unit of error.
	require.InDelta(t, assetAmount, totalAssetAmount, 1)
}

// assertAssetChan asserts that the channel between src and dst has the expected
// funding amount and assets.
func assertAssetChan(t *testing.T, src, dst *itest.IntegratedNode,
	fundingAmount uint64, channelAssets []*taprpc.Asset) {

	err := wait.NoError(func() error {
		a, err := getChannelCustomData(src, dst)
		if err != nil {
			return err
		}

		for _, channelAsset := range channelAssets {
			assetID := channelAsset.AssetGenesis.AssetId
			if !haveFundingAsset(a, assetID) {
				return fmt.Errorf("expected asset ID %x, to "+
					"be in channel", assetID)
			}
		}

		if a.Capacity != fundingAmount {
			return fmt.Errorf("expected capacity %d, got %d",
				fundingAmount, a.Capacity)
		}

		var expectedDecimalDisplay uint8
		if channelAssets[0].DecimalDisplay != nil {
			expectedDecimalDisplay = uint8(
				channelAssets[0].DecimalDisplay.DecimalDisplay,
			)
		}

		if a.FundingAssets[0].DecimalDisplay != expectedDecimalDisplay {
			return fmt.Errorf("expected decimal display %d, got %d",
				expectedDecimalDisplay,
				a.FundingAssets[0].DecimalDisplay)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// assertChannelKnown asserts that the given channel point is known in the
// node's graph.
func assertChannelKnown(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	txid, err := chainhash.NewHash(chanPoint.GetFundingTxidBytes())
	require.NoError(t, err)
	targetChanPoint := fmt.Sprintf(
		"%v:%d", txid.String(), chanPoint.OutputIndex,
	)

	err = wait.NoError(func() error {
		graphResp, err := node.DescribeGraph(
			ctxt, &lnrpc.ChannelGraphRequest{},
		)
		if err != nil {
			return err
		}

		found := false
		for _, edge := range graphResp.Edges {
			if edge.ChanPoint == targetChanPoint {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("channel %v not found",
				targetChanPoint)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// assertPendingChannelAssetData asserts that a pending channel has asset data.
func assertPendingChannelAssetData(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint, find func(string,
		*lnrpc.PendingChannelsResponse) (*pendingChan, error)) {

	ctxb := context.Background()

	err := wait.NoError(func() error {
		pendingChannels, err := node.PendingChannels(
			ctxb, &lnrpc.PendingChannelsRequest{},
		)
		if err != nil {
			return err
		}

		targetChanPointStr := fmt.Sprintf("%v:%v",
			chanPoint.GetFundingTxidStr(),
			chanPoint.GetOutputIndex())

		targetChan, err := find(targetChanPointStr, pendingChannels)
		if err != nil {
			return err
		}

		if len(targetChan.CustomChannelData) == 0 {
			return fmt.Errorf("pending channel %s has no "+
				"custom channel data", targetChanPointStr)
		}

		closeData, err := parseChannelData(
			targetChan.CustomChannelData,
		)
		if err != nil {
			return fmt.Errorf("error unmarshalling custom channel "+
				"data: %v", err)
		}

		if len(closeData.FundingAssets) == 0 {
			return fmt.Errorf("expected at least 1 funding asset, "+
				"got %d", len(closeData.FundingAssets))
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err, "timeout waiting for pending channel")
}

// assertPendingForceCloseChannelAssetData asserts that a pending force close
// channel has asset data.
func assertPendingForceCloseChannelAssetData(t *testing.T,
	node *itest.IntegratedNode, chanPoint *lnrpc.ChannelPoint) {

	assertPendingChannelAssetData(
		t, node, chanPoint, func(chanPoint string,
			resp *lnrpc.PendingChannelsResponse) (*pendingChan,
			error) {

			if len(resp.PendingForceClosingChannels) == 0 {
				return nil, fmt.Errorf("no pending force " +
					"close channels found")
			}

			for _, ch := range resp.PendingForceClosingChannels {
				if ch.Channel.ChannelPoint == chanPoint {
					return ch.Channel, nil
				}
			}

			return nil, fmt.Errorf("pending channel %s not found",
				chanPoint)
		},
	)
}

// assertWaitingCloseChannelAssetData asserts that a waiting close channel has
// asset data.
func assertWaitingCloseChannelAssetData(t *testing.T,
	node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint) {

	assertPendingChannelAssetData(
		t, node, chanPoint, func(chanPoint string,
			resp *lnrpc.PendingChannelsResponse) (*pendingChan,
			error) {

			if len(resp.WaitingCloseChannels) == 0 {
				return nil, fmt.Errorf("no waiting close " +
					"channels found")
			}

			for _, ch := range resp.WaitingCloseChannels {
				if ch.Channel.ChannelPoint == chanPoint {
					return ch.Channel, nil
				}
			}

			return nil, fmt.Errorf("pending channel %s not found",
				chanPoint)
		},
	)
}

// assertClosedChannelAssetData asserts that a closed channel has asset data.
func assertClosedChannelAssetData(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint) {

	ctxb := context.Background()

	targetChanPointStr := fmt.Sprintf("%v:%v",
		chanPoint.GetFundingTxidStr(), chanPoint.GetOutputIndex())

	var closedChan *lnrpc.ChannelCloseSummary
	err := wait.Predicate(func() bool {
		closedChannels, err := node.ClosedChannels(
			ctxb, &lnrpc.ClosedChannelsRequest{},
		)
		if err != nil {
			return false
		}

		for _, ch := range closedChannels.Channels {
			if ch.ChannelPoint == targetChanPointStr {
				closedChan = ch
				return true
			}
		}

		return false
	}, wait.DefaultTimeout)
	require.NoError(t, err)

	require.NotNil(t, closedChan)
	require.NotEmpty(t, closedChan.CustomChannelData)

	closeData, err := parseChannelData(closedChan.CustomChannelData)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(closeData.FundingAssets), 1)
}

// ---------------------------------------------------------------------------
// Invoice helpers
// ---------------------------------------------------------------------------

// createAssetInvoice creates an asset invoice on the destination node.
func createAssetInvoice(t *testing.T, dstRfqPeer, dst *itest.IntegratedNode,
	assetAmount uint64, assetID []byte,
	opts ...invoiceOpt) *lnrpc.AddInvoiceResponse {

	cfg := defaultInvoiceConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	timeoutSeconds := int64(rfq.DefaultInvoiceExpiry.Seconds())

	var peerPubKey []byte
	if dstRfqPeer != nil {
		peerPubKey = dstRfqPeer.PubKey[:]

		t.Logf("Asking peer %x for quote to buy assets to receive for "+
			"invoice over %d units; waiting up to %ds",
			dstRfqPeer.PubKey[:], assetAmount, timeoutSeconds)
	}

	request := &tchrpc.AddInvoiceRequest{
		AssetAmount: assetAmount,
		PeerPubkey:  peerPubKey,
		InvoiceRequest: &lnrpc.Invoice{
			Memo: fmt.Sprintf("this is an asset invoice for "+
				"%d units", assetAmount),
			Expiry:     timeoutSeconds,
			ValueMsat:  int64(cfg.msats),
			RouteHints: cfg.routeHints,
		},
	}

	switch {
	case len(cfg.groupKey) > 0:
		request.GroupKey = cfg.groupKey

	default:
		request.AssetId = assetID
	}

	resp, err := dst.TaprootAssetChannelsClient.AddInvoice(ctxt, request)
	if cfg.errSubStr != "" {
		require.ErrorContains(t, err, cfg.errSubStr)

		return nil
	}
	require.NoError(t, err)

	decodedInvoice, err := dst.LightningClient.DecodePayReq(
		ctxt, &lnrpc.PayReqString{
			PayReq: resp.InvoiceResult.PaymentRequest,
		},
	)
	require.NoError(t, err)

	rpcRate := resp.AcceptedBuyQuote.AskAssetRate
	rate, err := rpcutils.UnmarshalRfqFixedPoint(rpcRate)
	require.NoError(t, err)

	t.Logf("Got quote for %v asset units per BTC", rate)

	var mSatPerUnit float64

	if cfg.msats > 0 {
		require.EqualValues(t, decodedInvoice.NumMsat, cfg.msats)
		units := rfqmath.MilliSatoshiToUnits(cfg.msats, *rate)

		mSatPerUnit = float64(cfg.msats) / float64(units.ToUint64())
	} else {
		assetUnits := rfqmath.NewBigIntFixedPoint(assetAmount, 0)
		numMSats := rfqmath.UnitsToMilliSatoshi(assetUnits, *rate)
		mSatPerUnit = float64(decodedInvoice.NumMsat) /
			float64(assetAmount)

		require.EqualValues(t, numMSats, decodedInvoice.NumMsat)
	}

	t.Logf("Got quote for %d mSats at %3f msat/unit from peer %x with "+
		"SCID %d", decodedInvoice.NumMsat, mSatPerUnit,
		resp.AcceptedBuyQuote.Peer, resp.AcceptedBuyQuote.Scid)

	return resp.InvoiceResult
}

// ---------------------------------------------------------------------------
// Payment helpers
// ---------------------------------------------------------------------------

// payInvoiceWithAssets pays an invoice using assets.
func payInvoiceWithAssets(t *testing.T, payer, rfqPeer *itest.IntegratedNode,
	payReq string, assetID []byte,
	opts ...payOpt) (uint64, rfqmath.BigIntFixedPoint) {

	cfg := defaultPayConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	decodedInvoice, err := payer.LightningClient.DecodePayReq(
		ctxt, &lnrpc.PayReqString{
			PayReq: payReq,
		},
	)
	require.NoError(t, err)

	sendReq := &routerrpc.SendPaymentRequest{
		PaymentRequest:    payReq,
		TimeoutSeconds:    int32(PaymentTimeout.Seconds()),
		FeeLimitMsat:      int64(cfg.feeLimit),
		DestCustomRecords: cfg.destCustomRecords,
		MaxParts:          cfg.maxShards,
		OutgoingChanIds:   cfg.outgoingChanIDs,
		AllowSelfPayment:  cfg.allowSelfPayment,
	}

	if cfg.smallShards {
		sendReq.MaxShardSizeMsat = 80_000_000
	}

	var rfqBytes []byte
	cfg.rfq.WhenSome(func(i rfqmsg.ID) {
		rfqBytes = make([]byte, len(i[:]))
		copy(rfqBytes, i[:])
	})

	var peerPubKey []byte
	if rfqPeer != nil {
		peerPubKey = rfqPeer.PubKey[:]
	}

	request := &tchrpc.SendPaymentRequest{
		PeerPubkey:     peerPubKey,
		PaymentRequest: sendReq,
		RfqId:          rfqBytes,
		AllowOverpay:   cfg.allowOverpay,
	}

	switch {
	case len(cfg.groupKey) > 0:
		request.GroupKey = cfg.groupKey

	default:
		request.AssetId = assetID
	}

	stream, err := payer.TaprootAssetChannelsClient.SendPayment(
		ctxt, request,
	)
	require.NoError(t, err)

	// If an error is returned by the RPC method (meaning the stream itself
	// was established, no network or auth error), we expect the error to be
	// returned on the stream.
	if cfg.errSubStr != "" {
		msg, err := stream.Recv()
		if err != nil {
			require.ErrorContains(t, err, cfg.errSubStr)

			return 0, rfqmath.BigIntFixedPoint{}
		}

		// On errors we still get an empty set of RFQs as a response.
		if msg.GetAcceptedSellOrders() != nil {
			_, err = stream.Recv()
		}

		require.ErrorContains(t, err, cfg.errSubStr)

		return 0, rfqmath.BigIntFixedPoint{}
	}

	var (
		numUnits uint64
		rateVal  rfqmath.FixedPoint[rfqmath.BigInt]
	)

	tapPayment, err := getAssetPaymentResult(
		t, stream, cfg.payStatus == lnrpc.Payment_IN_FLIGHT,
	)
	require.NoError(t, err)

	payment := tapPayment.lndPayment
	require.Equal(t, cfg.payStatus, payment.Status)
	require.Equal(t, cfg.failureReason, payment.FailureReason)

	amountMsat := lnwire.MilliSatoshi(decodedInvoice.NumMsat)

	rateVal = tapPayment.assetRate
	milliSatsFP := rfqmath.MilliSatoshiToUnits(amountMsat, rateVal)
	numUnits = milliSatsFP.ScaleTo(0).ToUint64()

	return numUnits, rateVal
}

// sendAssetKeySendPayment sends a keysend payment with assets.
func sendAssetKeySendPayment(t *testing.T, src, dst *itest.IntegratedNode,
	amt uint64, assetID []byte, btcAmt fn.Option[int64],
	opts ...payOpt) {

	cfg := defaultPayConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	var preimage lntypes.Preimage
	_, err := rand.Read(preimage[:])
	require.NoError(t, err)

	hash := preimage.Hash()

	customRecords := make(map[uint64][]byte)
	customRecords[record.KeySendType] = preimage[:]

	sendReq := &routerrpc.SendPaymentRequest{
		Dest:              dst.PubKey[:],
		Amt:               btcAmt.UnwrapOr(500),
		DestCustomRecords: customRecords,
		PaymentHash:       hash[:],
		TimeoutSeconds:    int32(PaymentTimeout.Seconds()),
		MaxParts:          cfg.maxShards,
		OutgoingChanIds:   cfg.outgoingChanIDs,
		AllowSelfPayment:  cfg.allowSelfPayment,
	}

	request := &tchrpc.SendPaymentRequest{
		AssetAmount:    amt,
		PaymentRequest: sendReq,
	}

	switch {
	case len(cfg.groupKey) > 0:
		request.GroupKey = cfg.groupKey

	default:
		request.AssetId = assetID
	}

	stream, err := src.TaprootAssetChannelsClient.SendPayment(
		ctxt, request,
	)
	require.NoError(t, err)

	if cfg.errSubStr != "" {
		_, err := stream.Recv()
		require.ErrorContains(t, err, cfg.errSubStr)

		return
	}

	tapPayment, err := getAssetPaymentResult(t, stream, false)
	require.NoError(t, err)

	payment := tapPayment.lndPayment
	if payment.Status == lnrpc.Payment_FAILED {
		t.Logf("Failure reason: %v", payment.FailureReason)
	}
	require.Equal(t, cfg.payStatus, payment.Status)
	require.Equal(t, cfg.failureReason, payment.FailureReason)
}

// getAssetPaymentResult reads from the send payment stream until a final
// payment result is received.
func getAssetPaymentResult(t *testing.T,
	s tchrpc.TaprootAssetChannels_SendPaymentClient,
	isHodl bool) (*TapPayment, error) {

	// TODO(guggero): No idea why it makes a difference whether we
	// wait before calling s.Recv() or not, but it does. Without
	// the sleep, the test will fail with 'insufficient local
	// balance'. Probably something weird within lnd itself.
	time.Sleep(time.Second)

	var rateVal rfqmath.FixedPoint[rfqmath.BigInt]

	for {
		msg, err := s.Recv()
		if err != nil {
			return nil, err
		}

		quote := msg.GetAcceptedSellOrder()
		if quote != nil {
			rpcRate := quote.BidAssetRate
			rate, err := rpcutils.UnmarshalRfqFixedPoint(rpcRate)
			require.NoError(t, err)

			rateVal = *rate

			t.Logf("Got quote for %v asset units per BTC from "+
				"peer %v", rate, quote.Peer)
			continue
		}

		quotes := msg.GetAcceptedSellOrders()
		if quotes != nil {
			for _, quote := range quotes.AcceptedSellOrders {
				rpcRate := quote.BidAssetRate
				rate, err := rpcutils.UnmarshalRfqFixedPoint(
					rpcRate,
				)
				require.NoError(t, err)

				rateVal = *rate

				t.Logf("Got quote for %v asset units per BTC "+
					"from peer %v", rate, quote.Peer)
			}

			continue
		}

		payment := msg.GetPaymentResult()
		if payment == nil {
			err := fmt.Errorf("unexpected message: %v", msg)
			return nil, err
		}

		result := &TapPayment{
			lndPayment: payment,
			assetRate:  rateVal,
		}

		switch {
		case isHodl:
			return result, nil

		case payment.Status != lnrpc.Payment_IN_FLIGHT:
			return result, nil
		}
	}
}

// waitForSendEvent waits for a specific send event state on the event stream.
func waitForSendEvent(t *testing.T,
	sendEvents taprpc.TaprootAssets_SubscribeSendEventsClient,
	expectedState tapfreighter.SendState) {

	t.Helper()

	for {
		sendEvent, err := sendEvents.Recv()
		require.NoError(t, err)

		if sendEvent.SendState == expectedState.String() {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Channel close helpers
// ---------------------------------------------------------------------------

// noOpCoOpCloseBalanceCheck is a no-op co-op close balance check.
func noOpCoOpCloseBalanceCheck(_ *testing.T, _, _ *itest.IntegratedNode,
	_ *wire.MsgTx, _ *lnrpc.ChannelCloseUpdate, _ [][]byte, _ []byte,
	_ *itest.IntegratedNode) {
}

// closeAssetChannelAndAssert closes an asset channel and asserts the final
// balances.
func closeAssetChannelAndAssert(t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness,
	local, remote *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint, assetIDs [][]byte,
	groupKey []byte, universeTap *itest.IntegratedNode,
	balanceCheck coOpCloseBalanceCheck) {

	t.t.Helper()

	// Ensure the two parties are connected before attempting the close.
	// Channel closes after other close operations can sometimes race with
	// peer disconnection, causing "peer is offline" errors.
	net.EnsureConnected(t.t, local, remote)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	closeStream, _, err := net.CloseChannel(local, chanPoint, false)
	require.NoError(t.t, err)

	sendEvents, err := local.SubscribeSendEvents(
		ctxt, &taprpc.SubscribeSendEventsRequest{},
	)
	require.NoError(t.t, err)

	assertWaitingCloseChannelAssetData(t.t, local, chanPoint)
	assertWaitingCloseChannelAssetData(t.t, remote, chanPoint)

	mineBlocks(t, net, 1, 1)

	closeUpdate, err := net.WaitForChannelClose(closeStream)
	require.NoError(t.t, err)

	closeTxid, err := chainhash.NewHash(closeUpdate.ClosingTxid)
	require.NoError(t.t, err)

	closeTransaction := net.Miner.GetRawTransaction(*closeTxid)
	closeTx := closeTransaction.MsgTx()
	t.Logf("Channel closed with txid: %v", closeTxid)

	waitForSendEvent(t.t, sendEvents, tapfreighter.SendStateComplete)

	balanceCheck(
		t.t, local, remote, closeTx, closeUpdate, assetIDs, groupKey,
		universeTap,
	)

	assertClosedChannelAssetData(t.t, local, chanPoint)
	assertClosedChannelAssetData(t.t, remote, chanPoint)
}

// assertDefaultCoOpCloseBalance returns a default co-op close balance check
// function.
//
//nolint:lll
func assertDefaultCoOpCloseBalance(remoteBtcBalance,
	remoteAssetBalance bool) coOpCloseBalanceCheck {

	return func(t *testing.T, local, remote *itest.IntegratedNode,
		closeTx *wire.MsgTx, closeUpdate *lnrpc.ChannelCloseUpdate,
		assetIDs [][]byte, groupKey []byte,
		universeTap *itest.IntegratedNode) {

		defaultCoOpCloseBalanceCheck(
			t, local, remote, closeTx, closeUpdate, assetIDs,
			groupKey, universeTap, remoteBtcBalance,
			remoteAssetBalance,
		)
	}
}

// defaultCoOpCloseBalanceCheck implements the default co-op close
// balance check.
func defaultCoOpCloseBalanceCheck(t *testing.T,
	local, remote *itest.IntegratedNode,
	closeTx *wire.MsgTx, closeUpdate *lnrpc.ChannelCloseUpdate,
	assetIDs [][]byte, groupKey []byte, universeTap *itest.IntegratedNode,
	remoteBtcBalance, remoteAssetBalance bool) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	numOutputs := 2
	additionalOutputs := 1
	if remoteBtcBalance {
		numOutputs++
	}
	if remoteAssetBalance {
		numOutputs++
		additionalOutputs++
	}

	closeTxid := closeTx.TxHash()
	require.Len(t, closeTx.TxOut, numOutputs)

	outIdx := 0
	dummyAmt := int64(1000)
	require.LessOrEqual(t, closeTx.TxOut[outIdx].Value, dummyAmt)

	if remoteAssetBalance {
		outIdx++
		require.LessOrEqual(t, closeTx.TxOut[outIdx].Value, dummyAmt)
	}

	require.Len(t, closeUpdate.AdditionalOutputs, additionalOutputs)

	var remoteCloseOut *lnrpc.CloseOutput
	if remoteBtcBalance {
		// The remote node has received a couple of HTLCs with an above
		// dust value, so it should also have accumulated a non-dust
		// balance, even after subtracting 1k sats for the asset output.
		remoteCloseOut = closeUpdate.RemoteCloseOutput
		require.NotNil(t, remoteCloseOut)

		outIdx++
		require.EqualValues(
			t, remoteCloseOut.AmountSat-dummyAmt,
			closeTx.TxOut[outIdx].Value,
		)
	} else if remoteAssetBalance {
		// The remote node has received a couple of HTLCs but not enough
		// to go above dust. So it should still have an asset balance
		// that we can verify.
		remoteCloseOut = closeUpdate.RemoteCloseOutput
		require.NotNil(t, remoteCloseOut)
	}

	// The local node should have received the local BTC balance minus the
	// TX fees and 1k sats for the asset output.
	//
	// The exact close fee can vary with tx shape and lnd close-fee
	// estimation behavior. So instead of a fixed margin, bound the local
	// deduction by:
	//
	//   dummy output + (max expected fee at 20 sat/vB)
	//
	// using tx serialized size as a conservative upper bound for vsize.
	localCloseOut := closeUpdate.LocalCloseOutput
	require.NotNil(t, localCloseOut)
	outIdx++
	localDeduction := localCloseOut.AmountSat - closeTx.TxOut[outIdx].Value
	require.GreaterOrEqual(t, localDeduction, dummyAmt)

	const maxCloseFeeRateSatPerVbyte = int64(20)
	maxCloseFee := int64(
		closeTx.SerializeSize(),
	) * maxCloseFeeRateSatPerVbyte
	require.LessOrEqual(t, localDeduction, dummyAmt+maxCloseFee)

	localAuxOut := closeUpdate.AdditionalOutputs[0]

	var remoteAuxOut *lnrpc.CloseOutput
	if remoteAssetBalance {
		remoteAuxOut = closeUpdate.AdditionalOutputs[1]
	}
	if !localAuxOut.IsLocal && remoteAuxOut != nil {
		localAuxOut, remoteAuxOut = remoteAuxOut, localAuxOut
	}

	localAssetIndex, remoteAssetIndex := 1, 0
	if bytes.Equal(closeTx.TxOut[0].PkScript, localAuxOut.PkScript) {
		localAssetIndex, remoteAssetIndex = 0, 1
	}

	if remoteAuxOut != nil {
		require.Equal(
			t, remoteAuxOut.PkScript,
			closeTx.TxOut[remoteAssetIndex].PkScript,
		)
	}

	require.Equal(
		t, localAuxOut.PkScript,
		closeTx.TxOut[localAssetIndex].PkScript,
	)

	closedChans, err := local.ClosedChannels(
		ctxt, &lnrpc.ClosedChannelsRequest{
			Cooperative: true,
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, closedChans.Channels)

	var closedJsonChannel *rfqmsg.JsonAssetChannel
	for _, closedChan := range closedChans.Channels {
		if closedChan.ClosingTxHash == closeTx.TxHash().String() {
			closedJsonChannel, err = parseChannelData(
				closedChan.CustomChannelData,
			)
			require.NoError(t, err)

			break
		}
	}
	require.NotNil(t, closedJsonChannel)

	var localAssetCloseOut rfqmsg.JsonCloseOutput
	err = json.Unmarshal(
		localCloseOut.CustomChannelData, &localAssetCloseOut,
	)
	require.NoError(t, err)

	assetIDStrings := fn.Map(assetIDs, hex.EncodeToString)
	for assetIDStr, scriptKeyStr := range localAssetCloseOut.ScriptKeys {
		scriptKeyBytes, err := hex.DecodeString(scriptKeyStr)
		require.NoError(t, err)

		require.Contains(t, assetIDStrings, assetIDStr)

		localAssetIDs := fn.NewSet[string](fn.Map(
			closedJsonChannel.LocalAssets,
			func(t rfqmsg.JsonAssetTranche) string {
				return t.AssetID
			},
		)...)
		if !localAssetIDs.Contains(assetIDStr) {
			continue
		}

		decAssetID, err := hex.DecodeString(assetIDStr)
		require.NoError(t, err)

		a := assertUniverseProofExists(
			t, universeTap, decAssetID, groupKey, scriptKeyBytes,
			fmt.Sprintf("%v:%v", closeTxid, localAssetIndex),
		)

		itest.AssertBalances(
			t, asTapd(local), a.Amount,
			itest.WithAssetID(decAssetID),
			itest.WithScriptKeyType(asset.ScriptKeyBip86),
			itest.WithScriptKey(scriptKeyBytes),
		)
	}

	if !remoteAssetBalance {
		return
	}

	require.NotNil(t, remoteCloseOut)

	var remoteAssetCloseOut rfqmsg.JsonCloseOutput
	err = json.Unmarshal(
		remoteCloseOut.CustomChannelData, &remoteAssetCloseOut,
	)
	require.NoError(t, err)

	for assetIDStr, scriptKeyStr := range remoteAssetCloseOut.ScriptKeys {
		scriptKeyBytes, err := hex.DecodeString(scriptKeyStr)
		require.NoError(t, err)

		require.Contains(t, assetIDStrings, assetIDStr)

		remoteAssetIDs := fn.NewSet[string](fn.Map(
			closedJsonChannel.RemoteAssets,
			func(t rfqmsg.JsonAssetTranche) string {
				return t.AssetID
			},
		)...)
		if !remoteAssetIDs.Contains(assetIDStr) {
			continue
		}

		decAssetID, err := hex.DecodeString(assetIDStr)
		require.NoError(t, err)

		a := assertUniverseProofExists(
			t, universeTap, decAssetID, groupKey, scriptKeyBytes,
			fmt.Sprintf("%v:%v", closeTxid, remoteAssetIndex),
		)

		itest.AssertBalances(
			t, asTapd(remote), a.Amount,
			itest.WithAssetID(decAssetID),
			itest.WithScriptKeyType(asset.ScriptKeyBip86),
			itest.WithScriptKey(scriptKeyBytes),
		)
	}
}

// initiatorZeroAssetBalanceCoOpBalanceCheck is used when the initiator has a
// zero asset balance.
//
//nolint:lll
func initiatorZeroAssetBalanceCoOpBalanceCheck(t *testing.T, _,
	remote *itest.IntegratedNode, closeTx *wire.MsgTx,
	closeUpdate *lnrpc.ChannelCloseUpdate, assetIDs [][]byte,
	groupKey []byte, universeTap *itest.IntegratedNode) {

	numOutputs := 3

	closeTxid := closeTx.TxHash()
	require.Len(t, closeTx.TxOut, numOutputs)

	localOut, _ := closeTxOut(t, closeTx, closeUpdate, true)
	require.Greater(t, localOut.Value, int64(1000))

	require.Len(t, closeUpdate.AdditionalOutputs, 1)
	assetTxOut, assetOutputIndex := findTxOut(
		t, closeTx, closeUpdate.AdditionalOutputs[0].PkScript,
	)
	require.LessOrEqual(t, assetTxOut.Value, int64(1000))

	remoteCloseOut := closeUpdate.RemoteCloseOutput
	require.NotNil(t, remoteCloseOut)

	remoteAuxOut := closeUpdate.AdditionalOutputs[0]
	require.False(t, remoteAuxOut.IsLocal)

	var remoteAssetCloseOut rfqmsg.JsonCloseOutput
	err := json.Unmarshal(
		remoteCloseOut.CustomChannelData, &remoteAssetCloseOut,
	)
	require.NoError(t, err)

	assetIDStrings := fn.Map(assetIDs, hex.EncodeToString)
	for assetIDStr, scriptKeyStr := range remoteAssetCloseOut.ScriptKeys {
		scriptKeyBytes, err := hex.DecodeString(scriptKeyStr)
		require.NoError(t, err)

		require.Contains(t, assetIDStrings, assetIDStr)

		decAssetID, err := hex.DecodeString(assetIDStr)
		require.NoError(t, err)

		a := assertUniverseProofExists(
			t, universeTap, decAssetID, groupKey, scriptKeyBytes,
			fmt.Sprintf("%v:%v", closeTxid, assetOutputIndex),
		)

		itest.AssertBalances(
			t, asTapd(remote), a.Amount,
			itest.WithAssetID(decAssetID),
			itest.WithScriptKeyType(asset.ScriptKeyBip86),
			itest.WithScriptKey(scriptKeyBytes),
		)
	}
}

// closeTxOut returns either the local or remote output from the close
// transaction.
func closeTxOut(t *testing.T, closeTx *wire.MsgTx,
	closeUpdate *lnrpc.ChannelCloseUpdate, local bool) (*wire.TxOut, int) {

	var targetPkScript []byte
	if local {
		require.NotNil(t, closeUpdate.LocalCloseOutput)
		targetPkScript = closeUpdate.LocalCloseOutput.PkScript
	} else {
		require.NotNil(t, closeUpdate.RemoteCloseOutput)
		targetPkScript = closeUpdate.RemoteCloseOutput.PkScript
	}

	return findTxOut(t, closeTx, targetPkScript)
}

// findTxOut returns the transaction output with the target pk script.
func findTxOut(t *testing.T, tx *wire.MsgTx,
	targetPkScript []byte) (*wire.TxOut, int) {

	for i, txOut := range tx.TxOut {
		if bytes.Equal(txOut.PkScript, targetPkScript) {
			return txOut, i
		}
	}

	t.Fatalf("close output (targetPkScript=%x) not found in close "+
		"transaction", targetPkScript)

	return &wire.TxOut{}, 0
}

// findForceCloseTransfer finds the force close transfer for the given close
// txid.
func findForceCloseTransfer(t *testing.T, node1, node2 *itest.IntegratedNode,
	closeTxid *chainhash.Hash) *taprpc.ListTransfersResponse {

	var (
		ctxb   = context.Background()
		result *taprpc.ListTransfersResponse
		err    error
	)
	fErr := wait.NoError(func() error {
		result, err = node1.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{
				AnchorTxid: closeTxid.String(),
			},
		)
		if err != nil {
			return fmt.Errorf("unable to list node1 transfers: %w",
				err)
		}
		if len(result.Transfers) != 1 {
			return fmt.Errorf("node1 is missing force close " +
				"transfer")
		}

		forceCloseTransfer2, err := node2.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{
				AnchorTxid: closeTxid.String(),
			},
		)
		if err != nil {
			return fmt.Errorf("unable to list node2 transfers: %w",
				err)
		}
		if len(forceCloseTransfer2.Transfers) != 1 {
			return fmt.Errorf("node2 is missing force close " +
				"transfer")
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, fErr)

	return result
}

// ---------------------------------------------------------------------------
// Test asset network setup
// ---------------------------------------------------------------------------

// createTestAssetNetwork sets up the standard 5-node asset network:
// Charlie <-> Dave <-> Yara, and Erin <-> Fabia.
func createTestAssetNetwork(t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness,
	charlie, dave, erin, fabia, yara, universeTap *itest.IntegratedNode,
	mintedAsset *taprpc.Asset, assetSendAmount, charlieFundingAmount,
	daveFundingAmount,
	erinFundingAmount uint64, pushSat int64) (*lnrpc.ChannelPoint,
	*lnrpc.ChannelPoint, *lnrpc.ChannelPoint) {

	ctxb := context.Background()
	assetID := mintedAsset.AssetGenesis.AssetId
	var groupKey []byte
	if mintedAsset.AssetGroup != nil {
		groupKey = mintedAsset.AssetGroup.TweakedGroupKey
	}

	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptKeyBytes := fundingScriptKey.SerializeCompressed()

	// Send assets to Dave.
	daveAddr, err := dave.NewAddr(ctxb, &taprpc.NewAddrRequest{
		Amt:     assetSendAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	t.Logf("Sending %v asset units to Dave...", assetSendAmount)

	itest.AssertAddrCreated(t.t, asTapd(dave), mintedAsset, daveAddr)
	sendResp, err := charlie.SendAsset(ctxb, &taprpc.SendAssetRequest{
		TapAddrs: []string{daveAddr.Encoded},
	})
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, net.Miner.Client, asTapd(charlie), sendResp, assetID,
		[]uint64{mintedAsset.Amount - assetSendAmount, assetSendAmount},
		0, 1,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(dave), 1)

	// Send assets to Erin.
	erinAddr, err := erin.NewAddr(ctxb, &taprpc.NewAddrRequest{
		Amt:     assetSendAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	t.Logf("Sending %v asset units to Erin...", assetSendAmount)

	itest.AssertAddrCreated(t.t, asTapd(erin), mintedAsset, erinAddr)
	sendResp, err = charlie.SendAsset(ctxb, &taprpc.SendAssetRequest{
		TapAddrs: []string{erinAddr.Encoded},
	})
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, net.Miner.Client, asTapd(charlie), sendResp, assetID,
		[]uint64{
			mintedAsset.Amount - 2*assetSendAmount, assetSendAmount,
		}, 1, 2,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(erin), 1)

	t.Logf("Opening asset channels...")

	// Fund channels. We ensure peers are connected before each fund call
	// because channel funding can sometimes cause transient disconnects.
	net.EnsureConnected(t.t, charlie, dave)
	fundRespCD, err := charlie.FundChannel(
		ctxb, &tchrpc.FundChannelRequest{
			AssetAmount:        charlieFundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            pushSat,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", fundRespCD)

	net.EnsureConnected(t.t, dave, yara)
	fundRespDY, err := dave.FundChannel(
		ctxb, &tchrpc.FundChannelRequest{
			AssetAmount:        daveFundingAmount,
			AssetId:            assetID,
			PeerPubkey:         yara.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Dave and Yara: %v", fundRespDY)

	net.EnsureConnected(t.t, erin, fabia)
	fundRespEF, err := erin.FundChannel(
		ctxb, &tchrpc.FundChannelRequest{
			AssetAmount:        erinFundingAmount,
			AssetId:            assetID,
			PeerPubkey:         fabia.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            pushSat,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Erin and Fabia: %v", fundRespEF)

	// Assert pending channels.
	assertPendingChannels(
		t.t, charlie, mintedAsset, 1, charlieFundingAmount, 0,
	)
	assertPendingChannels(
		t.t, dave, mintedAsset, 2, daveFundingAmount,
		charlieFundingAmount,
	)
	assertPendingChannels(
		t.t, erin, mintedAsset, 1, erinFundingAmount, 0,
	)

	// Confirm all three channels.
	mineBlocks(t, net, 6, 3)

	charlieAssetBalance := mintedAsset.Amount - 2*assetSendAmount -
		charlieFundingAmount
	daveAssetBalance := assetSendAmount - daveFundingAmount
	erinAssetBalance := assetSendAmount - erinFundingAmount

	// Assert funding outputs in wallet.
	assertBalance(
		t.t, charlie, charlieFundingAmount,
		itest.WithAssetID(assetID),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes),
	)
	assertBalance(
		t.t, dave, daveFundingAmount, itest.WithAssetID(assetID),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes),
	)
	assertBalance(
		t.t, erin, erinFundingAmount, itest.WithAssetID(assetID),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes),
	)

	// Assert remaining wallet balances.
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, dave, daveAssetBalance, itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, erin, erinAssetBalance, itest.WithAssetID(assetID),
	)

	// Assert universe proofs for channel funding.
	assertUniverseProofExists(
		t.t, universeTap, assetID, groupKey, fundingScriptKeyBytes,
		fmt.Sprintf("%v:%v", fundRespCD.Txid, fundRespCD.OutputIndex),
	)
	assertUniverseProofExists(
		t.t, universeTap, assetID, groupKey, fundingScriptKeyBytes,
		fmt.Sprintf("%v:%v", fundRespDY.Txid, fundRespDY.OutputIndex),
	)
	assertUniverseProofExists(
		t.t, universeTap, assetID, groupKey, fundingScriptKeyBytes,
		fmt.Sprintf("%v:%v", fundRespEF.Txid, fundRespEF.OutputIndex),
	)

	// Assert channels show correct asset info.
	assertAssetChan(
		t.t, charlie, dave, charlieFundingAmount,
		[]*taprpc.Asset{mintedAsset},
	)
	assertAssetChan(
		t.t, dave, yara, daveFundingAmount,
		[]*taprpc.Asset{mintedAsset},
	)
	assertAssetChan(
		t.t, erin, fabia, erinFundingAmount,
		[]*taprpc.Asset{mintedAsset},
	)

	chanPointCD := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespCD.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespCD.Txid,
		},
	}
	chanPointDY := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespDY.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespDY.Txid,
		},
	}
	chanPointEF := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespEF.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespEF.Txid,
		},
	}

	return chanPointCD, chanPointDY, chanPointEF
}

// ---------------------------------------------------------------------------
// Additional payment helpers
// ---------------------------------------------------------------------------

// getPaymentResult reads from the lnd SendPaymentV2 stream until a final
// payment result is received.
func getPaymentResult(stream routerrpc.Router_SendPaymentV2Client,
	isHodl bool) (*lnrpc.Payment, error) {

	for {
		payment, err := stream.Recv()
		if err != nil {
			return nil, err
		}

		switch {
		case isHodl:
			return payment, nil

		case payment.Status != lnrpc.Payment_IN_FLIGHT:
			return payment, nil
		}
	}
}

// sendKeySendPayment sends a BTC-only keysend payment (no assets).
func sendKeySendPayment(t *testing.T, src, dst *itest.IntegratedNode,
	amt btcutil.Amount, opts ...payOpt) {

	cfg := defaultPayConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	var preimage lntypes.Preimage
	_, err := rand.Read(preimage[:])
	require.NoError(t, err)

	hash := preimage.Hash()

	customRecords := make(map[uint64][]byte)
	customRecords[record.KeySendType] = preimage[:]

	for key, value := range cfg.destCustomRecords {
		customRecords[key] = value
	}

	req := &routerrpc.SendPaymentRequest{
		Dest:              dst.PubKey[:],
		Amt:               int64(amt),
		DestCustomRecords: customRecords,
		PaymentHash:       hash[:],
		TimeoutSeconds:    int32(PaymentTimeout.Seconds()),
		FeeLimitMsat:      int64(cfg.feeLimit),
		MaxParts:          cfg.maxShards,
		OutgoingChanIds:   cfg.outgoingChanIDs,
		AllowSelfPayment:  cfg.allowSelfPayment,
		RouteHints:        cfg.routeHints,
	}

	stream, err := src.RouterClient.SendPaymentV2(ctxt, req)
	require.NoError(t, err)

	result, err := getPaymentResult(stream, false)
	require.NoError(t, err)
	require.Equal(t, lnrpc.Payment_SUCCEEDED, result.Status)
}

// createNormalInvoice creates a non-asset LN invoice.
func createNormalInvoice(t *testing.T, dst *itest.IntegratedNode,
	amountSat btcutil.Amount,
	opts ...invoiceOpt) *lnrpc.AddInvoiceResponse {

	cfg := defaultInvoiceConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	expirySeconds := 10
	invoiceResp, err := dst.LightningClient.AddInvoice(ctxt, &lnrpc.Invoice{
		Value:      int64(amountSat),
		Memo:       "normal invoice",
		Expiry:     int64(expirySeconds),
		RouteHints: cfg.routeHints,
	})
	require.NoError(t, err)

	return invoiceResp
}

// createAndPayNormalInvoice creates a normal (non-asset) invoice and pays it
// with assets.
func createAndPayNormalInvoice(t *testing.T, src, rfqPeer,
	dst *itest.IntegratedNode, amountSat btcutil.Amount, assetID []byte,
	opts ...payOpt) uint64 {

	invoiceResp := createNormalInvoice(t, dst, amountSat)
	numUnits, _ := payInvoiceWithAssets(
		t, src, rfqPeer, invoiceResp.PaymentRequest, assetID, opts...,
	)

	return numUnits
}

// createAndPayNormalInvoiceWithBtc creates a normal invoice and pays it with
// BTC (satoshis).
func createAndPayNormalInvoiceWithBtc(t *testing.T, src,
	dst *itest.IntegratedNode, amountSat btcutil.Amount) {

	invoiceResp := createNormalInvoice(t, dst, amountSat)

	payInvoiceWithSatoshi(t, src, invoiceResp)
}

// payInvoiceWithSatoshi pays an invoice using satoshis (not assets).
func payInvoiceWithSatoshi(t *testing.T, payer *itest.IntegratedNode,
	invoice *lnrpc.AddInvoiceResponse, opts ...payOpt) {

	payPayReqWithSatoshi(t, payer, invoice.PaymentRequest, opts...)
}

// payPayReqWithSatoshi pays a payment request using satoshis.
func payPayReqWithSatoshi(t *testing.T, payer *itest.IntegratedNode,
	payReq string, opts ...payOpt) {

	cfg := defaultPayConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, ccTransferTimeout)
	defer cancel()

	sendReq := &routerrpc.SendPaymentRequest{
		PaymentRequest:   payReq,
		TimeoutSeconds:   int32(PaymentTimeout.Seconds()),
		FeeLimitMsat:     int64(cfg.feeLimit),
		MaxParts:         cfg.maxShards,
		OutgoingChanIds:  cfg.outgoingChanIDs,
		AllowSelfPayment: cfg.allowSelfPayment,
	}

	if cfg.smallShards {
		sendReq.MaxShardSizeMsat = 80_000_000
	}

	stream, err := payer.RouterClient.SendPaymentV2(ctxt, sendReq)
	require.NoError(t, err)

	result, err := getPaymentResult(
		stream, cfg.payStatus == lnrpc.Payment_IN_FLIGHT,
	)
	if cfg.errSubStr != "" {
		require.ErrorContains(t, err, cfg.errSubStr)
	} else {
		require.NoError(t, err)
		require.Equal(t, cfg.payStatus, result.Status)
		require.Equal(t, cfg.failureReason, result.FailureReason)
	}
}

// payInvoiceWithSatoshiLastHop pays an invoice using a specific route built
// from the given hop pubkeys.
func payInvoiceWithSatoshiLastHop(t *testing.T,
	payer *itest.IntegratedNode,
	invoice *lnrpc.AddInvoiceResponse, hops [][]byte,
	opts ...payOpt) {

	cfg := defaultPayConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	decodedInvoice, err := payer.DecodePayReq(
		ctxt, &lnrpc.PayReqString{
			PayReq: invoice.PaymentRequest,
		},
	)
	require.NoError(t, err)

	routeRes, err := payer.RouterClient.BuildRoute(
		ctxb, &routerrpc.BuildRouteRequest{
			AmtMsat:     decodedInvoice.NumMsat,
			PaymentAddr: invoice.PaymentAddr,
			HopPubkeys:  hops,
		},
	)
	require.NoError(t, err)

	res, err := payer.RouterClient.SendToRouteV2(
		ctxt, &routerrpc.SendToRouteRequest{
			PaymentHash: invoice.RHash,
			Route:       routeRes.Route,
		},
	)
	require.NoError(t, err)

	switch cfg.payStatus {
	case lnrpc.Payment_FAILED:
		require.Equal(t, lnrpc.HTLCAttempt_FAILED, res.Status)
		require.NotNil(t, res.Failure)
		require.Nil(t, res.Preimage)

	case lnrpc.Payment_SUCCEEDED:
		require.Equal(t, lnrpc.HTLCAttempt_SUCCEEDED, res.Status)

	default:
	}
}

// ---------------------------------------------------------------------------
// Hodl invoice helpers
// ---------------------------------------------------------------------------

// assetHodlInvoice is a hodl invoice created for asset channel tests.
type assetHodlInvoice struct {
	preimage lntypes.Preimage
	payReq   string
}

// createAssetHodlInvoice creates a hodl invoice for the given asset amount.
func createAssetHodlInvoice(t *testing.T, dstRfqPeer,
	dst *itest.IntegratedNode, assetAmount uint64, assetID []byte,
	opts ...invoiceOpt) assetHodlInvoice {

	cfg := defaultInvoiceConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	timeoutSeconds := int64(rfq.DefaultInvoiceExpiry.Seconds())

	var rfqPeer []byte
	if dstRfqPeer != nil {
		rfqPeer = dstRfqPeer.PubKey[:]
	}

	t.Logf("Asking peer %x for quote to buy assets to receive for "+
		"invoice for %d units; waiting up to %ds",
		rfqPeer, assetAmount, timeoutSeconds)

	var preimage lntypes.Preimage
	_, err := rand.Read(preimage[:])
	require.NoError(t, err)

	payHash := preimage.Hash()
	request := &tchrpc.AddInvoiceRequest{
		AssetAmount: assetAmount,
		PeerPubkey:  rfqPeer,
		InvoiceRequest: &lnrpc.Invoice{
			Memo: fmt.Sprintf("this is an asset invoice for "+
				"%d units", assetAmount),
			Expiry: timeoutSeconds,
		},
		HodlInvoice: &tchrpc.HodlInvoice{
			PaymentHash: payHash[:],
		},
	}

	switch {
	case len(cfg.groupKey) > 0:
		request.GroupKey = cfg.groupKey

	default:
		request.AssetId = assetID
	}

	resp, err := dst.TaprootAssetChannelsClient.AddInvoice(ctxt, request)
	require.NoError(t, err)

	decodedInvoice, err := dst.DecodePayReq(ctxt, &lnrpc.PayReqString{
		PayReq: resp.InvoiceResult.PaymentRequest,
	})
	require.NoError(t, err)

	rpcRate := resp.AcceptedBuyQuote.AskAssetRate
	rate, err := rpcutils.UnmarshalRfqFixedPoint(rpcRate)
	require.NoError(t, err)

	assetUnits := rfqmath.NewBigIntFixedPoint(assetAmount, 0)
	numMSats := rfqmath.UnitsToMilliSatoshi(assetUnits, *rate)
	mSatPerUnit := float64(decodedInvoice.NumMsat) / float64(assetAmount)

	require.EqualValues(
		t, uint64(numMSats), uint64(decodedInvoice.NumMsat),
	)

	t.Logf("Got quote for %d msat at %v msat/unit from peer %x with "+
		"SCID %d", decodedInvoice.NumMsat, mSatPerUnit, rfqPeer,
		resp.AcceptedBuyQuote.Scid)

	return assetHodlInvoice{
		preimage: preimage,
		payReq:   resp.InvoiceResult.PaymentRequest,
	}
}

// ---------------------------------------------------------------------------
// Channel balance assertions
// ---------------------------------------------------------------------------

// assertChannelSatBalance asserts the satoshi balance of the given channel.
func assertChannelSatBalance(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint, local, remote int64) {

	targetChan := fetchChannel(t, node, chanPoint)

	require.InDelta(t, local, targetChan.LocalBalance, 1)
	require.InDelta(t, remote, targetChan.RemoteBalance, 1)
}

// assertChannelAssetBalance asserts the asset balance of the given channel.
func assertChannelAssetBalance(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint, local, remote uint64) {

	assertChannelAssetBalanceWithDelta(
		t, node, chanPoint, local, remote, 1,
	)
}

// assertChannelAssetBalanceWithDelta asserts the asset balance with a custom
// delta tolerance.
func assertChannelAssetBalanceWithDelta(t *testing.T,
	node *itest.IntegratedNode, chanPoint *lnrpc.ChannelPoint,
	local, remote uint64, delta float64) {

	targetChan := fetchChannel(t, node, chanPoint)

	assetBalance, err := parseChannelData(targetChan.CustomChannelData)
	require.NoError(t, err)

	require.Len(t, assetBalance.FundingAssets, 1)

	require.InDelta(t, local, assetBalance.LocalBalance, delta)
	require.InDelta(t, remote, assetBalance.RemoteBalance, delta)
}

// channelAssetBalance returns the local and remote asset balance for a channel.
func channelAssetBalance(t *testing.T, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint) (uint64, uint64) {

	targetChan := fetchChannel(t, node, chanPoint)

	assetBalance, err := parseChannelData(targetChan.CustomChannelData)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(assetBalance.FundingAssets), 1)

	return assetBalance.LocalBalance, assetBalance.RemoteBalance
}

// addRoutingFee adds the default routing fee (1 part per million fee rate plus
// 1000 milli-satoshi base fee) to the given milli-satoshi amount.
func addRoutingFee(amt lnwire.MilliSatoshi) lnwire.MilliSatoshi {
	return amt + (amt / 1000_000) + 1000
}

// ---------------------------------------------------------------------------
// Spendable balance helpers
// ---------------------------------------------------------------------------

// spendableBalance returns the total spendable (local script key) balance
// across all UTXOs for the given asset ID or group key.
func spendableBalance(client *itest.IntegratedNode, assetID,
	groupKey []byte) (uint64, error) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, ccShortTimeout)
	defer cancel()

	utxos, err := client.ListUtxos(ctxt, &taprpc.ListUtxosRequest{})
	if err != nil {
		return 0, err
	}

	var allAssets []*taprpc.Asset
	for _, utxo := range maps.Values(utxos.ManagedUtxos) {
		allAssets = append(allAssets, utxo.Assets...)
	}

	var assetSum uint64
	for _, a := range allAssets {
		match := false
		if len(groupKey) > 0 {
			match = a.AssetGroup != nil && bytes.Equal(
				a.AssetGroup.TweakedGroupKey, groupKey,
			)
		} else {
			match = bytes.Equal(
				a.AssetGenesis.AssetId, assetID,
			)
		}

		if match && a.ScriptKeyIsLocal {
			assetSum += a.Amount
		}
	}

	return assetSum, nil
}

// assertSpendableBalance asserts that the entire spendable balance equals the
// expected value.
func assertSpendableBalance(t *testing.T, client *itest.IntegratedNode,
	assetID, groupKey []byte, expectedBalance uint64) {

	t.Helper()

	err := wait.NoError(func() error {
		assetSum, err := spendableBalance(client, assetID, groupKey)
		if err != nil {
			return err
		}

		if assetSum != expectedBalance {
			return fmt.Errorf("expected balance %d, got %d",
				expectedBalance, assetSum)
		}

		return nil
	}, ccShortTimeout)
	if err != nil {
		ctxb := context.Background()
		balance, _ := spendableBalance(client, assetID, groupKey)

		transfers, err2 := client.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t, err2)

		numConfirmed := 0
		numUnconfirmed := 0
		for _, tr := range transfers.Transfers {
			if tr.AnchorTxBlockHeight > 0 {
				numConfirmed++
			} else {
				numUnconfirmed++
			}
		}

		t.Fatalf("Failed to assert balance: expected %d, got %d "+
			"(transfers: %d confirmed, %d unconfirmed): %v",
			expectedBalance, balance, numConfirmed,
			numUnconfirmed, err)
	}
}

// locateAssetTransfers finds and returns the asset transfer for the given
// transaction ID.
func locateAssetTransfers(t *testing.T, node *itest.IntegratedNode,
	txid chainhash.Hash) *taprpc.AssetTransfer {

	var transfer *taprpc.AssetTransfer
	err := wait.NoError(func() error {
		ctxb := context.Background()
		forceCloseTransfer, err := node.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{
				AnchorTxid: txid.String(),
			},
		)
		if err != nil {
			return fmt.Errorf("unable to list %v transfers: %w",
				node.Cfg.Name, err)
		}
		if len(forceCloseTransfer.Transfers) != 1 {
			return fmt.Errorf("%v is expecting %d transfers, "+
				"has %d", node.Cfg.Name, 1,
				len(forceCloseTransfer.Transfers))
		}

		transfer = forceCloseTransfer.Transfers[0]

		if transfer.AnchorTxBlockHash == nil {
			return fmt.Errorf("missing anchor block hash, " +
				"transfer not confirmed")
		}

		return nil
	}, ccTransferTimeout)
	require.NoError(t, err)

	return transfer
}

// ---------------------------------------------------------------------------
// HTLC event helpers
// ---------------------------------------------------------------------------

// subscribeEventsClient is a type alias for the HTLC events stream client.
type subscribeEventsClient = routerrpc.Router_SubscribeHtlcEventsClient

type htlcEventConfig struct {
	timeout            time.Duration
	numEvents          int
	withLinkFailure    bool
	withForwardFailure bool
	withFailureDetail  routerrpc.FailureDetail
}

func defaultHtlcEventConfig() *htlcEventConfig {
	return &htlcEventConfig{
		timeout: wait.DefaultTimeout,
	}
}

type htlcEventOpt func(*htlcEventConfig)

func withHtlcTimeout(timeout time.Duration) htlcEventOpt {
	return func(config *htlcEventConfig) {
		config.timeout = timeout
	}
}

func withNumEvents(numEvents int) htlcEventOpt {
	return func(config *htlcEventConfig) {
		config.numEvents = numEvents
	}
}

func withLinkFailure(detail routerrpc.FailureDetail) htlcEventOpt {
	return func(config *htlcEventConfig) {
		config.withLinkFailure = true
		config.withFailureDetail = detail
	}
}

func withForwardFailure() htlcEventOpt {
	return func(config *htlcEventConfig) {
		config.withForwardFailure = true
	}
}

// recvHtlcEventWithTimeout reads a single HTLC event from the stream with a
// timeout.
func recvHtlcEventWithTimeout(c subscribeEventsClient,
	timeout time.Duration) (*routerrpc.HtlcEvent, error) {

	type recvResult struct {
		evt *routerrpc.HtlcEvent
		err error
	}

	recvChan := make(chan recvResult, 1)

	go func() {
		evt, err := c.Recv()
		recvChan <- recvResult{
			evt: evt,
			err: err,
		}
	}()

	select {
	case result := <-recvChan:
		return result.evt, result.err

	case <-time.After(timeout):
		return nil, fmt.Errorf("Htlc event receive timeout")
	}
}

// assertHtlcEvents waits for HTLC events matching the config.
func assertHtlcEvents(t *testing.T, c subscribeEventsClient,
	opts ...htlcEventOpt) {

	t.Helper()

	cfg := defaultHtlcEventConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	deadline := time.Now().Add(cfg.timeout)
	var numEvents int

	for {
		type (
			linkFailEvent    = *routerrpc.HtlcEvent_LinkFailEvent
			forwardFailEvent = *routerrpc.HtlcEvent_ForwardFailEvent
		)

		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("Htlc event receive timeout")
			return
		}

		evt, err := recvHtlcEventWithTimeout(c, remaining)
		if err != nil {
			t.Fatalf("Htlc event receive timeout")
			return
		}

		if cfg.withLinkFailure {
			linkEvent, ok := evt.Event.(linkFailEvent)
			if !ok {
				continue
			}

			if linkEvent.LinkFailEvent.FailureDetail !=
				cfg.withFailureDetail {

				continue
			}
		}

		if cfg.withForwardFailure {
			_, ok := evt.Event.(forwardFailEvent)
			if !ok {
				continue
			}
		}

		numEvents++

		if numEvents == cfg.numEvents {
			return
		}
	}
}

// assertMinNumHtlcs asserts that the node has at least the expected number of
// pending HTLCs across all channels.
func assertMinNumHtlcs(t *testing.T, node *itest.IntegratedNode,
	expected int) {

	t.Helper()

	ctxb := context.Background()

	err := wait.NoError(func() error {
		listChansResp, err := node.ListChannels(
			ctxb, &lnrpc.ListChannelsRequest{},
		)
		if err != nil {
			return err
		}

		var numHtlcs int
		for _, channel := range listChansResp.Channels {
			numHtlcs += len(channel.PendingHtlcs)
		}

		if numHtlcs < expected {
			return fmt.Errorf("expected %v HTLCs, got %v",
				expected, numHtlcs)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// assertNumHtlcs asserts that the node has exactly the expected number of
// pending HTLCs across all channels.
func assertNumHtlcs(t *testing.T, node *itest.IntegratedNode,
	expected int) {

	t.Helper()

	ctxb := context.Background()

	err := wait.NoError(func() error {
		listChansResp, err := node.ListChannels(
			ctxb, &lnrpc.ListChannelsRequest{},
		)
		if err != nil {
			return err
		}

		var numHtlcs int
		for _, channel := range listChansResp.Channels {
			numHtlcs += len(channel.PendingHtlcs)
		}

		if numHtlcs != expected {
			return fmt.Errorf("expected %v HTLCs, got %v",
				expected, numHtlcs)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// assertHTLCNotActive asserts the node doesn't have an active pending HTLC
// with the given payment hash.
func assertHTLCNotActive(t *testing.T, hn *itest.IntegratedNode,
	cp *lnrpc.ChannelPoint, payHash []byte) *lnrpc.HTLC {

	var result *lnrpc.HTLC
	target := hex.EncodeToString(payHash)

	err := wait.NoError(func() error {
		ch := fetchChannel(t, hn, cp)

		for _, htlc := range ch.PendingHtlcs {
			h := hex.EncodeToString(htlc.HashLock)

			if h == target {
				result = htlc
				break
			}
		}

		if result == nil {
			return nil
		}

		return fmt.Errorf("node [%s:%x] still has: the payHash %x",
			hn.Cfg.Name, hn.PubKey[:], payHash)
	}, wait.DefaultTimeout)
	require.NoError(t, err, "timeout checking pending HTLC")

	return result
}

// assertInvoiceState asserts that an invoice with the given payment address
// has the expected state.
func assertInvoiceState(t *testing.T, hn *itest.IntegratedNode,
	payAddr []byte, expectedState lnrpc.Invoice_InvoiceState) {

	msg := &invoicesrpc.LookupInvoiceMsg{
		InvoiceRef: &invoicesrpc.LookupInvoiceMsg_PaymentAddr{
			PaymentAddr: payAddr,
		},
	}

	err := wait.NoError(func() error {
		invoice, err := hn.InvoicesClient.LookupInvoiceV2(
			context.Background(), msg,
		)
		if err != nil {
			return err
		}

		if invoice.State == expectedState {
			return nil
		}

		return fmt.Errorf("%s: invoice with payment address %x not "+
			"in state %s", hn.Cfg.Name, payAddr, expectedState)
	}, wait.DefaultTimeout)
	require.NoError(t, err, "timeout waiting for invoice settled state")
}

// ---------------------------------------------------------------------------
// Force close helpers
// ---------------------------------------------------------------------------

// forceCloseExpiryInfo holds expiry information for force close sweeps.
type forceCloseExpiryInfo struct {
	currentHeight uint32
	csvDelay      uint32

	cltvDelays map[lntypes.Hash]uint32

	localAssetBalance  uint64
	remoteAssetBalance uint64

	t    *testing.T
	node *itest.IntegratedNode
}

func (f *forceCloseExpiryInfo) blockTillExpiry(
	hash lntypes.Hash) uint32 {

	ctxb := context.Background()
	nodeInfo, err := f.node.LightningClient.GetInfo(
		ctxb,
		&lnrpc.GetInfoRequest{},
	)
	require.NoError(f.t, err)

	cltv, ok := f.cltvDelays[hash]
	require.True(f.t, ok)

	f.t.Logf("current_height=%v, expiry=%v, mining %v blocks",
		nodeInfo.BlockHeight, cltv, cltv-nodeInfo.BlockHeight)

	return cltv - nodeInfo.BlockHeight
}

func newCloseExpiryInfo(t *testing.T,
	node *itest.IntegratedNode) forceCloseExpiryInfo {

	ctxb := context.Background()

	listChansResp, err := node.ListChannels(
		ctxb, &lnrpc.ListChannelsRequest{},
	)
	require.NoError(t, err)

	mainChan := listChansResp.Channels[0]

	nodeInfo, err := node.LightningClient.GetInfo(
		ctxb, &lnrpc.GetInfoRequest{},
	)
	require.NoError(t, err)

	cltvs := make(map[lntypes.Hash]uint32)
	for _, htlc := range mainChan.PendingHtlcs {
		var payHash lntypes.Hash
		copy(payHash[:], htlc.HashLock)
		cltvs[payHash] = htlc.ExpirationHeight
	}

	assetData, err := parseChannelData(mainChan.CustomChannelData)
	require.NoError(t, err)

	return forceCloseExpiryInfo{
		csvDelay:           mainChan.CsvDelay,
		currentHeight:      nodeInfo.BlockHeight,
		cltvDelays:         cltvs,
		localAssetBalance:  assetData.LocalBalance,
		remoteAssetBalance: assetData.RemoteBalance,
		t:                  t,
		node:               node,
	}
}

// assertForceCloseSweeps asserts that the force close sweeps are initiated
// correctly and returns the final expected balances for alice and bob.
//
//nolint:lll
func assertForceCloseSweeps(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest,
	alice, bob *itest.IntegratedNode, chanPoint *lnrpc.ChannelPoint,
	aliceStartAmount uint64, assetInvoiceAmt, assetsPerMPPShard int,
	assetID, groupKey []byte, aliceHodlInvoices,
	bobHodlInvoices []assetHodlInvoice, mpp bool) (uint64, uint64) {

	// At this point, both sides should have 4 (or +4 with MPP) HTLCs
	// active.
	numHtlcs := 4
	numAdditionalShards := assetInvoiceAmt / assetsPerMPPShard
	if mpp {
		numHtlcs += numAdditionalShards * 2
	}
	t.Logf("Asserting both Alice and Bob have %d HTLCs...", numHtlcs)
	assertNumHtlcs(t.t, alice, numHtlcs)
	assertNumHtlcs(t.t, bob, numHtlcs)

	// Before we force close, we'll grab the current height, the CSV delay
	// needed, and also the absolute timeout of the set of active HTLCs.
	closeExpiryInfo := newCloseExpiryInfo(t.t, alice)

	// With all of the HTLCs established, we'll now force close the channel
	// with Alice.
	t.Logf("Force close by Alice w/ HTLCs...")
	_, closeTxid, err := net.CloseChannel(alice, chanPoint, true)
	require.NoError(t.t, err)

	t.Logf("Channel closed! Mining blocks, close_txid=%v", closeTxid)

	// The channel should first be in "waiting close" until it confirms.
	assertWaitingCloseChannelAssetData(t.t, alice, chanPoint)

	// Next, we'll mine a block which should start the clock ticking on the
	// relative timeout for Alice, and Bob.
	mineBlocks(t, net, 1, 1)

	// After force closing, Bob should now have a transfer that tracks the
	// force closed commitment transaction.
	locateAssetTransfers(t.t, bob, *closeTxid)

	t.Logf("Settling Bob's hodl invoice")

	// It should then go to "pending force closed".
	assertPendingForceCloseChannelAssetData(t.t, alice, chanPoint)

	// We'll signal Bob to settle one of his incoming HTLCs on Alice's
	// commitment transaction.
	_, err = bob.InvoicesClient.SettleInvoice(
		ctx, &invoicesrpc.SettleInvoiceMsg{
			Preimage: bobHodlInvoices[0].preimage[:],
		},
	)
	require.NoError(t.t, err)

	// We'll pause here for Bob to extend the sweep request to the sweeper.
	assertSweepExists(
		t.t, bob,
		walletrpc.WitnessType_TAPROOT_HTLC_ACCEPTED_REMOTE_SUCCESS,
	)

	_, err = waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	// Next, we'll mine an additional block, this should allow Bob to sweep
	// both his commitment output, and the incoming HTLC that we just
	// settled above. We use the txid from the mined block (not from the
	// mempool check above) because the sweeper may RBF between the two.
	bobSweepBlocks1 := mineBlocks(t, net, 1, 1)

	// At this point, we should have the next sweep transaction in the
	// mempool: Bob's incoming HTLC sweep directly off the commitment
	// transaction.
	_, err = waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	// We'll now mine the next block, which should confirm Bob's HTLC sweep
	// transaction.
	bobSweepBlocks2 := mineBlocks(t, net, 1, 1)

	// Wait for tapd to process the confirmed sweep transactions before
	// checking balances. We extract the txid from the mined blocks rather
	// than from the earlier mempool checks to avoid RBF mismatches.
	bobSweepTxHash1 := bobSweepBlocks1[0].Transactions[1].TxHash()
	bobSweepTxHash2 := bobSweepBlocks2[0].Transactions[1].TxHash()
	locateAssetTransfers(t.t, bob, bobSweepTxHash1)
	locateAssetTransfers(t.t, bob, bobSweepTxHash2)

	t.Logf("Confirming Bob's remote HTLC success sweep")

	// Bob's balance should now reflect that he's gained the value of the
	// HTLC, in addition to his settled balance. We need to subtract 1 from
	// the final balance due to the rounding down of the asset amount during
	// RFQ conversion.
	bobExpectedBalance := closeExpiryInfo.remoteAssetBalance +
		uint64(assetInvoiceAmt-1)
	t.Logf("Expecting Bob's balance to be %d", bobExpectedBalance)
	assertSpendableBalance(
		t.t, bob, assetID, groupKey, bobExpectedBalance,
	)

	// With Bob's HTLC settled, we'll now have Alice do the same. For her,
	// it'll be a 2nd level sweep, which requires an extra transaction.
	// Before we do that though, enough blocks have passed so Alice can now
	// sweep her to-local output.
	mineBlocks(t, net, 1, 0)

	_, err = waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	aliceToLocalBlocks := mineBlocks(t, net, 1, 1)

	// Wait for tapd to register the to-local sweep transfer. We use the
	// txid from the mined block to avoid RBF mismatches.
	aliceToLocalHash := aliceToLocalBlocks[0].Transactions[1].TxHash()
	locateAssetTransfers(t.t, alice, aliceToLocalHash)

	t.Logf("Confirming Alice's to-local sweep")

	// With this extra block mined, Alice's settled balance should be the
	// starting balance, minus the 2 HTLCs, plus her settled balance.
	aliceExpectedBalance := aliceStartAmount
	aliceExpectedBalance += closeExpiryInfo.localAssetBalance
	assertSpendableBalance(
		t.t, alice, assetID, groupKey, aliceExpectedBalance,
	)

	t.Logf("Settling Alice's hodl invoice")

	// With her commitment output swept above, we'll now settle one of
	// Alice's incoming HTLCs.
	_, err = alice.InvoicesClient.SettleInvoice(
		ctx, &invoicesrpc.SettleInvoiceMsg{
			Preimage: aliceHodlInvoices[0].preimage[:],
		},
	)
	require.NoError(t.t, err)

	// We'll pause here for Alice to extend the sweep request to the
	// sweeper.
	assertSweepExists(
		t.t, alice,
		walletrpc.WitnessType_TAPROOT_HTLC_ACCEPTED_LOCAL_SUCCESS,
	)

	// We'll now mine a block, which should trigger Alice's broadcast of the
	// second level sweep transaction.
	sweepBlocks := mineBlocks(t, net, 1, 0)

	// If the block mined above didn't also mine our sweep, then we'll mine
	// one final block which will confirm Alice's sweep transaction.
	if len(sweepBlocks[0].Transactions) == 1 {
		_, err := waitForNTxsInMempool(
			net.Miner.Client, 1, ccShortTimeout,
		)
		require.NoError(t.t, err)

		// With the sweep transaction in the mempool, we'll mine a block
		// to confirm the sweep.
		sweepBlocks = mineBlocks(t, net, 1, 1)
	}

	// Use the txid from the mined block to avoid RBF mismatches.
	sweepTxHash := sweepBlocks[0].Transactions[1].TxHash()
	locateAssetTransfers(t.t, alice, sweepTxHash)

	t.Logf("Confirming Alice's second level remote HTLC success sweep")

	// Next, we'll mine enough blocks to trigger the CSV expiry so Alice can
	// sweep the HTLC into her wallet.
	mineBlocks(t, net, closeExpiryInfo.csvDelay, 0)

	// We'll pause here and wait until the sweeper recognizes that we've
	// offered the second level sweep transaction.
	//
	assertSweepExists(
		t.t, alice,
		walletrpc.WitnessType_TAPROOT_HTLC_ACCEPTED_SUCCESS_SECOND_LEVEL,
	)

	t.Logf("Confirming Alice's local HTLC success sweep")

	// Now that we know the sweep was offered, we'll mine an extra block to
	// actually trigger a sweeper broadcast.
	sweepBlocks = mineBlocks(t, net, 1, 0)

	// If the block mined above didn't also mine our sweep, then we'll mine
	// one final block which will confirm Alice's sweep transaction.
	if len(sweepBlocks[0].Transactions) == 1 {
		_, err := waitForNTxsInMempool(
			net.Miner.Client, 1, ccShortTimeout,
		)
		require.NoError(t.t, err)

		sweepBlocks = mineBlocks(t, net, 1, 1)
	}

	sweepTxHash = sweepBlocks[0].Transactions[1].TxHash()
	locateAssetTransfers(t.t, alice, sweepTxHash)

	// With the sweep transaction confirmed, Alice's balance should have
	// incremented by the amt of the HTLC.
	aliceExpectedBalance += uint64(assetInvoiceAmt - 1)
	assertSpendableBalance(
		t.t, alice, assetID, groupKey, aliceExpectedBalance,
	)

	t.Logf("Mining enough blocks to time out the remaining HTLCs")

	// At this point, we've swept two HTLCs: one from the remote commit, and
	// one via the second layer. We'll now mine the remaining amount of
	// blocks to time out the HTLCs.
	blockToMine := closeExpiryInfo.blockTillExpiry(
		aliceHodlInvoices[1].preimage.Hash(),
	)
	mineBlocks(t, net, blockToMine, 0)

	// We'll wait for both Alice and Bob to present their respective sweeps
	// to the sweeper.
	numTimeoutHTLCs := 1
	if mpp {
		numTimeoutHTLCs += numAdditionalShards
	}
	assertSweepExists(
		t.t, alice,
		walletrpc.WitnessType_TAPROOT_HTLC_LOCAL_OFFERED_TIMEOUT,
	)
	assertSweepExists(
		t.t, bob,
		walletrpc.WitnessType_TAPROOT_HTLC_OFFERED_REMOTE_TIMEOUT,
	)

	t.Logf("Confirming initial HTLC timeout txns")

	timeoutSweeps, err := waitForNTxsInMempool(
		net.Miner.Client, 2, ccShortTimeout,
	)
	require.NoError(t.t, err)

	t.Logf("Asserting balance on sweeps: %v", timeoutSweeps)

	mineBlocks(t, net, 1, 2)

	bobSweeps, err := bob.WalletKitClient.ListSweeps(
		ctx, &walletrpc.ListSweepsRequest{
			Verbose: true,
		},
	)
	require.NoError(t.t, err)

	var bobSweepTx *wire.MsgTx
	for _, sweep := range bobSweeps.GetTransactionDetails().Transactions {
		for _, tx := range timeoutSweeps {
			if sweep.TxHash == tx.String() {
				txBytes, err := hex.DecodeString(
					sweep.RawTxHex,
				)
				require.NoError(t.t, err)

				bobSweepTx = &wire.MsgTx{}
				err = bobSweepTx.Deserialize(
					bytes.NewReader(txBytes),
				)
				require.NoError(t.t, err)
			}
		}
	}
	require.NotNil(
		t.t, bobSweepTx, "Bob's sweep transaction not found",
	)

	// There's always an extra input that pays for the fees. So we can only
	// count the remainder as HTLC inputs.
	numSweptHTLCs := len(bobSweepTx.TxIn) - 1

	// If we didn't yet sweep all HTLCs, then we need to wait for another
	// sweep.
	if numSweptHTLCs < numTimeoutHTLCs {
		// nolint:lll
		assertSweepExists(
			t.t, bob,
			walletrpc.WitnessType_TAPROOT_HTLC_OFFERED_REMOTE_TIMEOUT,
		)

		t.Logf("Confirming additional HTLC timeout sweep txns")

		additionalTimeoutSweeps, err := waitForNTxsInMempool(
			net.Miner.Client, 1, ccShortTimeout,
		)
		require.NoError(t.t, err)

		t.Logf("Asserting balance on additional timeout sweeps: %v",
			additionalTimeoutSweeps)

		// Finally, we'll mine a single block to confirm them.
		mineBlocks(t, net, 1, 1)
	}

	// At this point, Bob's balance should be incremented by an additional
	// HTLC value.
	bobExpectedBalance += uint64(assetInvoiceAmt - 1)
	assertSpendableBalance(
		t.t, bob, assetID, groupKey, bobExpectedBalance,
	)

	t.Logf("Mining extra blocks for Alice's CSV to expire on 2nd level txn")

	// Next, we'll mine additional blocks so Alice's CSV delay expires for
	// the second level timeout output.
	mineBlocks(t, net, closeExpiryInfo.csvDelay, 0)

	// Wait for Alice to extend the second level output to the sweeper
	// before we mine the next block to the sweeper.
	assertSweepExists(
		t.t, alice,
		walletrpc.WitnessType_TAPROOT_HTLC_OFFERED_TIMEOUT_SECOND_LEVEL,
	)

	t.Logf("Confirming Alice's final timeout sweep")

	// With the way the sweeper works, we'll now need to mine an extra block
	// to trigger the sweep.
	sweepBlocks = mineBlocks(t, net, 1, 0)

	// If the block mined above didn't also mine our sweep, then we'll mine
	// one final block which will confirm Alice's sweep transaction.
	if len(sweepBlocks[0].Transactions) == 1 {
		_, err := waitForNTxsInMempool(
			net.Miner.Client, 1, ccShortTimeout,
		)
		require.NoError(t.t, err)

		// We'll mine one final block which will confirm Alice's sweep
		// transaction.
		sweepBlocks = mineBlocks(t, net, 1, 1)
	}

	sweepTxHash = sweepBlocks[0].Transactions[1].TxHash()
	locateAssetTransfers(t.t, alice, sweepTxHash)

	return aliceExpectedBalance, bobExpectedBalance
}

// itestNode is a wrapper around an integrated lnd+tapd node.
type itestNode struct {
	node *itest.IntegratedNode
}

// multiRfqNodes contains all the itest nodes that are required to set up the
// multi RFQ network topology.
type multiRfqNodes struct {
	charlie, dave, erin, fabia, yara, george itestNode
	universeTap                              *itest.IntegratedNode
}

// sendAssetsAndAssert sends assets from sender to recipient and asserts the
// transfer was successful.
func sendAssetsAndAssert(ctx context.Context, t *ccHarnessTest,
	recipient, sender, universe *itest.IntegratedNode,
	mintedAsset *taprpc.Asset, assetSendAmount uint64,
	idx, numTransfers int, previousSentAmount uint64) {

	assetID := mintedAsset.AssetGenesis.AssetId
	recipientAddr, err := asTapd(recipient).NewAddr(
		ctx, &taprpc.NewAddrRequest{
			Amt:     assetSendAmount,
			AssetId: assetID,
			ProofCourierAddr: fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				universe.RPCAddr(),
			),
		},
	)
	require.NoError(t.t, err)

	t.Logf("Sending %v asset units to %s...", assetSendAmount,
		recipient.Cfg.Name)

	// We assume that we sent the same size in a previous send.
	totalSent := assetSendAmount + previousSentAmount

	// Send the assets to recipient.
	itest.AssertAddrCreated(
		t.t, asTapd(recipient), mintedAsset, recipientAddr,
	)
	sendResp, err := asTapd(sender).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{recipientAddr.Encoded},
		},
	)
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, asTapd(sender), sendResp,
		assetID,
		[]uint64{mintedAsset.Amount - totalSent, assetSendAmount},
		idx, idx+1,
	)
	itest.AssertNonInteractiveRecvComplete(
		t.t, asTapd(recipient), numTransfers,
	)
}

// createTestAssetNetworkGroupKey creates an asset network with grouped assets.
// It funds channels between Charlie->Dave and Erin->Fabia using multiple
// tranches of a grouped asset.
//
//nolint:lll
func createTestAssetNetworkGroupKey(ctx context.Context, t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness,
	charlie, dave, erin, fabia, universe *itest.IntegratedNode,
	mintedAssets []*taprpc.Asset,
	charlieFundingAmount, erinFundingAmount uint64,
	pushSat int64) (*lnrpc.ChannelPoint, *lnrpc.ChannelPoint) {

	var groupKey []byte
	for _, mintedAsset := range mintedAssets {
		require.NotNil(t.t, mintedAsset.AssetGroup)

		if groupKey == nil {
			groupKey = mintedAsset.AssetGroup.TweakedGroupKey
			continue
		}

		require.Equal(
			t.t, groupKey, mintedAsset.AssetGroup.TweakedGroupKey,
		)
	}

	// We first do a transfer to Charlie by itself, so we get the correct
	// asset pieces that we want for the channel funding.
	sendAssetsAndAssert(
		ctx, t, charlie, charlie, universe, mintedAssets[0],
		charlieFundingAmount/2, 0, 1, 0,
	)
	sendAssetsAndAssert(
		ctx, t, charlie, charlie, universe, mintedAssets[1],
		charlieFundingAmount/2, 1, 2, 0,
	)

	// We need to send some assets to Erin, so he can fund an asset channel
	// with Fabia.
	sendAssetsAndAssert(
		ctx, t, erin, charlie, universe, mintedAssets[0],
		erinFundingAmount/2, 2, 1, charlieFundingAmount/2,
	)
	sendAssetsAndAssert(
		ctx, t, erin, charlie, universe, mintedAssets[1],
		erinFundingAmount/2, 3, 2, charlieFundingAmount/2,
	)

	// Then we burn everything but a single asset piece.
	assetID1 := mintedAssets[0].AssetGenesis.AssetId
	assetID2 := mintedAssets[1].AssetGenesis.AssetId
	burnAmount1 := mintedAssets[0].Amount - charlieFundingAmount/2 -
		erinFundingAmount/2 - 1
	_, err := asTapd(charlie).BurnAsset(ctx, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: assetID1,
		},
		AmountToBurn:     burnAmount1,
		ConfirmationText: assetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	mineBlocks(t, net, 1, 1)

	burnAmount2 := mintedAssets[1].Amount - charlieFundingAmount/2 -
		erinFundingAmount/2 - 1
	_, err = asTapd(charlie).BurnAsset(ctx, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: assetID2,
		},
		AmountToBurn:     burnAmount2,
		ConfirmationText: assetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	mineBlocks(t, net, 1, 1)

	t.Logf("Opening asset channels...")

	net.EnsureConnected(t.t, charlie, dave)
	fundRespCD, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        charlieFundingAmount,
			GroupKey:           groupKey,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            pushSat,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", fundRespCD)

	net.EnsureConnected(t.t, erin, fabia)
	fundRespEF, err := asTapd(erin).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        erinFundingAmount,
			GroupKey:           groupKey,
			PeerPubkey:         fabia.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            pushSat,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Erin and Fabia: %v", fundRespEF)

	assertPendingChannels(
		t.t, charlie, mintedAssets[0], 1,
		charlieFundingAmount/2, 0,
	)
	assertPendingChannels(
		t.t, charlie, mintedAssets[1], 1,
		charlieFundingAmount/2, 0,
	)
	assertPendingChannels(
		t.t, erin, mintedAssets[0], 1, erinFundingAmount/2, 0,
	)
	assertPendingChannels(
		t.t, erin, mintedAssets[1], 1, erinFundingAmount/2, 0,
	)

	mineBlocks(t, net, 6, 2)

	var id1, id2 asset.ID
	copy(id1[:], assetID1)
	copy(id2[:], assetID2)

	fundingTree1, err := tapscript.NewChannelFundingScriptTreeUniqueID(id1)
	require.NoError(t.t, err)
	fundingScriptKeyBytes1 := fundingTree1.TaprootKey.SerializeCompressed()

	fundingTree2, err := tapscript.NewChannelFundingScriptTreeUniqueID(id2)
	require.NoError(t.t, err)
	fundingScriptKeyBytes2 := fundingTree2.TaprootKey.SerializeCompressed()

	assertBalance(
		t.t, charlie, charlieFundingAmount/2,
		itest.WithAssetID(assetID1),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes1),
	)
	assertBalance(
		t.t, charlie, charlieFundingAmount/2,
		itest.WithAssetID(assetID2),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes2),
	)
	assertBalance(
		t.t, erin, erinFundingAmount/2, itest.WithAssetID(assetID1),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes1),
	)
	assertBalance(
		t.t, erin, erinFundingAmount/2, itest.WithAssetID(assetID2),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithNumUtxos(1),
		itest.WithScriptKey(fundingScriptKeyBytes2),
	)

	assertBalance(
		t.t, charlie, 1, itest.WithAssetID(assetID1),
		itest.WithNumUtxos(1),
	)
	assertBalance(
		t.t, charlie, 1, itest.WithAssetID(assetID2),
		itest.WithNumUtxos(1),
	)

	assertBalance(t.t, erin, 0, itest.WithAssetID(assetID1))
	assertBalance(t.t, erin, 0, itest.WithAssetID(assetID2))

	assertUniverseProofExists(
		t.t, universe, assetID1, groupKey, fundingScriptKeyBytes1,
		fmt.Sprintf("%v:%v", fundRespCD.Txid, fundRespCD.OutputIndex),
	)
	assertUniverseProofExists(
		t.t, universe, assetID2, groupKey, fundingScriptKeyBytes2,
		fmt.Sprintf("%v:%v", fundRespCD.Txid, fundRespCD.OutputIndex),
	)
	assertUniverseProofExists(
		t.t, universe, assetID1, groupKey, fundingScriptKeyBytes1,
		fmt.Sprintf("%v:%v", fundRespEF.Txid, fundRespEF.OutputIndex),
	)
	assertUniverseProofExists(
		t.t, universe, assetID2, groupKey, fundingScriptKeyBytes2,
		fmt.Sprintf("%v:%v", fundRespEF.Txid, fundRespEF.OutputIndex),
	)

	assertAssetChan(
		t.t, charlie, dave, charlieFundingAmount, mintedAssets,
	)
	assertAssetChan(
		t.t, erin, fabia, erinFundingAmount, mintedAssets,
	)

	chanPointCD := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespCD.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespCD.Txid,
		},
	}
	chanPointEF := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespEF.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespEF.Txid,
		},
	}

	return chanPointCD, chanPointEF
}

// createTestMultiRFQAssetNetwork creates a multi-channel network topology for
// testing multi-RFQ functionality. The topology has Charlie at the center
// connected via BTC channels to Dave, Erin, Yara, and George, each of whom
// opens an asset channel to Fabia.
//
//nolint:lll
func createTestMultiRFQAssetNetwork(t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness, nodes multiRfqNodes,
	mintedAsset *taprpc.Asset, assetSendAmount, assetFundingAmount uint64,
	pushSat int64) {

	charlie := nodes.charlie.node
	dave := nodes.dave.node
	erin := nodes.erin.node
	fabia := nodes.fabia.node
	yara := nodes.yara.node
	george := nodes.george.node

	// Open normal sats channels between Charlie and the routing peers.
	_ = openChannelAndAssert(
		t, net, charlie, erin, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	_ = openChannelAndAssert(
		t, net, charlie, dave, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	_ = openChannelAndAssert(
		t, net, charlie, yara, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	_ = openChannelAndAssert(
		t, net, charlie, george, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)

	ctxb := context.Background()
	assetID := mintedAsset.AssetGenesis.AssetId
	var groupKey []byte
	if mintedAsset.AssetGroup != nil {
		groupKey = mintedAsset.AssetGroup.TweakedGroupKey
	}

	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptTreeBytes := fundingScriptKey.SerializeCompressed()

	courierAddr := fmt.Sprintf(
		"%s://%s", proof.UniverseRpcCourierType,
		charlie.RPCAddr(),
	)

	// Send assets to Dave, Erin, Yara, and George.
	recipients := []*itest.IntegratedNode{dave, erin, yara, george}
	for i, recipient := range recipients {
		addr, err := asTapd(recipient).NewAddr(
			ctxb, &taprpc.NewAddrRequest{
				Amt:              assetSendAmount,
				AssetId:          assetID,
				ProofCourierAddr: courierAddr,
			},
		)
		require.NoError(t.t, err)

		t.Logf("Sending %v asset units to %s...", assetSendAmount,
			recipient.Cfg.Name)

		itest.AssertAddrCreated(
			t.t, asTapd(recipient), mintedAsset, addr,
		)
		sendResp, err := asTapd(charlie).SendAsset(
			ctxb, &taprpc.SendAssetRequest{
				TapAddrs: []string{addr.Encoded},
			},
		)
		require.NoError(t.t, err)
		itest.ConfirmAndAssertOutboundTransfer(
			t.t, net.Miner.Client, asTapd(charlie), sendResp,
			assetID,
			[]uint64{
				mintedAsset.Amount -
					uint64(i+1)*assetSendAmount,
				assetSendAmount,
			}, i, i+1,
		)
		itest.AssertNonInteractiveRecvComplete(
			t.t, asTapd(recipient), 1,
		)
	}

	// Fund asset channels from each routing peer to Fabia.
	funders := []*itest.IntegratedNode{dave, erin, yara, george}
	for _, funder := range funders {
		net.EnsureConnected(t.t, funder, fabia)
		fundResp, err := asTapd(funder).FundChannel(
			ctxb, &tchrpc.FundChannelRequest{
				AssetAmount:        assetFundingAmount,
				AssetId:            assetID,
				PeerPubkey:         fabia.PubKey[:],
				FeeRateSatPerVbyte: 5,
				PushSat:            pushSat,
			},
		)
		require.NoError(t.t, err)
		t.Logf("Funded channel between %s and Fabia: %v",
			funder.Cfg.Name, fundResp)

		assertPendingChannels(
			t.t, funder, mintedAsset, 1, assetFundingAmount, 0,
		)
	}

	// Confirm all four channels.
	mineBlocks(t, net, 6, 4)

	// Assert balances.
	charlieAssetBalance := mintedAsset.Amount - 4*assetSendAmount
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID), itest.WithNumUtxos(1),
	)
	for _, recipient := range recipients {
		assertBalance(
			t.t, recipient, assetSendAmount-assetFundingAmount,
			itest.WithAssetID(assetID),
		)
	}

	// Assert universe proofs for all channels.
	for _, funder := range funders {
		// We need to get the funding outpoint from the channel.
		chans, err := funder.ListChannels(
			ctxb, &lnrpc.ListChannelsRequest{},
		)
		require.NoError(t.t, err)
		for _, ch := range chans.Channels {
			if ch.RemotePubkey == hex.EncodeToString(
				fabia.PubKey[:],
			) {

				assertUniverseProofExists(
					t.t, nodes.universeTap, assetID,
					groupKey, fundingScriptTreeBytes,
					ch.ChannelPoint,
				)
			}
		}
	}
}

// assertLNDInvoiceState polls for the given invoice state on the stream.
func assertLNDInvoiceState(t *testing.T,
	stream invoicesrpc.Invoices_SubscribeSingleInvoiceClient,
	expectedState lnrpc.Invoice_InvoiceState) {

	t.Helper()

	err := wait.NoError(func() error {
		inv, err := stream.Recv()
		if err != nil {
			return err
		}

		if inv.State != expectedState {
			return fmt.Errorf("expected state %v, got %v",
				expectedState, inv.State)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}
