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
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/stretchr/testify/require"
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

	t.Logf("Asset invoice: %v", ccToProtoJSON(t, invoice))

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

	t.Logf("Asset payment: %v", ccToProtoJSON(t, payment))

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

	timeoutSeconds := int64(wait.DefaultTimeout.Seconds())

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

	if cfg.errSubStr != "" {
		msg, err := stream.Recv()
		if err != nil {
			require.ErrorContains(t, err, cfg.errSubStr)

			return 0, rfqmath.BigIntFixedPoint{}
		}

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

		t.Logf("Received send event: %v", sendEvent.SendState)
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
		remoteCloseOut = closeUpdate.RemoteCloseOutput
		require.NotNil(t, remoteCloseOut)

		outIdx++
		require.EqualValues(
			t, remoteCloseOut.AmountSat-dummyAmt,
			closeTx.TxOut[outIdx].Value,
		)
	} else if remoteAssetBalance {
		remoteCloseOut = closeUpdate.RemoteCloseOutput
		require.NotNil(t, remoteCloseOut)
	}

	localCloseOut := closeUpdate.LocalCloseOutput
	require.NotNil(t, localCloseOut)
	outIdx++
	require.Greater(
		t, closeTx.TxOut[outIdx].Value,
		localCloseOut.AmountSat-dummyAmt,
	)

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

	// Fund channels.
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
