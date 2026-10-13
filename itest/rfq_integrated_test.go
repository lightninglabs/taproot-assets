//go:build itest

package itest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// rfqIntegratedScenario runs the RFQ test peers with actual asset channels.
type rfqIntegratedScenario struct {
	AliceLnd, BobLnd, CarolLnd       *rfqIntegratedPeer
	AliceTapd, BobTapd, CarolTapd    *IntegratedNode
	AliceBobChannel, BobCarolChannel *lnrpc.ChannelPoint
	net                              *IntegratedNetworkHarness
}

// rfqIntegratedPeer retains the small set of lntest RPC conveniences used by
// the manual SendToRoute scenario while running against an integrated node.
type rfqIntegratedPeer struct {
	PubKey [33]byte
	RPC    *rfqIntegratedRPC
}

type rfqIntegratedRPC struct {
	t *testing.T
	n *IntegratedNode
}

func (r *rfqIntegratedRPC) AddInvoice(req *lnrpc.Invoice) *lnrpc.AddInvoiceResponse {
	r.t.Helper()
	resp, err := r.n.LightningClient.AddInvoice(context.Background(), req)
	require.NoError(r.t, err)
	return resp
}

func (r *rfqIntegratedRPC) LookupInvoice(hash []byte) *lnrpc.Invoice {
	r.t.Helper()
	resp, err := r.n.LightningClient.LookupInvoice(
		context.Background(), &lnrpc.PaymentHash{RHash: hash},
	)
	require.NoError(r.t, err)
	return resp
}

func (r *rfqIntegratedRPC) DecodePayReq(paymentRequest string) *lnrpc.PayReq {
	r.t.Helper()
	resp, err := r.n.LightningClient.DecodePayReq(
		context.Background(), &lnrpc.PayReqString{PayReq: paymentRequest},
	)
	require.NoError(r.t, err)
	return resp
}

func (r *rfqIntegratedRPC) BuildRoute(req *routerrpc.BuildRouteRequest) *routerrpc.BuildRouteResponse {
	r.t.Helper()
	var resp *routerrpc.BuildRouteResponse
	err := wait.NoError(func() error {
		var err error
		resp, err = r.n.RouterClient.BuildRoute(context.Background(), req)
		return err
	}, wait.DefaultTimeout)
	require.NoError(r.t, err)
	return resp
}

func (r *rfqIntegratedRPC) SendToRouteV2(req *routerrpc.SendToRouteRequest) *lnrpc.HTLCAttempt {
	r.t.Helper()
	resp, err := r.n.RouterClient.SendToRouteV2(context.Background(), req)
	require.NoError(r.t, err)
	return resp
}

func rfqPeer(t *testing.T, n *IntegratedNode) *rfqIntegratedPeer {
	return &rfqIntegratedPeer{
		PubKey: n.PubKey,
		RPC:    &rfqIntegratedRPC{t: t, n: n},
	}
}

// rfqIntegratedTapd separates the overlapping Lightning and tapd RPC client
// interfaces for the existing mint helper.
type rfqIntegratedTapd struct {
	taprpc.TaprootAssetsClient
	wrpc.AssetWalletClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	tchrpc.TaprootAssetChannelsClient
	unirpc.UniverseClient
	tapdevrpc.TapDevClient
	authmailboxrpc.MailboxClient
}

func rfqTapd(n *IntegratedNode) *rfqIntegratedTapd {
	return &rfqIntegratedTapd{
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

func newRfqIntegratedScenario(t *harnessTest, opts ...RfqOption) *rfqIntegratedScenario {
	t.t.Helper()
	options := DefaultRfqOptions()
	for _, opt := range opts {
		opt(&options)
	}
	// The backend cleanup archives logs even when a test aborts early.
	logDir := filepath.Join(node.GetLogDir(), ".backendlogs",
		miner.HarnessNetParams.Name)
	require.NoError(t.t, os.MkdirAll(logDir, 0750))

	backend, cleanup, err := lntest.NewBackend(
		t.lndHarness.Miner().P2PAddress(), miner.HarnessNetParams,
	)
	require.NoError(t.t, err)
	require.NoError(t.t, backend.ConnectMiner())
	t.t.Cleanup(func() {
		require.NoError(t.t, cleanup())
		// The outer lnd harness still archives this shared log path.
		require.NoError(t.t, os.MkdirAll(logDir, 0750))
	})

	net := NewIntegratedNetworkHarness(
		t.t, "./tapd-integrated-itest", backend, miner.HarnessNetParams,
	)
	t.t.Cleanup(net.TearDown)
	net.Miner = t.lndHarness.Miner()
	lndArgs := []string{
		"--protocol.anchors", "--protocol.option-scid-alias",
		"--protocol.zero-conf", "--protocol.simple-taproot-chans",
		"--protocol.simple-taproot-overlay-chans",
		"--protocol.custom-message=17", "--rpcmiddleware.enable",
		"--trickledelay=50", "--gossip.sub-batch-delay=5ms",
	}
	tapdArgs := []string{
		"--allow-public-uni-proof-courier", "--universe.public-access=rw",
		"--universe.sync-all-assets", "--reorgsafedepth=1",
	}
	oracleFor := func(override string) string {
		if override != "" {
			return override
		}
		return options.oracleServerAddr
	}
	pilotFor := func(override string) string {
		if override != "" {
			return override
		}
		return options.pilotServerAddr
	}
	argsFor := func(oracle, pilot string) []string {
		args := append([]string{}, tapdArgs...)
		args = append(args, "--experimental.rfq.sendpricehint",
			"--experimental.rfq.acceptpricedeviationppm=50000")
		if oracle != "" {
			args = append(args, "--experimental.rfq.priceoracleaddress="+oracle,
				"--experimental.rfq.tls.insecure")
		}
		if pilot != "" {
			args = append(args, "--experimental.rfq.portfoliopilotaddress="+pilot)
		}
		return args
	}
	alicePort := port.NextAvailablePort()
	aliceArgs := append(append([]string{}, lndArgs...),
		fmt.Sprintf("--rpclisten=127.0.0.1:%d", alicePort))
	courier := fmt.Sprintf("--proofcourieraddr=%s://127.0.0.1:%d",
		proof.UniverseRpcCourierType, alicePort)
	alice := net.NewNode("RFQ-Alice", aliceArgs, append(argsFor(
		oracleFor(options.oracleServerAlice), pilotFor(options.pilotServerAlice),
	), courier))
	bob := net.NewNode("RFQ-Bob", lndArgs, append(argsFor(
		oracleFor(options.oracleServerBob), pilotFor(options.pilotServerBob),
	), courier))
	carol := net.NewNode("RFQ-Carol", lndArgs, append(argsFor(
		oracleFor(options.oracleServerCarol), pilotFor(options.pilotServerCarol),
	), courier))
	for _, n := range []*IntegratedNode{alice, bob, carol} {
		net.SendCoins(t.t, btcutil.SatoshiPerBitcoin, n)
	}
	net.EnsureConnected(t.t, alice, bob)
	net.EnsureConnected(t.t, bob, carol)
	// The BTC channels preserve the missing-asset-channel admission case
	// and give the intercept test its Bob -> Carol payment hop.
	openBTC := func(a, b *IntegratedNode) *lnrpc.ChannelPoint {
		t.t.Helper()
		stream, err := net.OpenChannel(a, b, lntest.OpenChannelParams{
			Amt: 300000, CommitmentType: lnrpc.CommitmentType_ANCHORS,
		})
		require.NoError(t.t, err)
		_, err = WaitForNTxsInMempool(net.Miner, 1, wait.MinerMempoolTimeout)
		require.NoError(t.t, err)
		for i := 0; i < 6; i++ {
			net.Miner.GenerateBlocks(1)
			time.Sleep(20 * time.Millisecond)
		}
		point, err := net.WaitForChannelOpen(stream)
		require.NoError(t.t, err)
		hash, err := lnrpc.GetChanPointFundingTxid(point)
		require.NoError(t.t, err)
		outpoint := &wire.OutPoint{Hash: *hash, Index: point.OutputIndex}
		require.NoError(t.t, net.AssertChannelExists(a, outpoint))
		require.NoError(t.t, net.AssertChannelExists(b, outpoint))
		return point
	}
	openBTC(alice, bob)
	bobCarol := openBTC(bob, carol)
	return &rfqIntegratedScenario{
		AliceLnd: rfqPeer(t.t, alice), BobLnd: rfqPeer(t.t, bob),
		CarolLnd: rfqPeer(t.t, carol), AliceTapd: alice, BobTapd: bob,
		CarolTapd: carol, BobCarolChannel: bobCarol, net: net,
	}
}

// fundAliceBobAssetChannel opens a backed asset channel and confirms that both
// endpoints see it active, with Bob holding the expected remote balance.
func (s *rfqIntegratedScenario) fundAliceBobAssetChannel(t *testing.T,
	assetID []byte, amounts ...uint64) {

	t.Helper()
	ctx := context.Background()
	amount := uint64(5000)
	if len(amounts) > 0 {
		amount = amounts[0]
	}
	// Bob must learn the genesis proof before it can verify the incoming
	// channel funding protocol.
	SyncUniverses(
		ctx, t, rfqTapd(s.BobTapd), rfqTapd(s.AliceTapd),
		s.AliceTapd.RPCAddr(), wait.DefaultTimeout,
	)
	resp, err := s.AliceTapd.FundChannel(ctx, &tchrpc.FundChannelRequest{
		AssetAmount: amount, AssetId: assetID,
		PeerPubkey: s.BobLnd.PubKey[:], FeeRateSatPerVbyte: 5,
	})
	require.NoError(t, err)
	_, err = WaitForNTxsInMempool(
		s.net.Miner, 1, wait.MinerMempoolTimeout,
	)
	require.NoError(t, err)
	for i := 0; i < 6; i++ {
		s.net.Miner.GenerateBlocks(1)
		time.Sleep(20 * time.Millisecond)
	}
	point := &lnrpc.ChannelPoint{
		OutputIndex: uint32(resp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: resp.Txid,
		},
	}
	s.AliceBobChannel = point
	txid, err := chainhash.NewHashFromStr(resp.Txid)
	require.NoError(t, err)
	outpoint := &wire.OutPoint{Hash: *txid, Index: uint32(resp.OutputIndex)}
	require.NoError(t, wait.NoError(func() error {
		return s.net.AssertChannelExists(s.AliceTapd, outpoint)
	}, wait.DefaultTimeout))
	require.NoError(t, wait.NoError(func() error {
		return s.net.AssertChannelExists(s.BobTapd, outpoint)
	}, wait.DefaultTimeout))
	require.NoError(t, wait.NoError(func() error {
		balance, err := s.BobTapd.LightningClient.ChannelBalance(
			ctx, &lnrpc.ChannelBalanceRequest{},
		)
		if err != nil {
			return err
		}
		var assets rfqmsg.JsonAssetChannelBalances
		if err := json.Unmarshal(balance.CustomChannelData, &assets); err != nil {
			return err
		}
		got := assets.OpenChannels[hex.EncodeToString(assetID)].RemoteBalance
		if got != amount {
			return fmt.Errorf(
				"Bob's remote asset balance: got %d, want %d",
				got, amount,
			)
		}
		return nil
	}, wait.DefaultTimeout))
}
