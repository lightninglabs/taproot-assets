package itest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// IntegratedNetworkHarness manages a set of IntegratedNodes for integration
// testing. It coordinates shared infrastructure such as chain backend
// configuration and node lifecycle.
type IntegratedNetworkHarness struct {
	t      *testing.T
	binary string

	// chainBackend provides the chain backend connection args that are
	// passed to each node's lnd instance (e.g. btcd RPC host/user/pass).
	chainBackend node.BackendConfig

	// netParams is the network parameters used by all nodes.
	netParams *chaincfg.Params

	// Miner is the btcd miner used for block generation and funding.
	Miner *miner.HarnessMiner

	// FeeServiceURL is the URL of an external fee estimation service.
	// When set, --fee.url=<url> is passed to each new node's lnd args so
	// the sweeper can obtain fee estimates for high conf targets that
	// btcd's built-in estimator cannot handle in regtest.
	FeeServiceURL string

	// activeNodes tracks all nodes managed by this harness, keyed by
	// node name.
	activeNodes map[string]*IntegratedNode
}

// NewIntegratedNetworkHarness creates a new network harness for integrated
// lnd+tapd node testing. The binary path should point to a compiled
// tapd-integrated-itest binary, and chainBackend provides the btcd (or other)
// connection arguments.
func NewIntegratedNetworkHarness(t *testing.T, binary string,
	chainBackend node.BackendConfig,
	netParams *chaincfg.Params) *IntegratedNetworkHarness {

	return &IntegratedNetworkHarness{
		t:            t,
		binary:       binary,
		chainBackend: chainBackend,
		netParams:    netParams,
		activeNodes:  make(map[string]*IntegratedNode),
	}
}

// NewNode creates, starts, and returns a new IntegratedNode. Chain backend
// connection args from the harness are automatically prepended to the node's
// lnd args so the caller only needs to pass test-specific overrides.
func (h *IntegratedNetworkHarness) NewNode(name string,
	extraLndArgs, extraTapdArgs []string) *IntegratedNode {

	h.t.Helper()

	// Get chain backend args (e.g. --bitcoin.node=btcd,
	// --btcd.rpchost=...) and merge with caller's extra args.
	chainArgs := h.chainBackend.GenArgs()
	lndArgs := append(chainArgs, extraLndArgs...)

	// If a fee service URL is configured, pass it to lnd so the web-based
	// fee estimator is used instead of btcd's limited built-in one.
	if h.FeeServiceURL != "" {
		lndArgs = append(lndArgs, "--fee.url="+h.FeeServiceURL)
	}

	n := NewIntegratedNode(
		h.t, name, h.binary, h.netParams, lndArgs, extraTapdArgs,
	)
	n.Start()

	h.activeNodes[name] = n

	return n
}

// TearDown stops all active nodes managed by this harness.
func (h *IntegratedNetworkHarness) TearDown() {
	h.t.Helper()

	for name, n := range h.activeNodes {
		h.t.Logf("Tearing down integrated node %s", name)
		n.Stop()
	}

	h.activeNodes = make(map[string]*IntegratedNode)
}

// ConnectNodes establishes a p2p connection from node a to node b. The
// function blocks until b appears in a's peer list or a timeout is reached.
func (h *IntegratedNetworkHarness) ConnectNodes(t *testing.T,
	a, b *IntegratedNode) {

	t.Helper()

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.DefaultTimeout,
	)
	defer cancel()

	req := &lnrpc.ConnectPeerRequest{
		Addr: &lnrpc.LightningAddress{
			Pubkey: b.PubKeyStr,
			Host:   b.P2PAddr(),
		},
	}

	_, err := a.ConnectPeer(ctx, req)
	require.NoErrorf(t, err, "unable to connect %s to %s",
		a.Cfg.Name, b.Cfg.Name)

	// Wait until b appears in a's peer list.
	err = wait.NoError(func() error {
		resp, err := a.ListPeers(
			ctx, &lnrpc.ListPeersRequest{},
		)
		if err != nil {
			return err
		}

		for _, peer := range resp.Peers {
			if peer.PubKey == b.PubKeyStr {
				return nil
			}
		}

		return fmt.Errorf("%s not found in %s's peer list",
			b.Cfg.Name, a.Cfg.Name)
	}, wait.DefaultTimeout)

	require.NoErrorf(t, err, "peers not connected within timeout: "+
		"%s -> %s", a.Cfg.Name, b.Cfg.Name)
}

// EnsureConnected ensures that nodes a and b are connected, tolerating the
// "already connected" error if they already have a connection and retrying
// if the server is still starting up.
func (h *IntegratedNetworkHarness) EnsureConnected(t *testing.T,
	a, b *IntegratedNode) {

	t.Helper()

	// Try connecting a -> b with retries for transient startup errors.
	req := &lnrpc.ConnectPeerRequest{
		Addr: &lnrpc.LightningAddress{
			Pubkey: b.PubKeyStr,
			Host:   b.P2PAddr(),
		},
	}

	err := wait.NoError(func() error {
		ctx, cancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer cancel()

		_, err := a.ConnectPeer(ctx, req)
		if err == nil {
			return nil
		}

		errStr := err.Error()

		// Already connected is fine.
		if strings.Contains(errStr, "already connected to peer") {
			return nil
		}

		// Server still starting up, retry.
		// nolint:lll
		if strings.Contains(errStr, "still in the process of starting") ||
			strings.Contains(errStr, "the RPC server is in the process of starting up") {

			return err
		}

		// Any other error is unexpected.
		return fmt.Errorf("unable to connect %s to %s: %w",
			a.Cfg.Name, b.Cfg.Name, err)
	}, wait.DefaultTimeout)

	require.NoError(t, err, "unable to connect %s to %s",
		a.Cfg.Name, b.Cfg.Name)

	// Wait until peers appear in each other's lists.
	findPeer := func(src, target *IntegratedNode) bool {
		ctx, cancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer cancel()

		resp, err := src.ListPeers(
			ctx, &lnrpc.ListPeersRequest{},
		)
		if err != nil {
			return false
		}

		for _, peer := range resp.Peers {
			if peer.PubKey == target.PubKeyStr {
				return true
			}
		}

		return false
	}

	err = wait.Predicate(func() bool {
		return findPeer(a, b) && findPeer(b, a)
	}, wait.DefaultTimeout)

	require.NoErrorf(t, err, "peers not connected within timeout: "+
		"%s <-> %s", a.Cfg.Name, b.Cfg.Name)
}

// SendCoins sends amt satoshis from the miner to the target node using a
// P2WKH address. 6 blocks are mined afterward for confirmation.
func (h *IntegratedNetworkHarness) SendCoins(t *testing.T,
	amt btcutil.Amount, target *IntegratedNode) {

	t.Helper()

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.DefaultTimeout,
	)
	defer cancel()

	// Get initial balance.
	initBal, err := target.WalletBalance(
		ctx, &lnrpc.WalletBalanceRequest{},
	)
	require.NoError(t, err)

	// Get new P2WKH address from target.
	addrResp, err := target.NewAddress(ctx, &lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	})
	require.NoError(t, err)

	addr, err := btcutil.DecodeAddress(addrResp.Address, h.netParams)
	require.NoError(t, err)

	addrScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Send from miner.
	output := &wire.TxOut{
		PkScript: addrScript,
		Value:    int64(amt),
	}
	_, err = h.Miner.SendOutputs([]*wire.TxOut{output}, 7500)
	require.NoErrorf(t, err, "unable to send coins to %s",
		target.Cfg.Name)

	// Mine 6 blocks for confirmation.
	_, err = h.Miner.Client.Generate(6)
	require.NoError(t, err, "unable to generate blocks")

	// Wait for confirmed balance to reflect the deposit.
	expectedBalance := btcutil.Amount(
		initBal.ConfirmedBalance+initBal.UnconfirmedBalance,
	) + amt

	err = wait.NoError(func() error {
		bal, err := target.WalletBalance(
			ctx, &lnrpc.WalletBalanceRequest{},
		)
		if err != nil {
			return err
		}

		if btcutil.Amount(bal.ConfirmedBalance) < expectedBalance {
			return fmt.Errorf("balance %d < expected %d",
				bal.ConfirmedBalance, expectedBalance)
		}

		return nil
	}, wait.DefaultTimeout)

	require.NoErrorf(t, err, "balance not updated for %s",
		target.Cfg.Name)
}

// OpenChannel opens a channel between srcNode and destNode with the given
// parameters. It waits for the "channel pending" notification and returns the
// open channel stream.
func (h *IntegratedNetworkHarness) OpenChannel(srcNode,
	destNode *IntegratedNode,
	p lntest.OpenChannelParams) (lnrpc.Lightning_OpenChannelClient,
	error) {

	// Use a background context for the stream — the returned stream's
	// lifetime extends beyond this function. Timeouts are handled via
	// time.After in the select below.
	ctx := context.Background()

	minConfs := int32(1)
	if p.SpendUnconfirmed {
		minConfs = 0
	}

	openReq := &lnrpc.OpenChannelRequest{
		NodePubkey:         destNode.PubKey[:],
		LocalFundingAmount: int64(p.Amt),
		PushSat:            int64(p.PushAmt),
		Private:            p.Private,
		MinConfs:           minConfs,
		SpendUnconfirmed:   p.SpendUnconfirmed,
		MinHtlcMsat:        int64(p.MinHtlc),
		RemoteMaxHtlcs:     uint32(p.RemoteMaxHtlcs),
		FundingShim:        p.FundingShim,
		SatPerVbyte:        uint64(p.SatPerVByte),
		CommitmentType:     p.CommitmentType,
	}

	respStream, err := srcNode.OpenChannel(ctx, openReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel between "+
			"%s and %s: %w", srcNode.Cfg.Name,
			destNode.Cfg.Name, err)
	}

	// Wait for the "channel pending" update.
	chanOpen := make(chan struct{})
	errChan := make(chan error)
	go func() {
		resp, err := respStream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		_, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
		if !ok {
			errChan <- fmt.Errorf("expected channel pending "+
				"update, instead got %v", resp)
			return
		}

		close(chanOpen)
	}()

	select {
	case <-time.After(wait.ChannelOpenTimeout):
		return nil, fmt.Errorf("timeout reached before chan pending " +
			"update sent")
	case err := <-errChan:
		return nil, err
	case <-chanOpen:
		return respStream, nil
	}
}

// WaitForChannelOpen waits for a "channel open" notification on the given
// stream and returns the channel point.
func (h *IntegratedNetworkHarness) WaitForChannelOpen(
	openChanStream lnrpc.Lightning_OpenChannelClient) (
	*lnrpc.ChannelPoint, error) {

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.ChannelOpenTimeout,
	)
	defer cancel()

	errChan := make(chan error)
	respChan := make(chan *lnrpc.ChannelPoint)
	go func() {
		resp, err := openChanStream.Recv()
		if err != nil {
			errChan <- fmt.Errorf("unable to read rpc resp: %w",
				err)
			return
		}
		fundingResp, ok :=
			resp.Update.(*lnrpc.OpenStatusUpdate_ChanOpen)
		if !ok {
			errChan <- fmt.Errorf("expected channel open "+
				"update, instead got %v", resp)
			return
		}

		respChan <- fundingResp.ChanOpen.ChannelPoint
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached while waiting for " +
			"channel open")
	case err := <-errChan:
		return nil, err
	case chanPoint := <-respChan:
		return chanPoint, nil
	}
}

// CloseChannel attempts to close the channel indicated by the passed channel
// point, initiated by the passed node. It returns the close channel stream
// and the close transaction hash.
func (h *IntegratedNetworkHarness) CloseChannel(lnNode *IntegratedNode,
	cp *lnrpc.ChannelPoint,
	force bool) (lnrpc.Lightning_CloseChannelClient, *chainhash.Hash,
	error) {

	// Use a background context for the stream — the returned stream's
	// lifetime extends beyond this function. The wait.NoError call below
	// provides the overall timeout.
	ctx := context.Background()

	var (
		closeRespStream lnrpc.Lightning_CloseChannelClient
		closeTxid       *chainhash.Hash
	)

	err := wait.NoError(func() error {
		closeReq := &lnrpc.CloseChannelRequest{
			ChannelPoint: cp,
			Force:        force,
		}
		if !force {
			closeReq.SatPerVbyte = 5
		}

		var err error
		closeRespStream, err = lnNode.CloseChannel(ctx, closeReq)
		if err != nil {
			return fmt.Errorf("unable to close channel: %w",
				err)
		}

		// Consume the "close pending" update.
		closeResp, err := closeRespStream.Recv()
		if err != nil {
			return fmt.Errorf("unable to recv from close "+
				"stream: %w", err)
		}

		pendingClose, ok :=
			closeResp.Update.(*lnrpc.CloseStatusUpdate_ClosePending)
		if !ok {
			return fmt.Errorf("expected close pending update, "+
				"instead got %v", closeResp)
		}

		closeTxid, err = chainhash.NewHash(
			pendingClose.ClosePending.Txid,
		)
		if err != nil {
			return fmt.Errorf("unable to decode closeTxid: "+
				"%v", err)
		}

		h.Miner.AssertTxInMempool(*closeTxid)

		return nil
	}, wait.ChannelCloseTimeout)
	if err != nil {
		return nil, nil, err
	}

	return closeRespStream, closeTxid, nil
}

// WaitForChannelClose waits for a "channel close" notification on the given
// stream and returns the close update.
func (h *IntegratedNetworkHarness) WaitForChannelClose(
	stream lnrpc.Lightning_CloseChannelClient) (
	*lnrpc.ChannelCloseUpdate, error) {

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.ChannelCloseTimeout,
	)
	defer cancel()

	errChan := make(chan error)
	updateChan := make(chan *lnrpc.CloseStatusUpdate_ChanClose)
	go func() {
		closeResp, err := stream.Recv()
		if err != nil {
			errChan <- err
			return
		}

		closeFin, ok :=
			closeResp.Update.(*lnrpc.CloseStatusUpdate_ChanClose)
		if !ok {
			errChan <- fmt.Errorf("expected channel close "+
				"update, instead got %v", closeResp)
			return
		}

		updateChan <- closeFin
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before channel " +
			"close update sent")
	case err := <-errChan:
		return nil, err
	case update := <-updateChan:
		return update.ChanClose, nil
	}
}

// AssertChannelExists asserts that an active channel identified by the
// specified channel point exists from the point-of-view of the node. It takes
// an optional set of check functions which can be used to make further
// assertions using the channel's values.
func (h *IntegratedNetworkHarness) AssertChannelExists(
	node *IntegratedNode, chanPoint *wire.OutPoint,
	checks ...func(*lnrpc.Channel)) error {

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.DefaultTimeout,
	)
	defer cancel()

	return wait.NoError(func() error {
		resp, err := node.ListChannels(
			ctx, &lnrpc.ListChannelsRequest{},
		)
		if err != nil {
			return fmt.Errorf("unable to fetch channels: %w",
				err)
		}

		for _, channel := range resp.Channels {
			if channel.ChannelPoint == chanPoint.String() {
				if !channel.Active {
					return fmt.Errorf("channel "+
						"%s inactive", chanPoint)
				}

				for _, check := range checks {
					check(channel)
				}

				return nil
			}
		}

		return fmt.Errorf("channel %s not found", chanPoint)
	}, wait.DefaultTimeout)
}

// AssertNodeKnown asserts that node knows about target in the network graph.
func (h *IntegratedNetworkHarness) AssertNodeKnown(node,
	target *IntegratedNode) error {

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.DefaultTimeout,
	)
	defer cancel()

	req := &lnrpc.NodeInfoRequest{
		PubKey: target.PubKeyStr,
	}

	return wait.NoError(func() error {
		info, err := node.GetNodeInfo(ctx, req)
		if err != nil {
			return err
		}

		if info.Node == nil {
			return fmt.Errorf("node %s has no info about %s",
				node.Cfg.Name, target.Cfg.Name)
		}

		return nil
	}, wait.DefaultTimeout)
}

// LookUpNodeByPub finds an active node by its hex-encoded public key.
func (h *IntegratedNetworkHarness) LookUpNodeByPub(
	pub string) (*IntegratedNode, error) {

	for _, n := range h.activeNodes {
		if n.PubKeyStr == pub {
			return n, nil
		}
	}

	return nil, fmt.Errorf("node with pubkey %s not found", pub)
}
