// This file contains the monitor. Quote checks guard what the pilot
// offers; the monitor watches what actually happens. Every 30 seconds
// it reads settled swaps from tapd and channel balances from lnd, with
// read-only macaroons, and sets the breaker's level. The ideas it
// illustrates:
//
//   - Trade edge. Trading at our own spread should never lose against
//     the reference price. A negative edge over an hour means
//     mispricing or a peer exploiting stale quotes, whatever the cause.
//   - Inventory floors. When one side of the inventory runs low,
//     trading continues on the other side only.
//   - A failed read is a signal too, and degrades trading.
//
// The edge window starts when the pilot starts, so a restart forgets
// losses settled before it. A production pilot would persist its record
// of losses, or count the full window on startup.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// monitorInterval is the interval between checks.
	monitorInterval = 30 * time.Second

	// edgeWindow is the window over which trade edge is summed.
	edgeWindow = time.Hour

	// pageSize is the number of swaps fetched per call.
	pageSize = 500

	// checkTimeout bounds the calls to tapd and lnd in one check.
	checkTimeout = 10 * time.Second
)

// forwardLister is the part of tapd's RFQ client the monitor uses. The
// call needs the rfq:read permission.
type forwardLister interface {
	ForwardingHistory(context.Context, *rfqrpc.ForwardingHistoryRequest,
		...grpc.CallOption) (*rfqrpc.ForwardingHistoryResponse, error)
}

// channelLister is the part of lnd's client the monitor uses. The calls
// need the offchain:read permission.
type channelLister interface {
	ListChannels(context.Context, *lnrpc.ListChannelsRequest,
		...grpc.CallOption) (*lnrpc.ListChannelsResponse, error)
	ChannelBalance(context.Context, *lnrpc.ChannelBalanceRequest,
		...grpc.CallOption) (*lnrpc.ChannelBalanceResponse, error)
}

// monitor checks the node's settled swaps and balances every
// monitorInterval, and sets the breaker's level:
//
//   - Trade edge. Each settled swap of the asset is valued at the
//     reference rate when the monitor first sees it, at most one
//     interval after settlement. A sale earns the BTC received less the
//     asset given, a purchase the asset received less the BTC paid. A
//     sum over edgeWindow below -maxLoss halts trading, below
//     -maxLoss/2 degrades it.
//   - Inventory floors. A local asset balance below minAsset degrades
//     trading and blocks buy requests, which would send more of the
//     asset out. A local BTC balance below minBTC degrades trading and
//     blocks sell requests, which would send more BTC out.
//
// A failed check degrades trading. A nil client disables its checks,
// as does a zero limit.
type monitor struct {
	tapd forwardLister
	lnd  channelLister

	pilot   *pilot
	breaker *breaker

	// maxLoss, minAsset and minBTC are in asset units, asset units and
	// msat.
	maxLoss  uint64
	minAsset uint64
	minBTC   uint64

	// since is the earliest settlement time counted. It starts when the
	// pilot starts. Resuming after a halt moves it to the time of
	// resumption, so swaps that led to the halt are not counted again.
	since time.Time

	// halted is true if the last check found trading halted.
	halted bool

	// edges maps each counted swap to its settlement time and edge.
	edges map[string]swapEdge
}

// swapEdge is the edge of a settled swap, in asset units.
type swapEdge struct {
	at    time.Time
	units *big.Int
}

// dialNode connects to a tapd or lnd RPC server, verifying its TLS
// certificate and sending the macaroon with every call.
func dialNode(addr, certPath, macPath string) (*grpc.ClientConn, error) {
	creds, err := credentials.NewClientTLSFromFile(certPath, "")
	if err != nil {
		return nil, err
	}

	mac, err := rfq.NewMacaroonDialOption(macPath)
	if err != nil {
		return nil, err
	}

	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds), mac)
}

// run checks every monitorInterval until the context is cancelled.
func (m *monitor) run(ctx context.Context) {
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	for {
		m.check(ctx)

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// check runs the checks and sets the breaker's level.
func (m *monitor) check(ctx context.Context) {
	// Checks pause while halted. Resuming starts a fresh trade edge
	// window.
	if m.breaker.halted() {
		m.halted = true
		return
	}
	if m.halted {
		m.halted = false
		m.since = time.Now()
		clear(m.edges)
	}

	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	var (
		reasons             []string
		blockBuy, blockSell bool
	)

	if m.tapd != nil && m.maxLoss > 0 {
		sum, err := m.tradeEdge(ctx)
		halt := new(big.Int).Neg(new(big.Int).SetUint64(m.maxLoss))
		degrade := new(big.Int).Quo(halt, big.NewInt(2))

		switch {
		case err != nil:
			reasons = append(reasons, fmt.Sprintf("trade edge "+
				"unknown: %v", err))

		case sum.Cmp(halt) < 0:
			m.breaker.trip(fmt.Sprintf("trade edge of %v units "+
				"over %v", sum, edgeWindow))
			return

		case sum.Cmp(degrade) < 0:
			reasons = append(reasons, fmt.Sprintf("trade edge of "+
				"%v units over %v", sum, edgeWindow))
		}
	}

	if m.lnd != nil {
		assetBal, btcBal, err := m.balances(ctx)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("balances "+
				"unknown: %v", err))
		}
		if err == nil && assetBal < m.minAsset {
			blockBuy = true
			reasons = append(reasons, fmt.Sprintf("asset balance "+
				"%d below %d units", assetBal, m.minAsset))
		}
		if err == nil && btcBal < m.minBTC {
			blockSell = true
			reasons = append(reasons, fmt.Sprintf("BTC balance %d "+
				"below %d msat", btcBal, m.minBTC))
		}
	}

	m.breaker.setDegraded(strings.Join(reasons, "; "), blockBuy, blockSell)
}

// tradeEdge values swaps of the asset settled since the later of since
// and the start of the window, and returns the sum of edges within the
// window.
func (m *monitor) tradeEdge(ctx context.Context) (*big.Int, error) {
	ref, err := m.pilot.referenceRate()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	from := now.Add(-edgeWindow)
	if m.since.After(from) {
		from = m.since
	}

	for offset := int32(0); ; offset += pageSize {
		resp, err := m.tapd.ForwardingHistory(
			ctx, &rfqrpc.ForwardingHistoryRequest{
				MinTimestamp:   uint64(from.Unix()),
				AssetSpecifier: m.pilot.rfqSpecifier(),
				Limit:          pageSize,
				Offset:         offset,
			},
		)
		if err != nil {
			return nil, err
		}

		for _, f := range resp.GetForwards() {
			key := fmt.Sprintf("%x/%d/%d", f.GetRfqId(),
				f.GetChanIdIn(), f.GetHtlcId())
			_, seen := m.edges[key]
			settled := f.GetSettledAt() != 0 && f.GetFailedAt() == 0
			if seen || !settled {
				continue
			}

			e := swapEdge{
				at:    time.Unix(int64(f.GetSettledAt()), 0),
				units: forwardEdge(f, ref),
			}
			m.edges[key] = e
			log.Printf("Swap settled: rfq_id=%x %v edge=%v units",
				f.GetRfqId(), f.GetPolicyType(), e.units)
		}

		if len(resp.GetForwards()) < pageSize {
			break
		}
	}

	sum := new(big.Int)
	for key, e := range m.edges {
		if e.at.Before(now.Add(-edgeWindow)) {
			delete(m.edges, key)
			continue
		}
		sum.Add(sum, e.units)
	}

	return sum, nil
}

// forwardEdge returns the edge of a swap in asset units, valuing its BTC
// leg at the reference rate.
func forwardEdge(f *rfqrpc.ForwardingEvent,
	ref rfqmath.BigIntFixedPoint) *big.Int {

	toUnits := func(msat uint64) *big.Int {
		units := rfqmath.MilliSatoshiToUnits(
			lnwire.MilliSatoshi(msat), ref,
		).ScaleTo(0)

		return new(big.Int).SetBytes(units.Coefficient.Bytes())
	}

	asset := new(big.Int).SetUint64(f.GetAssetAmt())

	// In a sale we receive BTC on the incoming channel and send the
	// asset. In a purchase we receive the asset and send BTC on the
	// outgoing channel.
	if f.GetPolicyType() == rfqrpc.RfqPolicyType_RFQ_POLICY_TYPE_SALE {
		return asset.Sub(toUnits(f.GetAmtInMsat()), asset)
	}

	return asset.Sub(asset, toUnits(f.GetAmtOutMsat()))
}

// balances returns the local balance of the asset across the node's
// asset channels, in asset units, and the node's local BTC balance
// across all channels, in msat.
func (m *monitor) balances(ctx context.Context) (uint64, uint64, error) {
	chans, err := m.lnd.ListChannels(ctx, &lnrpc.ListChannelsRequest{})
	if err != nil {
		return 0, 0, err
	}

	var assetBal uint64
	for _, c := range chans.GetChannels() {
		if len(c.GetCustomChannelData()) == 0 {
			continue
		}

		var data rfqmsg.JsonAssetChannel
		err := json.Unmarshal(c.GetCustomChannelData(), &data)
		if err != nil {
			return 0, 0, err
		}

		assetBal += m.pilot.assetBalance(&data)
	}

	bal, err := m.lnd.ChannelBalance(ctx, &lnrpc.ChannelBalanceRequest{})
	if err != nil {
		return 0, 0, err
	}

	return assetBal, bal.GetLocalBalance().GetMsat(), nil
}
