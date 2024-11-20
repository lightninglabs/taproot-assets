package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// CustomChannelRemoteReserve is the custom channel minimum remote
	// reserve that we'll use for our channels.
	CustomChannelRemoteReserve = 1062
)

// LndPbstChannelFunder is an implementation of the tapchannel.ChannelFunder
// interface that uses lnd to carry out the PSBT funding process.
type LndPbstChannelFunder struct {
	lnd *lndclient.LndServices
}

// NewLndPbstChannelFunder creates a new LndPbstChannelFunder instance.
func NewLndPbstChannelFunder(lnd *lndclient.LndServices) *LndPbstChannelFunder {
	return &LndPbstChannelFunder{
		lnd: lnd,
	}
}

// assetChanIntent is a concrete implementation of the
// tapchannel.AssetChanIntent.
type assetChanIntent struct {
	psbtTemplate *psbt.Packet

	lnd *lndclient.LndServices

	tempPID funding.PendingChanID
}

// FundingPsbt is the original PsbtTemplate, plus the P2TR funding output
// that'll create the channel.
func (a *assetChanIntent) FundingPsbt() (*psbt.Packet, error) {
	return a.psbtTemplate, nil
}

// BindPsbt accepts a new *unsigned* PSBT with any additional inputs or outputs
// (for change) added. This PSBT is still unsigned. This step performs final
// verification to ensure the PSBT is crafted in a manner that'll properly open
// the channel once broadcaster.
func (a *assetChanIntent) BindPsbt(ctx context.Context,
	finalPSBT *psbt.Packet) error {

	var psbtBuf bytes.Buffer
	if err := finalPSBT.Serialize(&psbtBuf); err != nil {
		return fmt.Errorf("unable to serialize base PSBT: %w", err)
	}

	_, err := a.lnd.Client.FundingStateStep(
		ctx, &lnrpc.FundingTransitionMsg{
			Trigger: &lnrpc.FundingTransitionMsg_PsbtVerify{
				PsbtVerify: &lnrpc.FundingPsbtVerify{
					PendingChanId: a.tempPID[:],
					FundedPsbt:    psbtBuf.Bytes(),
					SkipFinalize:  true,
				},
			},
		},
	)
	return err
}

// OpenChannel attempts to open a new asset holding private channel using the
// backing lnd node. The PSBT flow is by default. An AssetChanIntent is
// returned that includes the updated PSBT template that includes the funding
// output. Once all other inputs+outputs have been added, then BindPsbt should
// be called to progress the funding process. Afterward, the funding
// transaction should be signed+broadcast.
//
// NOTE: This is part of the tapchannel.ChannelFunder interface.
func (l *LndPbstChannelFunder) OpenChannel(ctx context.Context,
	req tapchannel.OpenChanReq) (tapchannel.AssetChanIntent, error) {

	var psbtBuf bytes.Buffer
	if req.PsbtTemplate != nil {
		err := req.PsbtTemplate.Serialize(&psbtBuf)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize base "+
				"PSBT: %w", err)
		}
	}

	// We'll map our high level params into a request for a: private,
	// taproot channel, that uses the PSBT funding flow.
	taprootCommitType := lnrpc.CommitmentType_SIMPLE_TAPROOT_OVERLAY
	channelOpenOptions := []lndclient.OpenChannelOption{
		lndclient.WithCommitmentType(&taprootCommitType),
		lndclient.WithFundingShim(&lnrpc.FundingShim{
			Shim: &lnrpc.FundingShim_PsbtShim{
				PsbtShim: &lnrpc.PsbtShim{
					PendingChanId: req.TempPID[:],
					NoPublish:     true,
					BasePsbt:      psbtBuf.Bytes(),
				},
			},
		}),
		lndclient.WithRemoteReserve(CustomChannelRemoteReserve),
	}

	// Limit the number of HTLCs that can be added to the channel by the
	// remote party.
	if req.RemoteMaxHtlc > 0 {
		channelOpenOptions = append(
			channelOpenOptions,
			lndclient.WithRemoteMaxHtlc(req.RemoteMaxHtlc),
		)
	}

	openChanStream, errChan, err := l.lnd.Client.OpenChannelStream(
		ctx, route.NewVertex(&req.PeerPub), req.ChanAmt, req.PushAmt,
		true, channelOpenOptions...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel with "+
			"lnd: %w", err)
	}

	// With our request extended, we'll now wait for the initial response
	// sent after the responder sends AcceptChannel.
	select {
	case resp := <-openChanStream:
		// Assert that we have a PSBT response from the node.
		if resp.PsbtFund == nil {
			return nil, fmt.Errorf("expected PSBT funding response")
		}

		fundingPSBT, err := psbt.NewFromRawBytes(
			bytes.NewReader(resp.PsbtFund.Psbt), false,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse PSBT: %w", err)
		}

		return &assetChanIntent{
			psbtTemplate: fundingPSBT,
			lnd:          l.lnd,
			tempPID:      req.TempPID,
		}, nil

	case err := <-errChan:
		return nil, err
	}
}

// ChannelAcceptor is used to accept and potentially influence parameters of
// incoming channels.
func (l *LndPbstChannelFunder) ChannelAcceptor(ctx context.Context,
	acceptor lndclient.AcceptorFunction) (chan error, error) {

	return l.lnd.Client.ChannelAcceptor(
		ctx, tapchannel.DefaultTimeout/2, acceptor,
	)
}

// A compile-time check to ensure that LndPbstChannelFunder fully implements
// the tapchannel.PsbtChannelFunder interface.
var _ tapchannel.PsbtChannelFunder = (*LndPbstChannelFunder)(nil)
