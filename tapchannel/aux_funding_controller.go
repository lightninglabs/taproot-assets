package tapchannel

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnwire"
)

// ErrorReporter is used to report an error back to the caller and/or peer that
// we're communicating with.
type ErrorReporter interface {
	// ReportError reports an error that occurred during the funding
	// process.
	ReportError(ctx context.Context, peer btcec.PublicKey,
		pid funding.PendingChanID, err error)
}

// PeerMessenger is an interface that allows us to send messages to a remote LN
// peer.
type PeerMessenger interface {
	// SendMessage sends a message to a remote peer.
	SendMessage(ctx context.Context, peer btcec.PublicKey,
		msg lnwire.Message) error
}

// OpenChanReq is a request to open a new asset channel with a remote peer.
type OpenChanReq struct {
	// ChanAmt is the amount of BTC to put into the channel. Some BTC is
	// required atm to pay on chain fees for the channel. Note that
	// additional fees can be added in the event of a force close by using
	// CPFP with the channel anchor outputs.
	ChanAmt btcutil.Amount

	// PeerPub is the identity public key of the remote peer we wish to
	// open the channel with.
	PeerPub btcec.PublicKey

	// TempPID is the temporary channel ID to use for this channel.
	TempPID funding.PendingChanID

	// PsbtTemplate is the PSBT template that we'll use to fund the channel.
	// This should already have all the inputs spending asset UTXOs added.
	PsbtTemplate *psbt.Packet
}

// AssetChanIntent is a handle returned by the PsbtChannelFunder that can be
// used to drive the new asset channel to completion. The intent includes the
// PSBT template returned by lnd which has the funding output for the new
// channel already populated.
type AssetChanIntent interface {
	// FundingPsbt is the original PsbtTemplate, plus the P2TR funding
	// output that'll create the channel.
	FundingPsbt() (*psbt.Packet, error)

	// BindPsbt accepts a new *unsigned* PSBT with any additional inputs or
	// outputs (for change) added. This PSBT is still unsigned. This step
	// performs final verification to ensure the PSBT is crafted in a manner
	// that'll properly open the channel once broadcaster.
	BindPsbt(context.Context, *psbt.Packet) error
}

// PsbtChannelFunder is an interface that abstracts the necessary steps needed
// fund a PSBT channel on using lnd.
type PsbtChannelFunder interface {
	// OpenChannel attempts to open a new asset holding private channel
	// using the backing lnd node. The PSBT flow is by default. An
	// AssetChanIntent is returned that includes the updated PSBT template
	// that includes the funding output. Once all other inputs+outputs have
	// been added, then BindPsbt should be called to progress the funding
	// process. Afterward, the funding transaction should be signed and
	// broadcast.
	OpenChannel(context.Context, OpenChanReq) (AssetChanIntent, error)
}
