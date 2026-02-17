package integration

import (
	"context"
	"fmt"

	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightningnetwork/lnd"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chancloser"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/lightningnetwork/lnd/sweep"
)

// BuildAuxComponents creates the lnd.AuxComponents struct from a running tapd
// Server. This enables lnd to handle custom Taproot Asset channels by
// delegating aux operations to tapd's implementations.
//
// The returned cleanup function stops the internal message router and should be
// called when the node shuts down.
func BuildAuxComponents(ctx context.Context,
	tapServer *taprootassets.Server) (*lnd.AuxComponents, func(), error) {

	if tapServer == nil {
		return nil, nil, fmt.Errorf("tapd server must not be nil")
	}

	router := msgmux.NewMultiMsgRouter()
	router.Start(ctx)

	err := router.RegisterEndpoint(tapServer)
	if err != nil {
		router.Stop()

		return nil, nil, fmt.Errorf("error registering tapd "+
			"endpoint: %w", err)
	}

	cleanup := func() {
		router.Stop()
	}

	return &lnd.AuxComponents{
		AuxLeafStore: fn.Some[lnwallet.AuxLeafStore](tapServer),
		MsgRouter:    fn.Some[msgmux.Router](router),
		AuxFundingController: fn.Some[funding.AuxFundingController](
			tapServer,
		),
		AuxSigner:     fn.Some[lnwallet.AuxSigner](tapServer),
		TrafficShaper: fn.Some[htlcswitch.AuxTrafficShaper](tapServer),
		AuxDataParser: fn.Some[lnd.AuxDataParser](tapServer),
		AuxChanCloser: fn.Some[chancloser.AuxChanCloser](tapServer),
		AuxSweeper:    fn.Some[sweep.AuxSweeper](tapServer),
		AuxContractResolver: fn.Some[lnwallet.AuxContractResolver](
			tapServer,
		),
		AuxChannelNegotiator: fn.Some[lnwallet.AuxChannelNegotiator](
			tapServer,
		),
	}, cleanup, nil
}

// EnsureRequiredCustomMessages appends any message types required by the
// Taproot Asset channel protocol to the given custom message allow list. In
// particular, tapd needs to send error messages (lnwire.MsgError) to peers
// through lnd's SendCustomMessage RPC. Since MsgError is outside the custom
// message range, it must be explicitly allowed.
//
// This function is idempotent: if the required types are already present in
// the slice, it returns it unchanged.
func EnsureRequiredCustomMessages(customMsgs []uint16) []uint16 {
	requiredMsgs := []uint16{
		uint16(lnwire.MsgError),
	}

	// Copy the input so we never mutate the caller's backing array.
	result := make([]uint16, len(customMsgs))
	copy(result, customMsgs)

	for _, required := range requiredMsgs {
		found := false
		for _, existing := range result {
			if existing == required {
				found = true
				break
			}
		}

		if !found {
			result = append(result, required)
		}
	}

	return result
}
