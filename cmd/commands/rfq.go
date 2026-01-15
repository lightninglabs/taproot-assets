package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/urfave/cli"
)

var rfqCommands = []cli.Command{
	{
		Name:      "rfq",
		ShortName: "r",
		Usage:     "Interact with Taproot Asset RFQs.",
		Category:  "Channels",
		Subcommands: []cli.Command{
			acceptedQuotesCommand,
			forwardingHistoryCommand,
		},
	},
}

var acceptedQuotesCommand = cli.Command{
	Name:      "acceptedquotes",
	ShortName: "q",
	Usage:     "show all accepted quotes of the node's peers",
	Description: `
	Lists all quotes that have been accepted by the node's peers.
`,
	Action: acceptedQuotes,
}

func acceptedQuotes(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRfqClient(ctx)
	defer cleanUp()

	resp, err := client.QueryPeerAcceptedQuotes(
		ctxc, &rfqrpc.QueryPeerAcceptedQuotesRequest{},
	)
	if err != nil {
		return fmt.Errorf("unable to query accepted quotes: %w", err)
	}

	printRespJSON(resp)

	return nil
}

const (
	minTimestampName = "min_timestamp"
	maxTimestampName = "max_timestamp"
	peerName         = "peer"
)

var forwardingHistoryCommand = cli.Command{
	Name:      "forwardinghistory",
	ShortName: "f",
	Usage:     "query historical asset forwarding events",
	Description: `
	Query historical records of asset forwarding events executed by the RFQ
	system. This provides accounting and record-keeping for edge nodes that
	perform asset swaps. Events are recorded when opened and updated when
	they settle or fail.
`,
	Flags: []cli.Flag{
		cli.Uint64Flag{
			Name: minTimestampName,
			Usage: "minimum Unix timestamp in seconds; only " +
				"events opened at or after this time are " +
				"returned",
		},
		cli.Uint64Flag{
			Name: maxTimestampName,
			Usage: "maximum Unix timestamp in seconds; only " +
				"events opened at or before this time are " +
				"returned",
		},
		cli.StringFlag{
			Name:  peerName,
			Usage: "filter by peer public key",
		},
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "filter by asset ID",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "filter by asset group key",
		},
		cli.IntFlag{
			Name:  limitName,
			Usage: "maximum number of records to return",
			Value: 100,
		},
		cli.IntFlag{
			Name:  offsetName,
			Usage: "number of records to skip",
			Value: 0,
		},
	},
	Action: queryForwardingHistory,
}

func queryForwardingHistory(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRfqClient(ctx)
	defer cleanUp()

	req := &rfqrpc.ForwardingHistoryRequest{
		MinTimestamp: ctx.Uint64(minTimestampName),
		MaxTimestamp: ctx.Uint64(maxTimestampName),
		Limit:        int32(ctx.Int(limitName)),
		Offset:       int32(ctx.Int(offsetName)),
	}

	// Parse peer if provided.
	if peerStr := ctx.String(peerName); peerStr != "" {
		peerBytes, err := hex.DecodeString(peerStr)
		if err != nil {
			return fmt.Errorf("invalid peer hex: %w", err)
		}
		req.Peer = peerBytes
	}

	// Parse asset specifier if provided.
	assetIDStr := ctx.String(assetIDName)
	groupKeyStr := ctx.String(groupKeyName)

	// Check for mutual exclusivity.
	if assetIDStr != "" && groupKeyStr != "" {
		return fmt.Errorf("cannot specify both --%s and --%s",
			assetIDName, groupKeyName)
	}

	if assetIDStr != "" || groupKeyStr != "" {
		req.AssetSpecifier = &rfqrpc.AssetSpecifier{}

		if assetIDStr != "" {
			assetID, err := hex.DecodeString(assetIDStr)
			if err != nil {
				return fmt.Errorf("invalid asset ID hex: %w",
					err)
			}
			req.AssetSpecifier.Id = &rfqrpc.AssetSpecifier_AssetId{
				AssetId: assetID,
			}
		} else if groupKeyStr != "" {
			groupKey, err := hex.DecodeString(groupKeyStr)
			if err != nil {
				return fmt.Errorf("invalid group key hex: %w",
					err)
			}
			req.AssetSpecifier.Id = &rfqrpc.AssetSpecifier_GroupKey{
				GroupKey: groupKey,
			}
		}
	}

	resp, err := client.ForwardingHistory(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to query forwarding history: %w", err)
	}

	printRespJSON(resp)

	return nil
}
