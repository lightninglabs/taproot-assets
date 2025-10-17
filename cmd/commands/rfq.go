package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/lightninglabs/taproot-assets/taprpc"
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

var forwardingHistoryCommand = cli.Command{
	Name:      "forwardinghistory",
	ShortName: "fh",
	Usage:     "query the forwarding history of the node",
	Description: `
	Query the forwarding history of the node. This shows all asset forwards
	that have been accepted and processed.
	`,
	Flags: []cli.Flag{
		cli.Uint64Flag{
			Name: "start_time",
			Usage: "start time for the query (unix timestamp in " +
				"seconds)",
		},
		cli.Uint64Flag{
			Name: "end_time",
			Usage: "end time for the query (unix timestamp in " +
				"seconds)",
		},
		cli.StringFlag{
			Name: "asset_id",
			Usage: "filter by asset ID (hex-encoded 32 bytes), " +
				"omit to query all assets",
		},
		cli.Int64Flag{
			Name:  "offset",
			Usage: "the offset for the page (default: 0)",
			Value: 0,
		},
		cli.Int64Flag{
			Name:  "limit",
			Usage: "the length limit for the page (default: 100)",
			Value: 100,
		},
		cli.BoolFlag{
			Name: "asc",
			Usage: "sort results in ascending order by timestamp " +
				"(default: descending)",
		},
	},
	Action: forwardingHistory,
}

func forwardingHistory(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getRfqClient(ctx)
	defer cleanUp()

	// Determine sort direction.
	direction := taprpc.SortDirection_SORT_DIRECTION_DESC
	if ctx.Bool("asc") {
		direction = taprpc.SortDirection_SORT_DIRECTION_ASC
	}

	// Build the request.
	req := &rfqrpc.QueryForwardingHistoryRequest{
		StartTime: ctx.Uint64("start_time"),
		EndTime:   ctx.Uint64("end_time"),
		Offset:    int32(ctx.Int64("offset")),
		Limit:     int32(ctx.Int64("limit")),
		Direction: direction,
	}

	// Parse the asset ID filter if provided.
	if ctx.IsSet("asset_id") {
		assetIDHex := ctx.String("asset_id")
		assetIDBytes, err := hex.DecodeString(assetIDHex)
		if err != nil {
			return fmt.Errorf("unable to decode asset ID: %w", err)
		}
		if len(assetIDBytes) != 32 {
			return fmt.Errorf("asset ID must be 32 bytes")
		}
		req.AssetIdFilter = assetIDBytes
	}

	resp, err := client.QueryForwardingHistory(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to query forwarding history: %w", err)
	}

	printRespJSON(resp)

	return nil
}
