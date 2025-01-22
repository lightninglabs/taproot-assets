package commands

import (
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
