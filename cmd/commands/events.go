package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/urfave/cli"
)

var eventCommands = []cli.Command{
	{
		Name:      "events",
		ShortName: "e",
		Usage: "Subscribe to live events from the Taproot Asset " +
			"daemon.",
		Category: "Events",
		Subcommands: []cli.Command{
			receiveEventsCommand,
			sendEventsCommand,
			mintEventsCommand,
		},
	},
}

var receiveEventsCommand = cli.Command{
	Name:      "receive",
	ShortName: "r",
	Usage:     "Subscribe to events around receiving inbound assets",
	Description: "Get live updates on the status of inbound asset " +
		"transfers to the local node. This command will block " +
		"until aborted manually by hitting Ctrl+C.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: addrName,
			Usage: "(optional) the address to receive events " +
				"for; if not set, events for all addresses " +
				"will be shown",
		},
	},
	Action: receiveEvents,
}

func receiveEvents(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	addr, err := client.SubscribeReceiveEvents(
		ctxc, &taprpc.SubscribeReceiveEventsRequest{
			FilterAddr: ctx.String(addrName),
		},
	)
	if err != nil {
		return fmt.Errorf("unable to subscribe to receive events: %w",
			err)
	}

	for {
		event, err := addr.Recv()
		if err != nil {
			return fmt.Errorf("unable to receive event: %w", err)
		}

		printRespJSON(event)
	}
}

var sendEventsCommand = cli.Command{
	Name:      "send",
	ShortName: "s",
	Usage:     "Subscribe to events around sending outbound assets",
	Description: "Get live updates on the status of outbound asset " +
		"transfers to the local node. This command will block " +
		"until aborted manually by hitting Ctrl+C.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: scriptKeyName,
			Usage: "(optional) the script key to receive events " +
				"for; if not set, events for all transfers " +
				"will be shown",
		},
	},
	Action: sendEvents,
}

func sendEvents(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	scriptKeyBytes, err := hex.DecodeString(ctx.String(scriptKeyName))
	if err != nil {
		return fmt.Errorf("unable to hex decode script key: %w", err)
	}

	send, err := client.SubscribeSendEvents(
		ctxc, &taprpc.SubscribeSendEventsRequest{
			FilterScriptKey: scriptKeyBytes,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to subscribe to send events: %w",
			err)
	}

	for {
		event, err := send.Recv()
		if err != nil {
			return fmt.Errorf("unable to receive event: %w", err)
		}

		printRespJSON(event)
	}
}

var mintEventsCommand = cli.Command{
	Name:      "mint",
	ShortName: "m",
	Usage:     "Subscribe to events around minting assets",
	Description: "Get live updates on the status of minting asset " +
		"batches on the local node. This command will block " +
		"until aborted manually by hitting Ctrl+C.",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: shortResponseName,
			Usage: "if true, then the current assets within the " +
				"batch of an event will not be returned in " +
				"the response in order to avoid printing a " +
				"large amount of data in case of large batches",
		},
	},
	Action: mintEvents,
}

func mintEvents(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	mint, err := client.SubscribeMintEvents(
		ctxc, &mintrpc.SubscribeMintEventsRequest{
			ShortResponse: ctx.Bool(shortResponseName),
		},
	)
	if err != nil {
		return fmt.Errorf("unable to subscribe to mint events: %w",
			err)
	}

	for {
		event, err := mint.Recv()
		if err != nil {
			return fmt.Errorf("unable to receive event: %w", err)
		}

		printRespJSON(event)
	}
}
