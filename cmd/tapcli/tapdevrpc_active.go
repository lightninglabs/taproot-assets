//go:build dev

package main

import (
	"fmt"

	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/urfave/cli"
)

var devCommands = []cli.Command{
	{
		Name:     "dev",
		Usage:    "Developer and debug subcommands.",
		Category: "Dev",
		Subcommands: []cli.Command{
			importProofCommand,
		},
	},
}

func getDevClient(ctx *cli.Context) (tapdevrpc.TapDevClient, func()) {
	conn := getClientConn(ctx, false)

	cleanUp := func() {
		conn.Close()
	}

	return tapdevrpc.NewTapDevClient(conn), cleanUp
}

var importProofCommand = cli.Command{
	Name:      "importproof",
	ShortName: "i",
	Usage:     "import a taproot asset proof",
	Description: `
	Imports a taproot asset proof that contains the full provenance of an
	asset. If the asset script key of the asset is known to the lnd node
	the daemon is connected to, then this results in a spendable asset being
	imported into the wallet.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: proofPathName,
			Usage: "the path to the proof file on disk; use the " +
				"dash character (-) to read from stdin instead",
		},
	},
	Action: importProof,
}

func importProof(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getDevClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(proofPathName) == "":
		return cli.ShowSubcommandHelp(ctx)
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
	proofFile, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read proof file: %w", err)
	}

	resp, err := client.ImportProof(ctxc, &tapdevrpc.ImportProofRequest{
		ProofFile: proofFile,
	})
	if err != nil {
		return fmt.Errorf("unable to import proof file: %w", err)
	}

	printRespJSON(resp)
	return nil
}
