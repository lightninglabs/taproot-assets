package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/urfave/cli"
)

var proofCommands = []cli.Command{
	{
		Name:      "proofs",
		ShortName: "p",
		Usage:     "Interact with Taro proofs.",
		Category:  "Proofs",
		Subcommands: []cli.Command{
			verifyProofCommand,
			exportProofCommand,
			importProofCommand,
		},
	},
}

const (
	proofPathName = "proof_file"
)

var verifyProofCommand = cli.Command{
	Name:        "verify",
	ShortName:   "v",
	Description: "verify a taro proof",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  proofPathName,
			Usage: "the file path to the .taro file",
		},
	},
	Action: verifyProof,
}

func verifyProof(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(proofPathName) == "":
		_ = cli.ShowCommandHelp(ctx, "verify")
		return nil
	}

	rawFile, err := os.ReadFile(proofPathName)
	if err != nil {
		return fmt.Errorf("unable to read proof file: %w", err)
	}

	resp, err := client.VerifyProof(ctxc, &tarorpc.ProofFile{
		RawProof: rawFile,
	})
	if err != nil {
		return fmt.Errorf("unable to verify file: %w", err)
	}

	printRespJSON(resp)
	return nil
}

const (
	scriptKeyName = "script_key"
)

var exportProofCommand = cli.Command{
	Name:        "export",
	ShortName:   "e",
	Description: "export a taro proof",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the asset to export",
		},
		cli.StringFlag{
			Name:  scriptKeyName,
			Usage: "the script key of the asset to export",
		},
	},
	Action: exportProof,
}

func exportProof(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(scriptKeyName) == "",
		ctx.String(assetIDName) == "":

		_ = cli.ShowCommandHelp(ctx, "export")
		return nil
	}

	scriptKeyBytes, err := hex.DecodeString(ctx.String(scriptKeyName))
	if err != nil {
		return fmt.Errorf("unable to decode script key: %v", err)
	}

	assetID, err := hex.DecodeString(ctx.String(assetIDName))
	if err != nil {
		return fmt.Errorf("unable to asset ID: %v", err)
	}

	resp, err := client.ExportProof(ctxc, &tarorpc.ExportProofRequest{
		AssetId:   assetID,
		ScriptKey: scriptKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("unable to verify file: %w", err)
	}

	// TODO(roasbeef): specify path on disk to obtain at?

	printRespJSON(resp)
	return nil
}

var importProofCommand = cli.Command{
	Name:        "import",
	ShortName:   "i",
	Description: "import a taro proof, resulting in a spendable asset",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  proofPathName,
			Usage: "the path to the proof file on disk",
		},
	},
	Action: importProof,
}

func importProof(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(proofPathName) == "":

		_ = cli.ShowCommandHelp(ctx, "import")
		return nil
	}

	proofFile, err := os.ReadFile(proofPathName)
	if err != nil {
		return fmt.Errorf("unable to read file: %v", err)
	}

	resp, err := client.ImportProof(ctxc, &tarorpc.ImportProofRequest{
		ProofFile: proofFile,
	})
	if err != nil {
		return fmt.Errorf("unable to verify file: %w", err)
	}

	printRespJSON(resp)
	return nil
}
