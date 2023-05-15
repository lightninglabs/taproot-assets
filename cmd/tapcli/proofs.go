package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/urfave/cli"
)

var proofCommands = []cli.Command{
	{
		Name:      "proofs",
		ShortName: "p",
		Usage:     "Interact with Taproot Asset proofs.",
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
	Description: "verify a taproot asset proof",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: proofPathName,
			Usage: "the path to the proof file on disk; use the " +
				"dash character (-) to read from stdin instead",
		},
	},
	Action: verifyProof,
}

func verifyProof(ctx *cli.Context) error {
	switch {
	case ctx.String(proofPathName) == "":
		return cli.ShowSubcommandHelp(ctx)
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
	rawFile, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read proof file: %w", err)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.VerifyProof(ctxc, &taprpc.ProofFile{
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
	Description: "export a taproot asset proof",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the asset to export",
		},
		cli.StringFlag{
			Name:  scriptKeyName,
			Usage: "the script key of the asset to export",
		},
		cli.StringFlag{
			Name: proofPathName,
			Usage: "(optional) the file to write the raw proof " +
				"to; use the dash character (-) to write " +
				"the raw binary proof to stdout instead of " +
				"the default JSON format",
		},
	},
	Action: exportProof,
}

func exportProof(ctx *cli.Context) error {
	switch {
	case ctx.String(scriptKeyName) == "",
		ctx.String(assetIDName) == "":
		return cli.ShowSubcommandHelp(ctx)
	}

	scriptKeyBytes, err := hex.DecodeString(ctx.String(scriptKeyName))
	if err != nil {
		return fmt.Errorf("unable to decode script key: %v", err)
	}

	assetID, err := hex.DecodeString(ctx.String(assetIDName))
	if err != nil {
		return fmt.Errorf("unable to asset ID: %v", err)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.ExportProof(ctxc, &taprpc.ExportProofRequest{
		AssetId:   assetID,
		ScriptKey: scriptKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("unable to verify file: %w", err)
	}

	// Write the raw (binary) proof to a file (or stdout) instead of in the
	// JSON format.
	if ctx.String(proofPathName) != "" {
		filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
		return writeToFile(filePath, resp.RawProof)
	}

	printRespJSON(resp)
	return nil
}

var importProofCommand = cli.Command{
	Name:      "import",
	ShortName: "i",
	Description: "import a taproot asset proof, resulting in a spendable " +
		"asset",
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
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(proofPathName) == "":
		return cli.ShowSubcommandHelp(ctx)
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
	proofFile, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read file: %v", err)
	}

	resp, err := client.ImportProof(ctxc, &taprpc.ImportProofRequest{
		ProofFile: proofFile,
	})
	if err != nil {
		return fmt.Errorf("unable to verify file: %w", err)
	}

	printRespJSON(resp)
	return nil
}

// readFile attempts to read a file from disk. If the passed fileName is equal
// to the dash character, then this function reads from stdin instead.
func readFile(fileName string) ([]byte, error) {
	if fileName == "-" {
		return io.ReadAll(os.Stdin)
	}

	return os.ReadFile(fileName)
}

// writeToFile attempts to write the given content to a file on disk. If the
// passed fileName is equal to the dash character, then this function writes to
// stdout instead.
func writeToFile(fileName string, content []byte) error {
	if fileName == "-" {
		_, err := os.Stdout.Write(content)
		if err != nil {
			return fmt.Errorf("error writing raw proof to stdout: "+
				"%v", err)
		}

		return nil
	}

	// Make sure all parent directories of the given path exist as well.
	if err := os.MkdirAll(path.Dir(fileName), defaultDirPerms); err != nil {
		return fmt.Errorf("unable to create directory %v: %v",
			path.Dir(fileName), err)
	}

	err := os.WriteFile(fileName, content, defaultFilePerms)
	if err != nil {
		return fmt.Errorf("unable to store file %v: %v", fileName, err)
	}

	return nil
}
