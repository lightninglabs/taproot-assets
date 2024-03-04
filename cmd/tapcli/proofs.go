package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
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
			decodeProofCommand,
			exportProofCommand,
			proveOwnershipCommand,
			verifyOwnershipCommand,
		},
	},
}

const (
	proofPathName = "proof_file"

	proofAtDepthName      = "proof_at_depth"
	withPrevWitnessesName = "latest_proof"
	withMetaRevealName    = "meta_reveal"
)

var verifyProofCommand = cli.Command{
	Name:      "verify",
	ShortName: "v",
	Usage:     "verify a taproot asset proof",
	Description: `
	Verify a taproot asset proof that contains the full provenance of an
	asset. Such a proof proves the existence of an asset, but does not
	prove that the creator of the proof can actually also spend the asset.
	To verify ownership, use the "verifyownership" command with a separate
	ownership proof.
`,
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
	if ctx.String(proofPathName) == "" {
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
		RawProofFile: rawFile,
	})
	if err != nil {
		return fmt.Errorf("unable to verify proof file: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var decodeProofCommand = cli.Command{
	Name:      "decode",
	ShortName: "d",
	Usage:     "decode a Taproot Asset proof",
	Description: `
	Decode a taproot asset proof that contains the full provenance of an
	asset into human readable format. Such a proof proves the existence 
	of an asset, but does not prove that the creator of the proof can 
	actually also spend the asset. To verify ownership, use the 
	"verifyownership" command with a separate ownership proof.
`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: proofPathName,
			Usage: "the path to the proof file on disk; use the " +
				"dash character (-) to read from stdin instead",
		},
		cli.Int64Flag{
			Name:  proofAtDepthName,
			Value: 0,
			Usage: "the index depth of the decoded proof to fetch " +
				"with 0 being the latest proof",
		},
		cli.BoolFlag{
			Name:  withPrevWitnessesName,
			Usage: "if true, previous witnesses will be returned",
		},
		cli.BoolFlag{
			Name: withMetaRevealName,
			Usage: "if true, will attempt to reveal the meta data " +
				"associated with the proof",
		},
	},
	Action: decodeProof,
}

func decodeProof(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	if !ctx.IsSet(proofPathName) {
		_ = cli.ShowCommandHelp(ctx, "decode")
		return nil
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
	rawFile, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read proof file: %w", err)
	}

	req := &taprpc.DecodeProofRequest{
		RawProof:          rawFile,
		ProofAtDepth:      uint32(ctx.Uint(proofAtDepthName)),
		WithPrevWitnesses: ctx.Bool(withPrevWitnessesName),
		WithMetaReveal:    ctx.Bool(withMetaRevealName),
	}

	resp, err := client.DecodeProof(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to verify file: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var verifyOwnershipCommand = cli.Command{
	Name:      "verifyownership",
	ShortName: "vo",
	Usage:     "verify a taproot asset ownership proof",
	Description: `
	Verify a taproot asset ownership proof. The proof does not contain the
	full asset provenance, only the last state transition proof. But that
	proof contains a signature to prove the asset can be spent by the
	creator of the proof. This command verifies that signature.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: proofPathName,
			Usage: "the path to the ownership proof file on " +
				"disk; use the dash character (-) to read " +
				"from stdin instead",
		},
	},
	Action: verifyOwnershipProof,
}

func verifyOwnershipProof(ctx *cli.Context) error {
	if ctx.String(proofPathName) == "" {
		return cli.ShowSubcommandHelp(ctx)
	}

	filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
	rawFile, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read ownership proof file: %w",
			err)
	}

	ctxc := getContext()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.VerifyAssetOwnership(
		ctxc, &wrpc.VerifyAssetOwnershipRequest{
			ProofWithWitness: rawFile,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to verify asset ownership: %w", err)
	}

	printRespJSON(resp)
	return nil
}

const (
	scriptKeyName = "script_key"
)

var exportProofCommand = cli.Command{
	Name:      "export",
	ShortName: "e",
	Usage:     "export a taproot asset proof",
	Description: `
	Export a taproot asset proof that contains the full provenance of an
	asset. Such a proof proves the existence of an asset, but does not
	prove that the creator of the proof can actually also spend the asset.
	To prove ownership, use the "proveownership" command to produce a
	separate ownership proof.
	`,
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
		return fmt.Errorf("unable to decode script key: %w", err)
	}

	assetID, err := hex.DecodeString(ctx.String(assetIDName))
	if err != nil {
		return fmt.Errorf("unable to decode asset ID: %w", err)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.ExportProof(ctxc, &taprpc.ExportProofRequest{
		AssetId:   assetID,
		ScriptKey: scriptKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("unable to export proof file: %w", err)
	}

	// Write the raw (binary) proof to a file (or stdout) instead of in the
	// JSON format.
	if ctx.String(proofPathName) != "" {
		filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
		return writeToFile(filePath, resp.RawProofFile)
	}

	printRespJSON(resp)
	return nil
}

var proveOwnershipCommand = cli.Command{
	Name:      "proveownership",
	ShortName: "po",
	Usage:     "generate a taproot asset ownership proof",
	Description: `
	Generates a binary proof that proves the ownership of an asset. This
	differs from the export command in that it generates a proof that
	contains a signature created with the script key of the asset. This
	signature proves that the asset can be spent by the creator of the
	ownership proof.
`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: assetIDName,
			Usage: "the asset ID of the asset to prove ownership " +
				"of",
		},
		cli.StringFlag{
			Name: scriptKeyName,
			Usage: "the script key of the asset to prove " +
				"ownership of",
		},
		cli.StringFlag{
			Name: proofPathName,
			Usage: "(optional) the file to write the ownership " +
				"proof file to; use the dash character (-) " +
				"to write the raw binary ownership proof to " +
				"stdout instead of the default JSON format",
		},
	},
	Action: proveOwnership,
}

func proveOwnership(ctx *cli.Context) error {
	switch {
	case ctx.String(scriptKeyName) == "",
		ctx.String(assetIDName) == "":
		return cli.ShowSubcommandHelp(ctx)
	}

	scriptKeyBytes, err := hex.DecodeString(ctx.String(scriptKeyName))
	if err != nil {
		return fmt.Errorf("unable to decode script key: %w", err)
	}

	assetID, err := hex.DecodeString(ctx.String(assetIDName))
	if err != nil {
		return fmt.Errorf("unable to decode asset ID: %w", err)
	}

	ctxc := getContext()
	client, cleanUp := getWalletClient(ctx)
	defer cleanUp()

	resp, err := client.ProveAssetOwnership(
		ctxc, &wrpc.ProveAssetOwnershipRequest{
			AssetId:   assetID,
			ScriptKey: scriptKeyBytes,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to generate ownership proof: %w", err)
	}

	// Write the raw (binary) proof to a file (or stdout) instead of in the
	// JSON format.
	if ctx.String(proofPathName) != "" {
		filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
		return writeToFile(filePath, resp.ProofWithWitness)
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
				"%w", err)
		}

		return nil
	}

	// Make sure all parent directories of the given path exist as well.
	if err := os.MkdirAll(filepath.Dir(fileName), defaultDirPerms); err != nil {
		return fmt.Errorf("unable to create directory %v: %w",
			filepath.Dir(fileName), err)
	}

	err := os.WriteFile(fileName, content, defaultFilePerms)
	if err != nil {
		return fmt.Errorf("unable to store file %v: %w", fileName, err)
	}

	return nil
}
