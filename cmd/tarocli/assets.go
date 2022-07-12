package main

import (
	"fmt"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/urfave/cli"
)

var assetsCommands = []cli.Command{
	{
		Name:      "assets",
		ShortName: "a",
		Usage:     "Interact with Taro assets.",
		Category:  "Assets",
		Subcommands: []cli.Command{
			mintAssetCommand,
			listAssetsCommand,
		},
	},
}

var (
	assetTypeName     = "type"
	assetTagName      = "name"
	assetSupplyName   = "supply"
	assetMetaName     = "meta"
	assetEmissionName = "enable_emission"
	skipBatchName     = "skip_batch"
)

var mintAssetCommand = cli.Command{
	Name:        "mint",
	ShortName:   "m",
	Usage:       "mint a new asset",
	Description: "Attempt to mint a new asset with the specified parameters",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetTypeName,
			Usage: "the type of asset, must either be: normal, or collectible",
		},
		cli.StringFlag{
			Name:  assetTagName,
			Usage: "the name/tag of the asset",
		},
		cli.Uint64Flag{
			Name:  assetSupplyName,
			Usage: "the target supply of the minted asset",
		},
		cli.StringFlag{
			Name:  assetMetaName,
			Usage: "the metadata associated with the asset",
		},
		cli.BoolFlag{
			Name: assetEmissionName,
			Usage: "if true, then the asset supports on going " +
				"emission",
		},
		cli.BoolFlag{
			Name:  skipBatchName,
			Usage: "if true, then the asset will be minted immediately",
		},
	},
	Action: mintAsset,
}

func mintAsset(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(assetTagName) == "":
		fallthrough
	case ctx.Int64(assetSupplyName) == 0:
		_ = cli.ShowCommandHelp(ctx, "mint")
		return nil
	}

	assetType := tarorpc.AssetType_NORMAL
	if ctx.String(assetTypeName) == "collectible" {
		assetType = tarorpc.AssetType_COLLECTIBLE
	}
	resp, err := client.MintAsset(ctxc, &tarorpc.MintAssetRequest{
		AssetType:      assetType,
		Name:           ctx.String(assetTagName),
		MetaData:       []byte(ctx.String(assetMetaName)),
		Amount:         ctx.Int64(assetSupplyName),
		EnableEmission: ctx.Bool(assetEmissionName),
		SkipBatch:      ctx.Bool(skipBatchName),
	})
	if err != nil {
		return fmt.Errorf("unable to mint asset: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var listAssetsCommand = cli.Command{
	Name:        "list",
	ShortName:   "l",
	Usage:       "list all assets",
	Description: "list all pending and mined assets",
	Action:      listAssets,
}

func listAssets(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	// TODO(roasbeef): need to reverse txid

	resp, err := client.ListAssets(ctxc, &tarorpc.ListAssetRequest{})
	if err != nil {
		return fmt.Errorf("unable to list assets: %w", err)
	}
	printRespJSON(resp)
	return nil
}
