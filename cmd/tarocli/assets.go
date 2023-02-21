package main

import (
	"encoding/hex"
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
			listUtxosCommand,
			listGroupsCommand,
			listAssetBalancesCommand,
			sendAssetsCommand,
			listTransfersCommand,
		},
	},
}

var (
	assetTypeName     = "type"
	assetTagName      = "name"
	assetSupplyName   = "supply"
	assetMetaName     = "meta"
	assetEmissionName = "enable_emission"
	assetGroupKeyName = "group_key"
	skipBatchName     = "skip_batch"
	groupByGroupName  = "by_group"
	assetIDName       = "asset_id"
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
		cli.StringFlag{
			Name:  assetGroupKeyName,
			Usage: "the specific group key to use to mint the asset",
		},
		cli.BoolFlag{
			Name:  skipBatchName,
			Usage: "if true, then the asset will be minted immediately",
		},
	},
	Action: mintAsset,
}

func parseAssetType(ctx *cli.Context) tarorpc.AssetType {
	assetType := tarorpc.AssetType_NORMAL
	if ctx.String(assetTypeName) == "collectible" {
		assetType = tarorpc.AssetType_COLLECTIBLE
	}

	return assetType
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

	var (
		groupKey    []byte
		err         error
		groupKeyStr = ctx.String(assetGroupKeyName)
	)

	if len(groupKeyStr) != 0 {
		groupKey, err = hex.DecodeString(groupKeyStr)
		if err != nil {
			return fmt.Errorf("invalid group key")
		}
	}

	resp, err := client.MintAsset(ctxc, &tarorpc.MintAssetRequest{
		Asset: &tarorpc.MintAsset{
			AssetType: parseAssetType(ctx),
			Name:      ctx.String(assetTagName),
			MetaData:  []byte(ctx.String(assetMetaName)),
			Amount:    ctx.Int64(assetSupplyName),
			GroupKey:  groupKey,
		},
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

var listUtxosCommand = cli.Command{
	Name:        "utxos",
	ShortName:   "u",
	Usage:       "list all utxos",
	Description: "list all utxos managing assets",
	Action:      listUtxos,
}

func listUtxos(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.ListUtxos(ctxc, &tarorpc.ListUtxosRequest{})
	if err != nil {
		return fmt.Errorf("unable to list utxos: %w", err)
	}
	printRespJSON(resp)
	return nil
}

var listGroupsCommand = cli.Command{
	Name:        "groups",
	ShortName:   "g",
	Usage:       "list all asset groups",
	Description: "list all asset groups known to the daemon",
	Action:      listGroups,
}

func listGroups(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.ListGroups(ctxc, &tarorpc.ListGroupsRequest{})
	if err != nil {
		return fmt.Errorf("unable to list asset groups: %w", err)
	}
	printRespJSON(resp)
	return nil
}

var listAssetBalancesCommand = cli.Command{
	Name:        "balance",
	ShortName:   "b",
	Usage:       "list asset balances",
	Description: "list balances for all assets or a selected asset",
	Action:      listAssetBalances,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  groupByGroupName,
			Usage: "Group asset balances by group key",
		},
		cli.StringFlag{
			Name: assetIDName,
			Usage: "A specific asset ID to run the balance query " +
				"against",
		},
		cli.StringFlag{
			Name: groupKeyName,
			Usage: "A specific asset group key to run the " +
				"balance query against. Must be used " +
				"together with --by_group",
		},
	},
}

func listAssetBalances(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	var err error

	req := &tarorpc.ListBalancesRequest{}

	if !ctx.Bool(groupByGroupName) {
		req.GroupBy = &tarorpc.ListBalancesRequest_AssetId{
			AssetId: true,
		}

		assetIDHexStr := ctx.String(assetIDName)
		if len(assetIDHexStr) != 0 {
			req.AssetFilter, err = hex.DecodeString(assetIDHexStr)
			if err != nil {
				return fmt.Errorf("invalid asset ID")
			}

			if len(req.AssetFilter) != 32 {
				return fmt.Errorf("invalid asset ID length")
			}
		}
	} else {
		req.GroupBy = &tarorpc.ListBalancesRequest_GroupKey{
			GroupKey: true,
		}

		assetGroupKeyHexStr := ctx.String(groupKeyName)
		req.GroupKeyFilter, err = hex.DecodeString(assetGroupKeyHexStr)
		if err != nil {
			return fmt.Errorf("invalid group key")
		}
	}

	resp, err := client.ListBalances(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to list asset balances: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var sendAssetsCommand = cli.Command{
	Name:        "send",
	ShortName:   "s",
	Usage:       "send an asset",
	Description: "send asset w/ a taro addr",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  addrName,
			Usage: "addr to send to",
		},
		// TODO(roasbeef): add arg for file name to write sender proof
		// blob
	},
	Action: sendAssets,
}

func sendAssets(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(addrName) == "":
		_ = cli.ShowCommandHelp(ctx, "send")
		return nil
	}

	resp, err := client.SendAsset(ctxc, &tarorpc.SendAssetRequest{
		TaroAddr: ctx.String(addrName),
	})
	if err != nil {
		return fmt.Errorf("unable to send assets: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var listTransfersCommand = cli.Command{
	Name:      "transfers",
	ShortName: "t",
	Usage:     "list asset transfers",
	Description: "list outgoing transfers of all assets or a selected " +
		"asset",
	Action: listTransfers,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: assetIDName,
			Usage: "A specific asset ID to list outgoing " +
				"transfers for",
		},
	},
}

func listTransfers(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	req := &tarorpc.ListTransfersRequest{}
	resp, err := client.ListTransfers(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to list asset transfers: %w", err)
	}

	printRespJSON(resp)
	return nil
}
