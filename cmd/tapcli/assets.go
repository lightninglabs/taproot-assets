package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/lightninglabs/taproot-assets/tapcfg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/urfave/cli"
)

var assetsCommands = []cli.Command{
	{
		Name:      "assets",
		ShortName: "a",
		Usage:     "Interact with Taproot Assets.",
		Category:  "Assets",
		Subcommands: []cli.Command{
			mintAssetCommand,
			listAssetsCommand,
			listUtxosCommand,
			listGroupsCommand,
			listAssetBalancesCommand,
			sendAssetsCommand,
			listTransfersCommand,
			fetchMetaCommand,
		},
	},
}

var (
	assetTypeName         = "type"
	assetTagName          = "name"
	assetSupplyName       = "supply"
	assetMetaBytesName    = "meta_bytes"
	assetMetaFilePathName = "meta_file_path"
	assetMetaTypeName     = "meta_type"
	assetEmissionName     = "enable_emission"
	assetShowWitnessName  = "show_witness"
	assetShowSpentName    = "show_spent"
	assetGroupKeyName     = "group_key"
	assetGroupAnchorName  = "group_anchor"
	batchKeyName          = "batch_key"
	groupByGroupName      = "by_group"
	assetIDName           = "asset_id"
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
			Name:  assetMetaBytesName,
			Usage: "the raw metadata associated with the asset",
		},
		cli.StringFlag{
			Name: assetMetaFilePathName,
			Usage: "a path to a file on disk that should be read " +
				"and used as the asset meta",
		},
		cli.IntFlag{
			Name:  assetMetaTypeName,
			Usage: "the type of the meta data for the asset",
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
		cli.StringFlag{
			Name:  assetGroupAnchorName,
			Usage: "the other asset in this batch that the new asset be grouped with",
		},
	},
	Action: mintAsset,
	Subcommands: []cli.Command{
		listBatchesCommand,
		finalizeBatchCommand,
		cancelBatchCommand,
	},
}

func parseAssetType(ctx *cli.Context) taprpc.AssetType {
	assetType := taprpc.AssetType_NORMAL
	if ctx.String(assetTypeName) == "collectible" {
		assetType = taprpc.AssetType_COLLECTIBLE
	}

	return assetType
}

func mintAsset(ctx *cli.Context) error {
	switch {
	case ctx.String(assetTagName) == "":
		fallthrough
	case ctx.Int64(assetSupplyName) == 0:
		return cli.ShowSubcommandHelp(ctx)
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

	// Both the meta bytes and the meta path can be set.
	var assetMeta *taprpc.AssetMeta
	switch {
	case ctx.String(assetMetaBytesName) != "" &&
		ctx.String(assetMetaFilePathName) != "":
		return fmt.Errorf("meta bytes or meta file path cannot " +
			"be both set")

	case ctx.String(assetMetaBytesName) != "":
		assetMeta = &taprpc.AssetMeta{
			Data: []byte(ctx.String(assetMetaBytesName)),
			Type: taprpc.AssetMetaType(ctx.Int(assetMetaTypeName)),
		}

	case ctx.String(assetMetaFilePathName) != "":
		metaPath := tapcfg.CleanAndExpandPath(
			ctx.String(assetMetaFilePathName),
		)
		metaFileBytes, err := ioutil.ReadFile(metaPath)
		if err != nil {
			return fmt.Errorf("unable to read meta file: %w", err)
		}

		assetMeta = &taprpc.AssetMeta{
			Data: metaFileBytes,
			Type: taprpc.AssetMetaType(ctx.Int(assetMetaTypeName)),
		}
	}

	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	resp, err := client.MintAsset(ctxc, &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType:   parseAssetType(ctx),
			Name:        ctx.String(assetTagName),
			AssetMeta:   assetMeta,
			Amount:      ctx.Uint64(assetSupplyName),
			GroupKey:    groupKey,
			GroupAnchor: ctx.String(assetGroupAnchorName),
		},
		EnableEmission: ctx.Bool(assetEmissionName),
	})
	if err != nil {
		return fmt.Errorf("unable to mint asset: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var finalizeBatchCommand = cli.Command{
	Name:        "finalize",
	ShortName:   "f",
	Usage:       "finalize a batch",
	Description: "Attempt to finalize a pending batch.",
	Action:      finalizeBatch,
}

func finalizeBatch(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	resp, err := client.FinalizeBatch(ctxc, &mintrpc.FinalizeBatchRequest{})
	if err != nil {
		return fmt.Errorf("unable to finalize batch: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var cancelBatchCommand = cli.Command{
	Name:        "cancel",
	ShortName:   "c",
	Usage:       "cancel a batch",
	Description: "Attempt to cancel a pending batch.",
	Action:      cancelBatch,
}

func cancelBatch(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	resp, err := client.CancelBatch(ctxc, &mintrpc.CancelBatchRequest{})
	if err != nil {
		return fmt.Errorf("unable to cancel batch: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var listBatchesCommand = cli.Command{
	Name:        "batches",
	ShortName:   "b",
	Usage:       "list all batches",
	Description: "List all batches",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  batchKeyName,
			Usage: "if set, the batch key for a specific batch",
		},
	},
	Action: listBatches,
}

func listBatches(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	var (
		batchKeyStr = ctx.String(batchKeyName)
		batchKey    []byte
		err         error
	)
	if len(batchKeyStr) != 0 {
		batchKey, err = hex.DecodeString(batchKeyStr)
		if err != nil {
			return fmt.Errorf("invalid batch key")
		}
	}

	resp, err := client.ListBatches(ctxc, &mintrpc.ListBatchRequest{
		BatchKey: batchKey,
	})
	if err != nil {
		return fmt.Errorf("unable to list batches: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var listAssetsCommand = cli.Command{
	Name:        "list",
	ShortName:   "l",
	Usage:       "list all assets",
	Description: "list all pending and mined assets",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  assetShowWitnessName,
			Usage: "include the asset's witness data",
		},
		cli.BoolFlag{
			Name:  assetShowSpentName,
			Usage: "include fully spent assets in the list",
		},
	},
	Action: listAssets,
}

func listAssets(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	// TODO(roasbeef): need to reverse txid

	resp, err := client.ListAssets(ctxc, &taprpc.ListAssetRequest{
		WithWitness:  ctx.Bool(assetShowWitnessName),
		IncludeSpent: ctx.Bool(assetShowSpentName),
	})
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

	resp, err := client.ListUtxos(ctxc, &taprpc.ListUtxosRequest{})
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

	resp, err := client.ListGroups(ctxc, &taprpc.ListGroupsRequest{})
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

	req := &taprpc.ListBalancesRequest{}

	if !ctx.Bool(groupByGroupName) {
		req.GroupBy = &taprpc.ListBalancesRequest_AssetId{
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
		req.GroupBy = &taprpc.ListBalancesRequest_GroupKey{
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
	Description: "send asset w/ a taproot asset addr",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name: addrName,
			Usage: "addr to send to; can be specified multiple " +
				"times to send to multiple addresses at once",
		},
		// TODO(roasbeef): add arg for file name to write sender proof
		// blob
	},
	Action: sendAssets,
}

func sendAssets(ctx *cli.Context) error {
	addrs := ctx.StringSlice(addrName)
	if ctx.NArg() != 0 || ctx.NumFlags() == 0 || len(addrs) == 0 {
		return cli.ShowSubcommandHelp(ctx)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.SendAsset(ctxc, &taprpc.SendAssetRequest{
		TapAddrs: addrs,
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

	req := &taprpc.ListTransfersRequest{}
	resp, err := client.ListTransfers(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to list asset transfers: %w", err)
	}

	printRespJSON(resp)
	return nil
}

const (
	metaName = "asset_meta"
)

var fetchMetaCommand = cli.Command{
	Name:  "meta",
	Usage: "fetch asset meta",
	Description: "fetch the meta bytes for an asset based on the " +
		"asset_id or meta_hash",
	Action: fetchMeta,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "asset_id to fetch meta for",
		},
		cli.StringFlag{
			Name:  metaName,
			Usage: "meta_hash to fetch meta for",
		},
	},
}

func fetchMeta(ctx *cli.Context) error {
	switch {
	case ctx.IsSet(metaName) && ctx.IsSet(assetIDName):
		return fmt.Errorf("only the asset_id or meta_hash can be set")

	case !ctx.IsSet(assetIDName) && !ctx.IsSet(metaName):
		return cli.ShowSubcommandHelp(ctx)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	req := &taprpc.FetchAssetMetaRequest{}
	if ctx.IsSet(assetIDName) {
		assetIDHex, err := hex.DecodeString(ctx.String(assetIDName))
		if err != nil {
			return fmt.Errorf("invalid asset ID")
		}

		req.Asset = &taprpc.FetchAssetMetaRequest_AssetId{
			AssetId: assetIDHex,
		}
	} else {
		metaBytes, err := hex.DecodeString(ctx.String(metaName))
		if err != nil {
			return fmt.Errorf("invalid meta hash")
		}

		req.Asset = &taprpc.FetchAssetMetaRequest_MetaHash{
			MetaHash: metaBytes,
		}
	}

	resp, err := client.FetchAssetMeta(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to fetch asset meta: %w", err)
	}

	printRespJSON(resp)
	return nil
}
