package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"

	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/tapcfg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
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
			burnAssetsCommand,
			listTransfersCommand,
			fetchMetaCommand,
		},
	},
}

var (
	assetTypeName                = "type"
	assetTagName                 = "name"
	assetSupplyName              = "supply"
	assetMetaBytesName           = "meta_bytes"
	assetMetaFilePathName        = "meta_file_path"
	assetMetaTypeName            = "meta_type"
	assetNewGroupedAssetName     = "new_grouped_asset"
	assetGroupedAssetName        = "grouped_asset"
	assetShowWitnessName         = "show_witness"
	assetShowSpentName           = "show_spent"
	assetGroupKeyName            = "group_key"
	assetGroupAnchorName         = "group_anchor"
	batchKeyName                 = "batch_key"
	groupByGroupName             = "by_group"
	assetIDName                  = "asset_id"
	shortResponseName            = "short"
	feeRateName                  = "sat_per_vbyte"
	assetAmountName              = "amount"
	burnOverrideConfirmationName = "override_confirmation_destroy_assets"
)

var mintAssetCommand = cli.Command{
	Name:        "mint",
	ShortName:   "m",
	Usage:       "mint a new asset",
	Description: "Attempt to mint a new asset with the specified parameters",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: assetTypeName,
			Usage: "the type of asset, must either be: normal, " +
				"or collectible",
		},
		cli.StringFlag{
			Name:  assetTagName,
			Usage: "the name/tag of the asset",
		},
		cli.Uint64Flag{
			Name:  assetSupplyName,
			Usage: "the target supply of the minted asset",
		},
		cli.Uint64Flag{
			Name:  assetVersionName,
			Usage: "the version of the asset to mint",
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
		cli.StringFlag{
			Name: assetMetaTypeName,
			Usage: "the type of the meta data for the asset, must " +
				"be either: opaque or json",
			Value: "opaque",
		},
		cli.BoolFlag{
			Name: assetNewGroupedAssetName,
			Usage: "if true, then the asset supports on going " +
				"emission",
		},
		cli.BoolFlag{
			Name: assetGroupedAssetName,
			Usage: "if true, then the asset is minted into a " +
				"specific group",
		},
		cli.StringFlag{
			Name: assetGroupKeyName,
			Usage: "the specific group key to use to mint the " +
				"asset",
		},
		cli.StringFlag{
			Name: assetGroupAnchorName,
			Usage: "the other asset in this batch that the new " +
				"asset be grouped with",
		},
		cli.BoolFlag{
			Name: shortResponseName,
			Usage: "if true, then the current assets within the " +
				"batch will not be returned in the response " +
				"in order to avoid printing a large amount " +
				"of data in case of large batches",
		},
	},
	Action: mintAsset,
	Subcommands: []cli.Command{
		listBatchesCommand,
		finalizeBatchCommand,
		cancelBatchCommand,
	},
}

func parseAssetType(ctx *cli.Context) (taprpc.AssetType, error) {
	switch ctx.String(assetTypeName) {
	case "normal":
		return taprpc.AssetType_NORMAL, nil

	case "collectible":
		return taprpc.AssetType_COLLECTIBLE, nil

	default:
		return 0, fmt.Errorf("unknown asset type '%v'",
			ctx.String(assetTypeName))
	}
}

func parseMetaType(metaType string,
	metaBytes []byte) (taprpc.AssetMetaType, error) {

	switch metaType {
	case "opaque":
		fallthrough
	case "blob":
		return taprpc.AssetMetaType_META_TYPE_OPAQUE, nil

	case "json":
		// If JSON is selected, the bytes must be valid.
		if !json.Valid(metaBytes) {
			return 0, fmt.Errorf("invalid JSON for meta: %s",
				metaBytes)
		}

		return taprpc.AssetMetaType_META_TYPE_JSON, nil

	// Otherwise, this is a custom meta type, we may not understand it, but
	// we want to support specifying arbitrary meta types.
	default:
		intType, err := strconv.Atoi(metaType)
		if err != nil {
			return 0, fmt.Errorf("invalid meta type: %s", metaType)
		}

		return taprpc.AssetMetaType(intType), nil
	}
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

	metaTypeStr := ctx.String(assetMetaTypeName)

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
		}

		assetMeta.Type, err = parseMetaType(metaTypeStr, assetMeta.Data)
		if err != nil {
			return fmt.Errorf("unable to parse meta type: %w", err)
		}

	case ctx.String(assetMetaFilePathName) != "":
		metaPath := tapcfg.CleanAndExpandPath(
			ctx.String(assetMetaFilePathName),
		)
		metaFileBytes, err := os.ReadFile(metaPath)
		if err != nil {
			return fmt.Errorf("unable to read meta file: %w", err)
		}

		assetMeta = &taprpc.AssetMeta{
			Data: metaFileBytes,
		}

		assetMeta.Type, err = parseMetaType(metaTypeStr, assetMeta.Data)
		if err != nil {
			return fmt.Errorf("unable to parse meta type: %w", err)
		}
	}

	assetType, err := parseAssetType(ctx)
	if err != nil {
		return err
	}

	var (
		amount        = ctx.Uint64(assetSupplyName)
		isCollectible = assetType == taprpc.AssetType_COLLECTIBLE
	)
	switch {
	// If the user did not specify the supply, we can silently assume they
	// are aware that the collectible amount is always 1.
	case isCollectible && !ctx.IsSet(assetSupplyName):
		amount = 1

	// If the user explicitly supplied a supply that is incorrect, we must
	// inform them instead of silently changing the value to 1, otherwise
	// there will be surprises later.
	case isCollectible && amount != 1:
		return fmt.Errorf("supply must be 1 for collectibles")

	// Check that the amount is greater than 0 for normal assets. This is
	// also checked in the RPC server, but we can avoid the round trip.
	case !isCollectible && amount == 0:
		return fmt.Errorf("supply must be set for normal assets")
	}

	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	resp, err := client.MintAsset(ctxc, &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType:       assetType,
			Name:            ctx.String(assetTagName),
			AssetMeta:       assetMeta,
			Amount:          amount,
			NewGroupedAsset: ctx.Bool(assetNewGroupedAssetName),
			GroupedAsset:    ctx.Bool(assetGroupedAssetName),
			GroupKey:        groupKey,
			GroupAnchor:     ctx.String(assetGroupAnchorName),
			AssetVersion: taprpc.AssetVersion(
				ctx.Uint64(assetVersionName),
			),
		},
		ShortResponse: ctx.Bool(shortResponseName),
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
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: shortResponseName,
			Usage: "if true, then the current assets within the " +
				"batch will not be returned in the response " +
				"in order to avoid printing a large amount " +
				"of data in case of large batches",
		},
		cli.Uint64Flag{
			Name: feeRateName,
			Usage: "if set, the fee rate in sat/vB to use for " +
				"the minting transaction",
		},
	},
	Action: finalizeBatch,
}

func parseFeeRate(ctx *cli.Context) (uint32, error) {
	if ctx.IsSet(feeRateName) {
		userFeeRate := ctx.Uint64(feeRateName)
		if userFeeRate > math.MaxUint32 {
			return 0, fmt.Errorf("fee rate exceeds 2^32")
		}

		// Convert from sat/vB to sat/kw. Round up to the fee floor if
		// the specified feerate is too low.
		feeRate := chainfee.SatPerKVByte(userFeeRate * 1000).
			FeePerKWeight()

		if feeRate < chainfee.FeePerKwFloor {
			feeRate = chainfee.FeePerKwFloor
		}

		return uint32(feeRate), nil
	}

	return uint32(0), nil
}

func finalizeBatch(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	feeRate, err := parseFeeRate(ctx)
	if err != nil {
		return err
	}

	resp, err := client.FinalizeBatch(ctxc, &mintrpc.FinalizeBatchRequest{
		ShortResponse: ctx.Bool(shortResponseName),
		FeeRate:       feeRate,
	})
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
		Filter: &mintrpc.ListBatchRequest_BatchKey{
			BatchKey: batchKey,
		},
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
		cli.Uint64Flag{
			Name: feeRateName,
			Usage: "if set, the fee rate in sat/vB to use for " +
				"the anchor transaction",
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

	feeRate, err := parseFeeRate(ctx)
	if err != nil {
		return err
	}

	resp, err := client.SendAsset(ctxc, &taprpc.SendAssetRequest{
		TapAddrs: addrs,
		FeeRate:  feeRate,
	})
	if err != nil {
		return fmt.Errorf("unable to send assets: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var burnAssetsCommand = cli.Command{
	Name:  "burn",
	Usage: "burn a number of asset units",
	Description: `
	Burn (destroy, remove from circulation) a number of asset units in a
	provable way. The returned burn proof is cryptographic evidence that the
	assets can no longer be spent and that the supply has been reduced by
	the specified amount.

	To avoid a dangling BTC output, not all assets within a commitment can
	be burned completely, there always must be a change output (either with
	a change amount or another asset that resides in the same commitment).
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID to burn units from",
		},
		cli.Uint64Flag{
			Name:  assetAmountName,
			Usage: "the amount of units to burn/destroy",
		},
		cli.BoolFlag{
			Name: burnOverrideConfirmationName,
			Usage: "if set, the confirmation prompt will be " +
				"skipped and the assets are burned/destroyed " +
				"immediately",
		},
	},
	Action: burnAssets,
}

func burnAssets(ctx *cli.Context) error {
	if ctx.NArg() != 0 || ctx.NumFlags() == 0 {
		return cli.ShowSubcommandHelp(ctx)
	}

	assetIDHex := ctx.String(assetIDName)
	assetIDBytes, err := hex.DecodeString(assetIDHex)
	if err != nil {
		return fmt.Errorf("invalid asset ID")
	}

	burnAmount := ctx.Uint64(assetAmountName)
	if burnAmount == 0 {
		return fmt.Errorf("invalid burn amount")
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	if !ctx.Bool(burnOverrideConfirmationName) {
		balance, err := client.ListBalances(
			ctxc, &taprpc.ListBalancesRequest{
				GroupBy: &taprpc.ListBalancesRequest_AssetId{
					AssetId: true,
				},
				AssetFilter: assetIDBytes,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to list current asset "+
				"balances: %w", err)
		}

		assetBalance, ok := balance.AssetBalances[assetIDHex]
		if !ok {
			return fmt.Errorf("couldn't fetch balance for asset %x",
				assetIDBytes)
		}

		msg := fmt.Sprintf("Please confirm destructive action.\n"+
			"Asset ID: %x\nCurrent available balance: %d\n"+
			"Amount to burn: %d\n Are you sure you want to "+
			"irreversibly burn (destroy, remove from circulation) "+
			"the specified amount of assets?\nPlease answer 'yes' "+
			"or 'no' and press enter: ", assetIDBytes,
			assetBalance.Balance, burnAmount)

		if !promptForConfirmation(msg) {
			return nil
		}
	}

	resp, err := client.BurnAsset(ctxc, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: assetIDBytes,
		},
		AmountToBurn:     burnAmount,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
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
