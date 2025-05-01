package commands

import (
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/tapcfg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/urfave/cli"
	"golang.org/x/exp/maps"
)

var (
	// nolint:lll
	scriptKeyTypeMap = map[string]taprpc.ScriptKeyType{
		"unknown":     taprpc.ScriptKeyType_SCRIPT_KEY_UNKNOWN,
		"bip86":       taprpc.ScriptKeyType_SCRIPT_KEY_BIP86,
		"script-path": taprpc.ScriptKeyType_SCRIPT_KEY_SCRIPT_PATH_EXTERNAL,
		"burn":        taprpc.ScriptKeyType_SCRIPT_KEY_BURN,
		"tombstone":   taprpc.ScriptKeyType_SCRIPT_KEY_TOMBSTONE,
		"channel":     taprpc.ScriptKeyType_SCRIPT_KEY_CHANNEL,
	}
)

// parseScriptKeyType parses the script key type query from the command line
// context. If the user didn't specify a script key type, the "show all" query
// type is returned.
func parseScriptKeyType(c *cli.Context) (*taprpc.ScriptKeyTypeQuery, error) {
	allScriptKeysQuery := &taprpc.ScriptKeyTypeQuery{
		Type: &taprpc.ScriptKeyTypeQuery_AllTypes{
			AllTypes: true,
		},
	}

	if !c.IsSet(scriptKeyTypeName) || c.String(scriptKeyTypeName) == "" {
		return allScriptKeysQuery, nil
	}

	scriptKeyType, ok := scriptKeyTypeMap[c.String(scriptKeyTypeName)]
	if !ok {
		return nil, fmt.Errorf("script key type '%v' is unknown",
			c.String(scriptKeyTypeName))
	}

	return &taprpc.ScriptKeyTypeQuery{
		Type: &taprpc.ScriptKeyTypeQuery_ExplicitType{
			ExplicitType: scriptKeyType,
		},
	}, nil
}

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
			listBurnsCommand,
			listTransfersCommand,
			fetchMetaCommand,
		},
	},
}

var (
	assetTypeName                 = "type"
	assetTagName                  = "name"
	assetSupplyName               = "supply"
	assetMetaBytesName            = "meta_bytes"
	assetMetaFilePathName         = "meta_file_path"
	assetMetaTypeName             = "meta_type"
	assetDecimalDisplayName       = "decimal_display"
	assetNewGroupedAssetName      = "new_grouped_asset"
	assetGroupedAssetName         = "grouped_asset"
	assetShowWitnessName          = "show_witness"
	assetShowSpentName            = "show_spent"
	assetShowLeasedName           = "show_leased"
	assetIncludeLeasedName        = "include_leased"
	assetShowUnconfMintsName      = "show_unconfirmed_mints"
	assetGroupKeyName             = "group_key"
	assetGroupAnchorName          = "group_anchor"
	anchorTxidName                = "anchor_txid"
	batchKeyName                  = "batch_key"
	groupByGroupName              = "by_group"
	assetIDName                   = "asset_id"
	shortResponseName             = "short"
	universeCommitmentsName       = "universe_commitments"
	feeRateName                   = "sat_per_vbyte"
	skipProofCourierPingCheckName = "skip-proof-courier-ping-check"
	assetAmountName               = "amount"
	burnOverrideConfirmationName  = "override_confirmation_destroy_assets"
	scriptKeyTypeName             = "script_key_type"
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
			Name: assetDecimalDisplayName,
			Usage: "the number of decimal places, " +
				"asset amounts, are shift to the left " +
				"converting asset integer amounts" +
				"into UI-recognizable fractional " +
				"quantity (e.g. an asset with amount" +
				"100 and decimal display of 2 is " +
				"displayed as 1.00 in the wallet)",
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
		cli.StringFlag{
			Name: "group_key_xpub",
			Usage: "the xpub of the group key to use to mint the " +
				"asset",
		},
		cli.StringFlag{
			Name: "group_key_derivation_path",
			Usage: "the derivation path that was used to derive " +
				"the group key xpub",
		},
		cli.StringFlag{
			Name: "group_key_fingerprint",
			Usage: "the master fingerprint of the key the xpub " +
				"was derived from",
		},
		cli.BoolFlag{
			Name: universeCommitmentsName,
			Usage: "if set, the asset group will be minted with " +
				"universe commitments enabled " +
				"(minter-controlled, on-chain attestations " +
				"that anchor and verify the state of an " +
				"asset group); this option restricts the " +
				"minting batch to a single asset group",
		},
	},
	Action: mintAsset,
	Subcommands: []cli.Command{
		listBatchesCommand,
		fundBatchCommand,
		sealBatchCommand,
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

func parseMetaType(metaType string) (taprpc.AssetMetaType, error) {
	switch metaType {
	case "opaque":
		fallthrough
	case "blob":
		return taprpc.AssetMetaType_META_TYPE_OPAQUE, nil

	case "json":
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

	var (
		metaTypeStr  = ctx.String(assetMetaTypeName)
		metaBytes    = ctx.String(assetMetaBytesName)
		metaFilePath = ctx.String(assetMetaFilePathName)
		decDisplay   = ctx.Uint64(assetDecimalDisplayName)
	)

	if decDisplay > math.MaxUint32 {
		return fmt.Errorf("decimal display must be a valid uint32")
	}

	metaType, err := parseMetaType(metaTypeStr)
	if err != nil {
		return fmt.Errorf("unable to parse meta type: %w", err)
	}

	// Before setting a non-empty meta, reject invalid combinations of
	// metadata-related flags.
	var assetMeta *taprpc.AssetMeta
	switch {
	case metaBytes != "" && metaFilePath != "":
		return fmt.Errorf("meta bytes and meta file path cannot both " +
			"be set")

	case metaBytes == "" && metaFilePath == "":
		switch metaType {
		// Opaque is the default if the meta_type flag is not set, so
		// having empty metadata is allowed.
		case taprpc.AssetMetaType_META_TYPE_OPAQUE:
		case taprpc.AssetMetaType_META_TYPE_JSON:
			// Set only the metadata type; if present, the decimal
			// display will be added as the actual metadata later.
			// The minter will ultimately reject empty metadata.
			assetMeta = &taprpc.AssetMeta{
				Type: metaType,
			}

		// A custom meta type requires metadata to be present.
		default:
			return fmt.Errorf("metadata must be present for " +
				"custom meta types")
		}
	}

	// One of meta bytes or the meta path can be set.
	switch {
	case ctx.String(assetMetaBytesName) != "":
		assetMeta = &taprpc.AssetMeta{
			Data: []byte(ctx.String(assetMetaBytesName)),
			Type: metaType,
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
			Type: metaType,
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

	gkXPub := ctx.String("group_key_xpub")
	gkPath := ctx.String("group_key_derivation_path")
	gkFingerprint := ctx.String("group_key_fingerprint")

	var externalKey *taprpc.ExternalKey
	switch {
	case (gkXPub != "" || gkPath != "" || gkFingerprint != "") &&
		(gkXPub == "" || gkPath == "" || gkFingerprint == ""):

		return fmt.Errorf("group key xpub, derivation path, and " +
			"fingerprint must all be set or all be empty")

	case gkXPub != "" && gkPath != "" && gkFingerprint != "":
		fingerPrintBytes, err := hex.DecodeString(gkFingerprint)
		if err != nil {
			return fmt.Errorf("cannot hex decode group key "+
				"fingerprint: %w", err)
		}

		externalKey = &taprpc.ExternalKey{
			Xpub:              gkXPub,
			MasterFingerprint: fingerPrintBytes,
			DerivationPath:    gkPath,
		}
	}

	resp, err := client.MintAsset(ctxc, &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType:       assetType,
			Name:            ctx.String(assetTagName),
			AssetMeta:       assetMeta,
			DecimalDisplay:  uint32(decDisplay),
			Amount:          amount,
			NewGroupedAsset: ctx.Bool(assetNewGroupedAssetName),
			GroupedAsset:    ctx.Bool(assetGroupedAssetName),
			GroupKey:        groupKey,
			GroupAnchor:     ctx.String(assetGroupAnchorName),
			AssetVersion: taprpc.AssetVersion(
				ctx.Uint64(assetVersionName),
			),
			ExternalGroupKey:    externalKey,
			UniverseCommitments: ctx.Bool(universeCommitmentsName),
		},
		ShortResponse: ctx.Bool(shortResponseName),
	})
	if err != nil {
		return fmt.Errorf("unable to mint asset: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var fundBatchCommand = cli.Command{
	Name:  "fund",
	Usage: "fund a batch",
	Description: `
	Attempt to fund a pending batch, or create a new funded batch if no
	batch exists yet. This is only needed if batch funding should happen
	separately from batch finalization. Otherwise, finalize can be used.
	`,
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
	Action: fundBatch,
}

func fundBatch(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	feeRate, err := parseFeeRate(ctx)
	if err != nil {
		return err
	}

	resp, err := client.FundBatch(ctxc, &mintrpc.FundBatchRequest{
		ShortResponse: ctx.Bool(shortResponseName),
		FeeRate:       feeRate,
	})
	if err != nil {
		return fmt.Errorf("unable to fund batch: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var sealBatchCommand = cli.Command{
	Name:  "seal",
	Usage: "seal a batch",
	Description: `
	Attempt to seal the pending batch by creating asset group witnesses for
	all assets in the batch. Custom witnesses can only be submitted via RPC.
	This command is only needed if batch sealing should happen separately
	from batch finalization. Otherwise, finalize can be used.
	`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: shortResponseName,
			Usage: "if true, then the current assets within the " +
				"batch will not be returned in the response " +
				"in order to avoid printing a large amount " +
				"of data in case of large batches",
		},
		cli.StringSliceFlag{
			Name: "group_signatures",
			Usage: "the asset ID and signature, separated by a " +
				"colon. This flag should not be used in " +
				"conjunction with 'signed_group_psbt'; use " +
				"one or the other.",
		},
		cli.StringSliceFlag{
			Name: "signed_group_psbt",
			Usage: "a signed group PSBT for a single asset group " +
				"in the batch. This flag should not be used " +
				"in conjunction with 'group_signatures'; use " +
				"one or the other.",
		},
	},
	Hidden: true,
	Action: sealBatch,
}

func sealBatch(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getMintClient(ctx)
	defer cleanUp()

	req := &mintrpc.SealBatchRequest{
		ShortResponse:           ctx.Bool(shortResponseName),
		SignedGroupVirtualPsbts: ctx.StringSlice("signed_group_psbt"),
	}

	sigs := ctx.StringSlice("group_signatures")
	for _, witness := range sigs {
		parts := strings.Split(witness, ":")
		assetIDHex, sigHex := parts[0], parts[1]
		assetIDBytes, err := hex.DecodeString(assetIDHex)
		if err != nil {
			return fmt.Errorf("invalid asset ID")
		}

		sigBytes, err := hex.DecodeString(sigHex)
		if err != nil {
			return fmt.Errorf("invalid signature")
		}

		req.GroupWitnesses = append(
			req.GroupWitnesses, &taprpc.GroupWitness{
				GenesisId: assetIDBytes,
				Witness:   [][]byte{sigBytes},
			},
		)
	}

	resp, err := client.SealBatch(ctxc, req)
	if err != nil {
		return fmt.Errorf("unable to seal batch: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var finalizeBatchCommand = cli.Command{
	Name:        "finalize",
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
		cli.BoolFlag{
			Name: "verbose",
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
		Verbose: ctx.Bool("verbose"),
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
		cli.BoolFlag{
			Name:  assetShowLeasedName,
			Usage: "include leased assets in the list",
		},
		cli.BoolFlag{
			Name: assetShowUnconfMintsName,
			Usage: "include freshly minted and not yet confirmed " +
				"assets in the list",
		},
		cli.StringFlag{
			Name: scriptKeyTypeName,
			Usage: "filter assets by the type of script key they " +
				"use; possible values are: " +
				strings.Join(maps.Keys(scriptKeyTypeMap), ", "),
		},
	},
	Action: listAssets,
}

func listAssets(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	// TODO(roasbeef): need to reverse txid

	scriptKeyQuery, err := parseScriptKeyType(ctx)
	if err != nil {
		return fmt.Errorf("unable to parse script key type: %w", err)
	}

	resp, err := client.ListAssets(ctxc, &taprpc.ListAssetRequest{
		WithWitness:             ctx.Bool(assetShowWitnessName),
		IncludeSpent:            ctx.Bool(assetShowSpentName),
		IncludeLeased:           ctx.Bool(assetShowLeasedName),
		IncludeUnconfirmedMints: ctx.Bool(assetShowUnconfMintsName),
		ScriptKeyType:           scriptKeyQuery,
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
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  assetShowLeasedName,
			Usage: "include leased assets in the list",
		},
		cli.StringFlag{
			Name: scriptKeyTypeName,
			Usage: "filter assets by the type of script key they " +
				"use; possible values are: " +
				strings.Join(maps.Keys(scriptKeyTypeMap), ", "),
		},
	},
	Action: listUtxos,
}

func listUtxos(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	scriptKeyQuery, err := parseScriptKeyType(ctx)
	if err != nil {
		return fmt.Errorf("unable to parse script key type: %w", err)
	}

	resp, err := client.ListUtxos(ctxc, &taprpc.ListUtxosRequest{
		IncludeLeased: ctx.Bool(assetShowLeasedName),
		ScriptKeyType: scriptKeyQuery,
	})
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
		cli.BoolFlag{
			Name:  assetIncludeLeasedName,
			Usage: "Include leased assets in balances",
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
		cli.StringFlag{
			Name: scriptKeyTypeName,
			Usage: "filter assets by the type of script key they " +
				"use; possible values are: " +
				strings.Join(maps.Keys(scriptKeyTypeMap), ", "),
		},
	},
}

func listAssetBalances(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	scriptKeyQuery, err := parseScriptKeyType(ctx)
	if err != nil {
		return fmt.Errorf("unable to parse script key type: %w", err)
	}

	req := &taprpc.ListBalancesRequest{
		IncludeLeased: ctx.Bool(assetIncludeLeasedName),
		ScriptKeyType: scriptKeyQuery,
	}

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
		cli.BoolFlag{
			Name:  skipProofCourierPingCheckName,
			Usage: "if set, skip the proof courier ping check",
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
		SkipProofCourierPingCheck: ctx.Bool(
			skipProofCourierPingCheckName,
		),
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

var listBurnsCommand = cli.Command{
	Name:  "listburns",
	Usage: "list burnt assets",
	Description: `
	List assets that have been burned by this daemon. These are assets that
	have been destroyed and are no longer spendable.

	Some filters may be used to return more specific results.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the burnt asset",
		},
		cli.StringFlag{
			Name:  assetGroupKeyName,
			Usage: "the group key of the burnt asset",
		},
		cli.StringFlag{
			Name: anchorTxidName,
			Usage: "the txid of the transaction the burn was " +
				"anchored to",
		},
	},
	Action: listBurns,
}

func listBurns(ctx *cli.Context) error {
	assetIDHex := ctx.String(assetIDName)
	assetIDBytes, err := hex.DecodeString(assetIDHex)
	if err != nil {
		return fmt.Errorf("invalid asset ID: %w", err)
	}

	groupKeyHex := ctx.String(assetGroupKeyName)
	groupKeyBytes, err := hex.DecodeString(groupKeyHex)
	if err != nil {
		return fmt.Errorf("invalid group key: %w", err)
	}

	anchorTxidStr := ctx.String(anchorTxidName)
	anchorTxid, err := hex.DecodeString(anchorTxidStr)
	if err != nil {
		return fmt.Errorf("invalid anchor txid: %w", err)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.ListBurns(
		ctxc, &taprpc.ListBurnsRequest{
			AssetId:         assetIDBytes,
			TweakedGroupKey: groupKeyBytes,
			AnchorTxid:      anchorTxid,
		},
	)
	if err != nil {
		return fmt.Errorf("could not list burns: %w", err)
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
