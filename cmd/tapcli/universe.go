package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/urfave/cli"
)

const (
	proofTypeName       = "proof_type"
	skipAmountsByIdName = "skip_amounts_by_id"
)

func getUniverseClient(ctx *cli.Context) (unirpc.UniverseClient, func()) {
	conn := getClientConn(ctx, false)

	cleanUp := func() {
		conn.Close()
	}

	return unirpc.NewUniverseClient(conn), cleanUp
}

// TODO(roasbeef): all should be able to connect to remote uni
var universeCommands = []cli.Command{
	{
		Name:      "universe",
		ShortName: "u",
		Usage:     "Interact with a local or remote tap universe",
		Category:  "Universe",
		Subcommands: []cli.Command{
			multiverseRootCommand,
			universeRootsCommand,
			universeDeleteRootCommand,
			universeLeavesCommand,
			universeKeysCommand,
			universeProofCommand,
			universeSyncCommand,
			universeFederationCommand,
			universeInfoCommand,
			universeStatsCommand,
		},
	},
}

var multiverseRootCommand = cli.Command{
	Name:        "multiverse",
	ShortName:   "m",
	Description: "Show the multiverse root",
	Usage: `
	Calculate the multiverse root from the current known asset universes of
	the given proof type.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: proofTypeName,
			Usage: "the type of proof to show the root for, " +
				"either 'issuance' or 'transfer'",
			Value: universe.ProofTypeIssuance.String(),
		},
	},
	Action: multiverseRoot,
}

func multiverseRoot(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	rpcProofType, err := parseProofType(ctx)
	if err != nil {
		return err
	}

	multiverseRoot, err := client.MultiverseRoot(
		ctxc, &unirpc.MultiverseRootRequest{
			ProofType: *rpcProofType,
		},
	)
	if err != nil {
		return err
	}

	printRespJSON(multiverseRoot)
	return nil
}

var universeRootsCommand = cli.Command{
	Name:        "roots",
	ShortName:   "r",
	Description: "Query for the set of known asset universe roots",
	Usage:       "list the known asset universe roots",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the universe to query for",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of the universe to query for",
		},
		cli.StringFlag{
			Name: proofTypeName,
			Usage: "the type of proof to show the roots for, " +
				"either 'issuance' or 'transfer'",
			Value: universe.ProofTypeIssuance.String(),
		},
		cli.BoolFlag{
			Name: skipAmountsByIdName,
			Usage: "skip showing the amounts by ID for grouped " +
				"assets to optimize response size and speed",
		},
	},
	Action: universeRoots,
}

func parseProofType(ctx *cli.Context) (*unirpc.ProofType, error) {
	proofType, err := universe.ParseStrProofType(ctx.String(proofTypeName))
	if err != nil {
		return nil, err
	}
	rpcProofType, err := tap.MarshalUniProofType(proofType)
	if err != nil {
		return nil, err
	}

	if rpcProofType == unirpc.ProofType_PROOF_TYPE_UNSPECIFIED {
		return nil, fmt.Errorf("invalid proof type")
	}

	return &rpcProofType, nil
}

func parseUniverseID(ctx *cli.Context, mustParse bool) (*unirpc.ID, error) {
	rpcProofType, err := parseProofType(ctx)
	if err != nil {
		return nil, err
	}

	switch {
	// Both the asset ID and the group key can't be set.
	case ctx.IsSet(assetIDName) && ctx.IsSet(groupKeyName):
		return nil, fmt.Errorf("only asset_id or group_key can be set, " +
			"not both")

	case mustParse && !ctx.IsSet(assetIDName) && !ctx.IsSet(groupKeyName):
		return nil, fmt.Errorf("either asset_id or group_key must be " +
			"set")

	case ctx.IsSet(assetIDName):
		assetIDBytes, err := hex.DecodeString(ctx.String(assetIDName))
		if err != nil {
			return nil, err
		}
		return &unirpc.ID{
			Id: &unirpc.ID_AssetId{
				AssetId: assetIDBytes,
			},
			ProofType: *rpcProofType,
		}, nil

	case ctx.IsSet(groupKeyName):
		groupKeyBytes, err := hex.DecodeString(
			ctx.String(groupKeyName),
		)
		if err != nil {
			return nil, err
		}

		return &unirpc.ID{
			Id: &unirpc.ID_GroupKey{
				GroupKey: groupKeyBytes,
			},
			ProofType: *rpcProofType,
		}, nil

	// Neither was set, so we'll return nil.
	default:
		return nil, nil
	}
}

func universeRoots(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	universeID, err := parseUniverseID(ctx, false)
	if err != nil {
		return err
	}

	// If neither an asset ID or group key is specified, then we'll query
	// for all the known universe roots.
	if universeID == nil {
		universeRoots, err := client.AssetRoots(
			ctxc, &unirpc.AssetRootRequest{
				WithAmountsById: !ctx.Bool(skipAmountsByIdName),
			},
		)
		if err != nil {
			return err
		}

		printRespJSON(universeRoots)
		return nil
	}

	rootReq := &unirpc.AssetRootQuery{
		Id: universeID,
	}

	universeRoot, err := client.QueryAssetRoots(ctxc, rootReq)
	if err != nil {
		return err
	}

	printRespJSON(universeRoot)
	return nil
}

var universeDeleteRootCommand = cli.Command{
	Name:        "delete",
	ShortName:   "d",
	Description: "Delete a known asset universe root",
	Usage:       "delete a known asset universe root",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the universe to delete",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of the universe to delete",
		},
		cli.StringFlag{
			Name: proofTypeName,
			Usage: "the type of proof to delete the roots for, " +
				"either 'issuance' or 'transfer'",
			Value: universe.ProofTypeIssuance.String(),
		},
	},
	Action: deleteUniverseRoot,
}

func deleteUniverseRoot(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	universeID, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}

	rootReq := &unirpc.DeleteRootQuery{
		Id: universeID,
	}

	_, err = client.DeleteAssetRoot(ctxc, rootReq)
	if err != nil {
		return err
	}

	return nil
}

var universeKeysCommand = cli.Command{
	Name:      "keys",
	ShortName: "k",
	Usage:     "return the known set of keys in a Universe",
	Description: `
	Query for the set of known keys for a given asset universe. Keys take the
	form: (outpoint, script_key), where outpoint is the outpoint that anchors
	and asset, and script_key is the key for that asset within an asset_id
	tree.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the universe to query for",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of the universe to query for",
		},
		cli.StringFlag{
			Name: proofTypeName,
			Usage: "the type of proof to show the keys for, " +
				"either 'issuance' or 'transfer'",
			Value: universe.ProofTypeIssuance.String(),
		},
	},
	Action: universeKeys,
}

func universeKeys(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	universeID, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}

	assetKeys := &unirpc.AssetLeafKeyResponse{}
	offset := 0

	for {
		tempKeys, err := client.AssetLeafKeys(
			ctxc, &unirpc.AssetLeafKeysRequest{
				Id:     universeID,
				Offset: int32(offset),
				Limit:  universe.MaxPageSize,
			},
		)

		if err != nil {
			return err
		}

		if len(tempKeys.AssetKeys) == 0 {
			break
		}

		assetKeys.AssetKeys = append(
			assetKeys.AssetKeys, tempKeys.AssetKeys...,
		)
		offset += universe.MaxPageSize
	}

	printRespJSON(assetKeys)
	return nil
}

var universeLeavesCommand = cli.Command{
	Name:      "leaves",
	ShortName: "l",
	Usage:     "return the known set of leaves in a Universe",
	Description: `
	Query for the set of known leaves for a given asset universe. A leaf in a
	universe is an entry that denotes either a new issuance event (asset
	minting) or an asset transfer. A leaf includes the asset under action, a
	state transition proof for that asset.`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the universe to query for",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of the universe to query for",
		},
		cli.StringFlag{
			Name: proofTypeName,
			Usage: "the type of proof to show the leaves for, " +
				"either 'issuance' or 'transfer'",
			Value: universe.ProofTypeIssuance.String(),
		},
	},
	Action: universeLeaves,
}

func universeLeaves(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	universeID, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}

	assetLeaves, err := client.AssetLeaves(ctxc, universeID)
	if err != nil {
		return err
	}

	printRespJSON(assetLeaves)
	return nil
}

const (
	outpointName = "outpoint"
)

var universeProofArgs = []cli.Flag{
	cli.StringFlag{
		Name:  assetIDName,
		Usage: "the asset ID of the universe to query for",
	},
	cli.StringFlag{
		Name:  groupKeyName,
		Usage: "the group key of the universe to query for",
	},
	cli.StringFlag{
		Name: outpointName,
		Usage: "the target outpoint on chain to locate a tap proof " +
			"within",
	},
	cli.StringFlag{
		Name: scriptKeyName,
		Usage: "the script key (scoped to an assetID) to query a " +
			"proof for",
	},
	cli.StringFlag{
		Name: proofTypeName,
		Usage: "the type of proof to query for, either 'issuance' or " +
			"'transfer'",
		Value: universe.ProofTypeIssuance.String(),
	},
}

var universeProofCommand = cli.Command{
	Name:      "proofs",
	ShortName: "p",
	Usage:     "retrieve or insert a new Universe proof",
	Description: `
	Query for the set of proofs known by the target universe. A proof may
	be either an issuance proof, or a proof that some transfer took place
	on chain. Proofs are namespaced based on a top level assetID/groupKey,
	so that must be specified for each command.

	Two sub-commands are available: proof querying (query) and proof
	insertion (insert).
	`,
	Subcommands: []cli.Command{
		universeProofQueryCommand,
		universeProofInsertInsert,
	},
}

var universeProofQueryCommand = cli.Command{
	Name:  "query",
	Usage: "query for a universe proof",
	Description: `
	Attempt to query the target universe for a given proof based on a top
	level asset id or group key, and the leaf key of: outpoint || script key.
	`,
	Flags:  universeProofArgs,
	Action: universeProofQuery,
}

func parseAssetKey(ctx *cli.Context) (*unirpc.AssetKey, error) {
	if !ctx.IsSet(outpointName) || !ctx.IsSet(scriptKeyName) {
		return nil, fmt.Errorf("outpoint and script key must be set")
	}

	outpoint, err := wire.NewOutPointFromString(ctx.String(outpointName))
	if err != nil {
		return nil, err
	}

	return &unirpc.AssetKey{
		Outpoint: &unirpc.AssetKey_Op{
			Op: &unirpc.Outpoint{
				HashStr: outpoint.Hash.String(),
				Index:   int32(outpoint.Index),
			},
		},
		ScriptKey: &unirpc.AssetKey_ScriptKeyStr{
			ScriptKeyStr: ctx.String(scriptKeyName),
		},
	}, nil
}

func universeProofQuery(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	assetKey, err := parseAssetKey(ctx)
	if err != nil {
		return err
	}

	universeID, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}
	uProof, err := client.QueryProof(ctxc, &unirpc.UniverseKey{
		Id:      universeID,
		LeafKey: assetKey,
	})
	if err != nil {
		return err
	}

	printRespJSON(uProof)
	return nil
}

var universeProofInsertInsert = cli.Command{
	Name:  "insert",
	Usage: "insert a new universe proof",
	Description: `
	Attempt to insert a new proof into the target universe. The proof can be
	accepted either via a file argument (proof_file), via stdin, or via a hex
	encoded string.
	`,
	Flags: append(universeProofArgs, cli.StringFlag{
		Name: proofPathName,
	}),
	Action: universeProofInsert,
}

func universeProofInsert(ctx *cli.Context) error {
	if ctx.String(proofPathName) == "" {
		return cli.ShowSubcommandHelp(ctx)
	}

	assetKey, err := parseAssetKey(ctx)
	if err != nil {
		return err
	}

	universeID, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}
	filePath := lncfg.CleanAndExpandPath(ctx.String(proofPathName))
	rawFile, err := readFile(filePath)
	if err != nil {
		return fmt.Errorf("unable to read proof file: %w", err)
	}

	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	// The input should be the raw state transition proof, so we'll
	// partially parse the proof so we can hand the raw proof bytes
	// (without the checksum) to the server.
	var proofFile proof.File
	if err := proofFile.Decode(bytes.NewReader(rawFile)); err != nil {
		return fmt.Errorf("unable to decode proof file: %w", err)
	}

	assetProof, err := proofFile.LastProof()
	if err != nil {
		return err
	}
	rpcAsset, err := taprpc.MarshalAsset(
		ctxc, &assetProof.Asset, false, true, nil,
	)
	if err != nil {
		return err
	}

	rawProof, err := proofFile.RawLastProof()
	if err != nil {
		return err
	}

	req := &unirpc.AssetProof{
		Key: &unirpc.UniverseKey{
			Id:      universeID,
			LeafKey: assetKey,
		},
		AssetLeaf: &unirpc.AssetLeaf{
			Asset: rpcAsset,
			Proof: rawProof,
		},
	}
	resp, err := client.InsertProof(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var (
	universeHostName = "universe_host"
)

var universeSyncCommand = cli.Command{
	Name:        "sync",
	ShortName:   "s",
	Description: "Attempt to sync Universe state with a remote Universe",
	Usage:       "synchronize universe state with a remote instance",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: universeHostName,
			Usage: "the host:port or just host of the remote " +
				"universe",
		},
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the sync with the universe",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of sync with the universe",
		},
		cli.StringFlag{
			Name: proofTypeName,
			Usage: "the type of proof to sync either 'issuance' " +
				"or 'transfer'",
			Value: universe.ProofTypeIssuance.String(),
		},
	},
	Action: universeSync,
}

func universeSync(ctx *cli.Context) error {
	if ctx.String(universeHostName) == "" {
		return cli.ShowSubcommandHelp(ctx)
	}

	universeID, err := parseUniverseID(ctx, false)
	if err != nil {
		return err
	}

	var targets []*unirpc.SyncTarget
	if universeID != nil {
		targets = append(targets, &unirpc.SyncTarget{
			Id: universeID,
		})
	}

	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	rpcProofType, err := parseProofType(ctx)
	if err != nil {
		return err
	}
	syncMode := unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY
	if *rpcProofType == unirpc.ProofType_PROOF_TYPE_TRANSFER {
		syncMode = unirpc.UniverseSyncMode_SYNC_FULL
	}

	syncResp, err := client.SyncUniverse(ctxc, &unirpc.SyncRequest{
		UniverseHost: ctx.String(universeHostName),
		SyncTargets:  targets,
		SyncMode:     syncMode,
	})
	if err != nil {
		return err
	}

	printRespJSON(syncResp)
	return nil
}

var universeFederationCommand = cli.Command{
	Name:      "federation",
	ShortName: "f",
	Usage:     "manage the set of active servers in the Universe Federation",
	Description: `
	Manage the set of active Universe Federation servers. These servers
	will be used to push out any new proof updates generated within the RPC
	interface. These servers will also be used to periodically reconcile
	Universe state roots for any active/known assets.
	`,
	Subcommands: []cli.Command{
		universeFederationListCommand,
		universeFederationAddCommand,
		universeFederationDelCommand,
		universeFederationConfigCommand,
	},
}

var universeFederationListCommand = cli.Command{
	Name:        "list",
	ShortName:   "l",
	Description: "List the set of active servers in the Federation",
	Flags:       []cli.Flag{},
	Action:      universeFederationList,
}

func universeFederationList(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	servers, err := client.ListFederationServers(
		ctxc, &unirpc.ListFederationServersRequest{},
	)
	if err != nil {
		return err
	}

	printRespJSON(servers)
	return nil
}

var universeFederationAddCommand = cli.Command{
	Name:      "add",
	ShortName: "a",
	Description: `
	Add a new server to the Federation. Newly added servers will be synced
	automatically, will also be used to push out newly validated proofs.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: universeHostName,
			Usage: "the address for the universe server, eg: " +
				"testnet.mydomain.com:10029. The default port " +
				"(10029) will be used if none is provided",
		},
	},
	Action: universeFederationAdd,
}

func universeFederationAdd(ctx *cli.Context) error {
	if ctx.String(universeHostName) == "" {
		return cli.ShowSubcommandHelp(ctx)
	}

	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	resp, err := client.AddFederationServer(
		ctxc, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: ctx.String(universeHostName),
				},
			},
		},
	)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

const universeServerID = "server_id"

var universeFederationDelCommand = cli.Command{
	Name:      "del",
	ShortName: "d",
	Description: `
	Remove a server from the Federation. Servers can be identified either
	via their ID, or the server host.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: universeHostName,
			Usage: "the host:port or just host of the remote " +
				"universe",
		},
		cli.IntFlag{
			Name:  universeServerID,
			Usage: "the ID of the universe server to delete",
		},
	},
	Action: universeFederationDel,
}

func universeFederationDel(ctx *cli.Context) error {
	if ctx.String(universeHostName) == "" &&
		ctx.Int(universeServerID) == 0 {

		return cli.ShowSubcommandHelp(ctx)
	}

	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	resp, err := client.DeleteFederationServer(
		ctxc, &unirpc.DeleteFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Id:   int32(ctx.Int(universeServerID)),
					Host: ctx.String(universeHostName),
				},
			},
		},
	)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var universeFederationConfigCommand = cli.Command{
	Name:      "config",
	ShortName: "c",
	Usage:     "Change the sync behavior of the local Universe",
	Description: `
	Manage the sync behavior of the local Universe. These settings are
	defined by the proof type (issuance or transfer), the sync behavior
	(insert from remote Universe or export to remote Universe), and the
	scope (all assets or specific assets).
        `,
	Subcommands: []cli.Command{
		universeFederationGlobalConfig,
		universeFederationLocalConfig,
		universeFederationConfigInfo,
	},
}

var (
	universeConfigScope    = "config_scope"
	proofInsertName        = "allow_insert"
	proofExportName        = "allow_export"
	universeSyncConfigArgs = []cli.Flag{
		cli.StringFlag{
			Name:  proofTypeName,
			Usage: "the type of proof",
		},
		cli.StringFlag{
			Name: proofInsertName,
			Usage: "if true, remote Universes can push proofs to " +
				"the local Universe",
		},
		cli.StringFlag{
			Name: proofExportName,
			Usage: "if true, remote Universes can pull proofs " +
				"from the local Universe",
		},
	}
)

func isValidBool(arg string) (bool, error) {
	// The cli.BoolFlag works for variables that are false by default, but
	// here we don't want a default for this argument.
	switch arg {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool flag")
	}
}

func parseConfigArgs(ctx *cli.Context) (*bool, *bool, error) {
	var (
		insertOpt, exportOpt bool
		err                  error
	)

	if !ctx.IsSet(proofInsertName) && !ctx.IsSet(proofExportName) {
		return nil, nil, fmt.Errorf("either insert or export must be " +
			"set")
	}

	// Parse the insert and export flags, which are not mutually exclusive.
	if ctx.IsSet(proofInsertName) {
		insertOpt, err = isValidBool(ctx.String(proofInsertName))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid proof insert flag")
		}
	}

	if ctx.IsSet(proofExportName) {
		exportOpt, err = isValidBool(ctx.String(proofExportName))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid proof export flag")
		}
	}

	switch {
	case ctx.IsSet(proofExportName) && ctx.IsSet(proofInsertName):
		return &insertOpt, &exportOpt, nil

	case ctx.IsSet(proofInsertName):
		return &insertOpt, nil, nil

	case ctx.IsSet(proofExportName):
		return nil, &exportOpt, nil

	default:
		return nil, nil, nil
	}
}

var universeFederationGlobalConfig = cli.Command{
	Name:      "global",
	ShortName: "g",
	Usage:     "Change the global sync behavior of the local Universe",
	Description: `
	Manage the sync behavior of the local Universe that will apply to all
	assets by default. Per-asset sync behavior will override global
	settings. These settings are defined by the proof type (issuance or
	transfer) and the sync behavior (insert from remote Universe or export
	to remote Universe).
        `,
	Flags:  universeSyncConfigArgs,
	Action: universeFederationUpdateGlobalConfig,
}

func universeFederationUpdateGlobalConfig(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	// There is no default proof type, so we need to make sure this
	// flag is set.
	if !ctx.IsSet(proofTypeName) {
		return fmt.Errorf("must specify proof type")
	}

	rpcProofType, err := parseProofType(ctx)
	if err != nil {
		return err
	}

	insertOpt, exportOpt, err := parseConfigArgs(ctx)
	if err != nil {
		return err
	}

	// Read the current global config for the matching proof type.
	syncConfigs, err := client.QueryFederationSyncConfig(
		ctxc, &unirpc.QueryFederationSyncConfigRequest{},
	)
	if err != nil {
		return err
	}

	// This should never occur, as we always have the default configs.
	if syncConfigs.GlobalSyncConfigs == nil {
		return fmt.Errorf("no global sync configs found")
	}

	currentConfig, err := fn.First(
		syncConfigs.GlobalSyncConfigs,
		func(cfg *unirpc.GlobalFederationSyncConfig) bool {
			return cfg.ProofType == *rpcProofType
		},
	)

	if err != nil {
		return fmt.Errorf("no existing config found")
	}

	// Modify the existing config and update it on disk.
	if insertOpt != nil {
		currentConfig.AllowSyncInsert = *insertOpt
	}
	if exportOpt != nil {
		currentConfig.AllowSyncExport = *exportOpt
	}

	configReq := &unirpc.SetFederationSyncConfigRequest{
		GlobalSyncConfigs: []*unirpc.GlobalFederationSyncConfig{
			currentConfig,
		},
	}

	resp, err := client.SetFederationSyncConfig(ctxc, configReq)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var universeFederationLocalConfig = cli.Command{
	Name:      "local",
	ShortName: "l",
	Usage: "Change the sync behavior of the local Universe for a " +
		"specific asset",
	Description: `
	Manage the sync behavior of the local Universe for a specific asset.
	Local settings will override global settings. These settings are
	defined by the proof type (issuance or transfer) and the sync behavior
	(insert from remote Universe or export to remote Universe).
        `,
	Flags: append(universeSyncConfigArgs,
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the universe to configure",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of the universe to configure",
		}),
	Action: universeFederationUpdateLocalConfig,
}

func universeFederationUpdateLocalConfig(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	universeID, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}

	if universeID == nil {
		return fmt.Errorf("invalid universe ID")
	}

	insertOpt, exportOpt, err := parseConfigArgs(ctx)
	if err != nil {
		return err
	}

	// Read the current local config for the matching Universe if it exists.
	syncConfigs, err := client.QueryFederationSyncConfig(
		ctxc, &unirpc.QueryFederationSyncConfigRequest{},
	)
	if err != nil {
		return err
	}

	var localConfig *unirpc.AssetFederationSyncConfig
	switch {
	case syncConfigs.AssetSyncConfigs == nil:
		// Create a new config for this asset.
		localConfig = &unirpc.AssetFederationSyncConfig{
			Id: universeID,
		}

	default:
		// We have some asset-specific configs, so search for one that
		// matches the specified asset.
		localConfig, err = fn.First(
			syncConfigs.AssetSyncConfigs,
			func(cfg *unirpc.AssetFederationSyncConfig) bool {
				return cfg.Id == universeID
			},
		)

		if err != nil {
			// Create a new config for this asset.
			localConfig = &unirpc.AssetFederationSyncConfig{
				Id: universeID,
			}
		}
	}

	if insertOpt != nil {
		localConfig.AllowSyncInsert = *insertOpt
	}
	if exportOpt != nil {
		localConfig.AllowSyncExport = *exportOpt
	}

	configReq := &unirpc.SetFederationSyncConfigRequest{
		AssetSyncConfigs: []*unirpc.AssetFederationSyncConfig{
			localConfig,
		},
	}

	resp, err := client.SetFederationSyncConfig(ctxc, configReq)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var universeFederationConfigInfo = cli.Command{
	Name:      "info",
	ShortName: "i",
	Usage:     "Get the sync behavior of the local Universe",
	Description: `
        Get the sync behavior of the local Universe. These settings are
        defined by the proof type (issuance or transfer), the sync behavior
        (insert from remote Universe or export to remote Universe), and the
        scope (all assets or specific assets).
        `,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  universeConfigScope,
			Usage: "the scope (global or local) of the config",
		},
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the universe",
		},
		cli.StringFlag{
			Name:  groupKeyName,
			Usage: "the group key of the universe",
		},
	},
	Action: universeFederationGetConfigInfo,
}

func universeFederationGetConfigInfo(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	validScopes := []string{"global", "local"}
	parseConfigScope := func(ctx *cli.Context) (string, error) {
		if !ctx.IsSet(universeConfigScope) {
			return "", fmt.Errorf("config scope not specified")
		}

		scope := ctx.String(universeConfigScope)
		isValid := fn.Any(validScopes, func(s string) bool {
			return s == scope
		})

		if !isValid {
			return "", fmt.Errorf("invalid config scope")
		}

		return scope, nil
	}

	// Fetch all configs, and then filter passed on the flags set.
	syncConfigs, err := client.QueryFederationSyncConfig(
		ctxc, &unirpc.QueryFederationSyncConfigRequest{},
	)
	if err != nil {
		return err
	}

	if !ctx.IsSet(assetIDName) && !ctx.IsSet(groupKeyName) {
		// The default scope is both global and local.
		if !ctx.IsSet(universeConfigScope) {
			printRespJSON(syncConfigs)
			return nil
		}

		scope, err := parseConfigScope(ctx)
		if err != nil {
			return err
		}

		switch scope {
		case "global":
			for _, config := range syncConfigs.GlobalSyncConfigs {
				config := config
				printRespJSON(config)
			}

			return nil

		case "local":
			return fmt.Errorf("local scope requires " +
				"universe ID fields")
		}
	}

	// Match configs for both proof types for the specified Universe.
	err = ctx.Set(proofTypeName, "issuance")
	if err != nil {
		return err
	}

	uniIdIssuance, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}

	err = ctx.Set(proofTypeName, "transfer")
	if err != nil {
		return err
	}

	uniIdTransfer, err := parseUniverseID(ctx, true)
	if err != nil {
		return err
	}

	matchingLocalConfig := func(c *unirpc.AssetFederationSyncConfig) bool {
		return c.Id == uniIdIssuance || c.Id == uniIdTransfer
	}

	printLocalConfig := func() error {
		localConfig := fn.Filter(
			syncConfigs.AssetSyncConfigs, matchingLocalConfig,
		)
		if len(localConfig) == 0 {
			return fmt.Errorf("no matching universe configs found")
		}

		for _, config := range localConfig {
			config := config
			printRespJSON(config)
		}

		return nil
	}

	// If an asset was specified, the scope can be missing or local.
	if !ctx.IsSet(universeConfigScope) {
		return printLocalConfig()
	}

	scope, err := parseConfigScope(ctx)
	if err != nil {
		return err
	}

	if scope == "global" {
		return fmt.Errorf("cannot specify global scope and a " +
			"specific asset")
	}

	return printLocalConfig()
}

var universeInfoCommand = cli.Command{
	Name:      "info",
	ShortName: "i",
	Usage:     "query for info related to the active local Universe server",
	Description: `
	Query for information related to the local Universe server.
	`,
	Action: universeInfo,
}

func universeInfo(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	resp, err := client.Info(ctxc, &unirpc.InfoRequest{})
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var universeStatsCommand = cli.Command{
	Name:      "stats",
	ShortName: "s",
	Usage:     "query for stats related to the active local Universe server",
	Description: `
	Query for a set of aggregate statistics related to the local Universe
	server.  The 'universe stats asset' sub-command can be used to query
	for stats for a given asset, asset name, or type.
	`,
	Action: universeStatsSummaryCommand,
	Subcommands: []cli.Command{
		universeAssetStatsCommand,
		universeEventStatsCommand,
	},
}

func universeStatsSummaryCommand(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	resp, err := client.UniverseStats(ctxc, &unirpc.StatsRequest{})
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

const (
	assetName = "asset_name"

	assetType = "asset_type"

	sortByName = "sort_by"

	startTime = "start_time"

	endTime = "end_time"
)

var universeAssetStatsCommand = cli.Command{
	Name:      "assets",
	ShortName: "a",
	Usage:     "query Universe stats for a single asset",
	Description: `
	Query for stats related to a given asset or series of assets identified
	by the set of available filters. This command support pagination (via
	the offset+limit) commands, and also allows for sorting by a given
	filter value.
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetName,
			Usage: "the name of the asset to query for",
		},
		cli.StringFlag{
			Name:  assetType,
			Usage: "the type of the asset to query for",
		},
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the asset to query for",
		},
		cli.StringFlag{
			Name: sortByName,
			Usage: "the name of the field to sort by, " +
				"[--sort_by=asset_name|asset_type|asset_id]",
		},
		cli.Int64Flag{
			Name:  limitName,
			Usage: "the maximum number of results to return",
		},
		cli.Int64Flag{
			Name:  offsetName,
			Usage: "the offset to start returning results from",
		},
	},
	Action: universeStatsQueryCommand,
}

func universeStatsQueryCommand(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	// Validate the user is attempting to sort by the correct value
	switch ctx.String(sortByName) {
	case "asset_name":
	case "asset_type":
	case "asset_id":
	default:
		return fmt.Errorf("invalid sort_by value: %v",
			ctx.String(sortByName))
	}

	var (
		assetID []byte
		err     error
	)
	if ctx.String(assetIDName) != "" {
		assetID, err = hex.DecodeString(ctx.String(assetIDName))
		if err != nil {
			return fmt.Errorf("unable to decode asset id: %w", err)
		}
	}

	resp, err := client.QueryAssetStats(ctxc, &unirpc.AssetStatsQuery{
		AssetNameFilter: ctx.String(assetName),
		AssetIdFilter:   assetID,
		AssetTypeFilter: func() unirpc.AssetTypeFilter {
			switch {
			case ctx.String(assetTypeName) == "normal":
				return unirpc.AssetTypeFilter_FILTER_ASSET_NORMAL

			case ctx.String(assetTypeName) == "collectible":
				return unirpc.AssetTypeFilter_FILTER_ASSET_COLLECTIBLE

			default:
				return unirpc.AssetTypeFilter_FILTER_ASSET_NONE
			}
		}(),
		SortBy: func() unirpc.AssetQuerySort {
			switch {
			case ctx.String(sortByName) == "asset_name":
				return unirpc.AssetQuerySort_SORT_BY_ASSET_NAME

			case ctx.String(sortByName) == "asset_id":
				return unirpc.AssetQuerySort_SORT_BY_ASSET_ID

			case ctx.String(sortByName) == "asset_type":
				return unirpc.AssetQuerySort_SORT_BY_ASSET_TYPE

			default:
				return unirpc.AssetQuerySort_SORT_BY_NONE
			}
		}(),
		Limit:  int32(ctx.Int64(limitName)),
		Offset: int32(ctx.Int64(offsetName)),
	})
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var universeEventStatsCommand = cli.Command{
	Name:      "events",
	ShortName: "e",
	Usage:     "query Universe event stats",
	Description: `
	Query for the number of sync and proof events for a given time
    	period, grouped by day.
	`,
	Flags: []cli.Flag{
		cli.Int64Flag{
			Name: startTime,
			Usage: "(optional) the unix timestamp to start " +
				"querying from; if not specified, will query " +
				"from last 30 days by default",
		},
		cli.Int64Flag{
			Name: offsetName,
			Usage: "(optional) the unix timestamp to end " +
				"querying from; if not specified, will query " +
				"until now by default",
		},
	},
	Action: universeEventStatsQueryCommand,
}

func universeEventStatsQueryCommand(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getUniverseClient(ctx)
	defer cleanUp()

	resp, err := client.QueryEvents(ctxc, &unirpc.QueryEventsRequest{
		StartTimestamp: ctx.Int64(startTime),
		EndTimestamp:   ctx.Int64(endTime),
	})
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}
