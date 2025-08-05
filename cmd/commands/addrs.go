package commands

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/urfave/cli"
)

var addrCommands = []cli.Command{
	{
		Name:      "addrs",
		ShortName: "ad",
		Usage:     "Interact with Taproot Asset addresses.",
		Category:  "Addresses",
		Subcommands: []cli.Command{
			newAddrCommand,
			queryAddrsCommand,
			decodeAddrCommand,
			receivesAddrCommand,
		},
	},
}

const (
	groupKeyName         = "group_key"
	amtName              = "amt"
	assetVersionName     = "asset_version"
	addressVersionName   = "address_version"
	proofCourierAddrName = "proof_courier_addr"
)

var newAddrCommand = cli.Command{
	Name:      "new",
	ShortName: "n",
	Usage:     "Create a Taproot Asset address",
	Description: "Create a new Taproot Asset address to receive an asset " +
		"on-chain",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset genesis ID of the asset to receive",
		},
		cli.StringFlag{
			Name: groupKeyName,
			Usage: "the group key of the asset to receive, if " +
				"the asset is part of a group",
		},
		cli.Uint64Flag{
			Name:  amtName,
			Usage: "the amt of the asset to receive",
		},
		cli.Uint64Flag{
			Name:  assetVersionName,
			Usage: "the asset version of the asset to receive",
		},
		cli.StringFlag{
			Name:  addressVersionName,
			Usage: "the version of address to generate",
		},
		cli.StringFlag{
			Name: proofCourierAddrName,
			Usage: "(optional) the address of the proof courier " +
				"to use for this specific address, if the " +
				"default proof courier should be " +
				"overwritten; format: protocol://host:port",
		},
	},
	Action: newAddr,
}

func newAddr(ctx *cli.Context) error {
	if ctx.String(assetIDName) == "" && ctx.String(groupKeyName) == "" {
		return cli.ShowSubcommandHelp(ctx)
	}

	var (
		assetID  []byte
		groupKey []byte
		err      error
	)
	switch {
	case ctx.IsSet(assetIDName) && ctx.IsSet(groupKeyName):
		return fmt.Errorf("cannot set both %s and %s, only one is "+
			"allowed", assetIDName, groupKeyName)

	case ctx.IsSet(assetIDName):
		assetID, err = hex.DecodeString(ctx.String(assetIDName))
		if err != nil {
			return fmt.Errorf("unable to decode assetID: %w", err)
		}

	case ctx.IsSet(groupKeyName):
		groupKey, err = hex.DecodeString(ctx.String(groupKeyName))
		if err != nil {
			return fmt.Errorf("unable to decode group key: %w", err)
		}
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	assetVersion, err := rpcutils.MarshalAssetVersion(
		asset.Version(ctx.Uint64(assetVersionName)),
	)
	if err != nil {
		return err
	}

	addrVersion := taprpc.AddrVersion_ADDR_VERSION_V1
	switch ctx.String(addressVersionName) {
	case "":
		// We know that if a group key is set, then we need to be using
		// at least a V2 address. So we can just use that if the user
		// specifies no explicit version.
		if len(groupKey) > 0 {
			addrVersion = taprpc.AddrVersion_ADDR_VERSION_V2
		}

	case "v0", "V0":
		addrVersion = taprpc.AddrVersion_ADDR_VERSION_V0
	case "v1", "V1":
		addrVersion = taprpc.AddrVersion_ADDR_VERSION_V1
	case "v2", "V2":
		addrVersion = taprpc.AddrVersion_ADDR_VERSION_V2
	default:
		return fmt.Errorf("unknown address version: %s",
			ctx.String(addressVersionName))
	}

	addr, err := client.NewAddr(ctxc, &taprpc.NewAddrRequest{
		AssetId:          assetID,
		GroupKey:         groupKey,
		Amt:              ctx.Uint64(amtName),
		AssetVersion:     assetVersion,
		ProofCourierAddr: ctx.String(proofCourierAddrName),
		AddressVersion:   addrVersion,
	})
	if err != nil {
		return fmt.Errorf("unable to make addr: %w", err)
	}

	printRespJSON(addr)
	return nil
}

const (
	createdAfterName = "created_after"

	createdBeforeName = "created_before"

	limitName = "limit"

	offsetName = "offset"
)

var queryAddrsCommand = cli.Command{
	Name:        "query",
	ShortName:   "q",
	Usage:       "Query for the set of created addresses",
	Description: "Query for the set of created addresses, supports pagination",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  createdAfterName,
			Usage: "a duration short hand (-1h, 2d, 2w, etc)",
		},
		cli.StringFlag{
			Name:  createdBeforeName,
			Usage: "a duration short hand (-2h, 3d, 2w, etc)",
		},
		cli.Int64Flag{
			Name:  limitName,
			Usage: "the max number of addrs to returned",
		},
		cli.Int64Flag{
			Name:  offsetName,
			Usage: "the number of addrs to skip before returning the first addr",
		},
	},
	Action: queryAddr,
}

func queryAddr(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	var start int64
	if ctx.IsSet(createdAfterName) {
		startOffset, err := time.ParseDuration(ctx.String(createdAfterName))
		if err != nil {
			return fmt.Errorf("unable to parse start: %w", err)
		}
		startTime := time.Now().Add(startOffset)
		start = startTime.Unix()
	}

	// Wrap with int64() so math.MaxInt64 will cross-compile on 32-bit arch.
	end := int64(math.MaxInt64)
	if ctx.IsSet(createdBeforeName) {
		endOffset, err := time.ParseDuration(ctx.String(createdBeforeName))
		if err != nil {
			return fmt.Errorf("unable to parse end: %w", err)
		}
		endTime := time.Now().Add(endOffset)
		start = endTime.Unix()
	}

	addrs, err := client.QueryAddrs(ctxc, &taprpc.QueryAddrRequest{
		CreatedAfter:  start,
		CreatedBefore: end,
		Limit:         int32(ctx.Int64(limitName)),
		Offset:        int32(ctx.Int64(offsetName)),
	})
	if err != nil {
		return fmt.Errorf("unable to make addrs: %w", err)
	}

	printRespJSON(addrs)
	return nil
}

const (
	addrName           = "addr"
	addrWithAmountName = "addr_with_amount"
)

var decodeAddrCommand = cli.Command{
	Name:      "decode",
	ShortName: "d",
	ArgsUsage: "[--addr | addr]",
	Usage:     "Attempt to decode a taproot asset addr",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  addrName,
			Usage: "the address to decode",
		},
	},
	Action: decodeAddr,
}

func decodeAddr(ctx *cli.Context) error {
	var addr string
	switch {
	case ctx.String(addrName) != "":
		addr = ctx.String(addrName)

	case len(ctx.Args()) > 0:
		addr = ctx.Args().First()

	default:
		return cli.ShowSubcommandHelp(ctx)
	}

	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	resp, err := client.DecodeAddr(ctxc, &taprpc.DecodeAddrRequest{
		Addr: addr,
	})
	if err != nil {
		return fmt.Errorf("unable to decode addr: %w", err)
	}

	printRespJSON(resp)
	return nil
}

var receivesAddrCommand = cli.Command{
	Name:      "receives",
	ShortName: "r",
	ArgsUsage: "[--addr | addr]",
	Usage:     "Show all inbound asset transfers",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  addrName,
			Usage: "show transfers of a single address only",
		},
	},
	Action: addrReceives,
}

func addrReceives(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	var addr string
	switch {
	case ctx.String(addrName) != "":
		addr = ctx.String(addrName)

	case len(ctx.Args()) > 0:
		addr = ctx.Args().First()
	}

	resp, err := client.AddrReceives(ctxc, &taprpc.AddrReceivesRequest{
		FilterAddr: addr,
	})
	if err != nil {
		return fmt.Errorf("unable to query addr receives: %w", err)
	}

	printRespJSON(resp)
	return nil
}
