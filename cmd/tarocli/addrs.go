package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/urfave/cli"
)

var addrCommands = []cli.Command{
	{
		Name:      "addrs",
		ShortName: "ad",
		Usage:     "Interact with Taro addresses.",
		Category:  "Addresses",
		Subcommands: []cli.Command{
			newAddrCommand,
			queryAddrsCommand,
			decodeAddrCommand,
		},
	},
}

const (
	assetIDName = "asset_id"

	keyFamName = "key_fam"

	amtName = "amt"
)

var newAddrCommand = cli.Command{
	Name:        "new",
	ShortName:   "n",
	Usage:       "create a Taro address",
	Description: "Create a new Taro address to receive an asset on-chain",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  assetIDName,
			Usage: "the asset ID of the asset to receive",
		},
		cli.StringFlag{
			Name:  keyFamName,
			Usage: "optional, the key family of the asset to receive",
		},
		cli.Uint64Flag{
			Name:  amtName,
			Usage: "the amt of the asset to receive",
		},
		cli.StringFlag{
			Name:  assetTypeName,
			Usage: "the type of the asset",
		},
	},
	Action: newAddr,
}

func newAddr(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	switch {
	case ctx.String(assetIDName) == "":
		_ = cli.ShowCommandHelp(ctx, "mint")
		return nil
	}

	assetID, err := hex.DecodeString(ctx.String(assetIDName))
	if err != nil {
		return fmt.Errorf("unable to decode asset ID: %v", err)
	}
	keyFam, err := hex.DecodeString(ctx.String(keyFamName))
	if err != nil {
		return fmt.Errorf("unable to decode key fam: %w", err)
	}

	addr, err := client.NewAddr(ctxc, &tarorpc.NewAddrRequest{
		AssetId:   assetID,
		FamKey:    keyFam,
		Amt:       ctx.Int64(amtName),
		AssetType: parseAssetType(ctx),
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

	end := math.MaxInt64
	if ctx.IsSet(createdBeforeName) {
		endOffset, err := time.ParseDuration(ctx.String(createdBeforeName))
		if err != nil {
			return fmt.Errorf("unable to parse end: %w", err)
		}
		endTime := time.Now().Add(endOffset)
		start = endTime.Unix()
	}

	addrs, err := client.QueryAddrs(ctxc, &tarorpc.QueryAddrRequest{
		CreatedAfter:  start,
		CreatedBefore: int64(end),
		Limit:         int32(ctx.Int64(limitName)),
		Offset:        int32(ctx.Int64(offsetName)),
	})
	if err != nil {
		return fmt.Errorf("unable to make addrs: %v", err)
	}

	printRespJSON(addrs)
	return nil
}

const addrName = "addr"

var decodeAddrCommand = cli.Command{
	Name:        "decode",
	ShortName:   "d",
	Usage:       "[--addr | addr]",
	Description: "attempt to decode a taro addr",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  addrName,
			Usage: "the address to decode",
		},
	},
	Action: decodeAddr,
}

func decodeAddr(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	var addr string
	switch {
	case ctx.String(addrName) != "":
		addr = ctx.String(addrName)

	case len(ctx.Args()) > 0:
		addr = ctx.Args().First()

	default:
		_ = cli.ShowCommandHelp(ctx, "mint")
		return nil
	}

	resp, err := client.DecodeAddr(ctxc, &tarorpc.Addr{
		Addr: addr,
	})
	if err != nil {
		return fmt.Errorf("unable to decode addr: %w", err)
	}

	printRespJSON(resp)
	return nil
}
