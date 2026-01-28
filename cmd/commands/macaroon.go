package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/proto"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"
)

var (
	macTimeoutFlag = cli.Uint64Flag{
		Name: "timeout",
		Usage: "the number of seconds the macaroon will be " +
			"valid before it times out",
	}
	macIPAddressFlag = cli.StringFlag{
		Name:  "ip_address",
		Usage: "the IP address the macaroon will be bound to",
	}
	macIPRangeFlag = cli.StringFlag{
		Name:  "ip_range",
		Usage: "the IP range the macaroon will be bound to",
	}
	macCustomCaveatNameFlag = cli.StringFlag{
		Name:  "custom_caveat_name",
		Usage: "the name of the custom caveat to add",
	}
	macCustomCaveatConditionFlag = cli.StringFlag{
		Name: "custom_caveat_condition",
		Usage: "the condition of the custom caveat to add, can be " +
			"empty if custom caveat doesn't need a value",
	}
	bakeFromRootKeyFlag = cli.StringFlag{
		Name: "root_key",
		Usage: "if the root key is known, it can be passed directly " +
			"as a hex encoded string, turning the command into " +
			"an offline operation",
	}
)

// NewBakeMacaroonCommand creates a new command for baking macaroons.
func NewBakeMacaroonCommand(actionOpts ...ActionOption) cli.Command {
	argsUsage := "[--save_to=] [--timeout=] [--ip_address=] " +
		"[--custom_caveat_name= [--custom_caveat_condition=]] " +
		"[--root_key_id=] [--allow_external_permissions] " +
		"[--root_key=] permissions..."

	return cli.Command{
		Name:     "bakemacaroon",
		Category: "Macaroons",
		Usage: "Bakes a new macaroon with the provided list of " +
			"permissions and restrictions.",
		ArgsUsage: argsUsage,

		//nolint:lll
		Description: `
	Bake a new macaroon that grants the provided permissions and
	optionally adds restrictions (timeout, IP address) to it.

	The new macaroon can either be shown on command line in hex serialized
	format or it can be saved directly to a file using the --save_to
	argument.

	A permission is a tuple of an entity and an action, separated by a
	colon. Multiple operations can be added as arguments, for example:

	tapcli bakemacaroon daemon:read assets:write

	For even more fine-grained permission control, it is also possible to
	specify single RPC method URIs that are allowed to be accessed by a
	macaroon. This can be achieved by specifying "uri:<methodURI>" pairs,
	for example:

	tapcli bakemacaroon uri:/taprpc.TaprootAssets/GetInfo uri:/universerpc.Universe/Info

	If the root key is known, it can be passed directly as a hex encoded
	string using the --root_key flag. This turns the command into an
	offline operation and the macaroon will be created without calling
	into the server's RPC endpoint.
	`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "save_to",
				Usage: "save the created macaroon to this " +
					"file using the default binary format",
			},
			macTimeoutFlag,
			macIPAddressFlag,
			macIPRangeFlag,
			macCustomCaveatNameFlag,
			macCustomCaveatConditionFlag,
			cli.Uint64Flag{
				Name: "root_key_id",
				Usage: "the numerical root key ID used " +
					"to create the macaroon",
			},
			cli.BoolFlag{
				Name: "allow_external_permissions",
				Usage: "whether permissions tapd is not " +
					"familiar with are allowed",
			},
			bakeFromRootKeyFlag,
		},
		Action: NewWrappedAction(bakeMacaroon, actionOpts...),
	}
}

// bakeMacaroon is the main action of the bakemacaroon command. It can be
// used to bake a new macaroon with the provided list of permissions and
// restrictions.
func bakeMacaroon(cliCtx *cli.Context, ctx context.Context,
	client taprpc.TaprootAssetsClient, silencePrint bool) (proto.Message,
	error) {

	// Show command help if no arguments.
	if cliCtx.NArg() == 0 {
		return nil, cli.ShowCommandHelp(cliCtx, "bakemacaroon")
	}
	args := cliCtx.Args()

	var (
		savePath          string
		rootKeyID         uint64
		parsedPermissions []*taprpc.MacaroonPermission
	)

	if cliCtx.String("save_to") != "" {
		savePath = lncfg.CleanAndExpandPath(cliCtx.String("save_to"))
	}

	if cliCtx.IsSet("root_key_id") {
		rootKeyID = cliCtx.Uint64("root_key_id")
	}

	// A command line argument can't be an empty string. So we'll check each
	// entry if it's a valid entity:action tuple. The content itself is
	// validated server side. We just make sure we can parse it correctly.
	for _, permission := range args {
		tuple := strings.Split(permission, ":")
		if len(tuple) != 2 {
			return nil, fmt.Errorf("unable to parse "+
				"permission tuple: %s", permission)
		}
		entity, action := tuple[0], tuple[1]
		if entity == "" {
			return nil, fmt.Errorf("invalid permission [%s]. "+
				"entity cannot be empty", permission)
		}
		if action == "" {
			return nil, fmt.Errorf("invalid permission [%s]. "+
				"action cannot be empty", permission)
		}

		// Now we can assume that we have a formally valid entity:action
		// tuple. The rest of the validation happens server side.
		parsedPermissions = append(
			parsedPermissions, &taprpc.MacaroonPermission{
				Entity: entity,
				Action: action,
			},
		)
	}

	var rawMacaroon *macaroon.Macaroon
	switch {
	// If the user provided a root key, we can bake the macaroon completely
	// offline.
	case cliCtx.IsSet(bakeFromRootKeyFlag.Name):
		macRootKey, err := hex.DecodeString(
			cliCtx.String(bakeFromRootKeyFlag.Name),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse macaroon "+
				"root key: %w", err)
		}

		ops := make([]bakery.Op, 0, len(parsedPermissions))
		for _, perm := range parsedPermissions {
			ops = append(ops, bakery.Op{
				Entity: perm.Entity,
				Action: perm.Action,
			})
		}

		mac, err := macaroons.BakeFromRootKey(macRootKey, ops)
		if err != nil {
			return nil, fmt.Errorf("unable to bake "+
				"macaroon: %w", err)
		}

		rawMacaroon = mac

	// Otherwise, we'll make an RPC call to the server to bake the macaroon
	// for us.
	default:
		// Now we have gathered all the input we need and can do the
		// actual RPC call.
		req := &taprpc.BakeMacaroonRequest{
			Permissions: parsedPermissions,
			RootKeyId:   rootKeyID,
			AllowExternalPermissions: cliCtx.Bool(
				"allow_external_permissions",
			),
		}
		resp, err := client.BakeMacaroon(ctx, req)
		if err != nil {
			return nil, err
		}

		// Now we should have gotten a valid macaroon. Unmarshal it so
		// we can add first-party caveats (if necessary) to it.
		macBytes, err := hex.DecodeString(resp.Macaroon)
		if err != nil {
			return nil, err
		}
		rawMacaroon = &macaroon.Macaroon{}
		if err = rawMacaroon.UnmarshalBinary(macBytes); err != nil {
			return nil, err
		}
	}

	// Now apply the desired constraints to the macaroon. This will always
	// create a new macaroon object, even if no constraints are added.
	constrainedMac, err := applyMacaroonConstraints(cliCtx, rawMacaroon)
	if err != nil {
		return nil, err
	}
	macBytes, err := constrainedMac.MarshalBinary()
	if err != nil {
		return nil, err
	}
	macHex := hex.EncodeToString(macBytes)

	// Now we can output the result. We either write it binary serialized to
	// a file or write to the standard output using hex encoding.
	switch {
	// If the user specified a save path, we'll write the macaroon to that
	// file.
	case savePath != "":
		err = os.WriteFile(savePath, macBytes, 0600)
		if err != nil {
			return nil, err
		}
		if !silencePrint {
			fmt.Printf("Macaroon saved to %s\n", savePath)
		}

	// Otherwise, we'll print the hex-encoded macaroon to the console.
	default:
		if !silencePrint {
			fmt.Printf("%s\n", macHex)
		}
	}

	return &taprpc.BakeMacaroonResponse{
		Macaroon: macHex,
	}, nil
}

// applyMacaroonConstraints parses and applies all currently supported macaroon
// condition flags from the command line to the given macaroon and returns a
// new macaroon instance.
func applyMacaroonConstraints(cliCtx *cli.Context,
	mac *macaroon.Macaroon) (*macaroon.Macaroon, error) {

	macConstraints := make([]macaroons.Constraint, 0)

	customCaveatCond := cliCtx.String(macCustomCaveatConditionFlag.Name)
	customCaveatCondProvided := cliCtx.IsSet(
		macCustomCaveatConditionFlag.Name,
	) && customCaveatCond != ""

	if customCaveatCondProvided &&
		!cliCtx.IsSet(macCustomCaveatNameFlag.Name) {

		return nil, fmt.Errorf("custom caveat condition requires " +
			"custom caveat name")
	}

	if cliCtx.IsSet(macTimeoutFlag.Name) {
		timeout := int64(cliCtx.Uint64(macTimeoutFlag.Name))
		if timeout <= 0 {
			return nil, fmt.Errorf("timeout must be greater " +
				"than 0")
		}
		macConstraints = append(
			macConstraints, macaroons.TimeoutConstraint(timeout),
		)
	}

	if cliCtx.IsSet(macIPAddressFlag.Name) {
		ipAddress := net.ParseIP(cliCtx.String(macIPAddressFlag.Name))
		if ipAddress == nil {
			return nil, fmt.Errorf("unable to parse "+
				"ip_address: %s", cliCtx.String("ip_address"))
		}

		macConstraints = append(
			macConstraints,
			macaroons.IPLockConstraint(ipAddress.String()),
		)
	}

	if cliCtx.IsSet(macIPRangeFlag.Name) {
		_, ipNet, err := net.ParseCIDR(
			cliCtx.String(macIPRangeFlag.Name),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse "+
				"ip_range %s: %w",
				cliCtx.String("ip_range"), err)
		}

		macConstraints = append(
			macConstraints,
			macaroons.IPLockConstraint(ipNet.String()),
		)
	}

	if cliCtx.IsSet(macCustomCaveatNameFlag.Name) {
		customCaveatName := cliCtx.String(macCustomCaveatNameFlag.Name)
		if containsWhiteSpace(customCaveatName) {
			return nil, fmt.Errorf("unexpected white space " +
				"found in custom caveat name")
		}
		if customCaveatName == "" {
			return nil, fmt.Errorf("invalid custom caveat name")
		}

		if customCaveatCondProvided {
			if containsWhiteSpace(customCaveatCond) {
				return nil, fmt.Errorf("unexpected white " +
					"space found in custom caveat " +
					"condition")
			}
		}

		// The custom caveat condition is optional, it could just be a
		// marker tag in the macaroon with just a name. The interceptor
		// itself doesn't care about the value anyway.
		macConstraints = append(
			macConstraints, macaroons.CustomConstraint(
				customCaveatName, customCaveatCond,
			),
		)
	}

	constrainedMac, err := macaroons.AddConstraints(
		mac, macConstraints...,
	)
	if err != nil {
		return nil, fmt.Errorf("error adding constraints: %w", err)
	}

	return constrainedMac, nil
}

// containsWhiteSpace returns true if the given string contains any character
// that is considered to be a white space or non-printable character such as
// space, tabulator, newline, carriage return and some more exotic ones.
func containsWhiteSpace(str string) bool {
	return strings.IndexFunc(str, unicode.IsSpace) >= 0
}
