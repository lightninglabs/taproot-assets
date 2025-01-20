package tapcliutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/proto"
)

// NewApp creates a new tapcli app with all the available commands.
func NewApp() cli.App {
	app := cli.NewApp()
	app.Name = "tapcli"
	app.Version = tap.Version()
	app.Usage = "control plane for your Taproot Assets Daemon (tapd)"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "rpcserver",
			Value: defaultRPCHostPort,
			Usage: "The host:port of tap daemon.",
		},
		cli.StringFlag{
			Name:      "tapddir",
			Value:     defaultTapdDir,
			Usage:     "The path to tap's base directory.",
			TakesFile: true,
		},
		cli.StringFlag{
			Name: "socksproxy",
			Usage: "The host:port of a SOCKS proxy through " +
				"which all connections to the Taproot Asset " +
				"daemon will be established over.",
		},
		cli.StringFlag{
			Name:      "tlscertpath",
			Value:     defaultTLSCertPath,
			Usage:     "The path to tapd's TLS certificate.",
			TakesFile: true,
		},
		cli.StringFlag{
			Name: "network, n",
			Usage: "The network tapd is running on, e.g. " +
				"mainnet, testnet, etc.",
			Value: "testnet",
		},
		cli.BoolFlag{
			Name:  "no-macaroons",
			Usage: "Disable macaroon authentication.",
		},
		cli.StringFlag{
			Name:      "macaroonpath",
			Usage:     "The path to macaroon file.",
			TakesFile: true,
		},
		cli.Int64Flag{
			Name:  "macaroontimeout",
			Value: 60,
			Usage: "Anti-replay macaroon validity time in seconds.",
		},
		cli.StringFlag{
			Name:  "macaroonip",
			Usage: "If set, lock macaroon to specific IP address.",
		},
		cli.StringFlag{
			Name: "profile, p",
			Usage: "Instead of reading settings from command " +
				"line parameters or using the default " +
				"profile, use a specific profile. If " +
				"a default profile is set, this flag can be " +
				"set to an empty string to disable reading " +
				"values from the profiles file.",
		},
		cli.StringFlag{
			Name: "macfromjar",
			Usage: "Use this macaroon from the profile's " +
				"macaroon jar instead of the default one. " +
				"Can only be used if profiles are defined.",
		},
	}

	// Add all the available commands.
	app.Commands = []cli.Command{
		stopCommand,
		debugLevelCommand,
		profileSubCommand,
		getInfoCommand,
	}
	app.Commands = append(app.Commands, assetsCommands...)
	app.Commands = append(app.Commands, addrCommands...)
	app.Commands = append(app.Commands, eventCommands...)
	app.Commands = append(app.Commands, proofCommands...)
	app.Commands = append(app.Commands, rfqCommands...)
	app.Commands = append(app.Commands, universeCommands...)
	app.Commands = append(app.Commands, devCommands...)

	return *app
}

// ClientInterfaceBundle is an interface that bundles all the client interfaces
// that are used by the tapcli.
type ClientInterfaceBundle interface {
	taprpc.TaprootAssetsClient
	assetwalletrpc.AssetWalletClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	tchrpc.TaprootAssetChannelsClient
	universerpc.UniverseClient
	tapdevrpc.TapDevClient
}

func getContext() context.Context {
	shutdownInterceptor, err := signal.Intercept()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctxc, cancel := context.WithCancel(context.Background())
	go func() {
		<-shutdownInterceptor.ShutdownChannel()
		cancel()
	}()
	return ctxc
}

func printJSON(resp interface{}) {
	b, err := json.Marshal(resp)
	if err != nil {
		Fatal(err)
	}

	var out bytes.Buffer
	_ = json.Indent(&out, b, "", "\t")
	out.WriteString("\n")
	_, _ = out.WriteTo(os.Stdout)
}

func printRespJSON(resp proto.Message) {
	jsonBytes, err := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
	if err != nil {
		fmt.Println("unable to decode response: ", err)
		return
	}

	fmt.Printf("%s\n", jsonBytes)
}

// nolint: lll
var debugLevelCommand = cli.Command{
	Name:  "debuglevel",
	Usage: "Set the debug level.",
	Description: `Logging level for all subsystems {trace, debug, info, warn, error, critical, off}
	You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems

	Use show to list available subsystems`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "show",
			Usage: "if true, then the list of available sub-systems will be printed out",
		},
		cli.StringFlag{
			Name:  "level",
			Usage: "the level specification to target either a coarse logging level, or granular set of specific sub-systems with logging levels for each",
		},
	},
	Action: debugLevel,
}

func debugLevel(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()
	req := &taprpc.DebugLevelRequest{
		Show:      ctx.Bool("show"),
		LevelSpec: ctx.String("level"),
	}

	resp, err := client.DebugLevel(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

var stopCommand = cli.Command{
	Name:  "stop",
	Usage: "Stop and shutdown the daemon.",
	Description: `
	Gracefully stop all daemon subsystems before stopping the daemon itself.
	This is equivalent to stopping it using CTRL-C.`,
	Action: stopDaemon,
}

func stopDaemon(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	_, err := client.StopDaemon(ctxc, &taprpc.StopRequest{})
	if err != nil {
		return err
	}

	return nil
}

var getInfoCommand = cli.Command{
	Name:        "getinfo",
	Usage:       "Get daemon info.",
	Description: "Returns basic information related to the active daemon.",
	Action:      getInfo,
}

func getInfo(ctx *cli.Context) error {
	ctxc := getContext()
	client, cleanUp := getClient(ctx)
	defer cleanUp()

	req := &taprpc.GetInfoRequest{}
	resp, err := client.GetInfo(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

// RpcClientHarness is a struct that contains the necessary information to
// manage a client connection and the response and error channels for the
// client.
type RpcClientHarness struct {
	// Ctx is the context for the client connection.
	Ctx context.Context

	// Client is the client RPC connection.
	Client ClientInterfaceBundle

	// ResponseChan is the channel to send the response to.
	ResponseChan chan<- interface{}

	// ErrChan is the channel to send the error to.
	ErrChan chan<- error
}

// NewRpcClientHarness creates a new RpcClientHarness.
func NewRpcClientHarness(ctx context.Context, client ClientInterfaceBundle,
	responseChan chan<- interface{},
	errChan chan<- error) *RpcClientHarness {

	return &RpcClientHarness{
		Ctx:          ctx,
		Client:       client,
		ResponseChan: responseChan,
		ErrChan:      errChan,
	}
}

// UnwrappedAction is a function signatures for unwrapped actions that are
// executed by the wrapped action.
type UnwrappedAction func(cliCtx *cli.Context, ctx context.Context,
	client taprpc.TaprootAssetsClient, silencePrint bool) (proto.Message,
	error)

// WrappedAction is a function signature for wrapped actions that are executed
// by cli.
type WrappedAction = func(*cli.Context) error

// NewWrappedAction creates a new WrappedAction that wraps an UnwrappedAction.
func NewWrappedAction(rpcClientHarness *RpcClientHarness,
	action UnwrappedAction) WrappedAction {

	return func(cliCtx *cli.Context) error {
		var (
			ctx           context.Context
			client        taprpc.TaprootAssetsClient
			clientCleanUp func()

			// We silence print statements if a client harness is
			// provided.
			silencePrint = rpcClientHarness != nil
		)

		// If an RPC client harness is provided, use it to get the
		// client and context. Otherwise, create a new RPC client
		// connection and context using the provided CLI context.
		switch rpcClientHarness {
		case nil:
			// No RPC client harness provided, create a new client
			// using the CLI context.
			ctx = getContext()

			// TODO(ffranr): Client here should satisfy interface
			//  ClientInterfaceBundle.
			client, clientCleanUp = getClient(cliCtx)
		default:
			// Use the provided RPC client harness to get the client
			// and context.
			ctx = rpcClientHarness.Ctx
			client = rpcClientHarness.Client
			clientCleanUp = func() {}
		}

		// Defer client cleanup.
		defer clientCleanUp()

		// Execute underlying action using the RPC client.
		resp, err := action(cliCtx, ctx, client, silencePrint)
		if err != nil {
			// If an RPC client harness is provided, send the error
			// to the error channel.
			if rpcClientHarness != nil {
				rpcClientHarness.ErrChan <- err
			}

			return err
		}

		// If an RPC client harness is provided, send the response to
		// the response channel.
		if rpcClientHarness != nil {
			rpcClientHarness.ResponseChan <- resp
		}

		return nil
	}
}
