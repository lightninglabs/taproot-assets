package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/taprpc"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/proto"
)

const (
	// Environment variables names that can be used to set the global flags.
	envVarRPCServer       = "TAPCLI_RPCSERVER"
	envVarTapDir          = "TAPCLI_TAPDIR"
	ewnvVarSocksProxy     = "TAPCLI_SOCKSPROXY"
	envVarTLSCert         = "TAPCLI_TLSCERTPATH"
	envVarNetwork         = "TAPCLI_NETWORK"
	envVarMacaroonPath    = "TAPCLI_MACAROONPATH"
	envVarMacaroonTimeout = "TAPCLI_MACAROONTIMEOUT"
	envVarMacaroonIP      = "TAPCLI_MACAROONIP"
	envVarProfile         = "TAPCLI_PROFILE"
	envVarMacFromJar      = "TAPCLI_MACFROMJAR"
)

// NewApp creates a new tapcli app with all the available commands.
func NewApp(actionOpts ...ActionOption) cli.App {
	app := cli.NewApp()
	app.Name = "tapcli"
	app.Version = tap.Version()
	app.Usage = "control plane for your Taproot Assets Daemon (tapd)"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "rpcserver",
			Value:  defaultRPCHostPort,
			Usage:  "The host:port of tap daemon.",
			EnvVar: envVarRPCServer,
		},
		cli.StringFlag{
			Name:      "tapddir",
			Value:     defaultTapdDir,
			Usage:     "The path to tap's base directory.",
			TakesFile: true,
			EnvVar:    envVarTapDir,
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
			EnvVar:    envVarTLSCert,
		},
		cli.StringFlag{
			Name: "network, n",
			Usage: "The network tapd is running on, e.g. " +
				"mainnet, testnet, etc.",
			Value:  "testnet",
			EnvVar: envVarNetwork,
		},
		cli.BoolFlag{
			Name:  "no-macaroons",
			Usage: "Disable macaroon authentication.",
		},
		cli.StringFlag{
			Name:      "macaroonpath",
			Usage:     "The path to macaroon file.",
			TakesFile: true,
			EnvVar:    envVarMacaroonPath,
		},
		cli.Int64Flag{
			Name:  "macaroontimeout",
			Value: 60,
			Usage: "Anti-replay macaroon validity time in " +
				"seconds.",
			EnvVar: envVarMacaroonTimeout,
		},
		cli.StringFlag{
			Name: "macaroonip",
			Usage: "If set, lock macaroon to specific IP " +
				"address.",
			EnvVar: envVarMacaroonIP,
		},
		cli.StringFlag{
			Name: "profile, p",
			Usage: "Instead of reading settings from command " +
				"line parameters or using the default " +
				"profile, use a specific profile. If " +
				"a default profile is set, this flag can be " +
				"set to an empty string to disable reading " +
				"values from the profiles file.",
			EnvVar: envVarProfile,
		},
		cli.StringFlag{
			Name: "macfromjar",
			Usage: "Use this macaroon from the profile's " +
				"macaroon jar instead of the default one. " +
				"Can only be used if profiles are defined.",
			EnvVar: envVarMacFromJar,
		},
	}

	// Add all the available commands.
	app.Commands = []cli.Command{
		stopCommand,
		debugLevelCommand,
		profileSubCommand,
		NewGetInfoCommand(actionOpts...),
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

// actionOpts contains the options for an action.
type actionOpts struct {
	ctx          context.Context
	client       RpcClientsBundle
	silencePrint bool
	respChan     chan<- lfn.Result[interface{}]
}

// ActionOption is a function type that can be used to set options for an
// action.
type ActionOption func(*actionOpts)

// defaultActionOpts returns the default action options.
func defaultActionOpts() *actionOpts {
	return &actionOpts{}
}

// ActionWithCtx is an option modifier function that sets the context for an
// action.
func ActionWithCtx(ctx context.Context) ActionOption {
	return func(opts *actionOpts) {
		opts.ctx = ctx
	}
}

// ActionWithClient is an option modifier function that sets the client for an
// action.
func ActionWithClient(client RpcClientsBundle) ActionOption {
	return func(opts *actionOpts) {
		opts.client = client
	}
}

// ActionWithSilencePrint is an option modifier function that sets the silence
// print option for an action.
func ActionWithSilencePrint(silencePrint bool) ActionOption {
	return func(opts *actionOpts) {
		opts.silencePrint = silencePrint
	}
}

// ActionRespChan is an option modifier function that sets the response channel
// for an action.
func ActionRespChan(respChan chan<- lfn.Result[interface{}]) ActionOption {
	return func(opts *actionOpts) {
		opts.respChan = respChan
	}
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

// NewGetInfoCommand creates a new command to get daemon info.
func NewGetInfoCommand(actionOpts ...ActionOption) cli.Command {
	return cli.Command{
		Name:  "getinfo",
		Usage: "Get daemon info.",
		Description: "Returns basic information related to the " +
			"active daemon.",
		Action: NewWrappedAction(getInfo, actionOpts...),
	}
}

// getInfo is the action function for the `getinfo` command.
func getInfo(_ *cli.Context, ctx context.Context,
	client taprpc.TaprootAssetsClient, silencePrint bool) (proto.Message,
	error) {

	resp, err := client.GetInfo(ctx, &taprpc.GetInfoRequest{})
	if err != nil {
		return nil, err
	}

	if !silencePrint {
		printRespJSON(resp)
	}

	return resp, nil
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
func NewWrappedAction(action UnwrappedAction,
	actionOpts ...ActionOption) WrappedAction {

	// Formulate the action options struct from the provided option
	// modifier functions.
	opts := defaultActionOpts()
	for _, actionOpt := range actionOpts {
		actionOpt(opts)
	}

	var (
		// Unpack options from opts to avoid overwriting below.
		ctx          = opts.ctx
		client       = opts.client
		silencePrint = opts.silencePrint
		respChan     = opts.respChan

		// By default, a no-operation client cleanup function is
		// specified because the caller is expected to handle the
		// cleanup for any client provided as an argument.
		clientCleanUp = func() {}
	)

	return func(cliCtx *cli.Context) error {
		// If a client is not provided, create a new client using the
		// CLI context.
		if client == nil {
			ctx = getContext()
			client, clientCleanUp = getRpcClientBundle(cliCtx)
		}

		// Defer client cleanup.
		defer clientCleanUp()

		// Execute underlying action using the RPC client.
		resp, err := action(cliCtx, ctx, client, silencePrint)
		if err != nil {
			// If a response channel is provided, send the error to
			// the response channel.
			if respChan != nil {
				respChan <- lfn.Err[interface{}](err)
			}

			return err
		}

		// If a response channel is provided, send the response to the
		// response channel.
		if respChan != nil {
			respChan <- lfn.Ok[interface{}](resp)
		}

		return nil
	}
}
