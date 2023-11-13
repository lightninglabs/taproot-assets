package main

import (
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "tapcli",
	Version: tap.Version(),
	Short:   "control plane for your Taproot Assets Daemon (tapd)",
	// Prevent cobra from printing duplicate errors.
	SilenceErrors: true,
}

func main() {
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.rpcServer, "rpcserver", defaultRPCHostPort,
		"The host:port of tap daemon.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.tapdDir, "tapddir", defaultTapdDir,
		"The path to tap's base directory.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.socksProxy, "socksproxy", "",
		"The host:port of a SOCKS proxy through which all connections "+
			"to the Taproot Asset daemon will be established over.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.tlsCertPath, "tlscertpath", defaultTLSCertPath,
		"The path to tapd's TLS certificate.",
	)
	rootCmd.PersistentFlags().StringVarP(
		&rootOpts.network, "network", "n", "testnet",
		"The network tapd is running on, e.g. mainnet, testnet, etc.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.chain, "chain", "bitcoin",
		"The chain tapd is running on, e.g. bitcoin",
	)
	rootCmd.PersistentFlags().BoolVar(
		&rootOpts.noMacaroons, "no-macaroons", false,
		"Disable macaroon authentication.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.macaroonPath, "macaroonpath", "",
		"The path to the macaroon file.",
	)
	rootCmd.PersistentFlags().Int64Var(
		&rootOpts.macaroonTimeout, "macaroontimeout", 60,
		"Anti-replay macaroon validity time in seconds.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.macaroonIP, "macaroonip", "",
		"If set, lock macaroon to specific IP address.",
	)
	// TODO(jhb): update for profile disable to be a space
	rootCmd.PersistentFlags().StringVarP(
		&rootOpts.profile, "profile", "p", "",
		"Instead of reading settings from command line parameters or "+
			"using the default profile, use a specific profile. "+
			"If a default profile is set, this flag can be set to "+
			"a space character to disable reading values from the "+
			"profiles file.",
	)
	rootCmd.PersistentFlags().StringVar(
		&rootOpts.macFromJar, "macfromjar", "",
		"Use this macaroon from the profile's macaroon jar instead of "+
			"the default one. Can only be used if profiles are "+
			"defined.",
	)

	rootCmd.AddCommand(
		newDebugLevelCmd(),
		newStopCmd(),
		newGetInfoCmd(),
	)

	// Define command groups to modify the top-level help message.
	assetCmds := cobra.Group{
		ID:    "Assets",
		Title: "Assets",
	}

	rootCmd.AddGroup(&assetCmds)
	rootCmd.AddCommand(newAssetRootCmd())

	if err := rootCmd.Execute(); err != nil {
		fatal(err)
	}
}

// usageTemplateNoGlobals matches the default usage template shown as part of
// help commands, but omits documentation about global flags.
var usageTemplateNoGlobals = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

type debugLevelCmd struct {
	show  bool
	level string

	cmd *cobra.Command
}

func newDebugLevelCmd() *cobra.Command {
	cc := &debugLevelCmd{}
	cc.cmd = &cobra.Command{
		Use:   "debuglevel",
		Short: "Set the debug level",
		Long: `Logging level for all subsystems {trace, debug, info, warn, error, critical, off}
		You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems

		Use '--show' to list available subsystems`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().BoolVar(
		&cc.show, "show", false,
		"if true, then the list of available sub-systems will be printed out",
	)
	cc.cmd.Flags().StringVar(
		&cc.level, "level", "",
		"the level specification to target either a coarse logging level, or granular set of specific sub-systems with logging levels for each",
	)

	return cc.cmd
}

func (c *debugLevelCmd) Execute(_ *cobra.Command, _ []string) error {
	if !c.show && c.level == "" {
		return c.cmd.Help()
	}

	ctxc := getContext()
	client, cleanUp := getClientCobra(&rootOpts)
	defer cleanUp()
	req := &taprpc.DebugLevelRequest{
		Show:      c.show,
		LevelSpec: c.level,
	}

	resp, err := client.DebugLevel(ctxc, req)
	if err != nil {
		return err
	}

	printRespJSON(resp)
	return nil
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop and shutdown the daemon.",
		Long: `Gracefully stop all daemon subsystems before stopping the daemon itself.
		This is equivalent to stopping it using CTRL-C.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctxc := getContext()
			client, cleanUp := getClientCobra(&rootOpts)
			defer cleanUp()

			_, err := client.StopDaemon(ctxc, &taprpc.StopRequest{})
			if err != nil {
				return err
			}

			return nil
		},
	}
}

func newGetInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "getinfo",
		Short: "Get daemon info.",
		Long:  "Returns basic information related to the active daemon.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctxc := getContext()
			client, cleanUp := getClientCobra(&rootOpts)
			defer cleanUp()

			req := &taprpc.GetInfoRequest{}
			resp, err := client.GetInfo(ctxc, req)
			if err != nil {
				return err
			}

			printRespJSON(resp)
			return nil
		},
	}
}
