package tarocfg

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btclog"
	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/verrpc"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/tor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultDataDirname      = "data"
	defaultTLSCertFilename  = "tls.cert"
	defaultTLSKeyFilename   = "tls.key"
	defaultAdminMacFilename = "admin.macaroon"
	defaultLogLevel         = "info"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "taro.log"
	defaultRPCPort          = 10029
	defaultRESTPort         = 8089

	defaultMaxLogFiles    = 3
	defaultMaxLogFileSize = 10

	// DefaultAutogenValidity is the default validity of a self-signed
	// certificate. The value corresponds to 14 months
	// (14 months * 30 days * 24 hours).
	defaultTLSCertDuration = 14 * 30 * 24 * time.Hour

	defaultConfigFileName = "taro.conf"

	// defaultBatchMintingInterval is the default interval used to
	// determine when a set of pending assets should be flushed into a new
	// batch.
	defaultBatchMintingInterval = time.Minute * 10

	// defaultHashMailAddr is the default address we'll use to deliver
	// optionally deliver proofs for asynchronous sends.
	defaultHashMailAddr = "mailbox.terminal.lightning.today:443"

	// DatabaseBackendSqlite is the name of the SQLite database backend.
	DatabaseBackendSqlite = "sqlite"

	// DatabaseBackendPostgres is the name of the Postgres database backend.
	DatabaseBackendPostgres = "postgres"

	// defaultProofTransferBackoffResetWait is the default amount of time
	// we'll wait before resetting the backoff of a proof transfer.
	defaultProofTransferBackoffResetWait = 10 * time.Minute

	// defaultProofTransferNumTries is the default number of times we'll
	// attempt to transfer a proof before ending the backoff procedure.
	defaultProofTransferNumTries = 4

	// defaultProofTransferInitialBackoff is the default initial backoff
	// time we'll use for proof transfers.
	defaultProofTransferInitialBackoff = 30 * time.Second

	// defaultProofTransferMaxBackoff is the default maximum backoff time
	// we'll use for proof transfers.
	defaultProofTransferMaxBackoff = 5 * time.Minute

	// defaultProofTransferReceiverAckTimeout is the default timeout we'll
	// use for waiting for a receiver to acknowledge a proof transfer.
	defaultProofTransferReceiverAckTimeout = 5 * time.Second
)

var (
	// DefaultTaroDir is the default directory where Taro tries to find its
	// configuration file and store its data. This is a directory in the
	// user's application data, for example:
	//   C:\Users\<username>\AppData\Local\Taro on Windows
	//   ~/.taro on Linux
	//   ~/Library/Application Support/Taro on MacOS
	DefaultTaroDir = btcutil.AppDataDir("taro", false)

	// DefaultConfigFile is the default full path of taro's configuration
	// file.
	DefaultConfigFile = filepath.Join(DefaultTaroDir, defaultConfigFileName)

	defaultNetwork = "testnet"

	defaultDataDir = filepath.Join(DefaultTaroDir, defaultDataDirname)
	defaultLogDir  = filepath.Join(DefaultTaroDir, defaultLogDirname)

	defaultTLSCertPath = filepath.Join(DefaultTaroDir, defaultTLSCertFilename)
	defaultTLSKeyPath  = filepath.Join(DefaultTaroDir, defaultTLSKeyFilename)

	defaultSqliteDatabaseFileName = "taro.db"

	// defaultLndMacaroon is the default macaroon file we use if the old,
	// deprecated --lnd.macaroondir config option is used.
	defaultLndMacaroon = "admin.macaroon"

	// defaultLndDir is the default location where we look for lnd's tls and
	// macaroon files.
	defaultLndDir = btcutil.AppDataDir("lnd", false)

	// defaultLndMacaroonPath is the default location where we look for a
	// macaroon to use when connecting to lnd.
	defaultLndMacaroonPath = filepath.Join(
		defaultLndDir, "data", "chain", "bitcoin", defaultNetwork,
		defaultLndMacaroon,
	)

	// defaultSqliteDatabasePath is the default path under which we store
	// the SQLite database file.
	defaultSqliteDatabasePath = filepath.Join(
		defaultDataDir, defaultNetwork, defaultSqliteDatabaseFileName,
	)

	// minimalCompatibleVersion is the minimum version and build tags
	// required in lnd to run pool.
	minimalCompatibleVersion = &verrpc.Version{
		AppMajor: 0,
		AppMinor: 15,
		AppPatch: 99,

		// We don't actually require the invoicesrpc calls. But if we
		// try to use lndclient on an lnd that doesn't have it enabled,
		// the library will try to load the invoices.macaroon anyway and
		// fail. So until that bug is fixed in lndclient, we require the
		// build tag to be active.
		BuildTags: []string{
			"signrpc", "walletrpc", "chainrpc", "invoicesrpc",
		},
	}
)

// ChainConfig houses the configuration options that govern which chain/network
// we operate on.
type ChainConfig struct {
	Network string `long:"network" description:"network to run on" choice:"regtest" choice:"testnet" choice:"simnet"`

	SigNetChallenge string `long:"signetchallenge" description:"Connect to a custom signet network defined by this challenge instead of using the global default signet test network -- Can be specified multiple times"`
}

// RpcConfig houses the set of config options that affect how clients connect
// to the main RPC server.
type RpcConfig struct {
	RawRPCListeners  []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
	RawRESTListeners []string `long:"restlisten" description:"Add an interface/port/socket to listen for REST connections"`

	TLSCertPath        string        `long:"tlscertpath" description:"Path to write the TLS certificate for tarod's RPC and REST services"`
	TLSKeyPath         string        `long:"tlskeypath" description:"Path to write the TLS private key for tarod's RPC and REST services"`
	TLSExtraIPs        []string      `long:"tlsextraip" description:"Adds an extra ip to the generated certificate"`
	TLSExtraDomains    []string      `long:"tlsextradomain" description:"Adds an extra domain to the generated certificate"`
	TLSAutoRefresh     bool          `long:"tlsautorefresh" description:"Re-generate TLS certificate and key if the IPs or domains are changed"`
	TLSDisableAutofill bool          `long:"tlsdisableautofill" description:"Do not include the interface IPs or the system hostname in TLS certificate, use first --tlsextradomain as Common Name instead, if set"`
	TLSCertDuration    time.Duration `long:"tlscertduration" description:"The duration for which the auto-generated TLS certificate will be valid for"`

	DisableRest    bool          `long:"norest" description:"Disable REST API"`
	DisableRestTLS bool          `long:"no-rest-tls" description:"Disable TLS for REST connections"`
	WSPingInterval time.Duration `long:"ws-ping-interval" description:"The ping interval for REST based WebSocket connections, set to 0 to disable sending ping messages from the server side"`
	WSPongWait     time.Duration `long:"ws-pong-wait" description:"The time we wait for a pong response message on REST based WebSocket connections before the connection is closed as inactive"`

	MacaroonPath string `long:"macaroonpath" description:"Path to write the admin macaroon for taro's RPC and REST services if it doesn't exist"`
	NoMacaroons  bool   `long:"no-macaroons" description:"Disable macaroon authentication, can only be used if server is not listening on a public interface."`

	RestCORS []string `long:"restcors" description:"Add an ip:port/hostname to allow cross origin access from. To allow all origins, set as \"*\"."`
}

// LndConfig is the main config we'll use to connect to the lnd node that backs
// up tarod.
type LndConfig struct {
	Host string `long:"host" description:"lnd instance rpc address"`

	// MacaroonDir is the directory that contains all the macaroon files
	// required for the remote connection.
	MacaroonDir string `long:"macaroondir" description:"DEPRECATED: Use macaroonpath."`

	// MacaroonPath is the path to the single macaroon that should be used
	// instead of needing to specify the macaroon directory that contains
	// all of lnd's macaroons. The specified macaroon MUST have all
	// permissions that all the subservers use, otherwise permission errors
	// will occur.
	MacaroonPath string `long:"macaroonpath" description:"The full path to the single macaroon to use, either the admin.macaroon or a custom baked one. Cannot be specified at the same time as macaroondir. A custom macaroon must contain ALL permissions required for all subservers to work, otherwise permission errors will occur."`

	TLSPath string `long:"tlspath" description:"Path to lnd tls certificate"`
}

// Config is the main config for the tarod cli command.
type Config struct {
	ShowVersion bool `long:"version" description:"Display version information and exit"`

	DebugLevel string `long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <global-level>,<subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	TaroDir    string `long:"tarodir" description:"The base directory that contains taro's data, logs, configuration file, etc."`
	ConfigFile string `long:"configfile" description:"Path to configuration file"`

	DataDir        string `long:"datadir" description:"The directory to store taro's data within"`
	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	CPUProfile string `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	Profile    string `long:"profile" description:"Enable HTTP profiling on either a port or host:port"`

	BatchMintingInterval time.Duration `long:"batch-minting-interval" description:"A duration (1m, 2h, etc) that governs how frequently pending assets are gather into a batch to be minted."`

	// The following options are used to configure the proof courier.
	ProofCourierMode string                    `long:"proofcouriermode" choice:"hashmail" description:"Type of proof courier to use."`
	HashMailCourier  *proof.HashMailCourierCfg `group:"proofcourier" namespace:"hashmailcourier"`

	ChainConf *ChainConfig
	RpcConf   *RpcConfig

	Lnd *LndConfig `group:"lnd" namespace:"lnd"`

	DatabaseBackend string                 `long:"databasebackend" description:"The database backend to use for storing all asset related data." choice:"sqlite" choice:"postgres"`
	Sqlite          *tarodb.SqliteConfig   `group:"sqlite" namespace:"sqlite"`
	Postgres        *tarodb.PostgresConfig `group:"postgres" namespace:"postgres"`

	// LogWriter is the root logger that all of the daemon's subloggers are
	// hooked up to.
	LogWriter *build.RotatingLogWriter

	// networkDir is the path to the directory of the currently active
	// network. This path will hold the files related to each different
	// network.
	networkDir string

	// ActiveNetParams contains parameters of the target chain.
	ActiveNetParams chaincfg.Params

	rpcListeners  []net.Addr
	restListeners []net.Addr

	net tor.Net
}

// DefaultConfig returns all default values for the Config struct.
func DefaultConfig() Config {
	return Config{
		TaroDir:        DefaultTaroDir,
		ConfigFile:     DefaultConfigFile,
		DataDir:        defaultDataDir,
		DebugLevel:     defaultLogLevel,
		LogDir:         defaultLogDir,
		MaxLogFiles:    defaultMaxLogFiles,
		MaxLogFileSize: defaultMaxLogFileSize,
		net:            &tor.ClearNet{},
		RpcConf: &RpcConfig{
			TLSCertPath:     defaultTLSCertPath,
			TLSKeyPath:      defaultTLSKeyPath,
			TLSCertDuration: defaultTLSCertDuration,
			WSPingInterval:  lnrpc.DefaultPingInterval,
			WSPongWait:      lnrpc.DefaultPongWait,
		},
		ChainConf: &ChainConfig{
			Network: defaultNetwork,
		},
		Lnd: &LndConfig{
			Host:         "localhost:10009",
			MacaroonPath: defaultLndMacaroonPath,
		},
		DatabaseBackend: DatabaseBackendSqlite,
		Sqlite: &tarodb.SqliteConfig{
			DatabaseFileName: defaultSqliteDatabasePath,
		},
		Postgres: &tarodb.PostgresConfig{
			Host:               "localhost",
			Port:               5432,
			MaxOpenConnections: 10,
		},
		LogWriter:            build.NewRotatingLogWriter(),
		BatchMintingInterval: defaultBatchMintingInterval,
		HashMailCourier: &proof.HashMailCourierCfg{
			Addr:               defaultHashMailAddr,
			ReceiverAckTimeout: defaultProofTransferReceiverAckTimeout,
			BackoffCfg: &proof.BackoffCfg{
				BackoffResetWait: defaultProofTransferBackoffResetWait,
				NumTries:         defaultProofTransferNumTries,
				InitialBackoff:   defaultProofTransferInitialBackoff,
				MaxBackoff:       defaultProofTransferMaxBackoff,
			},
		},
	}
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
func LoadConfig(interceptor signal.Interceptor) (*Config, btclog.Logger, error) {
	// Pre-parse the command line options to pick up an alternative config
	// file.
	preCfg := DefaultConfig()
	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", taro.Version(),
			"commit="+taro.Commit)
		os.Exit(0)
	}

	// If the config file path has not been modified by the user, then
	// we'll use the default config file path. However, if the user has
	// modified their taroddir, then we should assume they intend to use
	// the config file within it.
	configFileDir := CleanAndExpandPath(preCfg.TaroDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	switch {
	// User specified --taroddir but no --configfile. Update the config
	// file path to the tarod config directory, but don't require it to
	// exist.
	case configFileDir != DefaultTaroDir &&
		configFilePath == DefaultConfigFile:

		configFilePath = filepath.Join(
			configFileDir, lncfg.DefaultConfigFilename,
		)

	// User did specify an explicit --configfile, so we check that it does
	// exist under that path to avoid surprises.
	case configFilePath != DefaultConfigFile:
		if !fileExists(configFilePath) {
			return nil, nil, fmt.Errorf("specified config file does "+
				"not exist in %s", configFilePath)
		}
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	fileParser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(configFilePath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok {
			return nil, nil, err
		}

		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	flagParser := flags.NewParser(&cfg, flags.Default)
	if _, err := flagParser.Parse(); err != nil {
		return nil, nil, err
	}

	// Make sure everything we just loaded makes sense.
	cleanCfg, cfgLogger, err := ValidateConfig(cfg, interceptor)
	if err != nil {
		// Log help message in case of usage error.
		if _, ok := err.(*usageError); ok {
			// The logging system might not yet be initialized, so
			// we also write to stderr to make sure the message
			// appears somewhere.
			_, _ = fmt.Fprintln(os.Stderr, usageMessage)
			if cfgLogger != nil {
				cfgLogger.Warnf("Incorrect usage: %v",
					usageMessage)
			}
		}

		// The logging system might not yet be initialized, so we also
		// write to stderr to make sure the error appears somewhere.
		// We still try to log the error there since some packaging
		// solutions might only look at the log and not stdout/stderr.
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		if cfgLogger != nil {
			cfgLogger.Warnf("Error validating config: %v", err)
		}
		return nil, nil, err
	}

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		cfgLogger.Warnf("%v", configFileError)
	}

	return cleanCfg, cfgLogger, nil
}

// usageError is an error type that signals a problem with the supplied flags.
type usageError struct {
	err error
}

// Error returns the error string.
//
// NOTE: This is part of the error interface.
func (u *usageError) Error() string {
	return u.err.Error()
}

// ValidateConfig check the given configuration to be sane. This makes sure no
// illegal values or combination of values are set. All file system paths are
// normalized. The cleaned up config is returned on success.
func ValidateConfig(cfg Config, interceptor signal.Interceptor) (*Config,
	btclog.Logger, error) {

	// If the provided tarod directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	taroDir := CleanAndExpandPath(cfg.TaroDir)
	if taroDir != DefaultTaroDir {
		cfg.DataDir = filepath.Join(taroDir, defaultDataDirname)
		cfg.RpcConf.TLSCertPath = filepath.Join(
			taroDir, defaultTLSCertFilename,
		)
		cfg.RpcConf.TLSKeyPath = filepath.Join(
			taroDir, defaultTLSKeyFilename,
		)
		cfg.LogDir = filepath.Join(taroDir, defaultLogDirname)
	}

	funcName := "ValidateConfig"
	mkErr := func(format string, args ...interface{}) error {
		return fmt.Errorf(funcName+": "+format, args...)
	}
	makeDirectory := func(dir string) error {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			// Show a nicer error message if it's because a symlink
			// is linked to a directory that does not exist
			// (probably because it's not mounted).
			if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
				link, lerr := os.Readlink(e.Path)
				if lerr == nil {
					str := "is symlink %s -> %s mounted?"
					err = fmt.Errorf(str, e.Path, link)
				}
			}

			str := "Failed to create tarod directory '%s': %v"
			return mkErr(str, dir, err)
		}

		return nil
	}

	// As soon as we're done parsing configuration options, ensure all
	// paths to directories and files are cleaned and expanded before
	// attempting to use them later on.
	cfg.DataDir = CleanAndExpandPath(cfg.DataDir)
	cfg.RpcConf.TLSCertPath = CleanAndExpandPath(cfg.RpcConf.TLSCertPath)
	cfg.RpcConf.TLSKeyPath = CleanAndExpandPath(cfg.RpcConf.TLSKeyPath)
	cfg.LogDir = CleanAndExpandPath(cfg.LogDir)
	cfg.RpcConf.MacaroonPath = CleanAndExpandPath(cfg.RpcConf.MacaroonPath)

	// Multiple networks can't be selected simultaneously.  Count number of
	// network flags passed; assign active network params
	// while we're at it.
	switch cfg.ChainConf.Network {
	case "testnet":
		cfg.ActiveNetParams = chaincfg.TestNet3Params
	case "regtest":
		cfg.ActiveNetParams = chaincfg.RegressionNetParams
	case "simnet":
		cfg.ActiveNetParams = chaincfg.SimNetParams
	case "signet":
		cfg.ActiveNetParams = chaincfg.SigNetParams

		// Let the user overwrite the default signet parameters.
		// The challenge defines the actual signet network to
		// join and the seed nodes are needed for network
		// discovery.
		sigNetChallenge := chaincfg.DefaultSignetChallenge
		sigNetSeeds := chaincfg.DefaultSignetDNSSeeds
		if cfg.ChainConf.SigNetChallenge != "" {
			challenge, err := hex.DecodeString(
				cfg.ChainConf.SigNetChallenge,
			)
			if err != nil {
				return nil, nil, mkErr("Invalid "+
					"signet challenge, hex decode "+
					"failed: %v", err)
			}
			sigNetChallenge = challenge
		}

		chainParams := chaincfg.CustomSignetParams(
			sigNetChallenge, sigNetSeeds,
		)
		cfg.ActiveNetParams = chainParams
	default:
		return nil, nil, mkErr(fmt.Sprintf("invalid network: %v",
			cfg.ChainConf.Network))
	}

	// Validate profile port or host:port.
	if cfg.Profile != "" {
		str := "%s: The profile port must be between 1024 and 65535"

		// Try to parse Profile as a host:port.
		_, hostPort, err := net.SplitHostPort(cfg.Profile)
		if err == nil {
			// Determine if the port is valid.
			profilePort, err := strconv.Atoi(hostPort)
			if err != nil || profilePort < 1024 || profilePort > 65535 {
				return nil, nil, &usageError{mkErr(str)}
			}
		} else {
			// Try to parse Profile as a port.
			profilePort, err := strconv.Atoi(cfg.Profile)
			if err != nil || profilePort < 1024 || profilePort > 65535 {
				return nil, nil, &usageError{mkErr(str)}
			}

			// Since the user just set a port, we will serve debugging
			// information over localhost.
			cfg.Profile = net.JoinHostPort("127.0.0.1", cfg.Profile)
		}
	}

	// We'll now construct the network directory which will be where we
	// store all the data specific to this chain/network.
	cfg.networkDir = filepath.Join(
		cfg.DataDir, lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// We'll also update the database file location as well, if it wasn't
	// set.
	if cfg.Sqlite.DatabaseFileName == defaultSqliteDatabasePath {
		cfg.Sqlite.DatabaseFileName = filepath.Join(
			cfg.networkDir, defaultSqliteDatabaseFileName,
		)
	}

	// If a custom macaroon directory wasn't specified and the data
	// directory has changed from the default path, then we'll also update
	// the path for the macaroons to be generated.
	if cfg.RpcConf.MacaroonPath == "" {
		cfg.RpcConf.MacaroonPath = filepath.Join(
			cfg.networkDir, defaultAdminMacFilename,
		)
	}

	// Make sure only one of the macaroon options is used.
	switch {
	case cfg.Lnd.MacaroonPath != defaultLndMacaroonPath &&
		cfg.Lnd.MacaroonDir != "":

		return nil, nil, fmt.Errorf("use --lnd.macaroonpath only")

	case cfg.Lnd.MacaroonDir != "":
		// With the new version of lndclient we can only specify a
		// single macaroon instead of all of them. If the old
		// macaroondir is used, we use the admin macaroon located in
		// that directory.
		cfg.Lnd.MacaroonPath = path.Join(
			lncfg.CleanAndExpandPath(cfg.Lnd.MacaroonDir),
			defaultLndMacaroon,
		)

	case cfg.Lnd.MacaroonPath != "":
		cfg.Lnd.MacaroonPath = lncfg.CleanAndExpandPath(
			cfg.Lnd.MacaroonPath,
		)

	default:
		return nil, nil, fmt.Errorf("must specify --lnd.macaroonpath")
	}

	// Adjust the default lnd macaroon path if only the network is
	// specified.
	if cfg.ChainConf.Network != defaultNetwork &&
		cfg.Lnd.MacaroonPath == defaultLndMacaroonPath {

		cfg.Lnd.MacaroonPath = path.Join(
			defaultLndDir, "data", "chain", "bitcoin",
			cfg.ChainConf.Network, defaultLndMacaroon,
		)
	}

	// Create the taro directory and all other sub-directories if they
	// don't already exist. This makes sure that directory trees are also
	// created for files that point to outside the taroddir.
	dirs := []string{
		taroDir, cfg.DataDir, cfg.networkDir,
		filepath.Dir(cfg.RpcConf.TLSCertPath),
		filepath.Dir(cfg.RpcConf.TLSKeyPath),
		filepath.Dir(cfg.RpcConf.MacaroonPath),
	}
	for _, dir := range dirs {
		if err := makeDirectory(dir); err != nil {
			return nil, nil, err
		}
	}

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = filepath.Join(
		cfg.LogDir, lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// A log writer must be passed in, otherwise we can't function and would
	// run into a panic later on.
	if cfg.LogWriter == nil {
		return nil, nil, mkErr("log writer missing in config")
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems",
			cfg.LogWriter.SupportedSubsystems())
		os.Exit(0)
	}

	// Initialize logging at the default logging level.
	taro.SetupLoggers(cfg.LogWriter, interceptor)
	err := cfg.LogWriter.InitLogRotator(
		filepath.Join(cfg.LogDir, defaultLogFilename),
		cfg.MaxLogFileSize, cfg.MaxLogFiles,
	)
	if err != nil {
		str := "log rotation setup failed: %v"
		return nil, nil, mkErr(str, err)
	}

	taroCfgLog := cfg.LogWriter.GenSubLogger("CONF", nil)

	// Parse, validate, and set debug log level(s).
	err = build.ParseAndSetDebugLevels(cfg.DebugLevel, cfg.LogWriter)
	if err != nil {
		str := "error parsing debug level: %v"
		return nil, taroCfgLog, &usageError{mkErr(str, err)}
	}

	// At least one RPCListener is required. So listen on localhost per
	// default.
	if len(cfg.RpcConf.RawRPCListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRPCPort)
		cfg.RpcConf.RawRPCListeners = append(
			cfg.RpcConf.RawRPCListeners, addr,
		)
	}

	// Listen on localhost if no REST listeners were specified.
	if len(cfg.RpcConf.RawRESTListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRESTPort)
		cfg.RpcConf.RawRESTListeners = append(
			cfg.RpcConf.RawRESTListeners, addr,
		)
	}

	// Add default port to all RPC listener addresses if needed and remove
	// duplicate addresses.
	cfg.rpcListeners, err = lncfg.NormalizeAddresses(
		cfg.RpcConf.RawRPCListeners, strconv.Itoa(defaultRPCPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, taroCfgLog, mkErr("error normalizing RPC listen addrs: %v", err)
	}

	// Add default port to all REST listener addresses if needed and remove
	// duplicate addresses.
	cfg.restListeners, err = lncfg.NormalizeAddresses(
		cfg.RpcConf.RawRESTListeners, strconv.Itoa(defaultRESTPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, taroCfgLog, mkErr("error normalizing REST listen addrs: %v", err)
	}

	// For each of the RPC listeners (REST+gRPC), we'll ensure that users
	// have specified a safe combo for authentication. If not, we'll bail
	// out with an error. Since we don't allow disabling TLS for gRPC
	// connections we pass in tlsActive=true.
	err = lncfg.EnforceSafeAuthentication(
		cfg.rpcListeners, !cfg.RpcConf.NoMacaroons, true,
	)
	if err != nil {
		return nil, taroCfgLog, mkErr("error enforcing safe authentication on "+
			"RPC ports: %v", err)
	}

	if cfg.RpcConf.DisableRest {
		taroCfgLog.Infof("REST API is disabled!")
		cfg.restListeners = nil
	} else {
		err = lncfg.EnforceSafeAuthentication(
			cfg.restListeners, !cfg.RpcConf.NoMacaroons,
			!cfg.RpcConf.DisableRestTLS,
		)
		if err != nil {
			return nil, taroCfgLog, mkErr("error enforcing safe "+
				"authentication on REST ports: %v", err)
		}
	}

	// All good, return the sanitized result.
	return &cfg, taroCfgLog, nil
}

// getTLSConfig returns a TLS configuration for the gRPC server and credentials
// and a proxy destination for the REST reverse proxy.
func getTLSConfig(cfg *Config,
	cfgLogger btclog.Logger) ([]grpc.ServerOption, []grpc.DialOption,
	func(net.Addr) (net.Listener, error), error) {

	// Ensure we create TLS key and certificate if they don't exist.
	if !fileExists(cfg.RpcConf.TLSCertPath) &&
		!fileExists(cfg.RpcConf.TLSKeyPath) {

		cfgLogger.Infof("Generating TLS certificates...")
		certBytes, keyBytes, err := cert.GenCertPair(
			"taro autogenerated cert", cfg.RpcConf.TLSExtraIPs,
			cfg.RpcConf.TLSExtraDomains,
			cfg.RpcConf.TLSDisableAutofill,
			cfg.RpcConf.TLSCertDuration,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		// Now that we have the certificate and key, we'll store them
		// to the file system.
		err = cert.WriteCertPair(
			cfg.RpcConf.TLSCertPath, cfg.RpcConf.TLSKeyPath,
			certBytes, keyBytes,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		cfgLogger.Infof("Done generating TLS certificates")
	}

	certData, parsedCert, err := cert.LoadCert(
		cfg.RpcConf.TLSCertPath, cfg.RpcConf.TLSKeyPath,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	// We check whether the certificate we have on disk match the IPs and
	// domains specified by the config. If the extra IPs or domains have
	// changed from when the certificate was created, we will refresh the
	// certificate if auto refresh is active.
	refresh := false
	if cfg.RpcConf.TLSAutoRefresh {
		refresh, err = cert.IsOutdated(
			parsedCert, cfg.RpcConf.TLSExtraIPs,
			cfg.RpcConf.TLSExtraDomains,
			cfg.RpcConf.TLSDisableAutofill,
		)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		cfgLogger.Info("TLS certificate is expired or outdated, " +
			"generating a new one")

		err := os.Remove(cfg.RpcConf.TLSCertPath)
		if err != nil {
			return nil, nil, nil, err
		}

		err = os.Remove(cfg.RpcConf.TLSKeyPath)
		if err != nil {
			return nil, nil, nil, err
		}

		cfgLogger.Infof("Renewing TLS certificates...")
		certBytes, keyBytes, err := cert.GenCertPair(
			"taro autogenerated cert", cfg.RpcConf.TLSExtraIPs,
			cfg.RpcConf.TLSExtraDomains,
			cfg.RpcConf.TLSDisableAutofill,
			cfg.RpcConf.TLSCertDuration,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		// Now that we have the certificate and key, we'll store them
		// to the file system.
		err = cert.WriteCertPair(
			cfg.RpcConf.TLSCertPath, cfg.RpcConf.TLSKeyPath,
			certBytes, keyBytes,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		cfgLogger.Infof("Done renewing TLS certificates")

		// Reload the certificate data.
		certData, _, err = cert.LoadCert(
			cfg.RpcConf.TLSCertPath, cfg.RpcConf.TLSKeyPath,
		)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	tlsCfg := cert.TLSConfFromCert(certData)

	restCreds, err := credentials.NewClientTLSFromFile(
		cfg.RpcConf.TLSCertPath, "",
	)
	if err != nil {
		return nil, nil, nil, err
	}

	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	// For our REST dial options, we'll still use TLS, but also increase
	// the max message size that we'll decode to allow clients to hit
	// endpoints which return more data such as the DescribeGraph call.
	// We set this to 200MiB atm. Should be the same value as maxMsgRecvSize
	// in cmd/tarocli/main.go.
	restDialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(restCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(lnrpc.MaxGrpcMsgSize),
		),
	}

	// Return a function closure that can be used to listen on a given
	// address with the current TLS config.
	restListen := func(addr net.Addr) (net.Listener, error) {
		// For restListen we will call ListenOnAddress if TLS is
		// disabled.
		if cfg.RpcConf.DisableRestTLS {
			return lncfg.ListenOnAddress(addr)
		}

		return lncfg.TLSListenOnAddress(addr, tlsCfg)
	}

	return serverOpts, restDialOpts, restListen, nil
}

// fileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// getLnd returns an instance of the lnd services proxy.
func getLnd(network string, cfg *LndConfig,
	interceptor signal.Interceptor) (*lndclient.GrpcLndServices, error) {

	// We'll want to wait for lnd to be fully synced to its chain backend.
	// The call to NewLndServices will block until the sync is completed.
	// But we still want to be able to shutdown the daemon if the user
	// decides to not wait. For that we can pass down a context that we
	// cancel on shutdown.
	ctxc, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Make sure the context is canceled if the user requests shutdown.
	go func() {
		select {
		// Client requests shutdown, cancel the wait.
		case <-interceptor.ShutdownChannel():
			cancel()

		// The check was completed and the above defer canceled the
		// context. We can just exit the goroutine, nothing more to do.
		case <-ctxc.Done():
		}
	}()

	return lndclient.NewLndServices(&lndclient.LndServicesConfig{
		LndAddress:            cfg.Host,
		Network:               lndclient.Network(network),
		CustomMacaroonPath:    cfg.MacaroonPath,
		TLSPath:               cfg.TLSPath,
		CheckVersion:          minimalCompatibleVersion,
		BlockUntilChainSynced: true,
		BlockUntilUnlocked:    true,
		CallerCtx:             ctxc,
	})
}
