package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btclog"
	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/build"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/tor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultDataDirname      = "data"
	defaultChainSubDirname  = "chain"
	defaultTLSCertFilename  = "tls.cert"
	defaultTLSKeyFilename   = "tls.key"
	defaultAdminMacFilename = "admin.macaroon"
	defaultReadMacFilename  = "readonly.macaroon"
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

	defaultDataDir = filepath.Join(DefaultTaroDir, defaultDataDirname)
	defaultLogDir  = filepath.Join(DefaultTaroDir, defaultLogDirname)

	defaultTLSCertPath = filepath.Join(DefaultTaroDir, defaultTLSCertFilename)
	defaultTLSKeyPath  = filepath.Join(DefaultTaroDir, defaultTLSKeyFilename)
)

// ChainConfig...
type ChainConfig struct {
	ChainDir string `long:"chaindir" description:"The directory to store the chain's data within."`

	MainNet         bool   `long:"mainnet" description:"Use the main network"`
	TestNet3        bool   `long:"testnet" description:"Use the test network"`
	SimNet          bool   `long:"simnet" description:"Use the simulation test network"`
	RegTest         bool   `long:"regtest" description:"Use the regression test network"`
	SigNet          bool   `long:"signet" description:"Use the signet test network"`
	SigNetChallenge string `long:"signetchallenge" description:"Connect to a custom signet network defined by this challenge instead of using the global default signet test network -- Can be specified multiple times"`
}

// RpcConfig...
type RpcConfig struct {
	RawRPCListeners  []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
	RawRESTListeners []string `long:"restlisten" description:"Add an interface/port/socket to listen for REST connections"`

	TLSCertPath        string        `long:"tlscertpath" description:"Path to write the TLS certificate for lnd's RPC and REST services"`
	TLSKeyPath         string        `long:"tlskeypath" description:"Path to write the TLS private key for lnd's RPC and REST services"`
	TLSExtraIPs        []string      `long:"tlsextraip" description:"Adds an extra ip to the generated certificate"`
	TLSExtraDomains    []string      `long:"tlsextradomain" description:"Adds an extra domain to the generated certificate"`
	TLSAutoRefresh     bool          `long:"tlsautorefresh" description:"Re-generate TLS certificate and key if the IPs or domains are changed"`
	TLSDisableAutofill bool          `long:"tlsdisableautofill" description:"Do not include the interface IPs or the system hostname in TLS certificate, use first --tlsextradomain as Common Name instead, if set"`
	TLSCertDuration    time.Duration `long:"tlscertduration" description:"The duration for which the auto-generated TLS certificate will be valid for"`

	DisableRest    bool          `long:"norest" description:"Disable REST API"`
	DisableRestTLS bool          `long:"no-rest-tls" description:"Disable TLS for REST connections"`
	WSPingInterval time.Duration `long:"ws-ping-interval" description:"The ping interval for REST based WebSocket connections, set to 0 to disable sending ping messages from the server side"`
	WSPongWait     time.Duration `long:"ws-pong-wait" description:"The time we wait for a pong response message on REST based WebSocket connections before the connection is closed as inactive"`

	NoMacaroons  bool   `long:"no-macaroons" description:"Disable macaroon authentication, can only be used if server is not listening on a public interface."`
	AdminMacPath string `long:"adminmacaroonpath" description:"Path to write the admin macaroon for lnd's RPC and REST services if it doesn't exist"`
	ReadMacPath  string `long:"readonlymacaroonpath" description:"Path to write the read-only macaroon for lnd's RPC and REST services if it doesn't exist"`

	RestCORS []string `long:"restcors" description:"Add an ip:port/hostname to allow cross origin access from. To allow all origins, set as \"*\"."`
}

// Config...
type Config struct {
	ShowVersion bool `short:"V" long:"version" description:"Display version information and exit"`

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <global-level>,<subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	TaroDir    string `long:"tarodir" description:"The base directory that contains taro's data, logs, configuration file, etc."`
	ConfigFile string `short:"C" long:"configfile" description:"Path to configuration file"`

	DataDir        string `short:"b" long:"datadir" description:"The directory to store taro's data within"`
	LogDir         string `long:"logdir" description:"Directory to log output."`
	MaxLogFiles    int    `long:"maxlogfiles" description:"Maximum logfiles to keep (0 for no rotation)"`
	MaxLogFileSize int    `long:"maxlogfilesize" description:"Maximum logfile size in MB"`

	CPUProfile string `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	Profile    string `long:"profile" description:"Enable HTTP profiling on either a port or host:port"`

	ChainConf *ChainConfig
	RpcConf   *RpcConfig

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
			TestNet3: true,
		},
		LogWriter: build.NewRotatingLogWriter(),
	}
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
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
		fmt.Println(appName, "version", build.Version(),
			"commit="+build.Commit)
		os.Exit(0)
	}

	// If the config file path has not been modified by the user, then we'll
	// use the default config file path. However, if the user has modified
	// their lnddir, then we should assume they intend to use the config
	// file within it.
	configFileDir := CleanAndExpandPath(preCfg.TaroDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	switch {
	// User specified --lnddir but no --configfile. Update the config file
	// path to the lnd config directory, but don't require it to exist.
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
	cleanCfg, cfgLogger, err := ValidateConfig(
		cfg, interceptor, fileParser, flagParser,
	)
	if usageErr, ok := err.(*usageError); ok {
		// The logging system might not yet be initialized, so we also
		// write to stderr to make sure the error appears somewhere.
		_, _ = fmt.Fprintln(os.Stderr, usageMessage)
		cfgLogger.Warnf("Incorrect usage: %v", usageMessage)

		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		cfgLogger.Warnf("Error validating config: %v", usageErr.err)
	}
	if err != nil {
		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		cfgLogger.Warnf("Error validating config: %v", err)

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
func ValidateConfig(cfg Config, interceptor signal.Interceptor, fileParser,
	flagParser *flags.Parser) (*Config, btclog.Logger, error) {

	// If the provided lnd directory is not the default, we'll modify the
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

			str := "Failed to create lnd directory '%s': %v"
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
	cfg.RpcConf.AdminMacPath = CleanAndExpandPath(cfg.RpcConf.AdminMacPath)
	cfg.RpcConf.ReadMacPath = CleanAndExpandPath(cfg.RpcConf.ReadMacPath)

	// Multiple networks can't be selected simultaneously.  Count number of
	// network flags passed; assign active network params
	// while we're at it.
	numNets := 0
	if cfg.ChainConf.MainNet {
		numNets++
		cfg.ActiveNetParams = chaincfg.MainNetParams
	}
	if cfg.ChainConf.TestNet3 {
		numNets++
		cfg.ActiveNetParams = chaincfg.TestNet3Params
	}
	if cfg.ChainConf.RegTest {
		numNets++
		cfg.ActiveNetParams = chaincfg.RegressionNetParams
	}
	if cfg.ChainConf.SimNet {
		numNets++
		cfg.ActiveNetParams = chaincfg.SimNetParams
	}
	if cfg.ChainConf.SigNet {
		numNets++
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
	}
	if numNets > 1 {
		str := "The mainnet, testnet, regtest, and simnet " +
			"params can't be used together -- choose one " +
			"of the four"
		return nil, nil, mkErr(str)
	}

	// The target network must be provided, otherwise, we won't
	// know how to initialize the daemon.
	if numNets == 0 {
		str := "either --bitcoin.mainnet, or bitcoin.testnet," +
			"bitcoin.simnet, or bitcoin.regtest " +
			"must be specified"
		return nil, nil, mkErr(str)
	}

	cfg.ChainConf.ChainDir = filepath.Join(
		cfg.DataDir, defaultChainSubDirname,
		cfg.ActiveNetParams.Name,
	)

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
		cfg.DataDir, defaultChainSubDirname,
		lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// If a custom macaroon directory wasn't specified and the data
	// directory has changed from the default path, then we'll also update
	// the path for the macaroons to be generated.
	if cfg.RpcConf.AdminMacPath == "" {
		cfg.RpcConf.AdminMacPath = filepath.Join(
			cfg.networkDir, defaultAdminMacFilename,
		)
	}
	if cfg.RpcConf.ReadMacPath == "" {
		cfg.RpcConf.ReadMacPath = filepath.Join(
			cfg.networkDir, defaultReadMacFilename,
		)
	}

	// Create the taro directory and all other sub-directories if they
	// don't already exist. This makes sure that directory trees are also
	// created for files that point to outside the lnddir.
	dirs := []string{
		taroDir, cfg.DataDir, cfg.networkDir,
		filepath.Dir(cfg.RpcConf.TLSCertPath),
		filepath.Dir(cfg.RpcConf.TLSKeyPath),
		filepath.Dir(cfg.RpcConf.AdminMacPath),
		filepath.Dir(cfg.RpcConf.ReadMacPath),
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
		return nil, nil, &usageError{mkErr(str, err)}
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
		return nil, nil, mkErr("error normalizing RPC listen addrs: %v", err)
	}

	// Add default port to all REST listener addresses if needed and remove
	// duplicate addresses.
	cfg.restListeners, err = lncfg.NormalizeAddresses(
		cfg.RpcConf.RawRESTListeners, strconv.Itoa(defaultRESTPort),
		cfg.net.ResolveTCPAddr,
	)
	if err != nil {
		return nil, nil, mkErr("error normalizing REST listen addrs: %v", err)
	}

	// For each of the RPC listeners (REST+gRPC), we'll ensure that users
	// have specified a safe combo for authentication. If not, we'll bail
	// out with an error. Since we don't allow disabling TLS for gRPC
	// connections we pass in tlsActive=true.
	err = lncfg.EnforceSafeAuthentication(
		cfg.rpcListeners, !cfg.RpcConf.NoMacaroons, true,
	)
	if err != nil {
		return nil, nil, mkErr("error enforcing safe authentication on "+
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
			return nil, nil, mkErr("error enforcing safe "+
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
		err := cert.GenCertPair(
			"taro autogenerated cert", cfg.RpcConf.TLSCertPath,
			cfg.RpcConf.TLSKeyPath, cfg.RpcConf.TLSExtraIPs,
			cfg.RpcConf.TLSExtraDomains,
			cfg.RpcConf.TLSDisableAutofill,
			cfg.RpcConf.TLSCertDuration,
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
		err = cert.GenCertPair(
			"taro autogenerated cert", cfg.RpcConf.TLSCertPath,
			cfg.RpcConf.TLSKeyPath, cfg.RpcConf.TLSExtraIPs,
			cfg.RpcConf.TLSExtraDomains,
			cfg.RpcConf.TLSDisableAutofill,
			cfg.RpcConf.TLSCertDuration,
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
