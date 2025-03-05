package loadtest

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jessevdk/go-flags"
)

const (
	// defaultConfigPath is the default path of the configuration file.
	defaultConfigPath = "loadtest.conf"

	// defaultSuiteTimeout is the default timeout for the entire test suite.
	defaultSuiteTimeout = 120 * time.Minute

	// defaultTestTimeout is the default timeout for each test.
	defaultTestTimeout = 10 * time.Minute
)

// User defines the config options for a user in the network.
type User struct {
	Tapd *TapConfig `group:"tapd"  namespace:"tapd"`
	Lnd  *LndConfig `group:"lnd" namespace:"lnd"`
}

// TapConfig are the main parameters needed for identifying and creating a grpc
// client to a tapd subsystem.
//
// nolint:lll
type TapConfig struct {
	Name     string `long:"name" description:"the name of the tapd instance"`
	Host     string `long:"host" description:"the host to connect to"`
	Port     int    `long:"port" description:"the port to connect to"`
	RestPort int    `long:"restport" description:"the rest port to connect to"`

	TLSPath string `long:"tlspath" description:"Path to tapd's TLS certificate, leave empty if TLS is disabled"`
	MacPath string `long:"macpath" description:"Path to tapd's macaroon file"`
}

// LndConfig are the main parameters needed for identifying and creating a grpc
// client to a lnd subsystem.
type LndConfig struct {
	Name string `long:"name" description:"the name of the lnd instance"`
	Host string `long:"host" description:"the host to connect to"`
	Port int    `long:"port" description:"the port to connect to"`

	TLSPath string `long:"tlspath" description:"Path to lnd's TLS certificate, leave empty if TLS is disabled"`
	MacPath string `long:"macpath" description:"Path to tlnd's macaroon file"`
}

// BitcoinConfig defines exported config options for the connection to the
// btcd/bitcoind backend.
type BitcoinConfig struct {
	Host     string `long:"host" description:"bitcoind/btcd instance address"`
	Port     int    `long:"port" description:"bitcoind/btcd instance port"`
	User     string `long:"user" description:"bitcoind/btcd user name"`
	Password string `long:"password" description:"bitcoind/btcd password"`
	TLSPath  string `long:"tlspath" description:"Path to btcd's TLS certificate, if TLS is enabled"`
}

// PrometheusGatewayConfig defines exported config options for connecting to the
// Prometheus PushGateway.
//
//nolint:lll
type PrometheusGatewayConfig struct {
	Enabled bool   `long:"enabled" description:"Enable pushing metrics to Prometheus PushGateway"`
	Host    string `long:"host" description:"Prometheus PushGateway host address"`
	Port    int    `long:"port" description:"Prometheus PushGateway port"`
	PushURL string
}

// Config holds the main configuration for the performance testing binary.
//
//nolint:lll
type Config struct {
	// TestCases is a comma separated list of test cases that will be
	// executed.
	TestCases []string `long:"test-case" description:"the test case that will be executed"`

	// Alice is the configuration for the main user in the network.
	Alice *User `group:"alice" namespace:"alice" description:"alice related configuration"`

	// Bob is the configuration for the secondary user in the network.
	Bob *User `group:"bob" namespace:"bob" description:"bob related configuration"`

	// Network is the network that the nodes are connected to.
	Network string `long:"network" description:"the network the nodes are connected to" choice:"regtest" choice:"testnet" choice:"mainnet"`

	// Bitcoin is the configuration for the bitcoin backend.
	Bitcoin *BitcoinConfig `group:"bitcoin" namespace:"bitcoin" long:"bitcoin" description:"bitcoin client configuration"`

	// BatchSize is the number of assets to mint in a single batch. This is
	// only relevant for the mint test.
	BatchSize int `long:"mint-test-batch-size" description:"the number of assets to mint in a single batch; only relevant for the mint test"`

	// TotalNumGroups is the total number of groups that the minted assets
	// belong to.
	TotalNumGroups int `long:"mint-test-total-groups" description:"the total number of groups the minted assets belong to"`

	// MintSupplyMin is the minimum supply to mint per asset.
	MintSupplyMin int `long:"mint-test-supply-min" description:"the max supply to mint per asset"`

	// MintSupplyMax is the max suipply to mint per asset.
	MintSupplyMax int `long:"mint-test-supply-max" description:"the min supply to mint per asset"`

	// NumSends is the number of asset sends to perform. This is only
	// relevant for the send test.
	NumSends int `long:"send-test-num-sends" description:"the number of send operations to perform; only relevant for the send test"`

	// NumAssets is the number of assets to send in each send operation.
	// This is only relevant for the send test.
	NumAssets uint64 `long:"send-test-num-assets" description:"the number of assets to send in each send operation; only relevant for the send test"`

	// SendAssetType is the type of asset to attempt to send. This is only
	// relevant for the send test. Acceptable values are "normal" and
	// "collectible".
	SendAssetType string `long:"send-asset-type" description:"the type of asset to attempt to send; only relevant for the send test"`

	// SyncType is the type of sync to execute in the sync test. Acceptable
	// values include:
	//     "simplesyncer": re-uses simple syncer to perform a full sync
	//     "rest": syncs the roots over rest requests
	SyncType string `long:"sync-type" description:"the type of sync to execute"`

	// SyncPageSize is the page size to use in the sync test for calls made
	// to the universe server.
	SyncPageSize int `long:"sync-page-size" description:"the page size to use in the sync test when fetching data from the universe server"`

	// SyncNumClients is the number of clients to use in the sync test. This
	// many clients will try to sync in parallel.
	SyncNumClients int `long:"sync-num-clients" description:"the number of sync clients to use for the sync test"`

	// TestSuiteTimeout is the timeout for the entire test suite.
	TestSuiteTimeout time.Duration `long:"test-suite-timeout" description:"the timeout for the entire test suite"`

	// TestTimeout is the timeout for each test.
	TestTimeout time.Duration `long:"test-timeout" description:"the timeout for each test"`

	// PrometheusGateway is the configuration for the Prometheus
	// PushGateway.
	PrometheusGateway *PrometheusGatewayConfig `group:"prometheus-gateway" namespace:"prometheus-gateway" description:"Prometheus PushGateway configuration"`
}

// DefaultConfig returns the default configuration for the performance testing
// binary.
func DefaultConfig() Config {
	return Config{
		Alice: &User{
			Tapd: &TapConfig{
				Name: "alice",
			},
		},
		Bob: &User{
			Tapd: &TapConfig{
				Name: "bob",
			},
		},
		Network:          "regtest",
		BatchSize:        100,
		NumSends:         50,
		NumAssets:        1,
		SendAssetType:    "normal",
		TestSuiteTimeout: defaultSuiteTimeout,
		TestTimeout:      defaultTestTimeout,
		PrometheusGateway: &PrometheusGatewayConfig{
			Enabled: false,
			Host:    "localhost",
			Port:    9091,
		},
	}
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Load configuration file overwriting defaults with any specified options
func LoadConfig() (*Config, error) {
	// First, load any additional configuration options from the file.
	cfg := DefaultConfig()
	fileParser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(defaultConfigPath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok { //nolint:gosimple
			return nil, err
		}
	}

	// Make sure everything we just loaded makes sense.
	cleanCfg, err := ValidateConfig(cfg)
	if err != nil {
		return nil, err
	}

	return cleanCfg, nil
}

// ValidateConfig validates the given configuration and returns a clean version
// of it with sane defaults.
func ValidateConfig(cfg Config) (*Config, error) {
	// TODO (positiveblue): add validation logic.

	// Validate Prometheus PushGateway configuration.
	if cfg.PrometheusGateway.Enabled {
		gatewayHost := cfg.PrometheusGateway.Host
		gatewayPort := cfg.PrometheusGateway.Port

		if gatewayHost == "" {
			return nil, fmt.Errorf("gateway hostname may not be " +
				"empty")
		}

		if gatewayPort == 0 {
			return nil, fmt.Errorf("gateway port is not set")
		}

		// Construct the endpoint for Prometheus PushGateway.
		cfg.PrometheusGateway.PushURL = fmt.Sprintf(
			"%s:%d", gatewayHost, gatewayPort,
		)
	}

	return &cfg, nil
}

// networkParams parses the global network flag into a chaincfg.Params.
func networkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil

	case "testnet":
		return &chaincfg.TestNet3Params, nil

	case "regtest":
		return &chaincfg.RegressionNetParams, nil

	case "simnet":
		return &chaincfg.SimNetParams, nil

	case "signet":
		return &chaincfg.SigNetParams, nil

	default:
		return nil, fmt.Errorf("unknown network: %v", network)
	}
}
