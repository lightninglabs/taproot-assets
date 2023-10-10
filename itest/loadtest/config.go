package loadtest

import (
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/taproot-assets/taprpc"
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
}

// TapConfig are the main parameters needed for identifying and creating a grpc
// client to a tapd subsystem.
type TapConfig struct {
	Name string `long:"name" description:"the name of the tapd instance"`
	Host string `long:"host" description:"the host to connect to"`
	Port int    `long:"port" description:"the port to connect to"`

	TLSPath string `long:"tlspath" description:"Path to tapd's TLS certificate, leave empty if TLS is disabled"`
	MacPath string `long:"macpath" description:"Path to tapd's macaroon file"`
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

// Config holds the main configuration for the performance testing binary.
type Config struct {
	// TestCases is a comma separated list of test cases that will be
	// executed.
	TestCases []string `long:"test-case" description:"the test case that will be executed"`

	// Alice is the configuration for the main user in the network.
	Alice *User `group:"alice" namespace:"alice" description:"alice related configuration"`

	// Bob is the configuration for the secondary user in the network.
	Bob *User `group:"bob" namespace:"bob" description:"bob related configuration"`

	// Bitcoin is the configuration for the bitcoin backend.
	Bitcoin *BitcoinConfig `group:"bitcoin" namespace:"bitcoin" long:"bitcoin" description:"bitcoin client configuration"`

	// BatchSize is the number of assets to mint in a single batch. This is
	// only relevant for the mint test.
	BatchSize int `long:"mint-test-batch-size" description:"the number of assets to mint in a single batch; only relevant for the mint test"`

	// NumSends is the number of asset sends to perform. This is only
	// relevant for the send test.
	NumSends int `long:"send-test-num-sends" description:"the number of send operations to perform; only relevant for the send test"`

	// NumAssets is the number of assets to send in each send operation.
	// This is only relevant for the send test.
	NumAssets uint64 `long:"send-test-num-assets" description:"the number of assets to send in each send operation; only relevant for the send test"`

	// SendType is the type of asset to attempt to send. This is only
	// relevant for the send test.
	SendType taprpc.AssetType `long:"send-test-send-type" description:"the type of asset to attempt to send; only relevant for the send test"`

	// TestSuiteTimeout is the timeout for the entire test suite.
	TestSuiteTimeout time.Duration `long:"test-suite-timeout" description:"the timeout for the entire test suite"`

	// TestTimeout is the timeout for each test.
	TestTimeout time.Duration `long:"test-timeout" description:"the timeout for each test"`
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
		BatchSize:        100,
		NumSends:         50,
		NumAssets:        1, // We only mint collectibles.
		SendType:         taprpc.AssetType_COLLECTIBLE,
		TestSuiteTimeout: defaultSuiteTimeout,
		TestTimeout:      defaultTestTimeout,
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
	return &cfg, nil
}
