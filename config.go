package taprootassets

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/monitoring"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

// RPCConfig is a sub-config of the main server that packages up everything
// needed to start the RPC server.
type RPCConfig struct {
	LisCfg *lnd.ListenerCfg

	RPCListeners []net.Addr

	RESTListeners []net.Addr

	GrpcServerOpts []grpc.ServerOption

	RestDialOpts []grpc.DialOption

	RestListenFunc func(net.Addr) (net.Listener, error)

	WSPingInterval time.Duration

	WSPongWait time.Duration

	RestCORS []string

	NoMacaroons bool

	MacaroonPath string

	AllowPublicUniProofCourier bool

	AllowPublicStats bool

	LetsEncryptDir string

	LetsEncryptListen string

	LetsEncryptDomain string

	LetsEncryptEmail string
}

// DatabaseConfig is the config that holds all the persistence related structs
// and interfaces needed for tapd to function.
type DatabaseConfig struct {
	RootKeyStore *tapdb.RootKeyStore

	MintingStore tapgarden.MintingStore

	AssetStore *tapdb.AssetStore

	TapAddrBook *tapdb.TapAddressBook

	Multiverse *tapdb.MultiverseStore

	FederationDB *tapdb.UniverseFederationDB
}

// UniversePublicAccessStatus is a type that indicates the status of public
// access to the universe server.
type UniversePublicAccessStatus string

const (
	// UniversePublicAccessStatusNone indicates that no public access is
	// granted.
	UniversePublicAccessStatusNone UniversePublicAccessStatus = ""

	// UniversePublicAccessStatusRead indicates that read access is granted.
	UniversePublicAccessStatusRead UniversePublicAccessStatus = "r"

	// UniversePublicAccessStatusWrite indicates that write access is
	// granted.
	UniversePublicAccessStatusWrite UniversePublicAccessStatus = "w"

	// UniversePublicAccessStatusReadWrite indicates that read and write
	// access is granted.
	UniversePublicAccessStatusReadWrite UniversePublicAccessStatus = "rw"
)

// IsReadAccessGranted returns true if the status indicates that read access
// is granted.
func (s UniversePublicAccessStatus) IsReadAccessGranted() bool {
	return s == UniversePublicAccessStatusRead ||
		s == UniversePublicAccessStatusReadWrite
}

// IsWriteAccessGranted returns true if the status indicates that write access
// is granted.
func (s UniversePublicAccessStatus) IsWriteAccessGranted() bool {
	return s == UniversePublicAccessStatusWrite ||
		s == UniversePublicAccessStatusReadWrite
}

// ParseUniversePublicAccessStatus parses a string into a universe public access
// status.
func ParseUniversePublicAccessStatus(
	s string) (UniversePublicAccessStatus, error) {

	switch s {
	case "rw", "wr":
		return UniversePublicAccessStatusReadWrite, nil

	case "r":
		return UniversePublicAccessStatusRead, nil

	case "w":
		return UniversePublicAccessStatusWrite, nil

	case "":
		return UniversePublicAccessStatusNone, nil

	default:
		// This default case returns an error. It will capture the case
		// where the CLI argument is present but unset (empty value).
		return UniversePublicAccessStatusNone, fmt.Errorf("unknown "+
			"universe public access status: %s", s)
	}
}

// Config is the main config of the Taproot Assets server.
type Config struct {
	DebugLevel string

	// RuntimeID is a pseudo-random ID that is generated when the server
	// starts. It is used to identify the server to itself, to avoid
	// connecting to itself as a federation member.
	RuntimeID int64

	// EnableChannelFeatures indicates that tapd is running inside the
	// Lightning Terminal daemon (litd) and can provide Taproot Asset
	// channel functionality.
	EnableChannelFeatures bool

	ChainParams address.ChainParams

	Lnd *lndclient.LndServices

	SignalInterceptor signal.Interceptor

	ReOrgWatcher *tapgarden.ReOrgWatcher

	AssetMinter tapgarden.Planter

	AssetCustodian *tapgarden.Custodian

	ChainBridge tapgarden.ChainBridge

	AddrBook *address.Book

	// AddrBookDisableSyncer is a flag which, if true, will prevent the
	// daemon from trying to sync issuance proofs for unknown assets when
	// creating an address.
	AddrBookDisableSyncer bool

	DefaultProofCourierAddr *url.URL

	ProofArchive proof.Archiver

	AssetWallet tapfreighter.Wallet

	CoinSelect *tapfreighter.CoinSelect

	ChainPorter tapfreighter.Porter

	UniverseArchive *universe.Archive

	UniverseSyncer universe.Syncer

	UniverseFederation *universe.FederationEnvoy

	// UniFedSyncAllAssets is a flag that indicates whether the
	// universe federation syncer should default to syncing all assets.
	UniFedSyncAllAssets bool

	RfqManager *rfq.Manager

	PriceOracle rfq.PriceOracle

	UniverseStats universe.Telemetry

	AuxLeafSigner *tapchannel.AuxLeafSigner

	AuxFundingController *tapchannel.FundingController

	AuxTrafficShaper *tapchannel.AuxTrafficShaper

	AuxInvoiceManager *tapchannel.AuxInvoiceManager

	AuxChanCloser *tapchannel.AuxChanCloser

	AuxSweeper *tapchannel.AuxSweeper

	// UniversePublicAccess is a field that indicates the status of public
	// access (i.e. read/write) to the universe server.
	//
	// NOTE: This field does not influence universe federation syncing
	// behaviour.
	UniversePublicAccess UniversePublicAccessStatus

	// UniverseQueriesPerSecond is the maximum number of queries per
	// second across the set of active universe queries that is permitted.
	// Anything above this starts to get rate limited.
	UniverseQueriesPerSecond rate.Limit

	// UniverseQueriesBurst is the burst budget for the universe query rate
	// limiting.
	UniverseQueriesBurst int

	Prometheus monitoring.PrometheusConfig

	// LogWriter is the root logger that all of the daemon's subloggers are
	// hooked up to.
	LogWriter *build.RotatingLogWriter

	// LogMgr is the sublogger manager that is used to create subloggers for
	// the daemon.
	LogMgr *build.SubLoggerManager

	*RPCConfig

	*DatabaseConfig
}
