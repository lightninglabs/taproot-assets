package taprootassets

import (
	"net"
	"net/url"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/monitoring"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
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

// Config is the main config of the Taproot Assets server.
type Config struct {
	DebugLevel string

	// RuntimeID is a pseudo-random ID that is generated when the server
	// starts. It is used to identify the server to itself, to avoid
	// connecting to itself as a federation member.
	RuntimeID int64

	// TODO(roasbeef): use the Taproot Asset chain param wrapper here?
	ChainParams chaincfg.Params

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

	RfqManager *rfq.Manager

	UniverseStats universe.Telemetry

	// UniversePublicAccess is flag which, If true, and the Universe server
	// is on a public interface, valid proof from remote parties will be
	// accepted, and proofs will be queryable by remote parties.
	// This applies to federation syncing as well as RPC insert and query.
	UniversePublicAccess bool

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

	*RPCConfig

	*DatabaseConfig
}
