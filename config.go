package taprootassets

import (
	"net"
	"net/url"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
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

	Multiverse *tapdb.BaseMultiverse

	FederationDB *tapdb.UniverseFederationDB
}

// Config is the main config of the Taproot Assets server.
type Config struct {
	DebugLevel string

	// RuntimeID is a pseudo-random ID that is generated when the server
	// starts. It is used to identify the server to itself, to avoid
	// connecting to itself as a federation member.
	RuntimeID int64

	AcceptRemoteUniverseProofs bool

	// TODO(roasbeef): use the Taproot Asset chain param wrapper here?
	ChainParams chaincfg.Params

	Lnd *lndclient.LndServices

	SignalInterceptor signal.Interceptor

	ReOrgWatcher *tapgarden.ReOrgWatcher

	AssetMinter tapgarden.Planter

	AssetCustodian *tapgarden.Custodian

	ChainBridge tapgarden.ChainBridge

	AddrBook *address.Book

	DefaultProofCourierAddr *url.URL

	ProofArchive proof.Archiver

	AssetWallet tapfreighter.Wallet

	CoinSelect *tapfreighter.CoinSelect

	ChainPorter tapfreighter.Porter

	BaseUniverse *universe.MintingArchive

	UniverseSyncer universe.Syncer

	UniverseFederation *universe.FederationEnvoy

	UniverseStats universe.Telemetry

	// LogWriter is the root logger that all of the daemon's subloggers are
	// hooked up to.
	LogWriter *build.RotatingLogWriter

	*RPCConfig

	*DatabaseConfig
}
