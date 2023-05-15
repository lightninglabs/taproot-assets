package taro

import (
	"net"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tapdb"
	"github.com/lightninglabs/taro/tapfreighter"
	"github.com/lightninglabs/taro/tapgarden"
	"github.com/lightninglabs/taro/universe"
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

	UniverseForest *tapdb.BaseUniverseForest

	FederationDB *tapdb.UniverseFederationDB
}

// Config is the main config of the Taro server.
type Config struct {
	DebugLevel string

	// TODO(roasbeef): use the taro chain param wrapper here?
	ChainParams chaincfg.Params

	SignalInterceptor signal.Interceptor

	AssetMinter tapgarden.Planter

	AssetCustodian *tapgarden.Custodian

	ChainBridge tapgarden.ChainBridge

	AddrBook *address.Book

	ProofArchive proof.Archiver

	AssetWallet tapfreighter.Wallet

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
