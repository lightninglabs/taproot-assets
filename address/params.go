package address

import (
	"fmt"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
)

const (
	// MainnetHRP is the HRP for mainnet.
	MainnetHRP = "tarobc"

	// TestnetHRP is the HRP for testnet.
	TestnetHRP = "tarotb"

	// RegTestHRP is the HRP for regtest.
	RegTestHRP = "tarort"

	// SigNetHRP is the HRP for "the" signet.
	SigNetHRP = "tarotb"

	// SimNetHRP is the HRP for simnet.
	SimNetHRP = "tarosb"
)

// ChainParams defines a Taro-supporting network by its parameters. These
// parameters include those specified by chaincfg.Params, as well as a
// Taro-specific HRP used for Taro addresses. These parameters may be
// used by Taro applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type ChainParams struct {
	*chaincfg.Params

	// TaroHRP is the HRP to use for Taro addresses for the target network.
	TaroHRP string
}

// registerMtx is used to provide thread-safe access to the internal global
// vriables.
var registerMtx sync.RWMutex

// Register attempts to register a new taro ChainParams with the library. If a
// set of parameters for the network has already been registered, then an error
// is returned.
//
// TODO(jhb): Resolve duplicate networks?
func Register(params *ChainParams) error {
	registerMtx.Lock()
	defer registerMtx.Unlock()

	err := chaincfg.Register(params.Params)
	if err != nil {
		return err
	}

	bech32TaroPrefixes[params.TaroHRP+"1"] = struct{}{}
	return nil
}

var (
	// bech32TaroPrefixes holds the set of all supported prefixes for
	// bech32m encoded addresses.
	bech32TaroPrefixes = make(map[string]struct{})

	// MainNetTaro holds the chain params for mainnet.
	MainNetTaro = ChainParams{
		Params:  &chaincfg.MainNetParams,
		TaroHRP: MainnetHRP,
	}

	// TestNet3Taro holds the chain params for testnet.
	TestNet3Taro = ChainParams{
		Params:  &chaincfg.TestNet3Params,
		TaroHRP: TestnetHRP,
	}

	// RegressionNetParams holds the chain params for regtest.
	RegressionNetTaro = ChainParams{
		Params:  &chaincfg.RegressionNetParams,
		TaroHRP: RegTestHRP,
	}

	// SigNetTaro holds the chain params for signet.
	SigNetTaro = ChainParams{
		Params:  &chaincfg.SigNetParams,
		TaroHRP: SigNetHRP,
	}

	// SimNetTaro holds the chain params for simnet.
	SimNetTaro = ChainParams{
		Params:  &chaincfg.SimNetParams,
		TaroHRP: SimNetHRP,
	}
)

// IsBech32MTaroPrefix returns whether the prefix is a known prefix for Taro
// addresses on any supported network.  This is used when creating an address,
// encoding an address to a string, or decoding an address string into a TLV.
func IsBech32MTaroPrefix(prefix string) bool {
	registerMtx.RLock()
	defer registerMtx.RUnlock()

	prefix = strings.ToLower(prefix)
	_, ok := bech32TaroPrefixes[prefix]
	return ok
}

// IsForNet returns whether or not the HRP is associated with the
// passed network.
func IsForNet(hrp string, net *ChainParams) bool {
	return hrp == net.TaroHRP
}

// Net returns the ChainParams struct associated with a Taro HRP.
func Net(hrp string) (*ChainParams, error) {
	switch hrp {
	case MainNetTaro.TaroHRP:
		return &MainNetTaro, nil

	case TestNet3Taro.TaroHRP:
		return &TestNet3Taro, nil

	case RegressionNetTaro.TaroHRP:
		return &RegressionNetTaro, nil

	case SigNetTaro.TaroHRP:
		return &SigNetTaro, nil

	case SimNetTaro.TaroHRP:
		return &SimNetTaro, nil

	default:
		return nil, ErrUnsupportedHRP
	}
}

// ParamsForChain returns the ChainParams for a given chain based on its name.
func ParamsForChain(name string) ChainParams {
	switch name {
	case chaincfg.MainNetParams.Name:
		return MainNetTaro
	case chaincfg.TestNet3Params.Name:
		return TestNet3Taro
	case chaincfg.RegressionNetParams.Name:
		return RegressionNetTaro
	case chaincfg.SigNetParams.Name:
		return SigNetTaro
	case chaincfg.SimNetParams.Name:
		return SimNetTaro
	default:
		panic(fmt.Sprintf("unknown chain: %v", name))
	}
}

func init() {
	registerMtx.RLock()
	defer registerMtx.RUnlock()

	// Register all default networks when the package is initialized.
	bech32TaroPrefixes[MainNetTaro.TaroHRP+"1"] = struct{}{}
	bech32TaroPrefixes[TestNet3Taro.TaroHRP+"1"] = struct{}{}
	bech32TaroPrefixes[RegressionNetTaro.TaroHRP+"1"] = struct{}{}
	bech32TaroPrefixes[SigNetTaro.TaroHRP+"1"] = struct{}{}
	bech32TaroPrefixes[SimNetTaro.TaroHRP+"1"] = struct{}{}
}
