package address

import (
	"fmt"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
)

const (
	// MainnetHRP is the HRP for mainnet.
	MainnetHRP = "tapbc"

	// TestnetHRP is the HRP for testnet.
	TestnetHRP = "taptb"

	// RegTestHRP is the HRP for regtest.
	RegTestHRP = "taprt"

	// SigNetHRP is the HRP for "the" signet.
	SigNetHRP = "taptb"

	// SimNetHRP is the HRP for simnet.
	SimNetHRP = "tapsb"
)

// ChainParams defines a Taproot Asset supporting network by its parameters.
// These parameters include those specified by chaincfg.Params, as well as a
// Taproot Asset specific HRP used for Taproot Asset addresses. These parameters
// may be used by Taproot Asset applications to differentiate networks as well
// as addresses and keys for one network from those intended for use on another
// network.
type ChainParams struct {
	*chaincfg.Params

	// TapHRP is the HRP to use for Taproot Asset addresses for the target
	// network.
	TapHRP string
}

// registerMtx is used to provide thread-safe access to the internal global
// variables.
var registerMtx sync.RWMutex

// Register attempts to register a new Taproot Asset ChainParams with the
// library. If a set of parameters for the network has already been registered,
// then an error is returned.
//
// TODO(jhb): Resolve duplicate networks?
func Register(params *ChainParams) error {
	registerMtx.Lock()
	defer registerMtx.Unlock()

	err := chaincfg.Register(params.Params)
	if err != nil {
		return err
	}

	bech32TapPrefixes[params.TapHRP+"1"] = struct{}{}
	return nil
}

var (
	// bech32TapPrefixes holds the set of all supported prefixes for
	// bech32m encoded addresses.
	bech32TapPrefixes = make(map[string]struct{})

	// MainNetTap holds the chain params for mainnet.
	MainNetTap = ChainParams{
		Params: &chaincfg.MainNetParams,
		TapHRP: MainnetHRP,
	}

	// TestNet3Tap holds the chain params for testnet.
	TestNet3Tap = ChainParams{
		Params: &chaincfg.TestNet3Params,
		TapHRP: TestnetHRP,
	}

	// RegressionNetTap holds the chain params for regtest.
	RegressionNetTap = ChainParams{
		Params: &chaincfg.RegressionNetParams,
		TapHRP: RegTestHRP,
	}

	// SigNetTap holds the chain params for signet.
	SigNetTap = ChainParams{
		Params: &chaincfg.SigNetParams,
		TapHRP: SigNetHRP,
	}

	// SimNetTap holds the chain params for simnet.
	SimNetTap = ChainParams{
		Params: &chaincfg.SimNetParams,
		TapHRP: SimNetHRP,
	}
)

// IsBech32MTapPrefix returns whether the prefix is a known prefix for Taproot
// Asset addresses on any supported network. This is used when creating an
// address, encoding an address to a string, or decoding an address string into
// a TLV.
func IsBech32MTapPrefix(prefix string) bool {
	registerMtx.RLock()
	defer registerMtx.RUnlock()

	prefix = strings.ToLower(prefix)
	_, ok := bech32TapPrefixes[prefix]
	return ok
}

// IsForNet returns whether the HRP is associated with the passed network.
func IsForNet(hrp string, net *ChainParams) bool {
	return hrp == net.TapHRP
}

// Net returns the ChainParams struct associated with a Taproot Asset HRP.
func Net(hrp string) (*ChainParams, error) {
	switch hrp {
	case MainNetTap.TapHRP:
		return &MainNetTap, nil

	case TestNet3Tap.TapHRP:
		return &TestNet3Tap, nil

	case RegressionNetTap.TapHRP:
		return &RegressionNetTap, nil

	case SigNetTap.TapHRP:
		return &SigNetTap, nil

	case SimNetTap.TapHRP:
		// For simnet, we'll need to slightly modify the coin type as
		// lnd only ever expects the testnet coin type (1) instead of
		// the simnet coin type (115).
		simNet := SimNetTap
		simNetParamsCopy := *simNet.Params
		simNet.Params = &simNetParamsCopy
		simNet.HDCoinType = TestNet3Tap.HDCoinType

		return &SimNetTap, nil

	default:
		return nil, ErrUnsupportedHRP
	}
}

// ParamsForChain returns the ChainParams for a given chain based on its name.
func ParamsForChain(name string) ChainParams {
	switch name {
	case chaincfg.MainNetParams.Name:
		return MainNetTap

	case chaincfg.TestNet3Params.Name:
		return TestNet3Tap

	case chaincfg.RegressionNetParams.Name:
		return RegressionNetTap

	case chaincfg.SigNetParams.Name:
		return SigNetTap

	case chaincfg.SimNetParams.Name:
		// For simnet, we'll need to slightly modify the coin type as
		// lnd only ever expects the testnet coin type (1) instead of
		// the simnet coin type (115).
		simNet := SimNetTap
		simNet.HDCoinType = TestNet3Tap.HDCoinType

		return simNet

	default:
		panic(fmt.Sprintf("unknown chain: %v", name))
	}
}

func init() {
	registerMtx.RLock()
	defer registerMtx.RUnlock()

	// Register all default networks when the package is initialized.
	bech32TapPrefixes[MainNetTap.TapHRP+"1"] = struct{}{}
	bech32TapPrefixes[TestNet3Tap.TapHRP+"1"] = struct{}{}
	bech32TapPrefixes[RegressionNetTap.TapHRP+"1"] = struct{}{}
	bech32TapPrefixes[SigNetTap.TapHRP+"1"] = struct{}{}
	bech32TapPrefixes[SimNetTap.TapHRP+"1"] = struct{}{}
}
