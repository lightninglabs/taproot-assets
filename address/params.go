package address

import (
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
)

// Human-readable prefixes for bech32m encoded addresses for each network.
const (
	Bech32HRPTaroMainnet = "taro"
	Bech32HRPTaroTestnet = "tarot"
)

// ChainParams defines a Taro-supporting network by its parameters. These
// parameters include those specified by chaincfg.Params, as well as a
// Taro-specific HRP used for Taro addresses. These parameters may be
// used by Taro applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type ChainParams struct {
	*chaincfg.Params
	TaroHRP string
}

// TODO(jhb): Resolve duplicate networks?
func Register(params *ChainParams) error {
	err := chaincfg.Register(params.Params)
	if err != nil {
		return err
	}

	bech32TaroPrefixes[params.TaroHRP+"1"] = struct{}{}
	return nil
}

var (
	// Set of all supported prefixes for bech32m encoded addresses.
	bech32TaroPrefixes = make(map[string]struct{})

	// Default Taro-supportng networks.
	MainNetTaro  = ChainParams{&chaincfg.MainNetParams, Bech32HRPTaroMainnet}
	TestNet3Taro = ChainParams{&chaincfg.TestNet3Params, Bech32HRPTaroTestnet}
)

// IsBech32MTaroPrefix returns whether the prefix is a known prefix for Taro
// addresses on any supported network.  This is used when creating an address,
// encoding an address to a string, or decoding an address string into a TLV.
func IsBech32MTaroPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32TaroPrefixes[prefix]
	return ok
}

// IsForNet returns whether or not the HRP is associated with the
// passed network.
func IsForNet(hrp string, net *ChainParams) bool {
	return hrp == net.TaroHRP
}

func init() {
	// Register all default networks when the package is initialized.
	bech32TaroPrefixes[MainNetTaro.TaroHRP+"1"] = struct{}{}
	bech32TaroPrefixes[TestNet3Taro.TaroHRP+"1"] = struct{}{}
}
