package rfq

import (
	"fmt"
)

const (
	MockPriceOracleServiceAddress = "use_mock_price_oracle_service_" +
		"promise_to_not_use_on_mainnet"

	// MinAssetsPerBTC is the minimum number of asset units that one BTC
	// should cost. If the value is lower, then one asset unit would cost
	// too much to be able to represent small amounts of satoshis. With this
	// value, one asset unit would still cost 1k sats.
	MinAssetsPerBTC = 100_000
)

// CliConfig is a struct that holds tapd cli configuration options for the RFQ
// service.
//
// nolint: lll
type CliConfig struct {
	PriceOracleAddress string `long:"priceoracleaddress" description:"Price oracle gRPC server address (rfqrpc://<hostname>:<port>). To use the integrated mock, use the following value: use_mock_price_oracle_service_promise_to_not_use_on_mainnet"`

	AcceptPriceDeviationPpm uint64 `long:"acceptpricedeviationppm" description:"The default price deviation in parts per million that is accepted by the RFQ negotiator"`

	SkipAcceptQuotePriceCheck bool `long:"skipacceptquotepricecheck" description:"Accept any price quote returned by RFQ peer, skipping price validation"`

	MockOracleAssetsPerBTC uint64 `long:"mockoracleassetsperbtc" description:"Mock price oracle static asset units per BTC rate (for example number of USD cents per BTC if one asset unit represents a USD cent); whole numbers only, use either this or mockoraclesatsperasset depending on required precision"`

	// TODO(ffranr): Remove in favour of MockOracleAssetsPerBTC.
	MockOracleSatsPerAsset uint64 `long:"mockoraclesatsperasset" description:"Mock price oracle static satoshis per asset unit rate (for example number of satoshis to pay for one USD cent if one asset unit represents a USD cent); whole numbers only, use either this or mockoracleassetsperbtc depending on required precision"`
}

// Validate returns an error if the configuration is invalid.
func (c *CliConfig) Validate() error {
	// If the user has specified a mock oracle USD per BTC rate but the
	// price oracle address is not the mock price oracle service address,
	// then we'll return an error.
	if (c.MockOracleAssetsPerBTC > 0 || c.MockOracleSatsPerAsset > 0) &&
		c.PriceOracleAddress != MockPriceOracleServiceAddress {

		return fmt.Errorf("mockoracleassetsperbtc or "+
			"mockoraclesatsperasset can only be used "+
			"with the mock price oracle service, set "+
			"priceoracleaddress to %s",
			MockPriceOracleServiceAddress)
	}

	// If the user has specified the mock price oracle service address but
	// has not set the mock oracle USD per BTC rate, then we'll return an
	// error.
	if c.PriceOracleAddress == MockPriceOracleServiceAddress &&
		c.MockOracleAssetsPerBTC == 0 && c.MockOracleSatsPerAsset == 0 {

		return fmt.Errorf("mockoracleassetsperbtc or " +
			"mockoraclesatsperasset must be set when " +
			"using the mock price oracle service")
	}

	// Only one of the mock oracle rates can be set.
	if c.MockOracleAssetsPerBTC > 0 && c.MockOracleSatsPerAsset > 0 {
		return fmt.Errorf("only one of mockoracleassetsperbtc or " +
			"mockoraclesatsperasset can be set")
	}

	// The MockOracleAssetsPerBTC is more precise for tracking the actual
	// BTC price but less optimal for just specifying a dummy or test rate
	// for an asset that isn't BTC. The smaller the value, the more one
	// asset costs. If we allowed a value of 1, then one asset unit would
	// cost 1 BTC, which cannot really easily be transported over the
	// network. So we require a value of at least 100k, which would still
	// mean that one asset unit costs 1k sats.
	if c.MockOracleAssetsPerBTC > 0 &&
		c.MockOracleAssetsPerBTC < MinAssetsPerBTC {

		return fmt.Errorf("mockoracleassetsperbtc must be at least "+
			"%d asset units per BTC, otherwise one asset "+
			"unit would cost more than 1k sats per unit",
			MinAssetsPerBTC)
	}

	// Ensure that if the price oracle address not the mock price oracle
	// service address then it must be a valid gRPC address.
	if c.PriceOracleAddress != "" &&
		c.PriceOracleAddress != MockPriceOracleServiceAddress {

		_, err := ParsePriceOracleAddress(c.PriceOracleAddress)
		if err != nil {
			return fmt.Errorf("invalid price oracle service URI "+
				"address: %w", err)
		}
	}

	return nil
}
