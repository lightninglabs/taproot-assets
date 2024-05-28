package rfq

import (
	"fmt"
)

const (
	MockPriceOracleServiceAddress = "use_mock_price_oracle_service_" +
		"promise_to_not_use_on_mainnet"
)

// CliConfig is a struct that holds tapd cli configuration options for the RFQ
// service.
//
// nolint: lll
type CliConfig struct {
	PriceOracleAddress string `long:"priceoracleaddress" description:"Price oracle gRPC server address (rfqrpc://<hostname>:<port>). To use the integrated mock, use the following value: use_mock_price_oracle_service_promise_to_not_use_on_mainnet"`

	SkipAcceptQuotePriceCheck bool `long:"skipacceptquotepricecheck" description:"Accept any price quote returned by RFQ peer, skipping price validation"`

	MockOracleCentPerSat uint64 `long:"mockoraclecentpersat" description:"Mock price oracle static USD cent per sat rate"`
}

// Validate returns an error if the configuration is invalid.
func (c *CliConfig) Validate() error {
	// If the user has specified a mock oracle USD per BTC rate but the
	// price oracle address is not the mock price oracle service address,
	// then we'll return an error.
	if c.MockOracleCentPerSat > 0 &&
		c.PriceOracleAddress != MockPriceOracleServiceAddress {

		return fmt.Errorf("mockoraclecentpersat can only be used "+
			"with the mock price oracle service, set "+
			"priceoracleaddress to %s",
			MockPriceOracleServiceAddress)
	}

	// If the user has specified the mock price oracle service address but
	// has not set the mock oracle USD per BTC rate, then we'll return an
	// error.
	if c.PriceOracleAddress == MockPriceOracleServiceAddress &&
		c.MockOracleCentPerSat == 0 {

		return fmt.Errorf("mockoraclecentpersat must be set when " +
			"using the mock price oracle service")
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
