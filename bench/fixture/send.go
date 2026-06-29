package fixture

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/tapfreighter"
)

// Send extends Storage with the parts of the send/transfer path that do
// not require a real lnd Signer: CoinSelect (backed by the AssetStore).
//
// ChainPorter and AssetWallet need a real Signer to construct vPSBT
// witnesses; in-process benches that exercise those paths drive them
// through scenario harnesses rather than full RPC handlers. The Send
// fixture leaves those fields nil so any handler that needs them returns
// a clear error rather than silently misbehaving.
type Send struct {
	*Storage

	CoinSelect *tapfreighter.CoinSelect
}

// NewSend constructs a Send fixture and registers cleanup.
func NewSend(tb testing.TB) *Send {
	tb.Helper()

	st := NewStorage(tb)
	coinSelect := tapfreighter.NewCoinSelect(st.AssetStore)
	st.Config.CoinSelect = coinSelect

	return &Send{
		Storage:    st,
		CoinSelect: coinSelect,
	}
}
