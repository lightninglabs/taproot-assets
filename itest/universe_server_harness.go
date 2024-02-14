package itest

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/stretchr/testify/require"
)

type universeServerHarness struct {
	// service is the instance of the universe tap service.
	service *tapdHarness

	// ListenAddr is the address that the service is listening on.
	ListenAddr string

	// lndHarness is the instance of the lnd harness that the service is
	// using.
	LndHarness *node.HarnessNode
}

func newUniverseServerHarness(t *testing.T, ht *harnessTest,
	lndHarness *node.HarnessNode) *universeServerHarness {

	service, err := newTapdHarness(t, ht, tapdConfig{
		NetParams: harnessNetParams,
		LndNode:   lndHarness,
	})
	require.NoError(t, err)

	return &universeServerHarness{
		service:    service,
		ListenAddr: service.rpcHost(),
		LndHarness: lndHarness,
	}
}

// Start starts the service.
func (h *universeServerHarness) Start(_ chan error) error {
	return h.service.start(false)
}

// Stop stops the service.
func (h *universeServerHarness) Stop() error {
	// Don't delete temporary data on stop. This will allow us to cleanly
	// restart the service mid-test.
	return h.service.stop(false)
}

// Ensure that universeServerHarness implements the proof.CourierHarness
// interface.
var _ proof.CourierHarness = (*universeServerHarness)(nil)
