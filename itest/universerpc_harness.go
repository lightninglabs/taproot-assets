package itest

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/stretchr/testify/require"
)

// UniverseRPCHarness is an integration testing harness for the universe tap
// service.
type UniverseRPCHarness struct {
	// service is the instance of the universe tap service.
	service *tapdHarness

	// ListenAddr is the address that the service is listening on.
	ListenAddr string
}

// NewUniverseRPCHarness creates a new test harness for a universe tap service.
func NewUniverseRPCHarness(t *testing.T, ht *harnessTest,
	lndHarness *node.HarnessNode) *UniverseRPCHarness {

	service, err := newTapdHarness(
		t, ht, tapdConfig{
			NetParams: harnessNetParams,
			LndNode:   lndHarness,
		},
	)
	require.NoError(t, err)

	return &UniverseRPCHarness{
		service:    service,
		ListenAddr: service.rpcHost(),
	}
}

// Start starts the service.
func (h *UniverseRPCHarness) Start(_ chan error) error {
	return h.service.start(false)
}

// Stop stops the service.
func (h *UniverseRPCHarness) Stop() error {
	return h.service.stop(true)
}

// Ensure that NewUniverseRPCHarness implements the proof.CourierHarness
// interface.
var _ proof.CourierHarness = (*UniverseRPCHarness)(nil)
