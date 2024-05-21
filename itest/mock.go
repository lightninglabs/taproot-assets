package itest

import (
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightningnetwork/lnd/lnwire"
)

// MockAliasManager is a mock implementation of the AliasManager interface.
type MockAliasManager struct {
}

// AddLocalAlias is a mock implementation of the AliasManager interface.
func (m *MockAliasManager) AddLocalAlias(_ lnwire.ShortChannelID,
	_ lnwire.ShortChannelID, _ bool, _ bool) error {

	return nil
}

// DeleteLocalAlias is a mock implementation of the AliasManager interface.
func (m *MockAliasManager) DeleteLocalAlias(_ lnwire.ShortChannelID,
	_ lnwire.ShortChannelID) error {

	return nil
}

// Ensure MockAliasManager implements the AliasAdder interface.
var _ rfq.ScidAliasManager = (*MockAliasManager)(nil)
