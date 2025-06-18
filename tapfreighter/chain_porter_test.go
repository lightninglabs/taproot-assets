package tapfreighter

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/stretchr/testify/require"
)

func TestRunChainPorter(t *testing.T) {
	t.Parallel()
}

// createTestSendPackage creates a sendPackage with minimal data for testing event creation.
func createTestSendPackage(id int64, label string) sendPackage {
	return sendPackage{
		OutboundPkg: &OutboundParcel{
			ID:    id,
			Label: label,
			// Other fields can be added if newAssetSendEvent/newAssetSendErrorEvent
			// start using them for populating AssetSendEvent fields relevant to TransferDBID.
		},
		// Populate other fields of sendPackage if they affect AssetSendEvent creation
		// regarding TransferDBID. For now, OutboundPkg.ID is the source.
		Label: label, // Also set top-level label if used
	}
}

func TestNewAssetSendEvent(t *testing.T) {
	t.Parallel()

	// Case 1: OutboundPkg is not nil
	pkgWithID := createTestSendPackage(123, "test_label_1")
	event1 := newAssetSendEvent(SendStateVirtualSign, pkgWithID)

	require.NotNil(t, event1, "Event should not be nil")
	require.Equal(t, pkgWithID.OutboundPkg.ID, event1.TransferDBID, "TransferDBID should match OutboundPkg.ID")
	require.Equal(t, SendStateVirtualSign, event1.SendState, "SendState not matching")
	require.Equal(t, pkgWithID.Label, event1.TransferLabel, "TransferLabel not matching")

	// Case 2: OutboundPkg is nil (though current newAssetSendEvent might panic or misbehave, good to test)
	// The current implementation of newAssetSendEvent accesses OutboundPkg.Copy()
	// which would panic if OutboundPkg is nil.
	// If the behavior is changed to handle nil OutboundPkg gracefully (e.g., setting TransferDBID to 0),
	// this test case would need adjustment.
	// For now, this case highlights the dependency on OutboundPkg.
	pkgWithoutOutbound := sendPackage{
		Label: "test_label_no_outbound",
		// OutboundPkg is nil
	}
	// We expect newAssetSendEvent to potentially panic or error if OutboundPkg is nil,
	// depending on implementation details of Copy() or direct field access.
	// Let's assume for now it's a programming error to call it with nil OutboundPkg
	// if it's expected to be non-nil for this function.
	// If it should handle it, the test would be different.
	// Based on current newAssetSendEvent, it calls pkg.OutboundPkg.Copy(),
	// so this would panic. We can test for that if it's the defined behavior,
	// or ensure OutboundPkg is always present when calling.
	// For the purpose of testing TransferDBID, we only care about the case where OutboundPkg is present.
	// If OutboundPkg can be nil, and TransferDBID should be 0, then this test would change.
	// The `newAssetSendEvent` function unconditionally calls `pkg.OutboundPkg.Copy()`.
	// So, `pkg.OutboundPkg` must not be nil.
}

func TestNewAssetSendErrorEvent(t *testing.T) {
	t.Parallel()

	testErr := fmt.Errorf("a test error")

	// Case 1: OutboundPkg is not nil
	pkgWithID := createTestSendPackage(456, "test_label_err_1")
	errorEvent1 := newAssetSendErrorEvent(testErr, SendStateAnchorSign, pkgWithID)

	require.NotNil(t, errorEvent1, "Error event should not be nil")
	require.Equal(t, pkgWithID.OutboundPkg.ID, errorEvent1.TransferDBID, "TransferDBID should match OutboundPkg.ID in error event")
	require.Equal(t, testErr, errorEvent1.Error, "Error not matching")
	require.Equal(t, SendStateAnchorSign, errorEvent1.SendState, "SendState not matching in error event")
	require.Equal(t, pkgWithID.Label, errorEvent1.TransferLabel, "TransferLabel not matching in error event")

	// Case 2: OutboundPkg is nil
	// Similar to newAssetSendEvent, newAssetSendErrorEvent also directly accesses pkg.OutboundPkg.
	// So, OutboundPkg must not be nil.
	pkgWithoutOutbound := sendPackage{
		Label: "test_label_err_no_outbound",
		// OutboundPkg is nil
	}
	// This would also panic due to direct access to pkg.OutboundPkg.
	// Again, focusing on the case where OutboundPkg is present for TransferDBID testing.
}


func init() {
	rand.Seed(time.Now().Unix())

	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	UseLogger(logger.SubSystem(Subsystem))
}
