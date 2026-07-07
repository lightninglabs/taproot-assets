package tapcfg

import (
	"testing"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/stretchr/testify/require"
)

// TestValidateReOrgSafeDepth pins the accepted range of the re-org
// safe depth. Out-of-range values used to pass startup cleanly and
// then fail every anchoring registration after its transaction had
// already broadcast.
func TestValidateReOrgSafeDepth(t *testing.T) {
	t.Parallel()

	maxConfs := int32(chainntnfs.MaxNumConfs)

	testCases := []struct {
		name  string
		depth int32

		// disabled runs the case with the anchoring watcher off,
		// the state a node is in after the kill switch is set.
		disabled bool

		valid bool
	}{
		{name: "negative", depth: -1, valid: false},
		{name: "zero", depth: 0, valid: false},
		{name: "one collapses act gating", depth: 1, valid: true},
		{name: "default", depth: defaultReOrgSafeDepth, valid: true},
		{
			name:  "testnet default",
			depth: testnetDefaultReOrgSafeDepth,
			valid: true,
		},
		{name: "notifier maximum", depth: maxConfs, valid: true},
		{
			name:  "beyond notifier maximum",
			depth: maxConfs + 1,
			valid: false,
		},

		// The ceiling is a property of the anchoring watcher's
		// registration path. The legacy watcher subscribes for a
		// single confirmation and counts depth itself, so a node
		// that has rolled back onto it must still start on a depth
		// the anchoring path would have refused — otherwise the
		// kill switch cannot be used for the one thing it is
		// documented to do.
		{
			name:     "beyond notifier maximum, watcher disabled",
			depth:    maxConfs + 1,
			disabled: true,
			valid:    true,
		},
		{
			name:     "far beyond notifier maximum, disabled",
			depth:    10 * maxConfs,
			disabled: true,
			valid:    true,
		},

		// A nonsensical depth is refused on either path.
		{
			name:     "zero, watcher disabled",
			depth:    0,
			disabled: true,
			valid:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReOrgSafeDepth(
				tc.depth, tc.disabled, btclog.Disabled,
			)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
