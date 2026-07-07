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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReOrgSafeDepth(tc.depth, btclog.Disabled)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
