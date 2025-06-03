package tapfreighter

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
)

// TestOutboundParcelCopy tests that OutboundParcel.Copy() works as expected.
func TestOutboundParcelCopy(t *testing.T) {
	// Set to true to debug print.
	debug := false

	// Please set the depth value carefully. Sometimes our copy functions
	// are deeply nested in other packages and do not need changes. Often
	// types are recursive and too deep copy may end up in stack-overlow.
	const maxDepth = 5
	p := &OutboundParcel{}
	test.FillFakeData(t, debug, maxDepth, p)

	// We allow aliasing here deep down (for now).
	strict := false
	test.AssertCopyEqual(t, debug, strict, p)
}
