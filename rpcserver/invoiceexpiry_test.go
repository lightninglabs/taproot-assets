package rpcserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateInvoiceExpiry checks that a negative invoice expiry is rejected
// while a zero (default) or positive expiry is accepted.
func TestValidateInvoiceExpiry(t *testing.T) {
	t.Parallel()

	// A negative expiry is meaningless and must be rejected.
	err := validateInvoiceExpiry(-1)
	require.ErrorContains(t, err, "must not be negative")

	// A zero expiry is allowed; it is later replaced with the default.
	require.NoError(t, validateInvoiceExpiry(0))

	// A positive expiry is used as-is.
	require.NoError(t, validateInvoiceExpiry(3600))
}
