package rfqmsg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewID tests that we can easily derive 1000 new IDs without any errors.
func TestNewID(t *testing.T) {
	const numIDs = 1000

	for range numIDs {
		_, err := NewID()
		require.NoError(t, err)
	}
}
