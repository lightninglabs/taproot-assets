package fn

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsCanceled tests the IsCanceled function.
func TestIsCanceled(t *testing.T) {
	require.False(t, IsCanceled(nil))
	require.True(t, IsCanceled(context.Canceled))
	require.True(t, IsCanceled(errRpcCanceled))
	require.True(t, IsCanceled(fmt.Errorf("foo: %w", context.Canceled)))
	require.True(t, IsCanceled(fmt.Errorf("foo: %w", errRpcCanceled)))
}
