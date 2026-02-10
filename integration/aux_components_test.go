package integration

import (
	"context"
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

func TestBuildAuxComponentsNilServer(t *testing.T) {
	t.Parallel()

	_, _, err := BuildAuxComponents(context.Background(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not be nil")
}

func TestEnsureRequiredCustomMessages(t *testing.T) {
	t.Parallel()

	msgError := uint16(lnwire.MsgError)

	tests := []struct {
		name     string
		input    []uint16
		contains uint16
		length   int
	}{
		{
			name:     "nil slice gets MsgError",
			input:    nil,
			contains: msgError,
			length:   1,
		},
		{
			name:     "empty slice gets MsgError",
			input:    []uint16{},
			contains: msgError,
			length:   1,
		},
		{
			name:     "existing MsgError not duplicated",
			input:    []uint16{msgError},
			contains: msgError,
			length:   1,
		},
		{
			name:     "other messages preserved",
			input:    []uint16{100, 200},
			contains: msgError,
			length:   3,
		},
		{
			name:     "MsgError already present with others",
			input:    []uint16{100, msgError, 200},
			contains: msgError,
			length:   3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := EnsureRequiredCustomMessages(tc.input)

			require.Len(t, result, tc.length)
			require.Contains(t, result, tc.contains)
		})
	}
}
