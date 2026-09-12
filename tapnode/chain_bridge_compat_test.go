package tapnode

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

type legacyPublisher struct {
	ChainBridge

	calls int
	err   error
}

func (l *legacyPublisher) PublishTransaction(_ context.Context,
	_ *wire.MsgTx, _ string) error {

	l.calls++
	return l.err
}

type capabilityPublisher struct {
	*legacyPublisher

	definitiveCalls int
	definitiveErr   error
}

func (c *capabilityPublisher) ValidateAndPublishTransaction(_ context.Context,
	_ *wire.MsgTx, _ string) error {

	c.definitiveCalls++
	return c.definitiveErr
}

func TestValidateAndPublishTransactionCompatibility(t *testing.T) {
	t.Parallel()

	t.Run("legacy fallback", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("ambiguous publish error")
		bridge := &legacyPublisher{err: expectedErr}
		err := ValidateAndPublishTransaction(
			t.Context(), bridge, &wire.MsgTx{}, "compat",
		)

		require.ErrorIs(t, err, expectedErr)
		require.Equal(t, 1, bridge.calls)
	})

	t.Run("optional capability", func(t *testing.T) {
		t.Parallel()

		expectedErr := NewDefinitivePublishError(
			errors.New("policy rejection"),
		)
		base := &legacyPublisher{}
		bridge := &capabilityPublisher{
			legacyPublisher: base,
			definitiveErr:   expectedErr,
		}
		err := ValidateAndPublishTransaction(
			t.Context(), bridge, &wire.MsgTx{}, "compat",
		)

		require.ErrorIs(t, err, expectedErr)
		require.Equal(t, 1, bridge.definitiveCalls)
		require.Zero(t, base.calls)
	})
}
