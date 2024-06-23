package tappsbt_test

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

// TestEncodeAsPsbt tests the encoding of a virtual packet as a PSBT.
func TestEncodeAsPsbt(t *testing.T) {
	t.Parallel()

	pkg := tappsbt.RandPacket(t, test.RandBool())
	packet, err := pkg.EncodeAsPsbt()
	require.NoError(t, err)

	b64, err := packet.B64Encode()
	require.NoError(t, err)

	require.NotEmpty(t, b64)
}
