package tappsbt_test

import (
	"testing"

	tappsbtmock "github.com/lightninglabs/taproot-assets/internal/mock/tappsbt"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestEncodeAsPsbt tests the encoding of a virtual packet as a PSBT.
func TestEncodeAsPsbt(t *testing.T) {
	t.Parallel()

	pkg := tappsbtmock.RandPacket(t, test.RandBool())
	packet, err := pkg.EncodeAsPsbt()
	require.NoError(t, err)

	b64, err := packet.B64Encode()
	require.NoError(t, err)

	require.NotEmpty(t, b64)
}
