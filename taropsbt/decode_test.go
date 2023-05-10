package taropsbt

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/stretchr/testify/require"
)

// assertEqualPackets asserts that two packets are equal and prints a nice diff
// if they are not.
func assertEqualPackets(t *testing.T, expected, actual *VPacket) {
	if !reflect.DeepEqual(expected.ChainParams, actual.ChainParams) {
		require.Equal(t, expected.ChainParams, actual.ChainParams)
		require.Fail(t, "ChainParams not equal")
	}

	require.Len(t, expected.Inputs, len(actual.Inputs))
	for idx := range expected.Inputs {
		e := expected.Inputs[idx]
		a := actual.Inputs[idx]

		if !reflect.DeepEqual(e, a) {
			require.Equal(t, e, a, "input %d not equal", idx)
			require.Fail(t, "input not equal")
		}
	}

	require.Len(t, expected.Outputs, len(actual.Outputs))

	for idx := range expected.Outputs {
		e := expected.Outputs[idx]
		a := actual.Outputs[idx]

		if !reflect.DeepEqual(e, a) {
			require.Equalf(t, e, a, "output %d not equal", idx)
			require.Fail(t, "output not equal")
		}
	}
}

// TestNewFromRawBytes tests the decoding of a virtual packet from raw bytes.
func TestNewFromRawBytes(t *testing.T) {
	t.Parallel()

	pkg := RandPacket(t)
	packet, err := pkg.EncodeAsPsbt()
	require.NoError(t, err)

	var buf bytes.Buffer
	err = packet.Serialize(&buf)
	require.NoError(t, err)

	decoded, err := NewFromRawBytes(&buf, false)
	require.NoError(t, err)

	assertEqualPackets(t, pkg, decoded)
}

// TestNewFromPsbt tests the decoding of a virtual packet from a PSBT packet.
func TestNewFromPsbt(t *testing.T) {
	t.Parallel()

	pkg := RandPacket(t)
	packet, err := pkg.EncodeAsPsbt()
	require.NoError(t, err)

	decoded, err := NewFromPsbt(packet)
	require.NoError(t, err)

	assertEqualPackets(t, pkg, decoded)
}

// TestMinimalContent tests the decoding of a virtual packet with the minimal
// amount of information set.
func TestMinimalContent(t *testing.T) {
	t.Parallel()

	addr, _, _ := address.RandAddr(t, testParams)

	pkg, err := FromAddresses([]*address.Taro{addr.Taro}, 1)
	require.NoError(t, err)
	pkg.Outputs = append(pkg.Outputs, &VOutput{
		ScriptKey: asset.RandScriptKey(t),
	})
	var buf bytes.Buffer
	err = pkg.Serialize(&buf)
	require.NoError(t, err)

	decoded, err := NewFromRawBytes(&buf, false)
	require.NoError(t, err)

	assertEqualPackets(t, pkg, decoded)
}

// TestDecodeBase64 tests the decoding of a virtual packet from a base64 string.
func TestDecodeBase64(t *testing.T) {
	t.Parallel()

	// The test data file just contains a random packet from a previous
	// integration test run.
	fileContent, err := os.ReadFile(filepath.Join("testdata", "psbt.b64"))
	require.NoError(t, err)

	packet, err := NewFromRawBytes(bytes.NewBuffer(fileContent), true)
	require.NoError(t, err)

	require.Len(t, packet.Outputs, 2)

	// Make sure we re-encode the PSBT to the exact same base64 string.
	reEncoded, err := packet.B64Encode()
	require.NoError(t, err)

	require.Equal(t, string(fileContent), reEncoded)
}

// TestDecodeHex tests the decoding of a virtual packet from a hex string.
func TestDecodeHex(t *testing.T) {
	t.Parallel()

	// The test data file just contains a random packet from a previous
	// integration test run.
	fileContent, err := os.ReadFile(filepath.Join("testdata", "psbt.hex"))
	require.NoError(t, err)
	rawBytes, err := hex.DecodeString(string(fileContent))
	require.NoError(t, err)

	packet, err := NewFromRawBytes(bytes.NewBuffer(rawBytes), false)
	require.NoError(t, err)

	require.Len(t, packet.Outputs, 2)
}
