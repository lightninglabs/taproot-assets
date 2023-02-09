package taropsbt

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/stretchr/testify/require"
)

func assertEqualProof(t *testing.T, expected, actual *mssmt.Proof) {
	t.Helper()

	for i, node := range expected.Nodes {
		other := actual.Nodes[i]
		require.True(t, mssmt.IsEqualNode(node, other))
	}
}

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

		// Proofs cannot be compared directly, so we'll compare them
		// separately.
		eProof := e.assetProof
		aProof := a.assetProof

		e.assetProof = nil
		a.assetProof = nil

		if !reflect.DeepEqual(e, a) {
			require.Equal(t, e, a, "input %d not equal", idx)
			require.Fail(t, "input not equal")
		}

		require.Equal(t, eProof == nil, aProof == nil)
		if eProof != nil {
			require.Equal(
				t, eProof.AssetProof == nil,
				aProof.AssetProof == nil,
			)
			if eProof.AssetProof != nil {
				assertEqualProof(
					t, &eProof.AssetProof.Proof,
					&aProof.AssetProof.Proof,
				)
			}

			assertEqualProof(
				t, &eProof.TaroProof.Proof,
				&aProof.TaroProof.Proof,
			)
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

	pkg := randomPacket(t)
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

	pkg := randomPacket(t)
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

	addr := address.RandAddr(t, testParams)

	pkg := FromAddress(addr.Taro)
	var buf bytes.Buffer
	err := pkg.Serialize(&buf)
	require.NoError(t, err)

	decoded, err := NewFromRawBytes(&buf, false)
	require.NoError(t, err)

	assertEqualPackets(t, pkg, decoded)
}

// TestDecodeBase64 tests the decoding of a virtual packet from a base64 string.
func TestDecodeBase64(t *testing.T) {
	t.Parallel()

	fileContent, err := os.ReadFile(filepath.Join("testdata", "psbt.b64"))
	require.NoError(t, err)

	packet, err := NewFromRawBytes(bytes.NewBuffer(fileContent), true)
	require.NoError(t, err)

	require.Len(t, packet.Outputs, 2)
}
