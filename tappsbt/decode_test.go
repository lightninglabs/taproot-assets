package tappsbt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

var (
	generatedTestVectorName = "psbt_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"psbt_encoding_error_cases.json",
	}
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

// TestEncodingDecoding tests the decoding of a virtual packet from raw bytes.
func TestEncodingDecoding(t *testing.T) {
	t.Parallel()

	testVectors := &TestVectors{}
	assertEncodingDecoding := func(comment string, pkg *VPacket) {
		// Encode the packet as a PSBT packet then as base64.
		packet, err := pkg.EncodeAsPsbt()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = packet.Serialize(&buf)
		require.NoError(t, err)

		testVectors.ValidTestCases = append(
			testVectors.ValidTestCases, &ValidTestCase{
				Packet: NewTestFromVPacket(t, pkg),
				Expected: base64.StdEncoding.EncodeToString(
					buf.Bytes(),
				),
				Comment: comment,
			},
		)

		// Make sure we can read the packet back from the raw bytes.
		decoded, err := NewFromRawBytes(&buf, false)
		require.NoError(t, err)

		assertEqualPackets(t, pkg, decoded)

		// Also make sure we can decode the packet from the base PSBT.
		decoded, err = NewFromPsbt(packet)
		require.NoError(t, err)

		assertEqualPackets(t, pkg, decoded)
	}

	testCases := []struct {
		name string
		pkg  func(t *testing.T) *VPacket
	}{{
		name: "minimal packet",
		pkg: func(t *testing.T) *VPacket {
			addr, _, _ := address.RandAddr(t, testParams, nil)

			pkg, err := FromAddresses([]*address.Tap{addr.Tap}, 1)
			require.NoError(t, err)
			pkg.Outputs = append(pkg.Outputs, &VOutput{
				ScriptKey: asset.RandScriptKey(t),
			})

			return pkg
		},
	}, {
		name: "random packet",
		pkg: func(t *testing.T) *VPacket {
			return RandPacket(t)
		},
	}}

	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			pkg := testCase.pkg(t)
			assertEncodingDecoding(testCase.name, pkg)
		})
		if !success {
			return
		}
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
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

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			p := validCase.Packet.ToVPacket(t)

			packetString, err := p.B64Encode()
			require.NoError(tt, err)

			areEqual := validCase.Expected == packetString

			// Create nice diff if things don't match.
			if !areEqual {
				expectedPacket, err := NewFromRawBytes(
					strings.NewReader(validCase.Expected),
					true,
				)
				require.NoError(tt, err)

				require.Equal(tt, p, expectedPacket)

				// Make sure we still fail the test.
				require.Equal(
					tt, validCase.Expected, packetString,
				)
			}

			// We also want to make sure that the address is decoded
			// correctly from the encoded TLV stream.
			decoded, err := NewFromRawBytes(
				strings.NewReader(validCase.Expected), true,
			)
			require.NoError(tt, err)

			require.Equal(tt, p, decoded)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			require.PanicsWithValue(tt, invalidCase.Error, func() {
				invalidCase.Packet.ToVPacket(tt)
			})
		})
	}
}
