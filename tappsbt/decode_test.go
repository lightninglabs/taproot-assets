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

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	generatedTestVectorName = "psbt_encoding_generated.json"

	// packetHexFileName is the name of the file that contains a hex encoded
	// virtual packet. This packet was obtained from a unit test and is a
	// valid regtest packet.
	packetHexFileName = filepath.Join(testDataFileName, "packet.hex")

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"psbt_encoding_error_cases.json",
	}
)

// assertEqualPackets asserts that two packets are equal and prints a nice diff
// if they are not.
func assertEqualPackets(t *testing.T, expected, actual *VPacket) {
	if expected.Version != actual.Version {
		require.Fail(t, "Version not equal")
	}

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

// TestGlobalUnknownFields tests that the global Unknown fields mandatory for a
// valid VPacket are present for an encoded VPacket. We also test that when
// decoding a VPacket from a Packet, a Packet with missing mandatory fields is
// rejected, and extra global Unknown fields are permitted.
func TestGlobalUnknownFields(t *testing.T) {
	// Make a random packet.
	pkg := RandPacket(t, false, false)

	// An encoded valid packet should have exactly three global Unknown
	// fields.
	packet, err := pkg.EncodeAsPsbt()
	require.NoError(t, err)
	require.Len(t, packet.Unknowns, 3)

	// Specifically, the isVirtual marker, HRP, and Version must be present.
	requiredKeys := [][]byte{
		PsbtKeyTypeGlobalTapIsVirtualTx,
		PsbtKeyTypeGlobalTapChainParamsHRP,
		PsbtKeyTypeGlobalTapPsbtVersion,
	}
	for _, key := range requiredKeys {
		_, err := findCustomFieldsByKeyPrefix(packet.Unknowns, key)
		require.NoError(t, err)
	}

	// Decoding a VPacket from this minimal Packet must succeed.
	_, err = NewFromPsbt(packet)
	require.NoError(t, err)

	var packetBuf bytes.Buffer
	err = packet.Serialize(&packetBuf)
	require.NoError(t, err)

	cloneBuffer := func(b *bytes.Buffer) *bytes.Buffer {
		return bytes.NewBuffer(bytes.Clone(b.Bytes()))
	}

	// If we remove a mandatory VPacket field from the Packet, decoding
	// must fail.
	invalidPacketBytes := cloneBuffer(&packetBuf)
	invalidPacket, err := psbt.NewFromRawBytes(invalidPacketBytes, false)
	require.NoError(t, err)

	invalidPacket.Unknowns = invalidPacket.Unknowns[1:]
	_, err = NewFromPsbt(invalidPacket)
	require.Error(t, err)

	// If we add a global Unknown field to the valid Packet, decoding must
	// still succeed.
	extraPacketBytes := cloneBuffer(&packetBuf)
	extraPacket, err := psbt.NewFromRawBytes(extraPacketBytes, false)
	require.NoError(t, err)

	// The VPacket global Unknown keys start at 0x70, so we'll use a key
	// value very far from that.
	extraUnknown := &psbt.Unknown{
		Key:   []byte{0xaa},
		Value: []byte("really_cool_unknown_value"),
	}
	extraPacket.Unknowns = append(extraPacket.Unknowns, extraUnknown)

	// The decoded VPacket should not contain the extra Unknown field, but
	// the decoder should succeed.
	_, err = NewFromPsbt(extraPacket)
	require.NoError(t, err)
}

// TestEncodingDecoding tests the decoding of a virtual packet from raw bytes.
func TestEncodingDecoding(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name                 string
		pkg                  func(t *testing.T) *VPacket
		encodeErr, decodeErr error
	}

	testVectors := &TestVectors{}
	assertEncodingDecoding := func(tCase testCase) {
		comment := tCase.name
		pkg := tCase.pkg(t)
		// Encode the packet as a PSBT packet then as base64.
		packet, err := pkg.EncodeAsPsbt()
		if tCase.encodeErr != nil {
			require.ErrorIs(t, err, tCase.encodeErr)
			return
		}

		require.NoError(t, err)

		var buf bytes.Buffer
		err = packet.Serialize(&buf)
		require.NoError(t, err)

		testVectorBuf := bytes.NewBuffer(buf.Bytes())
		decoded, err := NewFromRawBytes(&buf, false)
		switch {
		// Don't add an invalid test case as a valid test vector.
		case tCase.decodeErr != nil:
			require.ErrorIs(t, err, tCase.decodeErr)
			return
		default:
			expected := base64.StdEncoding.EncodeToString(
				testVectorBuf.Bytes(),
			)
			testVectors.ValidTestCases = append(
				testVectors.ValidTestCases, &ValidTestCase{
					Packet:   NewTestFromVPacket(t, pkg),
					Expected: expected,
					Comment:  comment,
				},
			)
		}

		// Make sure we can read the packet back from the raw bytes.
		require.NoError(t, err)
		assertEqualPackets(t, pkg, decoded)

		// Also make sure we can decode the packet from the base PSBT.
		decoded, err = NewFromPsbt(packet)
		require.NoError(t, err)

		assertEqualPackets(t, pkg, decoded)
	}

	testCases := []testCase{{
		name: "minimal packet",
		pkg: func(t *testing.T) *VPacket {
			proofCourierAddr := address.RandProofCourierAddr(t)
			addr, _, _ := address.RandAddr(
				t, testParams, proofCourierAddr,
			)

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
			return RandPacket(t, true, true)
		},
	}, {
		name: "random packet with no explicit version",
		pkg: func(t *testing.T) *VPacket {
			return RandPacket(t, false, true)
		},
	}, {
		name: "invalid packet version",
		pkg: func(t *testing.T) *VPacket {
			validVers := fn.NewSet(uint8(V0), uint8(V1))
			pkt := RandPacket(t, false, true)

			invalidPktVersion := test.RandInt[uint8]()
			for validVers.Contains(invalidPktVersion) {
				invalidPktVersion = test.RandInt[uint8]()
			}

			pkt.Version = VPacketVersion(invalidPktVersion)
			return pkt
		},
		decodeErr: ErrInvalidVPacketVersion,
	}, {
		name: "random packet with colliding alt leaves",
		pkg: func(t *testing.T) *VPacket {
			pkt := RandPacket(t, true, true)
			firstLeaf := asset.RandAltLeaf(t)
			secondLeaf := asset.RandAltLeaf(t)

			firstLeafKey := asset.ToSerialized(
				firstLeaf.ScriptKey.PubKey,
			)
			leafKeyCopy, err := firstLeafKey.ToPubKey()
			require.NoError(t, err)

			secondLeaf.ScriptKey = asset.NewScriptKey(leafKeyCopy)
			altLeaves := []asset.AltLeaf[asset.Asset]{
				firstLeaf, secondLeaf,
			}

			pkt.Outputs[0].AltLeaves = asset.CopyAltLeaves(
				altLeaves,
			)
			pkt.Outputs[1].AltLeaves = asset.CopyAltLeaves(
				altLeaves,
			)

			return pkt
		},
		encodeErr: asset.ErrDuplicateScriptKeys,
	}, {
		name: "random packet with excessive alt leaves",
		pkg: func(t *testing.T) *VPacket {
			pkt := RandPacket(t, true, true)

			numLeaves := 2000
			altLeaves := make(
				[]asset.AltLeaf[asset.Asset], numLeaves,
			)
			for idx := range numLeaves {
				altLeaves[idx] = asset.RandAltLeaf(t)
			}

			pkt.Outputs[0].AltLeaves = altLeaves
			pkt.Outputs[1].AltLeaves = altLeaves

			return pkt
		},
		decodeErr: tlv.ErrRecordTooLarge,
	}}

	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			assertEncodingDecoding(testCase)
		})
		if !success {
			return
		}
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
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

			// We also want to make sure that the packet is decoded
			// correctly from the encoded TLV stream.
			decoded, err := NewFromRawBytes(
				strings.NewReader(validCase.Expected), true,
			)
			require.NoError(tt, err)

			require.Equal(tt, p, decoded)

			// And finally, we want to make sure that if we get a
			// raw byte blob we can also decode the packet and the
			// result is the same.
			rawBytes, err := base64.StdEncoding.DecodeString(
				validCase.Expected,
			)
			require.NoError(tt, err)
			decodedFromBytes, err := NewFromRawBytes(
				bytes.NewReader(rawBytes), false,
			)
			require.NoError(tt, err)

			require.Equal(tt, p, decodedFromBytes)
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

// TestFileDecoding ensures that we can decode a vPSBT packet from a hex encoded
// file. This is useful for quickly inspecting the contents of a packet while
// debugging.
func TestFileDecoding(t *testing.T) {
	packetHex, err := os.ReadFile(packetHexFileName)
	require.NoError(t, err)

	packetBytes, err := hex.DecodeString(
		strings.Trim(string(packetHex), "\n"),
	)
	require.NoError(t, err)

	packet, err := NewFromRawBytes(bytes.NewReader(packetBytes), false)
	require.NoError(t, err)

	rootAsset := packet.Outputs[1].Asset
	splitAsset := packet.Outputs[0].Asset
	splitWitness := splitAsset.PrevWitnesses[0]

	locator := &commitment.SplitLocator{
		OutputIndex: splitAsset.OutputIndex,
		AssetID:     splitAsset.Genesis.ID(),
		ScriptKey:   asset.ToSerialized(splitAsset.ScriptKey.PubKey),
		Amount:      splitAsset.Amount,
	}
	splitNoWitness := splitAsset.Copy()
	splitNoWitness.PrevWitnesses[0].SplitCommitment = nil
	splitLeaf, err := splitNoWitness.Leaf()
	require.NoError(t, err)

	verify := mssmt.VerifyMerkleProof(
		locator.Hash(), splitLeaf, &splitWitness.SplitCommitment.Proof,
		rootAsset.SplitCommitmentRoot,
	)
	require.True(t, verify)
}
