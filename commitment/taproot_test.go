package commitment

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

var (
	testEncodedPreimage = "00c01876a9148f15527faa0d84ce8bd364e32d4b627fb4" +
		"8efb9288"
)

// TestTapscriptPreimage tests the various methods of the TapscriptPreimage
// struct.
func TestTapscriptPreimage(t *testing.T) {
	t.Parallel()

	// Create a script tree that we'll use for our tapscript sibling test
	// cases.
	scriptInternalKey := test.RandPrivKey().PubKey()
	leaf1 := test.ScriptHashLock(t, []byte("foobar"))
	leaf1Hash := leaf1.TapHash()
	leaf2 := test.ScriptSchnorrSig(t, scriptInternalKey)

	// The order doesn't matter here as they are sorted before hashing.
	branch := txscript.NewTapBranch(leaf1, leaf2)
	branchHash := branch.TapHash()

	// Create a random byte slice with the same structure as a Taproot
	// Asset commitment root, that can be used in a TapLeaf.
	randTapCommitmentRoot := func(version asset.Version) []byte {
		var dummyRootSum [8]byte
		binary.BigEndian.PutUint64(
			dummyRootSum[:], test.RandInt[uint64](),
		)
		dummyRootHashParts := [][]byte{
			{byte(version)}, TaprootAssetsMarker[:],
			fn.ByteSlice(test.RandHash()), dummyRootSum[:],
		}
		return bytes.Join(dummyRootHashParts, nil)
	}

	testCases := []struct {
		name            string
		makePreimage    func(t *testing.T) *TapscriptPreimage
		expectedType    TapscriptPreimageType
		expectedName    string
		expectedEmpty   bool
		expectedHash    *chainhash.Hash
		expectedHashErr string
	}{{
		name: "invalid type",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return &TapscriptPreimage{
				siblingType: 123,
			}
		},
		expectedType:    123,
		expectedName:    "UnknownSiblingType(123)",
		expectedEmpty:   true,
		expectedHashErr: ErrInvalidEmptyTapscriptPreimage.Error(),
	}, {
		name: "empty leaf pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return &TapscriptPreimage{}
		},
		expectedType:    LeafPreimage,
		expectedName:    "LeafPreimage",
		expectedEmpty:   true,
		expectedHashErr: ErrInvalidEmptyTapscriptPreimage.Error(),
	}, {
		name: "empty branch pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return &TapscriptPreimage{
				siblingType: BranchPreimage,
			}
		},
		expectedType:    BranchPreimage,
		expectedName:    "BranchPreimage",
		expectedEmpty:   true,
		expectedHashErr: ErrInvalidEmptyTapscriptPreimage.Error(),
	}, {
		name: "invalid size leaf pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return &TapscriptPreimage{
				siblingPreimage: []byte("b"),
			}
		},
		expectedType:    LeafPreimage,
		expectedName:    "LeafPreimage",
		expectedEmpty:   false,
		expectedHashErr: ErrInvalidTapscriptPreimageLen.Error(),
	}, {
		name: "invalid size branch pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return &TapscriptPreimage{
				siblingType:     BranchPreimage,
				siblingPreimage: []byte("too short"),
			}
		},
		expectedType:    BranchPreimage,
		expectedName:    "BranchPreimage",
		expectedEmpty:   false,
		expectedHashErr: ErrInvalidTapscriptPreimageLen.Error(),
	}, {
		name: "tap commitment leaf pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			tapCommitmentRoot := randTapCommitmentRoot(asset.V0)
			var encodedLeaf bytes.Buffer

			_ = encodedLeaf.WriteByte(
				byte(txscript.BaseLeafVersion),
			)
			_ = wire.WriteVarBytes(
				&encodedLeaf, 0, tapCommitmentRoot,
			)

			return &TapscriptPreimage{
				siblingType:     LeafPreimage,
				siblingPreimage: encodedLeaf.Bytes(),
			}
		},
		expectedType:    LeafPreimage,
		expectedName:    "LeafPreimage",
		expectedEmpty:   false,
		expectedHashErr: ErrPreimageIsTapCommitment.Error(),
	}, {
		name: "valid leaf pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			preimage, err := NewPreimageFromLeaf(leaf1)
			require.NoError(t, err)
			return preimage
		},
		expectedType:  LeafPreimage,
		expectedName:  "LeafPreimage",
		expectedEmpty: false,
		expectedHash:  &leaf1Hash,
	}, {
		name: "valid branch pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return fn.Ptr(NewPreimageFromBranch(branch))
		},
		expectedType:  BranchPreimage,
		expectedName:  "BranchPreimage",
		expectedEmpty: false,
		expectedHash:  &branchHash,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			preimage := tc.makePreimage(tt)

			require.Equal(tt, tc.expectedType, preimage.siblingType)
			require.Equal(
				tt, tc.expectedName,
				preimage.siblingType.String(),
			)
			require.Equal(tt, tc.expectedEmpty, preimage.IsEmpty())

			hash, err := preimage.TapHash()
			if tc.expectedHashErr != "" {
				require.ErrorContains(
					tt, err, tc.expectedHashErr,
				)
				return
			}

			require.NoError(tt, err)
			require.Equal(tt, tc.expectedHash, hash)
		})
	}
}

// TestMaybeDecodeTapscriptPreimage tests the MaybeDecodeTapscriptPreimage
// function.
func TestMaybeDecodeTapscriptPreimage(t *testing.T) {
	testBytes, err := hex.DecodeString(testEncodedPreimage)
	require.NoError(t, err)
	preimage, hash, err := MaybeDecodeTapscriptPreimage(testBytes)
	require.NoError(t, err)
	require.NotNil(t, hash)
	require.False(t, preimage.IsEmpty())
}

// TestMaybeEncodeTapscriptPreimage tests the MaybeEncodeTapscriptPreimage
// function.
func TestMaybeEncodeTapscriptPreimage(t *testing.T) {
	preImage := []byte("hash locks are cool")
	siblingLeaf := test.ScriptHashLock(t, preImage)

	leafPreimage, err := NewPreimageFromLeaf(siblingLeaf)
	require.NoError(t, err)
	encodedPreimage, _, err := MaybeEncodeTapscriptPreimage(leafPreimage)
	require.NoError(t, err)

	require.Equal(
		t, testEncodedPreimage, hex.EncodeToString(encodedPreimage),
	)
}
