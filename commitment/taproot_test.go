package commitment

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/stretchr/testify/require"
)

func TestTapscriptPreimage(t *testing.T) {
	t.Parallel()

	// Create a script tree that we'll use for our tapscript sibling test
	// cases.
	scriptInternalKey := test.RandPrivKey(t).PubKey()
	leaf1 := test.ScriptHashLock(t, []byte("foobar"))
	leaf1Hash := leaf1.TapHash()
	leaf2 := test.ScriptSchnorrSig(t, scriptInternalKey)

	// The order doesn't matter here as they are sorted before hashing.
	branch := txscript.NewTapBranch(leaf1, leaf2)
	branchHash := branch.TapHash()

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
				SiblingType: 123,
			}
		},
		expectedType:    123,
		expectedName:    "UnKnownSiblingType(123)",
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
				SiblingType: BranchPreimage,
			}
		},
		expectedType:    BranchPreimage,
		expectedName:    "BranchPreimage",
		expectedEmpty:   true,
		expectedHashErr: ErrInvalidEmptyTapscriptPreimage.Error(),
	}, {
		name: "invalid size branch pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return &TapscriptPreimage{
				SiblingType:     BranchPreimage,
				SiblingPreimage: []byte("too short"),
			}
		},
		expectedType:    BranchPreimage,
		expectedName:    "BranchPreimage",
		expectedEmpty:   false,
		expectedHashErr: ErrInvalidTapscriptPreimageLen.Error(),
	}, {
		name: "valid leaf pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return NewPreimageFromLeaf(leaf1)
		},
		expectedType:  LeafPreimage,
		expectedName:  "LeafPreimage",
		expectedEmpty: false,
		expectedHash:  &leaf1Hash,
	}, {
		name: "valid branch pre-image",
		makePreimage: func(t *testing.T) *TapscriptPreimage {
			return NewPreimageFromBranch(branch)
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

			require.Equal(tt, tc.expectedType, preimage.SiblingType)
			require.Equal(
				tt, tc.expectedName,
				preimage.SiblingType.String(),
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
