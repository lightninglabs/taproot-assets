package proof

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

var (
	testTimeout = 5 * time.Second
)

func randAssetID() *asset.ID {
	var a asset.ID
	copy(a[:], test.RandBytes(32))

	return &a
}

// TestFileArchiverProofCollision tests that we can store two different proofs
// with the same script key but different outpoints.
func TestFileArchiverProofCollision(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// First, we'll make a temp directory we'll use as the root of our file
	// system.
	tempDir := t.TempDir()

	fileArchive, err := NewFileArchiver(tempDir)
	require.NoError(t, err)

	// We store two different proofs with the same script key but different
	// outpoints. This should result in two different files on disk.
	var (
		scriptKey = *test.RandPubKey(t)
		assetID   = randAssetID()
		testOp1   = test.RandOp(t)
		testOp2   = test.RandOp(t)
		locator1  = Locator{
			AssetID:   assetID,
			ScriptKey: scriptKey,
			OutPoint:  &testOp1,
		}
		locator2 = Locator{
			AssetID:   assetID,
			ScriptKey: scriptKey,
			OutPoint:  &testOp2,
		}
		blob1 = []byte("this is the first blob")
		blob2 = []byte("this is the second blob")
	)
	err = fileArchive.ImportProofs(
		ctx, MockHeaderVerifier, MockGroupVerifier, false,
		&AnnotatedProof{
			Locator: locator1,
			Blob:    blob1,
		},
	)
	require.NoError(t, err)
	err = fileArchive.ImportProofs(
		ctx, MockHeaderVerifier, MockGroupVerifier, false,
		&AnnotatedProof{
			Locator: locator2,
			Blob:    blob2,
		},
	)
	require.NoError(t, err)

	// When retrieving the proofs, we should get the same blobs back.
	proof1, err := fileArchive.FetchProof(ctx, locator1)
	require.NoError(t, err)
	require.EqualValues(t, blob1, proof1)

	proof2, err := fileArchive.FetchProof(ctx, locator2)
	require.NoError(t, err)
	require.EqualValues(t, blob2, proof2)
}

// TestFileArchiver tests that the file archiver functions as advertised when
// it comes to writing and also reading proof file on disk.
func TestFileArchiver(t *testing.T) {
	t.Parallel()

	// First, we'll make a temp directory we'll use as the root of our file
	// system.
	tempDir := t.TempDir()

	fileArchive, err := NewFileArchiver(tempDir)
	require.NoError(t, err)

	// We'll use a fake verifier that just returns that the proof is valid.
	archive := NewMultiArchiver(
		NewMockVerifier(t), testTimeout, fileArchive,
	)

	ctx := context.Background()

	var testCases = []struct {
		name string

		locator Locator

		proofBlob func() Blob

		fetchFunc func(*FileArchiver) error

		expectedFetchError error
		expectedStoreError error
	}{
		// Attempting to fetch a proof that doesn't exist on disk should
		// return an error.
		{
			name: "proof not found",
			locator: Locator{
				AssetID:   randAssetID(),
				ScriptKey: *test.RandPubKey(t),
			},
			expectedFetchError: ErrProofNotFound,
		},

		// Attempting to fetch a file on disk that doesn't have an asset
		// ID specified should return an error.
		{
			name: "invalid asset ID",
			locator: Locator{
				ScriptKey: *test.RandPubKey(t),
			},
			expectedFetchError: ErrInvalidLocatorID,
		},

		// Fetching w/ the assetID, but not script key should return an
		// error as well.
		{
			name: "invalid script key",
			locator: Locator{
				AssetID: randAssetID(),
			},
			expectedFetchError: ErrInvalidLocatorKey,
		},

		// Storing a proof with assetID and script key, but no outpoint
		// should return an error as well.
		{
			name: "invalid outpoint",
			locator: Locator{
				AssetID:   randAssetID(),
				ScriptKey: *test.RandPubKey(t),
			},
			proofBlob: func() Blob {
				return bytes.Repeat([]byte{0x01}, 100)
			},
			expectedStoreError: ErrOutPointMissing,
		},

		// We should be able to insert a proof, then get it right back
		// the same way we found it.
		{
			name: "proof happy path",
			locator: Locator{
				AssetID:   randAssetID(),
				ScriptKey: *test.RandPubKey(t),
				OutPoint:  &wire.OutPoint{},
			},
			proofBlob: func() Blob {
				return bytes.Repeat([]byte{0x01}, 100)
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var proofBlob Blob
			if testCase.proofBlob != nil {
				proofBlob = testCase.proofBlob()
				proof := &AnnotatedProof{
					Blob:    proofBlob,
					Locator: testCase.locator,
				}

				err = archive.ImportProofs(
					ctx, MockHeaderVerifier,
					MockGroupVerifier, false, proof,
				)

				if testCase.expectedStoreError != nil {
					require.ErrorIs(
						t, err,
						testCase.expectedStoreError,
					)

					return
				}

				require.NoError(t, err)
			}

			diskProof, err := archive.FetchProof(
				ctx, testCase.locator,
			)
			require.ErrorIs(t, err, testCase.expectedFetchError)

			if testCase.proofBlob != nil {
				require.Equal(t, proofBlob, diskProof)
			}
		})
	}
}
