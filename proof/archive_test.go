package proof

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"

	"github.com/lightninglabs/taro/asset"
	"github.com/stretchr/testify/require"
)

func randAssetID(t *testing.T) *asset.ID {
	var a asset.ID
	_, err := rand.Read(a[:])
	require.NoError(t, err)

	return &a
}

type fakeVerifier struct {
	t   *testing.T
	loc Locator
}

func newFakeVerifier(t *testing.T) *fakeVerifier {
	return &fakeVerifier{
		t: t,
	}
}

func (f *fakeVerifier) feedLocator(loc *Locator) {
	f.loc = *loc
}

func (f *fakeVerifier) Verify(c context.Context,
	blobReader io.Reader) (*AssetSnapshot, error) {

	return &AssetSnapshot{
		Asset: &asset.Asset{

			FamilyKey: &asset.FamilyKey{
				FamKey: *randPubKey(f.t),
			},
			ScriptKey: asset.NewScriptKeyTweaked(randPubKey(f.t)),
		},
	}, nil
}

// TestFileArchiver tests that the file archiver functions as advertised when
// it comes to writing and also reading proof file on disk.
func TestFileArchiver(t *testing.T) {
	t.Parallel()

	// First, we'll make a temp directory we'll use as the root of our file
	// system.
	dir, err := ioutil.TempDir("", "taro-proofs-")
	require.NoError(t, err)

	defer os.RemoveAll(dir)

	fileArchive, err := NewFileArchiver(dir)
	require.NoError(t, err)

	// We'll use a fake verifier that just returns that the proof is valid.
	archive := NewMultiArchiver(newFakeVerifier(t), fileArchive)

	ctx := context.Background()

	var tests = []struct {
		name string

		locator Locator

		proofBlob func() Blob

		fetchFunc func(*FileArchiver) error

		expectedErorr error
	}{
		// Attempting to fetch a proof that doesn't exist on disk should
		// return an error.
		{
			name: "proof not found",
			locator: Locator{
				AssetID:   randAssetID(t),
				ScriptKey: *randPubKey(t),
			},
			expectedErorr: ErrProofNotFound,
		},

		// Attempting to fetch a file on disk that doesn't have an asset ID
		// specified should return an error.
		{
			name: "invalid asset ID",
			locator: Locator{
				ScriptKey: *randPubKey(t),
			},
			expectedErorr: ErrInvalidLocatorID,
		},

		// Fetching w/ the assetID, but not script key should return an
		// error as well.
		{
			name: "invalid script key",
			locator: Locator{
				AssetID: randAssetID(t),
			},
			expectedErorr: ErrInvalidLocatorKey,
		},

		// We should be able to insert a proof, then get it right back
		// the same way we found it.
		{
			name: "proof happy path",
			locator: Locator{
				AssetID:   randAssetID(t),
				ScriptKey: *randPubKey(t),
			},
			proofBlob: func() Blob {
				return bytes.Repeat([]byte{0x01}, 100)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var proofBlob Blob
			if test.proofBlob != nil {
				proofBlob = test.proofBlob()
				proof := &AnnotatedProof{
					Blob:    proofBlob,
					Locator: test.locator,
				}
				require.NoError(
					t, archive.ImportProofs(ctx, proof),
				)
			}

			diskProof, err := archive.FetchProof(ctx, test.locator)
			require.ErrorIs(t, err, test.expectedErorr)

			if test.proofBlob != nil {
				require.Equal(t, proofBlob, diskProof)
			}
		})
	}
}
