package proof

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestBIPTestVectorsBackwardCompatible tests that the BIP test vectors are
// passing against an older code base (this test file will be copied to an old
// version of tapd together with the test vectors in the CI).
func TestBIPTestVectorsBackwardCompatible(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVectorBackwardCompatible(tt, testVectors)
		})
	}
}

// runBIPTestVectorBackwardCompatible runs the tests in a single BIP test vector
// file.
func runBIPTestVectorBackwardCompatible(t *testing.T,
	testVectors *TestVectors) {

	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			// We want to make sure that the proof can be decoded
			// from the hex string and that the decoded proof's meta
			// hash matches.
			decoded := &Proof{}
			err := decoded.Decode(hex.NewDecoder(
				strings.NewReader(validCase.Expected),
			))
			require.NoError(tt, err)

			if decoded.MetaReveal != nil {
				metaHash := decoded.MetaReveal.MetaHash()
				require.Equal(
					tt,
					validCase.Proof.Asset.GenesisMetaHash,
					hex.EncodeToString(metaHash[:]),
				)
			}

			// We can't verify the full proof chain but at least we
			// can verify the inclusion/exclusion proofs.
			_, err = decoded.VerifyProofs()
			require.NoError(tt, err)

			// If there is a genesis reveal, we can validate the
			// full proof chain, as it's the first proof in the
			// chain.
			if decoded.GenesisReveal != nil {
				vCtx := VerifierCtx{
					HeaderVerifier: MockHeaderVerifier,
					MerkleVerifier: DefaultMerkleVerifier,
					GroupVerifier:  MockGroupVerifier,
					ChainLookupGen: MockChainLookup,
				}
				_, err = decoded.Verify(
					context.Background(), nil,
					MockChainLookup, vCtx,
				)
				require.NoError(tt, err)
			}
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			require.PanicsWithValue(tt, invalidCase.Error, func() {
				invalidCase.Proof.ToProof(tt)
			})
		})
	}
}
