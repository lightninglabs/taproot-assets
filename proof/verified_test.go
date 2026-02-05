package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyAnnotatedProofs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("valid proof", func(t *testing.T) {
		proofHex, err := os.ReadFile(proofFileHexFileName)
		require.NoError(t, err)

		proofBytes, err := hex.DecodeString(
			strings.Trim(string(proofHex), "\n"),
		)
		require.NoError(t, err)

		proofFile := &File{}
		require.NoError(
			t, proofFile.Decode(bytes.NewReader(proofBytes)),
		)

		lastProof, err := proofFile.LastProof()
		require.NoError(t, err)

		annotated := &AnnotatedProof{
			Blob: proofBytes,
		}

		verified, err := VerifyAnnotatedProofs(
			ctx, MockVerifierCtx, annotated,
		)
		require.NoError(t, err)
		require.Len(t, verified, 1)

		verifiedProof := verified[0].AnnotatedProof()
		require.Same(t, annotated, verifiedProof)
		require.NotNil(t, verifiedProof.AssetSnapshot)
		require.NotNil(t, verifiedProof.AssetID)
		require.Equal(t, lastProof.Asset.ID(), *verifiedProof.AssetID)
		require.True(
			t, verifiedProof.ScriptKey.IsEqual(
				lastProof.Asset.ScriptKey.PubKey,
			),
		)

		if lastProof.Asset.GroupKey != nil {
			require.NotNil(t, verifiedProof.GroupKey)
			require.True(
				t, verifiedProof.GroupKey.IsEqual(
					&lastProof.Asset.GroupKey.GroupPubKey,
				),
			)
		}
	})

	t.Run("invalid proof", func(t *testing.T) {
		annotated := &AnnotatedProof{
			Blob: []byte("not a proof"),
		}

		_, err := VerifyAnnotatedProofs(ctx, MockVerifierCtx, annotated)
		require.Error(t, err)
	})
}
