package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestVerifyFileRoot verifies that a full proof file must start at a genesis
// proof, while the suffix verifier accepts a trusted input state as its root.
func TestVerifyFileRoot(t *testing.T) {
	t.Parallel()

	proofHex, err := os.ReadFile(ownershipProofHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.TrimSpace(string(proofHex)),
	)
	require.NoError(t, err)

	p := &Proof{}
	require.NoError(t, p.Decode(bytes.NewReader(proofBytes)))
	require.NotEmpty(t, p.ChallengeWitness)
	require.False(t, p.Asset.IsGenesisAsset())

	f, err := NewFile(V0, *p)
	require.NoError(t, err)

	_, err = f.Verify(context.Background(), MockVerifierCtx)
	require.ErrorIs(t, err, ErrProofFileInvalid)

	// Build a valid suffix whose only input file begins at a standalone
	// ownership proof. VerifyProofSuffix is the sole API that may establish
	// this explicit current-state trust boundary.
	amt := uint64(100)
	inputProof, inputKey := RandGenesisProofWithKey(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil,
		asset.V0,
	)
	inputProof.Asset.GroupKey = nil
	inputProof.GroupKeyReveal = nil
	inputProof.GenesisReveal = nil
	fakePrevID := asset.PrevID{
		OutPoint: test.RandOp(t),
		ID:       inputProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			inputProof.Asset.ScriptKey.PubKey,
		),
	}
	inputProof.PrevOut = fakePrevID.OutPoint
	inputProof.Asset.PrevWitnesses = []asset.Witness{{
		PrevID: &fakePrevID,
	}}
	inputProof.AnchorTx.TxIn[0].PreviousOutPoint = fakePrevID.OutPoint
	reanchorProof(t, &inputProof)
	inputProof.ChallengeWitness = signOwnershipWitness(
		t, &inputProof.Asset, inputKey,
	)

	recipientKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	inputProofBytes, err := inputProof.Bytes()
	require.NoError(t, err)
	suffixPtr, err := Decode(inputProofBytes)
	require.NoError(t, err)
	suffix := *suffixPtr
	suffix.ChallengeWitness = nil
	suffix.Asset = *inputProof.Asset.Copy()
	suffix.Asset.ScriptKey = asset.NewScriptKeyBip86(
		test.PubToKeyDesc(recipientKey.PubKey()),
	)
	signAssetTransfer(t, &inputProof, &suffix.Asset, inputKey, nil)
	suffix.PrevOut = inputProof.OutPoint()
	suffix.AnchorTx.TxIn[0].PreviousOutPoint = suffix.PrevOut
	reanchorProof(t, &suffix)

	inputFile, err := NewFile(V0, inputProof)
	require.NoError(t, err)
	inputPrevID := asset.PrevID{
		OutPoint: inputProof.OutPoint(),
		ID:       inputProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			inputProof.Asset.ScriptKey.PubKey,
		),
	}

	snapshot, err := VerifyProofSuffix(
		context.Background(), &suffix, map[asset.PrevID]*File{
			inputPrevID: inputFile,
		}, &BaseVerifier{}, MockVerifierCtx,
	)
	require.NoError(t, err)
	require.True(t, suffix.Asset.DeepEqual(snapshot.Asset))

	// A multi-input suffix places non-primary input files in the suffix's
	// AdditionalInputs. The same explicit trust boundary must propagate to
	// those nested ownership roots.
	mergeSuffix, mergeInputs, inputKeys := buildMergeSuffixWithKeys(
		t, false,
	)
	primaryPrevID, err := mergeSuffix.Asset.PrimaryPrevID()
	require.NoError(t, err)
	require.NotNil(t, primaryPrevID)

	for prevID, inputFile := range mergeInputs {
		if prevID == *primaryPrevID {
			continue
		}

		inputProof, err := inputFile.LastProof()
		require.NoError(t, err)
		inputKey := inputKeys[prevID]
		require.NotNil(t, inputKey)
		inputProof.ChallengeWitness = signOwnershipWitness(
			t, &inputProof.Asset, inputKey,
		)
		mergeInputs[prevID], err = NewFile(V0, *inputProof)
		require.NoError(t, err)
	}

	_, err = VerifyProofSuffix(
		context.Background(), mergeSuffix, mergeInputs, &BaseVerifier{},
		MockVerifierCtx,
	)
	require.NoError(t, err)
}
