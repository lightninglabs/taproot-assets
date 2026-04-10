package diagnostics

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServiceStartCreatesRunDir(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)

	service := newService(rootDir, 4, func() time.Time {
		return now
	})

	require.NoError(t, service.Start())
	t.Cleanup(func() {
		require.NoError(t, service.Stop())
	})

	runDir := service.RunDir()
	require.NotEmpty(t, runDir)

	base := filepath.Base(runDir)
	require.Regexp(t, regexp.MustCompile(`^ts\d+-pid\d+$`), base)

	info, err := os.Stat(runDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestServiceWritesFailureArtifacts(t *testing.T) {
	t.Parallel()

	service, err := NewService(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, service.Start())
	t.Cleanup(func() {
		require.NoError(t, service.Stop())
	})

	service.CaptureProofValidationFailure(ProofValidationFailure{
		Stage: StageProofVerificationPostBroadcast,
		Error: "verification failed",
		OutputProofs: []ArtifactFile{{
			FileName: "output-proof.bin",
			Data:     []byte{1, 2, 3},
		}},
		InputProofs: []ArtifactFile{{
			FileName: "input-proof.bin",
			Data:     []byte{4, 5},
		}},
	})

	proofFailuresDir := filepath.Join(service.RunDir(), "proof-failures")
	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(proofFailuresDir)
		return err == nil && len(entries) == 1
	}, time.Second, 20*time.Millisecond)

	entries, err := os.ReadDir(proofFailuresDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	eventDir := filepath.Join(proofFailuresDir, entries[0].Name())
	_, err = os.Stat(filepath.Join(eventDir, "metadata.json"))
	require.NoError(t, err)

	outputProof, err := os.ReadFile(
		filepath.Join(eventDir, "output-proof.bin"),
	)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, outputProof)

	inputProof, err := os.ReadFile(
		filepath.Join(eventDir, "input-proof.bin"),
	)
	require.NoError(t, err)
	require.Equal(t, []byte{4, 5}, inputProof)
}

func TestServiceDropsReportsWhenQueueIsFull(t *testing.T) {
	t.Parallel()

	service := newService(t.TempDir(), 1, time.Now)
	require.NoError(t, service.Start())
	t.Cleanup(func() {
		require.NoError(t, service.Stop())
	})

	for idx := 0; idx < 1000; idx++ {
		service.CaptureProofValidationFailure(ProofValidationFailure{
			Stage: StageProofVerificationPreBroadcast,
			Error: "full queue test",
		})
	}

	require.Eventually(t, func() bool {
		return service.DroppedReports() > 0
	}, time.Second, 20*time.Millisecond)
}

func TestCloneFailureDeepCopiesPointersAndArtifacts(t *testing.T) {
	t.Parallel()

	vPktIdx := 2
	vPktOutIdx := 4
	transferOutIdx := 6

	failure := ProofValidationFailure{
		VPacketIndex:        &vPktIdx,
		VPacketOutputIndex:  &vPktOutIdx,
		TransferOutputIndex: &transferOutIdx,
		OutputProofs: []ArtifactFile{{
			FileName: "output-proof.bin",
			Data:     []byte{1, 2, 3},
		}},
		InputProofs: []ArtifactFile{{
			FileName: "input-proof.bin",
			Data:     []byte{4, 5, 6},
		}},
	}

	cloned := cloneFailure(failure)

	*failure.VPacketIndex = 10
	*failure.VPacketOutputIndex = 11
	*failure.TransferOutputIndex = 12
	failure.OutputProofs[0].Data[0] = 99
	failure.InputProofs[0].Data[0] = 88

	require.NotSame(t, failure.VPacketIndex, cloned.VPacketIndex)
	require.NotSame(
		t, failure.VPacketOutputIndex, cloned.VPacketOutputIndex,
	)
	require.NotSame(
		t, failure.TransferOutputIndex, cloned.TransferOutputIndex,
	)

	require.Equal(t, 2, *cloned.VPacketIndex)
	require.Equal(t, 4, *cloned.VPacketOutputIndex)
	require.Equal(t, 6, *cloned.TransferOutputIndex)
	require.Equal(t, []byte{1, 2, 3}, cloned.OutputProofs[0].Data)
	require.Equal(t, []byte{4, 5, 6}, cloned.InputProofs[0].Data)
}
