//go:build unix

package commands

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// TestFundBatchRejectsNonRegularAnchorPsbt ensures --anchor_psbt is not
// read when the path is not a regular file. A device such as /dev/zero
// never reaches EOF, so os.ReadFile allocates without a bound.
func TestFundBatchRejectsNonRegularAnchorPsbt(t *testing.T) {
	t.Run("dev zero", func(t *testing.T) {
		ctx := fundBatchCLIContext(t, []string{
			"--" + anchorPsbtName, "/dev/zero",
		})
		req, err := fundBatchRequest(ctx)
		require.Error(t, err)
		require.Nil(t, req)
		require.ErrorContains(t, err, "not a regular file")
		require.ErrorContains(t, err, "/dev/zero")
	})

	t.Run("character device", func(t *testing.T) {
		ctx := fundBatchCLIContext(t, []string{
			"--" + anchorPsbtName, "/dev/null",
		})
		req, err := fundBatchRequest(ctx)
		summary := "<nil>"
		if req != nil {
			summary = fmt.Sprintf(
				"anchor_len=%d", len(req.AnchorPsbt),
			)
		}
		require.Error(
			t, err, "accepted non-regular --%s: %s",
			anchorPsbtName, summary,
		)
		require.Nil(t, req)
		require.ErrorContains(t, err, "not a regular file")
	})

	t.Run("fifo with contents", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "anchor.fifo")
		require.NoError(t, syscall.Mkfifo(path, 0o600))

		errCh := make(chan error, 1)
		go func() {
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				errCh <- err
				return
			}
			defer f.Close()

			_, err = f.Write([]byte{0x70, 0x73, 0x62, 0x74})
			errCh <- err
		}()

		ctx := fundBatchCLIContext(t, []string{
			"--" + anchorPsbtName, path,
		})
		req, err := fundBatchRequest(ctx)
		summary := "<nil>"
		if req != nil {
			summary = fmt.Sprintf(
				"anchor_len=%d", len(req.AnchorPsbt),
			)
		}
		require.Error(
			t, err, "accepted fifo --%s: %s", anchorPsbtName,
			summary,
		)
		require.Nil(t, req)
		require.ErrorContains(t, err, "not a regular file")

		select {
		case writeErr := <-errCh:
			if writeErr != nil &&
				!errors.Is(writeErr, syscall.EPIPE) &&
				!errors.Is(writeErr, io.ErrClosedPipe) {

				require.NoError(t, writeErr)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("fifo writer blocked")
		}
	})
}

// TestFinalizeBatchRejectsNonRegularSignedPsbt ensures --signed_psbt is
// rejected the same way as --anchor_psbt when the path is not a regular
// file.
func TestFinalizeBatchRejectsNonRegularSignedPsbt(t *testing.T) {
	ctx := finalizeBatchCLIContext(t, []string{
		"--" + signedPsbtName, "/dev/null",
	})
	req, err := finalizeBatchRequest(ctx)
	summary := "<nil>"
	if req != nil {
		summary = fmt.Sprintf("signed_len=%d", len(req.SignedPsbt))
	}
	require.Error(
		t, err, "accepted non-regular --%s: %s", signedPsbtName,
		summary,
	)
	require.Nil(t, req)
	require.ErrorContains(t, err, "not a regular file")
}

// TestPrepareBatchPreservesOutputOnWriteError ensures a failed write of
// --output_psbt does not destroy a file that was already there.
// os.WriteFile truncates the destination before the payload is written.
func TestPrepareBatchPreservesOutputOnWriteError(t *testing.T) {
	if os.Getenv("TAPCLI_PREPARE_WRITE_LIMIT") != "1" {
		cmd := exec.Command(
			os.Args[0],
			"-test.run",
			"^TestPrepareBatchPreservesOutputOnWriteError$",
			"-test.v",
			"-test.count=1",
		)
		// The child lowers RLIMIT_FSIZE. Do not forward
		// GOCOVERDIR: a coverage meta write into that
		// directory fails with "file too large".
		cmd.Env = append(
			envWithoutGoCoverDir(os.Environ()),
			"TAPCLI_PREPARE_WRITE_LIMIT=1",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}

		return
	}

	signal.Ignore(syscall.SIGXFSZ)

	dir := t.TempDir()
	path := filepath.Join(dir, "batch.psbt")
	original := []byte("previous-prepared-psbt")
	require.NoError(t, os.WriteFile(path, original, 0o600))

	var lim syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_FSIZE, &lim))

	// Lower only the soft limit. The coverage runtime writes its
	// meta file after this test returns, and that write fails
	// with "file too large" while the limit is still in place.
	// Leave the hard limit unchanged so the soft limit can be
	// restored before that write.
	soft := lim.Cur
	lim.Cur = 32
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim))
	defer func() {
		lim.Cur = soft
		require.NoError(t, syscall.Setrlimit(
			syscall.RLIMIT_FSIZE, &lim,
		))
	}()

	psbt := bytes.Repeat([]byte{0x70}, 256)
	resp := &mintrpc.PrepareBatchResponse{
		Batch: &mintrpc.MintingBatch{BatchPsbt: psbt},
	}
	client := &recordingMintClient{resp: resp}

	stdout, err := runPrepareBatch(t, []string{
		"--" + outputPsbtName, path,
	}, client)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to write")
	require.Equal(t, 1, client.prepareCalls)

	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(
		t, original, got,
		"existing --%s was destroyed by the failed write",
		outputPsbtName,
	)

	want, marshalErr := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
	require.NoError(t, marshalErr)
	require.Contains(t, stdout, string(want))

	entries, dirErr := os.ReadDir(dir)
	require.NoError(t, dirErr)
	require.Len(t, entries, 1)
}

// envWithoutGoCoverDir copies env without GOCOVERDIR. Re-execs that
// lower RLIMIT_FSIZE must not inherit the parent's coverage
// directory: the runtime writes a meta file there on exit, and that
// write fails with "file too large".
func envWithoutGoCoverDir(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOCOVERDIR=") {
			continue
		}
		filtered = append(filtered, kv)
	}

	return filtered
}
