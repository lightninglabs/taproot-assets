package commands

import (
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
)

// prepareBatchCLIContext builds a CLI context for the prepare command flags.
func prepareBatchCLIContext(t *testing.T, args []string) *cli.Context {
	t.Helper()

	app := cli.NewApp()
	set := flag.NewFlagSet("prepare", flag.ContinueOnError)
	for _, cmdFlag := range prepareBatchCommand.Flags {
		cmdFlag.Apply(set)
	}
	require.NoError(t, set.Parse(args))

	return cli.NewContext(app, set, nil)
}

// recordingMintClient records PrepareBatch calls. onPrepare runs after the
// call is counted and before the response is returned, so a test can make
// the output path unwritable once the batch is committed.
type recordingMintClient struct {
	mintrpc.MintClient

	prepareCalls int
	openCalls    int
	resp         *mintrpc.PrepareBatchResponse
	err          error
	onPrepare    func()
}

func (c *recordingMintClient) PrepareBatch(_ context.Context,
	_ *mintrpc.PrepareBatchRequest,
	_ ...grpc.CallOption) (*mintrpc.PrepareBatchResponse, error) {

	c.prepareCalls++
	if c.onPrepare != nil {
		c.onPrepare()
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.resp == nil {
		return &mintrpc.PrepareBatchResponse{}, nil
	}

	return c.resp, nil
}

func runPrepareBatch(t *testing.T, args []string,
	client *recordingMintClient) (string, error) {

	t.Helper()

	ctx := prepareBatchCLIContext(t, args)

	var (
		stdout string
		err    error
	)
	stdout = captureStdout(t, func() {
		err = prepareBatchWith(
			ctx, context.Background,
			func(*cli.Context) (mintrpc.MintClient, func()) {
				client.openCalls++
				return client, func() {}
			},
		)
	})

	return stdout, err
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = orig
	})

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	return string(out)
}

// TestPrepareBatchRejectsUnwritableOutputBeforeCommit ensures an unwritable
// --output_psbt path is rejected before PrepareBatch commits the batch.
func TestPrepareBatchRejectsUnwritableOutputBeforeCommit(t *testing.T) {
	testCases := []struct {
		name string
		path func(t *testing.T) string
	}{
		{
			name: "parent is a file",
			path: func(t *testing.T) string {
				parent := filepath.Join(t.TempDir(), "not-dir")
				require.NoError(t, os.WriteFile(
					parent, []byte("x"), 0o600,
				))

				return filepath.Join(parent, "batch.psbt")
			},
		},
		{
			name: "output path is a directory",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
		},
		{
			name: "existing file is read only",
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "batch.psbt")
				require.NoError(t, os.WriteFile(
					path, []byte("keep"), 0o600,
				))
				require.NoError(t, os.Chmod(path, 0o400))

				return path
			},
		},
		{
			name: "parent directory is read only",
			path: func(t *testing.T) string {
				dir := filepath.Join(t.TempDir(), "ro")
				require.NoError(t, os.Mkdir(dir, 0o755))
				require.NoError(t, os.Chmod(dir, 0o555))
				t.Cleanup(func() {
					_ = os.Chmod(dir, 0o755)
				})

				return filepath.Join(dir, "batch.psbt")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path(t)
			client := &recordingMintClient{
				resp: &mintrpc.PrepareBatchResponse{
					Batch: &mintrpc.MintingBatch{
						BatchPsbt: []byte{
							0x70, 0x73, 0x62, 0x74,
						},
					},
				},
			}

			stdout, err := runPrepareBatch(t, []string{
				"--" + outputPsbtName, path,
			}, client)
			require.Error(t, err)
			require.ErrorContains(t, err, "unable to write")
			require.Zero(t, client.openCalls)
			require.Zero(
				t, client.prepareCalls,
				"PrepareBatch committed the batch before "+
					"--%s was checked: %s",
				outputPsbtName, path,
			)
			require.Empty(
				t, stdout,
				"response printed for a prepare that must "+
					"not have run",
			)
		})
	}
}

// TestPrepareBatchPrintsResponseWhenOutputWriteFails ensures a successful
// PrepareBatch still prints the response when the PSBT file cannot be
// written afterwards. The batch is already committed at that point.
func TestPrepareBatchPrintsResponseWhenOutputWriteFails(t *testing.T) {
	psbt := []byte{0x70, 0x73, 0x62, 0x74}

	t.Run("write fails after commit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "batch.psbt")
		resp := &mintrpc.PrepareBatchResponse{
			Batch: &mintrpc.MintingBatch{BatchPsbt: psbt},
		}
		client := &recordingMintClient{
			resp: resp,
			onPrepare: func() {
				require.NoError(t, os.RemoveAll(path))
				require.NoError(t, os.Mkdir(path, 0o700))
			},
		}

		stdout, err := runPrepareBatch(t, []string{
			"--" + outputPsbtName, path,
		}, client)
		require.Error(t, err)
		require.ErrorContains(t, err, "unable to write")
		require.Equal(t, 1, client.openCalls)
		require.Equal(t, 1, client.prepareCalls)

		want, marshalErr := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
		require.NoError(t, marshalErr)
		require.Contains(t, stdout, string(want))
	})

	t.Run("nil batch after commit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "batch.psbt")
		resp := &mintrpc.PrepareBatchResponse{}
		client := &recordingMintClient{resp: resp}

		stdout, err := runPrepareBatch(t, []string{
			"--" + outputPsbtName, path,
		}, client)
		require.Error(t, err)
		require.ErrorContains(t, err, "no batch")
		require.Equal(t, 1, client.openCalls)
		require.Equal(t, 1, client.prepareCalls)

		want, marshalErr := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
		require.NoError(t, marshalErr)
		require.Contains(t, stdout, string(want))
		_, statErr := os.Stat(path)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

// TestPrepareBatchWritesOutputPsbt writes the packet and prints the response
// when the output path is writable.
func TestPrepareBatchWritesOutputPsbt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "batch.psbt")
	psbt := []byte{0x70, 0x73, 0x62, 0x74}
	resp := &mintrpc.PrepareBatchResponse{
		Batch: &mintrpc.MintingBatch{BatchPsbt: psbt},
	}
	client := &recordingMintClient{resp: resp}

	stdout, err := runPrepareBatch(t, []string{
		"--" + outputPsbtName, path,
	}, client)
	require.NoError(t, err)
	require.Equal(t, 1, client.openCalls)
	require.Equal(t, 1, client.prepareCalls)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, psbt, got)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	want, err := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
	require.NoError(t, err)
	require.Contains(t, stdout, string(want))
}
