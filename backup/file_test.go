package backup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFileNoPath asserts that a File without a path refuses to do anything.
func TestFileNoPath(t *testing.T) {
	t.Parallel()

	f := NewFile("")

	require.ErrorIs(t, f.UpdateAndSwap([]byte("x")), ErrNoBackupFile)

	_, err := f.Extract()
	require.ErrorIs(t, err, ErrNoBackupFile)
}

// TestFileUpdateAndSwap covers the write, replace and read back cycle of the
// on-disk swapper.
func TestFileUpdateAndSwap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, DefaultBackupFileName)
	tempPath := filepath.Join(dir, DefaultTempBackupFileName)
	f := NewFile(path)

	require.Equal(t, path, f.Path())

	// Nothing written yet.
	_, err := f.Extract()
	require.ErrorIs(t, err, ErrNoBackupFile)

	// Empty payloads are refused so a bug can never truncate the backup.
	require.ErrorContains(t, f.UpdateAndSwap(nil), "empty")
	require.NoFileExists(t, path)

	// First write.
	first := []byte("first backup")
	require.NoError(t, f.UpdateAndSwap(first))

	got, err := f.Extract()
	require.NoError(t, err)
	require.Equal(t, first, got)

	// The temp file must not linger and the file is private.
	require.NoFileExists(t, tempPath)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// Second write replaces the content.
	second := []byte("second, longer backup payload")
	require.NoError(t, f.UpdateAndSwap(second))

	got, err = f.Extract()
	require.NoError(t, err)
	require.Equal(t, second, got)
	require.NoFileExists(t, tempPath)

	// Shorter content must fully replace, not overlay.
	third := []byte("3")
	require.NoError(t, f.UpdateAndSwap(third))

	got, err = f.Extract()
	require.NoError(t, err)
	require.Equal(t, third, got)
}

// TestFileStaleTempRemoved asserts that a leftover temp file from a crashed
// attempt is discarded and does not leak into the new backup.
func TestFileStaleTempRemoved(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, DefaultBackupFileName)
	tempPath := filepath.Join(dir, DefaultTempBackupFileName)
	f := NewFile(path)

	require.NoError(t, os.WriteFile(tempPath, []byte("stale"), 0o600))

	payload := []byte("fresh")
	require.NoError(t, f.UpdateAndSwap(payload))

	got, err := f.Extract()
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoFileExists(t, tempPath)
}

// TestFileMissingDirectory asserts that a write into a directory that does not
// exist yet creates it, as a custom --backup.filepath may point anywhere.
func TestFileMissingDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "missing", "nested")
	path := filepath.Join(dir, DefaultBackupFileName)
	f := NewFile(path)

	require.NoError(t, f.UpdateAndSwap([]byte("x")))
	require.FileExists(t, path)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

// TestFileDirectoryIsFile asserts that a path whose parent is a regular file
// fails cleanly without leaving anything behind.
func TestFileDirectoryIsFile(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(parent, []byte("x"), 0o600))

	path := filepath.Join(parent, DefaultBackupFileName)
	require.ErrorContains(t, NewFile(path).UpdateAndSwap([]byte("x")),
		"unable to create backup directory")
	require.NoFileExists(t, path)
}

// TestFileExtractUnreadable asserts that read errors other than a missing
// file are surfaced rather than treated as an empty backup.
func TestFileExtractUnreadable(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, DefaultBackupFileName)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o000))

	_, err := NewFile(path).Extract()
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNoBackupFile)
}
