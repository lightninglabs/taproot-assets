package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// DefaultBackupFileName is the default name of the on-disk asset
	// wallet backup file that is kept up to date by the Updater.
	DefaultBackupFileName = "assets.backup"

	// DefaultTempBackupFileName is the name of the temporary file the
	// Updater writes to before atomically renaming it over the main
	// backup file.
	DefaultTempBackupFileName = "temp-dont-use-assets.backup"
)

var (
	// ErrNoBackupFile is returned when no backup file path is configured
	// or the file does not exist on disk yet.
	ErrNoBackupFile = errors.New("backup file does not exist")
)

// Swapper is an interface that allows the Updater to atomically replace the
// persisted backup with a new version and to read back what is currently
// persisted.
type Swapper interface {
	// UpdateAndSwap atomically replaces the persisted backup with the
	// given packed (encoded and encrypted) bytes.
	UpdateAndSwap(packed []byte) error

	// Extract returns the currently persisted packed backup bytes.
	// ErrNoBackupFile is returned if nothing has been persisted yet.
	Extract() ([]byte, error)
}

// File is a Swapper implementation backed by a single file on disk. Updates
// are written to a temporary sibling file first, synced, and then renamed
// over the main file so a crash can never leave a half written backup.
type File struct {
	fileName string
}

// NewFile creates a new File swapper for the given path.
func NewFile(fileName string) *File {
	return &File{fileName: fileName}
}

// Path returns the path of the main backup file.
func (f *File) Path() string {
	return f.fileName
}

// target returns the path the backup is actually written to. A symlink at the
// configured path is followed, so the operator's link to another volume is
// kept and the file behind it is replaced.
func (f *File) target() string {
	resolved, err := filepath.EvalSymlinks(f.fileName)
	if err != nil {
		return f.fileName
	}

	return resolved
}

// UpdateAndSwap writes the packed backup to a temporary file, syncs it and
// then atomically renames it over the main backup file.
func (f *File) UpdateAndSwap(packed []byte) error {
	if f.fileName == "" {
		return ErrNoBackupFile
	}
	if len(packed) == 0 {
		return fmt.Errorf("refusing to write empty backup file")
	}

	target := f.target()
	tempFileName := filepath.Join(
		filepath.Dir(target), DefaultTempBackupFileName,
	)

	// A custom path may point into a directory that does not exist yet.
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("unable to create backup directory: %w", err)
	}

	// A stale temp file from a crashed previous attempt is discarded.
	if _, err := os.Stat(tempFileName); err == nil {
		log.Infof("Found stale temp backup file %v, removing",
			tempFileName)

		if err := os.Remove(tempFileName); err != nil {
			return fmt.Errorf("unable to remove stale temp "+
				"backup file: %w", err)
		}
	}

	if err := writeTemp(tempFileName, packed); err != nil {
		_ = os.Remove(tempFileName)
		return err
	}

	log.Debugf("Swapping backup file %v -> %v", tempFileName, target)

	if err := os.Rename(tempFileName, target); err != nil {
		_ = os.Remove(tempFileName)
		return fmt.Errorf("unable to rename temp backup file: %w",
			err)
	}

	// Sync the containing directory so the rename itself is durable. Not
	// every platform or file system supports this, and the data itself is
	// already synced, so a failure here is not fatal. Windows cannot open
	// directories for syncing at all, so skip it there.
	if runtime.GOOS != "windows" {
		if err := syncDir(dir); err != nil {
			log.Warnf("Unable to sync backup directory %v: %v",
				dir, err)
		}
	}

	return nil
}

// writeTemp creates the temp file, writes the payload, syncs and closes it.
func writeTemp(tempFileName string, packed []byte) error {
	tempFile, err := os.OpenFile(
		tempFileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return fmt.Errorf("unable to create temp backup file: %w",
			err)
	}

	if _, err := tempFile.Write(packed); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("unable to write temp backup file: %w",
			err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("unable to sync temp backup file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("unable to close temp backup file: %w",
			err)
	}

	return nil
}

// Extract reads the currently persisted backup file. ErrNoBackupFile is
// returned if no path is configured or the file does not exist.
func (f *File) Extract() ([]byte, error) {
	if f.fileName == "" {
		return nil, ErrNoBackupFile
	}

	data, err := os.ReadFile(f.fileName)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNoBackupFile

	case err != nil:
		return nil, fmt.Errorf("unable to read backup file: %w", err)
	}

	return data, nil
}

// syncDir fsyncs a directory so that a preceding rename in it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	return d.Sync()
}

// A compile time assertion to ensure File meets the Swapper interface.
var _ Swapper = (*File)(nil)
