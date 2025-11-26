package tapcfg

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ensureDirWritable verifies that the provided directory exists, is a directory
// and is writable by creating a temporary file within it.
func ensureDirWritable(dir string) error {
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("not accessible (dir=%s): %w", dir, err)
	}

	if !dirInfo.IsDir() {
		return fmt.Errorf("not a directory (dir=%s)", dir)
	}

	tmpFile, err := os.CreateTemp(dir, "tapd-tmpdir-check-*")
	if err != nil {
		return fmt.Errorf("not writable (dir=%s): %w", dir, err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("not writable (dir=%s): %w", dir, err)
	}

	return nil
}

// checkSQLiteTempDir checks temp directory locations on Linux/Darwin
// and verifies the first writable option. SQLite honors SQLITE_TMPDIR first,
// then TMPDIR, then falls back to /var/tmp, /usr/tmp and /tmp.
//
// NOTE: SQLite requires a writable temp directory because several internal
// operations need temporary files when they cannot be done purely in memory.
func checkSQLiteTempDir() error {
	// This check only runs for Linux/Darwin.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}

	// SQLite will use the first available temp directory; we mirror that
	// behavior by trying environment variables and standard fallback
	// directories in order.
	var errs []string

	type dirSource struct {
		path   string
		source string
	}

	sources := []dirSource{
		{path: os.Getenv("SQLITE_TMPDIR"), source: "env=SQLITE_TMPDIR"},
		{path: os.Getenv("TMPDIR"), source: "env=TMPDIR"},
		{path: "/var/tmp", source: "fallback=/var/tmp"},
		{path: "/usr/tmp", source: "fallback=/usr/tmp"},
		{path: "/tmp", source: "fallback=/tmp"},
	}

	for _, s := range sources {
		if s.path == "" {
			continue
		}

		err := ensureDirWritable(s.path)
		if err != nil {
			err = fmt.Errorf("(%s) %w", s.source, err)
			errs = append(errs, err.Error())
			continue
		}

		// Found a writable temp directory.
		return nil
	}

	return fmt.Errorf("no writable temp directory found; attempts=%s",
		strings.Join(errs, "; "))
}
