//go:build !stdlog && !nolog
// +build !stdlog,!nolog

package build

import "os"

// LoggingType is a log type that writes to both stdout and the log rotator, if
// present.
const LoggingType = LogTypeDefault

// Write writes the byte slice to both stdout and the log rotator, if present.
func (w *LogWriter) Write(b []byte) (int, error) {
	os.Stdout.Write(b)
	if w.RotatorPipe != nil {
		n, err := w.RotatorPipe.Write(b)
		if err != nil {
			return n, err
		}
	}
	return len(b), nil
}
