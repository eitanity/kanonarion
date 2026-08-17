package cli

import (
	"io"
	"log/slog"
)

// discardLogger is the logger a test wires into a decorator whose logging is not
// the subject of the test. It is a real logger, not nil: a nil one would make
// every retry log a panic that only fires on the path a test rarely reaches.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
