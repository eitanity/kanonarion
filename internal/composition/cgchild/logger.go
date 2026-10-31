package cgchild

import (
	"io"
	"log/slog"
	"strings"

	"code.eitanity.com/kanonarion/internal/recordstamp"
)

// NewLogger is the logger a command writes its diagnostics with: level by
// name (info unless debug, warn or error), JSON or text, with the ledgers'
// time encoding.
func NewLogger(level string, json bool, w io.Writer) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: CanonicalTimeAttr}
	if json {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// CanonicalTimeAttr rewrites a log line's time into the encoding the ledgers
// write, so a line and a record can be laid beside each other directly:
// slog's default is the local offset at millisecond precision, and every
// record in the store is UTC at nanosecond precision.
func CanonicalTimeAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) != 0 || a.Key != slog.TimeKey || a.Value.Kind() != slog.KindTime {
		return a
	}
	return slog.String(slog.TimeKey, recordstamp.Format(a.Value.Time()))
}
