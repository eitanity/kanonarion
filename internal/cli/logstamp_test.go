package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/recordstamp"
)

// canonicalStamp is the shape a stored record's timestamp has: UTC, with a
// fixed-width nine-digit fraction or no fraction at all.
var canonicalStamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{9})?Z$`)

// A log line and a stored record carry the same stamp, so a reader holding one
// can line it up against the other directly.
//
// slog's default is the local offset at millisecond precision — "…08.467+09:30"
// — while every ledger writes UTC at nanosecond precision. Correlating the two
// then costs a timezone conversion and a precision reconciliation before the
// comparison starts, which is the work a shared encoding exists to remove.
func TestLogger_EmitsTheCanonicalStamp(t *testing.T) {
	restore := jsonOut
	t.Cleanup(func() { jsonOut = restore })

	for _, tc := range []struct {
		name string
		json bool
	}{{"text", false}, {"json", true}} {
		t.Run(tc.name, func(t *testing.T) {
			jsonOut = tc.json
			var buf bytes.Buffer
			buildLogger("info", &buf).InfoContext(context.Background(), "probe")

			stamp := loggedStamp(t, tc.json, buf.String())
			if !canonicalStamp.MatchString(stamp) {
				t.Fatalf("log stamp %q is not the encoding a record carries; a reader has to normalise "+
					"before they can match a line against a row", stamp)
			}
			if _, err := recordstamp.Parse(stamp); err != nil {
				t.Errorf("the ledgers' own parser cannot read the log stamp %q: %v", stamp, err)
			}
		})
	}
}

// The rewrite itself, on a fixed instant, so the assertion does not depend on
// what the clock happened to read.
func TestCanonicalTimeAttr(t *testing.T) {
	zone := time.FixedZone("ACST", 9*3600+1800)
	at := time.Date(2026, 1, 1, 21, 30, 0, 467000000, zone)

	got := canonicalTimeAttr(nil, slog.Time(slog.TimeKey, at))
	if want := "2026-01-01T12:00:00.467000000Z"; got.Value.String() != want {
		t.Errorf("time attr = %q, want %q", got.Value.String(), want)
	}

	// Only the top-level time attribute. A value a caller logged under its own
	// key, or a nested one, is the caller's to spell.
	other := slog.Time("observed_at", at)
	if canonicalTimeAttr(nil, other).Value.Kind() != slog.KindTime {
		t.Error("a caller's own time attribute was rewritten")
	}
	if canonicalTimeAttr([]string{"group"}, slog.Time(slog.TimeKey, at)).Value.Kind() != slog.KindTime {
		t.Error("a grouped attribute named time was rewritten")
	}
	if got := canonicalTimeAttr(nil, slog.String(slog.TimeKey, "already a string")); got.Value.String() != "already a string" {
		t.Error("a time attribute that is not a time was rewritten")
	}
}

// loggedStamp pulls the time out of one emitted line, in whichever format the
// handler wrote it.
func loggedStamp(t *testing.T, isJSON bool, line string) string {
	t.Helper()
	line = strings.TrimSpace(line)
	if line == "" {
		t.Fatal("the logger emitted nothing")
	}
	if isJSON {
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		stamp, ok := fields[slog.TimeKey].(string)
		if !ok {
			t.Fatalf("log line %q carries no %s", line, slog.TimeKey)
		}
		return stamp
	}
	field, _, _ := strings.Cut(line, " ")
	stamp, ok := strings.CutPrefix(field, slog.TimeKey+"=")
	if !ok {
		t.Fatalf("log line %q does not open with %s=", line, slog.TimeKey)
	}
	return stamp
}
