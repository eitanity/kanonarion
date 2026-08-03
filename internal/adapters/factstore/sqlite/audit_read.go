package sqlite

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
)

// auditLogName is the assurance log's file name under a store root.
const auditLogName = "audit.jsonl"

// AuditLogPath returns the assurance log's path for a store root. The reader and
// the writer agree on it here rather than each joining the name for itself.
func AuditLogPath(storeRoot string) string { return filepath.Join(storeRoot, auditLogName) }

// LedgerEntry is one readable line of the assurance log, normalised.
//
// Fields is the line's body whichever envelope it arrived in: the payload map
// for a generic event, and the flat fact fields for the historical
// fact_record_written layout. One shape means a reader renders and filters
// every event the same way and cannot silently know about only one of the two.
type LedgerEntry struct {
	Line      int
	Type      audit.EventType
	Timestamp time.Time
	Fields    map[string]any
}

// LedgerFault is one line the reader could not read, with where it is and why.
//
// After and Before bracket it with the nearest readable timestamps on either
// side, because a torn line carries no timestamp of its own and would otherwise
// be unplaceable in time — which is precisely what a reader answering "what
// happened on this date" needs in order to state that its count for that window
// is a lower bound. Either may be zero at the ends of the file.
type LedgerFault struct {
	Line   int
	Reason string
	After  time.Time
	Before time.Time
}

// Ledger is one whole read of the assurance log.
//
// LinesRead counts every line the file held, so LinesRead - len(Faults) is the
// number of events recovered and the two numbers can be reconciled against a
// wc -l by anyone who doubts the reader.
type Ledger struct {
	Path      string
	LinesRead int
	Entries   []LedgerEntry
	Faults    []LedgerFault
}

// maxLedgerLine bounds a single line. The default bufio.Scanner limit (64 KiB)
// is not enough: a torn line is two events spliced together, and a walk_completed
// payload is already large. A line longer than this is reported as a fault rather
// than truncated into something that might still parse.
const maxLedgerLine = 4 << 20

// ReadLedger reads the whole assurance log at path.
//
// Every line is accounted for. A line that does not parse is recorded as a fault
// with its line number and skipped — never dropped, and never fatal: a strict
// parse would abort on the first torn line of a production ledger and take the
// other 28,000 events with it, which is the opposite of what an append-only
// evidence trail is for. An unreadable line is a fault seam to report, not a
// reason to refuse the read.
//
// Entries come back in chronological order rather than file order. The two
// almost always agree — the log is append-only — but "almost always" is not a
// property a reader answering a first-awareness question can rest on, and the
// sort is a few milliseconds over the whole file. Ties keep file order.
//
// A missing file is an error: no ledger and an empty ledger are different
// answers, and only the caller knows whether it expected a store to be there.
func ReadLedger(path string) (Ledger, error) {
	f, err := os.Open(path) // #nosec G304 -- path constructed from operator-controlled store root
	if err != nil {
		return Ledger{}, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	led := Ledger{Path: path}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLedgerLine)
	// pending indexes faults still waiting for a following timestamp.
	var pending []int
	var last time.Time
	for sc.Scan() {
		led.LinesRead++
		entry, perr := parseLedgerLine(led.LinesRead, sc.Bytes())
		if perr != nil {
			led.Faults = append(led.Faults, LedgerFault{Line: led.LinesRead, Reason: perr.Error(), After: last})
			pending = append(pending, len(led.Faults)-1)
			continue
		}
		for _, i := range pending {
			led.Faults[i].Before = entry.Timestamp
		}
		pending = pending[:0]
		last = entry.Timestamp
		led.Entries = append(led.Entries, entry)
	}
	if serr := sc.Err(); serr != nil {
		// A line too long for the buffer is the one scan error that is a property
		// of the data rather than of the file handle, and it stops the scan dead.
		// Report it as a fault on the line it stopped at and keep what was read:
		// losing 30,000 recovered events to one oversized line is the silence this
		// reader exists to prevent.
		if errors.Is(serr, bufio.ErrTooLong) {
			led.LinesRead++
			led.Faults = append(led.Faults, LedgerFault{
				Line:   led.LinesRead,
				Reason: fmt.Sprintf("line exceeds %d bytes and was not read", maxLedgerLine),
				After:  last,
			})
		} else if !errors.Is(serr, io.EOF) {
			return led, fmt.Errorf("reading audit log %s: %w", path, serr)
		}
	}

	sort.SliceStable(led.Entries, func(i, j int) bool {
		return led.Entries[i].Timestamp.Before(led.Entries[j].Timestamp)
	})
	return led, nil
}

// ledgerLine is the union of the two on-disk shapes. Both carry event_type and
// timestamp at the top level; only the generic envelope carries payload, and
// only the fact-record line carries the flat fields, which are picked up by the
// second decode into a map.
type ledgerLine struct {
	EventType audit.EventType `json:"event_type"`
	Timestamp string          `json:"timestamp"`
	Payload   map[string]any  `json:"payload"`
}

// flatOnly are the fact-record line's envelope fields. They are lifted out of
// the flat body so the entry's Fields carry only the event's own facts, matching
// what a payload holds for every other event type.
var flatOnly = map[string]struct{}{"event_type": {}, "timestamp": {}}

// parseLedgerLine normalises one line into a LedgerEntry, or reports why it
// could not be read.
//
// A line whose event_type this binary does not recognise is NOT a fault: it is
// an event written by a newer build, and refusing it would make an older reader
// report a newer store's evidence as damage. A line with no parseable timestamp
// IS a fault — an event that cannot be placed in time cannot take part in any
// answer this reader gives, and counting it as readable would put it in a
// coverage window it has no claim on.
func parseLedgerLine(n int, raw []byte) (LedgerEntry, error) {
	var head ledgerLine
	if err := json.Unmarshal(raw, &head); err != nil {
		return LedgerEntry{}, fmt.Errorf("line %d is not valid JSON: %w", n, err)
	}
	ts, err := time.Parse(time.RFC3339Nano, head.Timestamp)
	if err != nil {
		return LedgerEntry{}, fmt.Errorf("line %d has no readable timestamp: %w", n, err)
	}
	fields := head.Payload
	if fields == nil {
		// The historical flat layout: the facts sit beside the envelope fields.
		var flat map[string]any
		if uerr := json.Unmarshal(raw, &flat); uerr != nil {
			return LedgerEntry{}, fmt.Errorf("line %d is not a JSON object: %w", n, uerr)
		}
		fields = make(map[string]any, len(flat))
		for k, v := range flat {
			if _, skip := flatOnly[k]; skip {
				continue
			}
			fields[k] = v
		}
	}
	return LedgerEntry{Line: n, Type: head.EventType, Timestamp: ts.UTC(), Fields: fields}, nil
}

// Coverage reports the ledger's own window: the first and last event it holds.
//
// It is what makes "no event" distinguishable from "no coverage". A query that
// returns nothing over a window the ledger never spanned has found no evidence
// of absence, and a reader that reported only the empty result would let that
// read as proof nothing happened. Both are zero when the ledger holds no
// readable event at all.
func (l Ledger) Coverage() (first, last time.Time) {
	if len(l.Entries) == 0 {
		return time.Time{}, time.Time{}
	}
	return l.Entries[0].Timestamp, l.Entries[len(l.Entries)-1].Timestamp
}

// FaultsWithin reports the faults whose position in the file could fall inside
// [since, until], using the readable timestamps that bracket each one.
//
// A fault is counted whenever its bracket OVERLAPS the window rather than only
// when it is contained by it: the line's own time is unknown, so an overlap is
// the strongest thing that can be said, and under-reporting here would let a
// window that may be missing events claim to be complete. Zero bounds mean
// unbounded on that side.
func (l Ledger) FaultsWithin(since, until time.Time) []LedgerFault {
	var out []LedgerFault
	for _, f := range l.Faults {
		// The fault lies somewhere in (After, Before). An unknown end is open.
		if !until.IsZero() && !f.After.IsZero() && f.After.After(until) {
			continue
		}
		if !since.IsZero() && !f.Before.IsZero() && f.Before.Before(since) {
			continue
		}
		out = append(out, f)
	}
	return out
}
