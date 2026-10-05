package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	extsqlite "github.com/eitanity/kanonarion/internal/extract/adapters/store/sqlite"
	stdlibsqlite "github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
)

// setAsideRows collects the stored generations the reads behind one answer set
// aside, so the answer can be served and the generations stated beside it.
type setAsideRows []recordseal.SetAsideRow

// take folds a store read's set-aside report into s and returns nil for it, so
// the answer the read returned beside it is served. Any other error comes back
// unchanged: an altered row still fails the read.
func (s *setAsideRows) take(err error) error {
	merged, ok := recordseal.MergeSetAside(*s, err)
	if !ok {
		return err
	}
	*s = merged
	return nil
}

// merge folds other into s, one row per generation.
func (s setAsideRows) merge(other setAsideRows) setAsideRows {
	if len(other) == 0 {
		return s
	}
	merged, _ := recordseal.MergeSetAside(s, &recordseal.SetAside{Rows: other})
	return merged
}

// statement is the sentence every surface states a set-aside in, empty when
// nothing was set aside.
func (s setAsideRows) statement() string {
	if len(s) == 0 {
		return ""
	}
	return (&recordseal.SetAside{Rows: s}).Error()
}

// write states the set-aside generations on w, one line each.
func (s setAsideRows) write(w io.Writer) {
	for _, r := range s {
		_, _ = fmt.Fprintf(w, "set aside %s %s: %s\n", r.Kind, r.Label(), recordseal.SetAsideRemedy)
	}
}

// json projects the set-aside generations for a --json document, nil when there
// are none so the key is absent.
func (s setAsideRows) json() []setAsideJSON {
	if len(s) == 0 {
		return nil
	}
	out := make([]setAsideJSON, 0, len(s))
	for _, r := range s {
		row := setAsideJSON{
			Kind:            r.Kind,
			PipelineVersion: r.Generation.PipelineVersion,
			ContentHash:     r.ContentHash,
			Reason:          recordseal.SetAsideRemedy,
		}
		if idKeyedKinds[r.Kind] {
			row.ID = r.ID
		} else {
			row.Coordinate = r.ID
		}
		if snap := r.Generation.Snapshot; snap.Source != "" || snap.Version != "" {
			row.DatabaseSnapshot = &unreadableSnapshotJSON{Source: snap.Source, Version: snap.Version}
		}
		out = append(out, row)
	}
	return out
}

// noServable is the refusal for a coordinate whose every generation this build
// reads was set aside: what was set aside, then remedy, the re-scan line the
// caller can name.
func (s setAsideRows) noServable(coord coordinate.ModuleCoordinate, remedy string) error {
	msg := fmt.Sprintf("no vulnerability record for %s that this build can serve: %s", coord, s.statement())
	if remedy != "" {
		msg += "\n" + remedy
	}
	return &exitError{code: ExitNotFound, msg: msg}
}

// annotate appends the set-aside statement to a refusal reached after a read set
// generations aside, so the refusal says what it was decided without. The exit
// code the refusal carries is kept, and a refusal that already states it is
// returned as it is.
func (s setAsideRows) annotate(err error) error {
	if err == nil || len(s) == 0 || strings.Contains(err.Error(), s.statement()) {
		return err
	}
	return fmt.Errorf("%w\n%s", err, s.statement())
}

// idKeyedKinds are the set-aside kinds whose identity is an id rather than a
// module coordinate, so a document states it under "id".
var idKeyedKinds = map[string]bool{
	walksqlite.RecordKind:     true,
	extsqlite.RecordKind:      true,
	vulnports.SetAsideKindRun: true,
	stdlibsqlite.RecordKind:   true,
}

// setAsideJSON is one stored generation a read set aside, under the keys a
// readable record states the same facts in. Kind is always stated, so a
// document drawing on several stores tells its rows apart; the rest are absent
// where the head of the stored bytes did not yield them.
type setAsideJSON struct {
	Kind             string                  `json:"kind"`
	ID               string                  `json:"id,omitempty"`
	Coordinate       string                  `json:"coordinate,omitempty"`
	PipelineVersion  string                  `json:"pipeline_version,omitempty"`
	DatabaseSnapshot *unreadableSnapshotJSON `json:"database_snapshot,omitempty"`
	ContentHash      string                  `json:"content_hash,omitempty"`
	Reason           string                  `json:"reason"`
}

// setAsideRelay states, once each, the generations a scan's writes and reuse
// reads set aside. The scan reports from its module workers concurrently, so it
// serialises them; a command that scans points it at its stderr, and until one
// does it logs at warn level so nothing is dropped unseen.
type setAsideRelay struct {
	mu     sync.Mutex
	w      io.Writer
	logger *slog.Logger
	seen   map[string]bool
}

func newSetAsideRelay(logger *slog.Logger) *setAsideRelay {
	return &setAsideRelay{logger: logger, seen: map[string]bool{}}
}

// to directs the statements to w.
func (r *setAsideRelay) to(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.w = w
}

// report states each row not already stated.
func (r *setAsideRelay) report(rows []recordseal.SetAsideRow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range rows {
		label := row.Label()
		if r.seen[label] {
			continue
		}
		r.seen[label] = true
		if r.w != nil {
			_, _ = fmt.Fprintf(r.w, "set aside %s %s: %s\n", row.Kind, label, recordseal.SetAsideRemedy)
			continue
		}
		r.logger.Warn("set aside a stored "+row.Kind+" generation",
			"generation", label, "meaning", recordseal.SetAsideRemedy)
	}
}

// storeSetAside collects, for one invocation, the generations the call graph,
// licence and example stores set aside. A --json document carries what it takes
// from it; Run states the rest on stderr when the command ends, so none is
// dropped unseen.
var storeSetAside = &setAsideCollector{}

// setAsideCollector gathers set-aside generations from a store's reads and
// writes, one entry per generation, until a document takes them or the
// invocation ends. Reads may run concurrently, so it is locked.
type setAsideCollector struct {
	mu     sync.Mutex
	seen   map[string]bool
	unread setAsideRows
}

// report records each row not already recorded.
func (c *setAsideCollector) report(rows []recordseal.SetAsideRow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	for _, r := range rows {
		label := r.Kind + " " + r.Label()
		if c.seen[label] {
			continue
		}
		c.seen[label] = true
		c.unread = append(c.unread, r)
	}
}

// take hands over the rows not yet stated, for a document to carry; nil when
// there are none.
func (c *setAsideCollector) take() setAsideRows {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.unread
	c.unread = nil
	return out
}

// collect folds a store read's set-aside report into the invocation's rows and
// returns nil for it, so the answer beside it is served and the rows stated
// once. Any other error, a NothingServable included, comes back unchanged.
func (c *setAsideCollector) collect(err error) error {
	rows, ok := recordseal.MergeSetAside(nil, err)
	if !ok {
		return err
	}
	c.report(rows)
	return nil
}

// pending reports whether rows are held that no document has taken yet.
func (c *setAsideCollector) pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.unread) > 0
}

// takeFor hands over the rows not yet stated of one kind for one identity, for a
// document section about that coordinate to carry; nil when there are none.
func (c *setAsideCollector) takeFor(kind, id string) setAsideRows {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out, rest setAsideRows
	for _, r := range c.unread {
		if r.Kind == kind && r.ID == id {
			out = append(out, r)
			continue
		}
		rest = append(rest, r)
	}
	c.unread = rest
	return out
}

// sectionSetAside takes, for a document section about one coordinate, the
// generations its read of kind set aside, with those an all-set-aside refusal in
// err carries, and reports whether err was that refusal.
func sectionSetAside(kind string, coord coordinate.ModuleCoordinate, err error) (setAsideRows, bool) {
	rows := storeSetAside.takeFor(kind, coord.String())
	var none *recordseal.NothingServable
	if !errors.As(err, &none) {
		return rows, false
	}
	return rows.merge(none.Aside.Rows), true
}

// flush states on w, one line each, the rows no document took. A row the
// command's own error already names is not stated twice.
func (c *setAsideCollector) flush(w io.Writer, cmdErr error) {
	named := ""
	if cmdErr != nil {
		named = cmdErr.Error()
	}
	for _, r := range c.take() {
		if named != "" && strings.Contains(named, r.Label()) {
			continue
		}
		_, _ = fmt.Fprintf(w, "set aside %s %s: %s\n", r.Kind, r.Label(), recordseal.SetAsideRemedy)
	}
}

// reset forgets every row, so one invocation never states another's.
func (c *setAsideCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen, c.unread = nil, nil
}
