package cli

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// setAsideRows collects the stored generations the reads behind one answer set
// aside, so the answer can be served and the generations stated beside it.
type setAsideRows []vulnports.UnreadableRow

// take folds a store read's set-aside report into s and returns nil for it, so
// the answer the read returned beside it is served. Any other error comes back
// unchanged: an altered row still fails the read.
func (s *setAsideRows) take(err error) error {
	merged, ok := vulnports.MergeSetAside(*s, err)
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
	merged, _ := vulnports.MergeSetAside(s, &vulnports.SetAsideGenerations{Rows: other})
	return merged
}

// statement is the sentence every surface states a set-aside in, empty when
// nothing was set aside.
func (s setAsideRows) statement() string {
	if len(s) == 0 {
		return ""
	}
	return (&vulnports.SetAsideGenerations{Rows: s}).Error()
}

// write states the set-aside generations on w, one line each.
func (s setAsideRows) write(w io.Writer) {
	for _, r := range s {
		_, _ = fmt.Fprintf(w, "set aside %s: %s\n", r.SetAsideLabel(), vulnports.SetAsideRemedy)
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
			Coordinate:      r.ID,
			PipelineVersion: r.Generation.PipelineVersion,
			ContentHash:     r.ContentHash,
			Reason:          vulnports.SetAsideRemedy,
		}
		if r.Generation.SnapshotSource != "" || r.Generation.SnapshotVersion != "" {
			row.DatabaseSnapshot = &unreadableSnapshotJSON{Source: r.Generation.SnapshotSource, Version: r.Generation.SnapshotVersion}
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

// setAsideJSON is one stored generation a read set aside, under the keys a
// readable record states the same facts in. Each is absent where the head of
// the stored bytes did not yield it.
type setAsideJSON struct {
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
func (r *setAsideRelay) report(rows []vulnports.UnreadableRow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range rows {
		label := row.SetAsideLabel()
		if r.seen[label] {
			continue
		}
		r.seen[label] = true
		if r.w != nil {
			_, _ = fmt.Fprintf(r.w, "set aside %s: %s\n", label, vulnports.SetAsideRemedy)
			continue
		}
		r.logger.Warn("set aside a stored vulnerability record generation",
			"generation", label, "meaning", vulnports.SetAsideRemedy)
	}
}
