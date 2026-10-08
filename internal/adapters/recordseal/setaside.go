package recordseal

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// SetAsideRemedy says what a set-aside generation is and what reads it. It names
// no direction: no store records which build wrote a row, so the row may come
// from an earlier build or a later one.
const SetAsideRemedy = "written in a canonical shape this build cannot reproduce; its bytes hash to their own seal, " +
	"so nothing was altered — read it with the build that wrote it, or upgrade"

// Drift is the classification Classify reaches when the stored bytes hash to
// their own seal, for a store that settles that question itself because its
// stored bytes are not the whole sealed record.
func Drift(verifyErr error) error {
	// No direction is claimed: the store does not record which build wrote a row,
	// and a record a later build wrote fails here exactly as an earlier one does.
	return fmt.Errorf("%w: the stored bytes hash to their own seal, so nothing has been altered — "+
		"this build cannot reproduce them because an earlier or a later build wrote them in a different "+
		"canonical shape; read the record with the build that wrote it, or re-derive it, rather than "+
		"investigate it: %w", ErrGenerationDrift, verifyErr)
}

// Snapshot names the dataset a generation was derived against on top of its
// pipeline, such as a vulnerability record's advisory database. Zero when the
// record has none or its stored head did not yield one.
type Snapshot struct {
	// Name is how prose names the dataset, such as "vuln-db".
	Name    string
	Source  string
	Version string
}

// Generation places one stored generation among a coordinate's many. Each field
// is empty where the head of the stored bytes did not yield it.
type Generation struct {
	PipelineVersion string
	Snapshot        Snapshot
}

// String renders the generation for prose, empty when there is none to state.
func (g Generation) String() string {
	var parts []string
	if g.PipelineVersion != "" {
		parts = append(parts, "pipeline "+g.PipelineVersion)
	}
	if g.Snapshot.Version != "" {
		parts = append(parts, g.Snapshot.Name+" "+g.Snapshot.Version)
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// SetAsideRow names one stored generation a read or a write left out because
// this build cannot reproduce it, and why.
type SetAsideRow struct {
	// Kind says what the row is in prose, such as "vulnerability record".
	Kind string
	// ID is the bare identity the stored bytes carry, empty when they could not
	// be read far enough to name it.
	ID          string
	Generation  Generation
	ContentHash string
	// Reason is the classification the store reached, which matches
	// ErrGenerationDrift.
	Reason error
}

// Label renders the row as identity, generation and content hash, each where
// the stored head yielded it.
func (r SetAsideRow) Label() string {
	label := r.ID
	if label == "" {
		label = "unidentified record"
	}
	if gen := r.Generation.String(); gen != "" {
		label += " " + gen
	}
	if r.ContentHash != "" {
		label += " content_hash " + r.ContentHash
	}
	return label
}

// SetAside reports that a read or a write answered over the stored generations
// this build can reproduce and left out the ones named in Rows. It is returned
// WITH the answer, never instead of it.
//
// It never unwraps to a store's integrity sentinel: drift is excused and
// alteration is not, so a row whose bytes do not hash to their own seal still
// fails the operation as an integrity error.
type SetAside struct {
	Rows []SetAsideRow
}

// Error names every set-aside generation, then what that means.
func (e *SetAside) Error() string {
	parts := make([]string, 0, len(e.Rows))
	for _, r := range e.Rows {
		parts = append(parts, r.Label())
	}
	noun := "generation"
	if len(e.Rows) != 1 {
		noun = "generations"
	}
	return fmt.Sprintf("set aside %d stored %s %s: %s — %s",
		len(e.Rows), e.kind(), noun, strings.Join(parts, "; "), SetAsideRemedy)
}

// kind is the rows' common kind, or the neutral "record" when they differ.
func (e *SetAside) kind() string {
	kind := ""
	for i, r := range e.Rows {
		if i > 0 && r.Kind != kind {
			return "record"
		}
		kind = r.Kind
	}
	if kind == "" {
		return "record"
	}
	return kind
}

// Unwrap exposes each row's own classification, so errors.Is still finds
// ErrGenerationDrift.
func (e *SetAside) Unwrap() []error {
	out := make([]error, 0, len(e.Rows))
	for _, r := range e.Rows {
		if r.Reason != nil {
			out = append(out, r.Reason)
		}
	}
	return out
}

// MergeSetAside folds the set-aside rows err carries into into, one row per
// generation, and reports whether err was a set-aside at all. A caller reading
// several groups states each generation once.
func MergeSetAside(into []SetAsideRow, err error) ([]SetAsideRow, bool) {
	if !IsSetAside(err) {
		return into, false
	}
	var aside *SetAside
	_ = errors.As(err, &aside)
	for _, r := range aside.Rows {
		dup := false
		for _, have := range into {
			if have.ContentHash == r.ContentHash && have.ID == r.ID && have.Generation == r.Generation {
				dup = true
				break
			}
		}
		if !dup {
			into = append(into, r)
		}
	}
	return into, true
}

// IsSetAside reports whether err is a set-aside returned beside an answer. A
// NothingServable unwraps to one too, but it is the absence of an answer, so it
// is not one: folding it in would serve an empty answer as a complete one.
func IsSetAside(err error) bool {
	if errors.As(err, new(*NothingServable)) {
		return false
	}
	return errors.As(err, new(*SetAside))
}

// NothingServable is the answer for a coordinate whose every generation was set
// aside: no record this build can serve. It is an absence, not an integrity
// failure, and it unwraps to the SetAside that says why.
type NothingServable struct {
	// Kind and ID name what was asked for, such as "call graph record" and a
	// coordinate.
	Kind  string
	ID    string
	Aside *SetAside
}

func (e *NothingServable) Error() string {
	return fmt.Sprintf("no %s for %s that this build can serve: %s", e.Kind, e.ID, e.Aside.Error())
}

func (e *NothingServable) Unwrap() error { return e.Aside }

// Reporter is where a store names the generations it set aside. It is
// configuration rather than a return value because the composing read sits
// under reads whose answer must stay the answer; the zero value logs each row at
// warn level, so none is dropped unseen.
type Reporter func([]SetAsideRow)

// Report names rows through r, or logs them when r is unset.
func (r Reporter) Report(rows []SetAsideRow) {
	if len(rows) == 0 {
		return
	}
	if r != nil {
		r(rows)
		return
	}
	for _, row := range rows {
		slog.Warn("set aside a stored "+row.Kind+" generation",
			"generation", row.Label(), "meaning", SetAsideRemedy)
	}
}
