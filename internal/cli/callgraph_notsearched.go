package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// Reasons a coordinate was not searched, as the JSON document states them.
const (
	notSearchedSuperseded  = "superseded"
	notSearchedNotAnalysed = "not_analysed"
	notSearchedOtherFrame  = "other_frame"
)

// notSearchedJSON is one coordinate an answer could not read. Remedy is absent
// where no command can be named: a local coordinate whose working tree no
// record names.
type notSearchedJSON struct {
	Coordinate string   `json:"coordinate"`
	Pipelines  []string `json:"pipelines,omitempty"`
	Reason     string   `json:"reason"`
	// Frames are the build frames an other_frame coordinate is held under.
	Frames []string `json:"frames,omitempty"`
	Remedy string   `json:"remedy,omitempty"`
}

// storeNotSearched collects, for one invocation, the coordinates the edge and
// implementer queries could not read. A --json document takes them; Run states
// the rest on stderr, as storeSetAside does, because the plain callers and
// callees documents are bare arrays with nowhere to carry them.
var storeNotSearched = &notSearchedCollector{}

type notSearchedCollector struct {
	mu   sync.Mutex
	rows []ports.UnservedCoordinate
}

// report adds rows not already held.
func (c *notSearchedCollector) report(rows []ports.UnservedCoordinate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range rows {
		if !slices.ContainsFunc(c.rows, func(h ports.UnservedCoordinate) bool { return h.Coordinate == r.Coordinate }) {
			c.rows = append(c.rows, r)
		}
	}
}

// take hands over the rows held, sorted by coordinate, and forgets them.
func (c *notSearchedCollector) take() notSearchedRows {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.rows
	c.rows = nil
	slices.SortFunc(out, func(a, b ports.UnservedCoordinate) int {
		if d := strings.Compare(a.Coordinate.Path(), b.Coordinate.Path()); d != 0 {
			return d
		}
		return strings.Compare(a.Coordinate.Version(), b.Coordinate.Version())
	})
	return out
}

// flush states on w the rows no document took.
func (c *notSearchedCollector) flush(w io.Writer) {
	_ = c.take().write(w) //nolint:errcheck // best-effort stderr at exit, as storeSetAside.flush
}

func (c *notSearchedCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = nil
}

// notSearchedRows is the sorted set one answer could not read.
type notSearchedRows []ports.UnservedCoordinate

// json projects the rows for a document, nil when there are none so the key is
// absent.
func (s notSearchedRows) json() []notSearchedJSON {
	if len(s) == 0 {
		return nil
	}
	out := make([]notSearchedJSON, 0, len(s))
	for _, r := range s {
		reason := notSearchedSuperseded
		if len(r.Pipelines) == 0 {
			reason = notSearchedNotAnalysed
		}
		remedy, _ := domain.ReanalysisCommand(r.Coordinate, r.AnalysisRoot, false)
		var frames []string
		if len(r.Frames) > 0 {
			reason, remedy = notSearchedOtherFrame, frameRemedy(r)
			frames, _ = domain.HeldFrames(frameRecords(r.Frames), domain.BuildFrame{})
		}
		out = append(out, notSearchedJSON{
			Coordinate: r.Coordinate.String(),
			Pipelines:  r.Pipelines,
			Reason:     reason,
			Frames:     frames,
			Remedy:     remedy,
		})
	}
	return out
}

// write states the rows as two notices, superseded and never analysed, each
// naming its coordinates and then one remedy line per coordinate.
func (s notSearchedRows) write(w io.Writer) error {
	var superseded, unanalysed, otherFrame notSearchedRows
	for _, r := range s {
		switch {
		case len(r.Frames) > 0:
			otherFrame = append(otherFrame, r)
		case len(r.Pipelines) == 0:
			unanalysed = append(unanalysed, r)
		default:
			superseded = append(superseded, r)
		}
	}
	if err := superseded.writeNotice(w,
		"coordinate(s) hold call graphs only from superseded extraction logic and were not searched",
		"re-derive with"); err != nil {
		return err
	}
	if err := unanalysed.writeNotice(w,
		"module version(s) in the build scope have no call graph at any pipeline and were not searched",
		"analyse with"); err != nil {
		return err
	}
	return otherFrame.writeNotice(w,
		"module version(s) in the build scope are held only under other frames and were not searched",
		"or produce this frame's with")
}

// frameRecords carries frames in the shape the shared frame helper reads.
func frameRecords(frames []domain.BuildFrame) []domain.CallGraphRecord {
	out := make([]domain.CallGraphRecord, 0, len(frames))
	for _, f := range frames {
		out = append(out, domain.CallGraphRecord{Frame: f})
	}
	return out
}

// frameRemedy produces the read frame's record for an other-frame row.
func frameRemedy(r ports.UnservedCoordinate) string {
	return frameReanalysis(r.Coordinate, r.AnalysisRoot)
}

func (s notSearchedRows) writeNotice(w io.Writer, what, how string) error {
	if len(s) == 0 {
		return nil
	}
	names := make([]string, 0, len(s))
	for _, r := range s {
		name := r.Coordinate.String()
		switch {
		case len(r.Frames) > 0:
			frames, flags := domain.HeldFrames(frameRecords(r.Frames), domain.BuildFrame{})
			name += " (" + strings.Join(frames, ", ") + "; read with " + strings.Join(flags, " or ") + ")"
		case len(r.Pipelines) > 0:
			name += " (pipeline " + strings.Join(r.Pipelines, ", ") + ")"
		}
		names = append(names, name)
	}
	var b strings.Builder
	b.WriteString("notice: " + strconv.Itoa(len(s)) + " " + what + ": " + strings.Join(names, ", ") + " — " + how + ":\n")
	for _, r := range s {
		if len(r.Frames) > 0 {
			b.WriteString("  " + frameRemedy(r) + "\n")
			continue
		}
		if line, ok := domain.ReanalysisCommand(r.Coordinate, r.AnalysisRoot, false); ok {
			b.WriteString("  " + line + "\n")
			continue
		}
		// A local coordinate whose working tree no record names gets the house
		// sentence, prefixed with the coordinate so the reader knows which tree.
		b.WriteString("  " + r.Coordinate.String() + ": " + domain.ReanalysisInstruction(r.Coordinate, r.AnalysisRoot) + "\n")
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("writing not-searched notice: %w", err)
	}
	return nil
}

// reportNotSearched collects what an answer could not read: the coordinates
// holding superseded edges touching the queried symbols (touching), and, under
// a build scope, every module version in it with no served graph.
func reportNotSearched(ctx context.Context, uc QueryCallGraphUseCase, sc buildScope, touching []ports.UnservedCoordinate) error {
	storeNotSearched.report(touching)
	if !sc.modules.IsRestricted() {
		return nil
	}
	inScope, err := uc.UnservedCoordinates(ctx, sc.modules.Coordinates(), cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("naming the scope's unanalysed modules: %w", err)
	}
	storeNotSearched.report(inScope)
	return nil
}

// edgeGapsFunc names the coordinates holding superseded edges touching what an
// edge query read.
type edgeGapsFunc func(ctx context.Context, sc buildScope) ([]ports.UnservedCoordinate, error)

// edgeGaps asks the store about the one symbol a one-hop query read.
func edgeGaps(uc QueryCallGraphUseCase, symbolID string, callers bool, opts ports.EdgeQueryOptions) edgeGapsFunc {
	return func(ctx context.Context, sc buildScope) ([]ports.UnservedCoordinate, error) {
		find := uc.NotSearchedByCallees
		if callers {
			find = uc.NotSearchedByCallers
		}
		touching, err := find(ctx, []string{symbolID}, cgapp.PipelineVersion, sc.modules, opts)
		if err != nil {
			return nil, fmt.Errorf("naming the call graphs this answer could not read: %w", err)
		}
		return touching, nil
	}
}

// knownGaps hands over what a traversal already named, level by level.
func knownGaps(touching []ports.UnservedCoordinate) edgeGapsFunc {
	return func(context.Context, buildScope) ([]ports.UnservedCoordinate, error) { return touching, nil }
}

// supersededCoordinatesOf lists the coordinates of modulePath that stored holds
// and served does not: the generations an implementers answer could not read.
func supersededCoordinatesOf(modulePath string, stored, served []ports.CallGraphCoordinate) ([]coordinate.ModuleCoordinate, error) {
	isServed := map[string]bool{}
	for _, s := range served {
		isServed[s.ModulePath+"@"+s.ModuleVersion] = true
	}
	var out []coordinate.ModuleCoordinate
	for _, s := range stored {
		if s.ModulePath != modulePath || isServed[s.ModulePath+"@"+s.ModuleVersion] {
			continue
		}
		c, err := coordinate.NewModuleCoordinate(s.ModulePath, s.ModuleVersion)
		if err != nil {
			return nil, fmt.Errorf("call graph record %s@%s names no module: %w", s.ModulePath, s.ModuleVersion, err)
		}
		out = append(out, c)
	}
	return out, nil
}
