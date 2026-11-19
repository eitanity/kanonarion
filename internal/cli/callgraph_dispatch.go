package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/gotoolchain"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
)

// dispatchReader is the optional read naming the dependency dispatch facts of
// the symbols an edge answer covers. It is asserted rather than added to
// QueryCallGraphUseCase, as worktreeRouter is.
type dispatchReader interface {
	DependencyDispatchOf(ctx context.Context, symbolIDs []string, pipelineVersion string, scope coordinate.ModuleSet, toolchain gotoolchain.Version) (map[string]string, bool, error)
}

// dependencyDispatchSinks is the dependency-dispatch-unmeasured sink of each of
// ids that carries one, ordered by site.
func dependencyDispatchSinks(ctx context.Context, uc QueryCallGraphUseCase, ids []string, sc buildScope) ([]domain.SoundnessSink, error) {
	r, ok := uc.(dispatchReader)
	if !ok {
		return nil, nil
	}
	facts, _, err := r.DependencyDispatchOf(ctx, ids, cgapp.PipelineVersion, sc.modules, sc.toolchain)
	if err != nil {
		return nil, err //nolint:wrapcheck // the use case names the read
	}
	sinks := make([]domain.SoundnessSink, 0, len(facts))
	for id, detail := range facts {
		sinks = append(sinks, domain.SoundnessSink{Kind: domain.SinkDependencyDispatchUnmeasured, Site: id, Detail: detail})
	}
	sort.Slice(sinks, func(i, j int) bool { return sinks[i].Site < sinks[j].Site })
	return sinks, nil
}

// dispatchClause is the statement a non-empty callers answer carries when it
// covers a method a dependency can call: the list holds the module's own
// callers, and a call made inside a dependency's body is not among them.
func dispatchClause(sinks []domain.SoundnessSink) string {
	if len(sinks) == 0 {
		return ""
	}
	const shown = 3
	described := make([]string, 0, min(len(sinks), shown))
	for _, s := range sinks[:min(len(sinks), shown)] {
		described = append(described, s.Describe())
	}
	more := ""
	if len(sinks) > shown {
		more = fmt.Sprintf("; and %d more", len(sinks)-shown)
	}
	return "; calls a dependency makes through an interface are not listed — " + strings.Join(described, "; ") + more
}

// dispatchJSON is one dependency dispatch sink on a JSON document.
type dispatchJSON struct {
	Kind   string `json:"kind"`
	Site   string `json:"site"`
	Detail string `json:"detail"`
}

func toDispatchJSON(sinks []domain.SoundnessSink) []dispatchJSON {
	out := make([]dispatchJSON, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, dispatchJSON{Kind: string(s.Kind), Site: s.Site, Detail: s.Detail})
	}
	return out
}

// storeDispatchNotice holds, for one invocation, the dependency dispatch
// statement of a single-hop --json answer. That document is a bare array with
// nowhere to carry it, so Run states it on stderr, as storeNotSearched does.
var storeDispatchNotice = &dispatchNoticeCollector{}

type dispatchNoticeCollector struct {
	mu    sync.Mutex
	lines []string
}

// report holds the statement of one answer's sinks.
func (c *dispatchNoticeCollector) report(kind, symbolID string, sinks []domain.SoundnessSink) {
	if len(sinks) == 0 {
		return
	}
	parts := make([]string, 0, len(sinks))
	for _, s := range sinks {
		parts = append(parts, s.Describe())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, "notice: the "+kind+" of "+symbolID+
		" do not include calls a dependency makes through an interface: "+strings.Join(parts, "; ")+"\n")
}

// flush states on w what no document took.
func (c *dispatchNoticeCollector) flush(w io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		_, _ = io.WriteString(w, l) //nolint:errcheck // best-effort stderr at exit, as storeNotSearched.flush
	}
	c.lines = nil
}

func (c *dispatchNoticeCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = nil
}
