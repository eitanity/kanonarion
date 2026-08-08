package staticcha_test

import (
	"context"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

var wrapCoord, _ = coordinate.NewModuleCoordinate("example.com/wrapmod", "v1.0.0")

// wrapModuleFiles carries the two kinds of method value side by side, because
// they are not the same fact and a fix that treats them alike is wrong.
//
// ConfirmEmail is a method on a CONCRETE type: the wrapper SSA materialises for
// `h.ConfirmEmail` calls exactly one written method, and the edge out of the
// wrapper is as certain as any static call in the program.
//
// Save is a method on an INTERFACE: the wrapper for `s.Save` calls whatever
// implements Store, which is a class-hierarchy over-approximation and must not
// be recorded as though it were exact. Two implementations exist so the
// over-approximation is visible as a fan-out rather than collapsing to one edge
// that would read as certain by accident.
var wrapModuleFiles = map[string]string{
	"go.mod": "module example.com/wrapmod\n\ngo 1.21\n",
	"wrapmod.go": `package wrapmod

type Store interface{ Save(int) }

type memStore struct{}

func (m *memStore) Save(int) {}

type fileStore struct{}

func (f *fileStore) Save(int) {}

func NewStore(useFile bool) Store {
	if useFile {
		return &fileStore{}
	}
	return &memStore{}
}

type Handlers struct{}

// ConfirmEmail is registered as a method value on a concrete receiver and is
// never called by name.
func (h *Handlers) ConfirmEmail(int) {}

type Router struct{ routes map[string]func(int) }

func NewRouter() *Router { return &Router{routes: map[string]func(int){}} }

func (r *Router) Get(path string, h func(int)) { r.routes[path] = h }

func (r *Router) Serve(path string) {
	if h, ok := r.routes[path]; ok {
		h(1)
	}
}

// Late.Only is registered as a method value and never invoked through any
// matching dynamic call — its signature is its own, so CHA cannot bind it. The
// reference to it resolves through to the method, so the wrapper is not in the
// graph at all and must not be given edges of its own.
type Late struct{}

func (l *Late) Only(string, bool) {}

var lateSink func(string, bool)

func MountLate(l *Late) { lateSink = l.Only }

// Mount is the registration site for both kinds of method value.
func Mount(r *Router, h *Handlers, s Store) {
	r.Get("/confirm", h.ConfirmEmail)
	r.Get("/save", s.Save)
}

func Main() {
	r := NewRouter()
	Mount(r, &Handlers{}, NewStore(false))
	MountLate(&Late{})
	r.Serve("/confirm")
}
`,
}

func analyseWrapModule(t *testing.T) domain.CallGraphRecord {
	t.Helper()
	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, makeZip(t, wrapCoord, wrapModuleFiles))
	rec, err := a.Analyse(context.Background(), zipPath, wrapCoord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %v (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
	return rec
}

// isWrapperID reports whether a node ID names an SSA-materialised method-value
// or method-expression wrapper — the "$bound" and "$thunk" forms nobody wrote.
func isWrapperID(id string) bool {
	return strings.Contains(id, "$bound") || strings.Contains(id, "$thunk")
}

// wrapperNodes returns the record's wrapper nodes and, for each, its outgoing
// and incoming edges.
func wrapperEdges(rec domain.CallGraphRecord) (nodes []domain.CallNode, out, in map[string][]domain.CallEdge) {
	out = map[string][]domain.CallEdge{}
	in = map[string][]domain.CallEdge{}
	for _, n := range rec.Nodes {
		if isWrapperID(n.ID) {
			nodes = append(nodes, n)
		}
	}
	for _, e := range rec.Edges {
		if isWrapperID(e.FromID) {
			out[e.FromID] = append(out[e.FromID], e)
		}
		if isWrapperID(e.ToID) {
			in[e.ToID] = append(in[e.ToID], e)
		}
	}
	return nodes, out, in
}

// TestAnalyse_AReachedWrapperNeverEndsTheInvocationPath is the measured defect
// and its control in one assertion, because either alone is satisfiable by the
// wrong fix.
//
// The zero: no wrapper that something reaches may be a dead end, because the
// one thing a wrapper is for is the hop to the method it wraps.
//
// The control: the graph must still CONTAIN wrappers. A change that simply
// stopped recording the wrapper node would drive the dead-end count to zero and
// would be a regression, not a fix — the caller would then reach nothing at all
// where before it at least reached the wrapper.
func TestAnalyse_AReachedWrapperNeverEndsTheInvocationPath(t *testing.T) {
	rec := analyseWrapModule(t)
	nodes, out, in := wrapperEdges(rec)

	if len(nodes) == 0 {
		t.Fatal("the control failed: no wrapper nodes in the graph at all, so the zero below is vacuous")
	}

	for _, n := range nodes {
		if len(in[n.ID]) == 0 {
			t.Errorf("%s has no in-edge: a wrapper nothing reaches was recorded as a floating subgraph", n.ID)
		}
		if len(out[n.ID]) == 0 {
			t.Errorf("%s has %d in-edge(s) and no out-edge: the invocation path stops one hop short of the method that runs",
				n.ID, len(in[n.ID]))
		}
	}
}

// TestAnalyse_ConcreteMethodValueRoundTripsRegistrationAndInvocation closes the
// round trip on one fixture. The registration path names the method somebody
// wrote; the invocation path reaches it through the wrapper. Neither half is
// the answer on its own.
func TestAnalyse_ConcreteMethodValueRoundTripsRegistrationAndInvocation(t *testing.T) {
	rec := analyseWrapModule(t)
	const (
		method  = "example.com/wrapmod.(*Handlers).ConfirmEmail"
		wrapper = "(*example.com/wrapmod.Handlers).ConfirmEmail$bound"
	)

	// The registration half: Mount hands the method over as a value.
	var registered bool
	for _, e := range rec.Edges {
		if e.Kind.IsReference() && e.ToID == method && strings.HasSuffix(e.FromID, ".Mount") {
			registered = true
		}
	}
	if !registered {
		t.Errorf("no reference edge from the registration site to %s", method)
	}

	// The invocation half: something reaches the wrapper, and the wrapper
	// reaches the method.
	var intoWrapper, wrapperToMethod *domain.CallEdge
	for i := range rec.Edges {
		e := &rec.Edges[i]
		if e.ToID == wrapper && !e.Kind.IsReference() {
			intoWrapper = e
		}
		if e.FromID == wrapper && e.ToID == method {
			wrapperToMethod = e
		}
	}
	if intoWrapper == nil {
		t.Fatalf("nothing invokes %s, so the fixture no longer reproduces the scenario", wrapper)
	}
	if wrapperToMethod == nil {
		t.Fatalf("%s does not reach %s: the invocation path is still truncated", wrapper, method)
	}

	// The recovered hop is a call. A reference says a value was taken; this says
	// the wrapper invokes the method, which is what the wrapper's body does.
	if wrapperToMethod.Kind.IsReference() {
		t.Errorf("the wrapper hop is tagged a reference; it is an invocation")
	}
	// And it is exact. A concrete receiver means exactly one written method, so
	// downgrading the edge would understate what was measured. Composing it with
	// the weaker hop into the wrapper is the reader's side of the boundary —
	// see domain.WeakestConfidence — not something to bake into the edge.
	if wrapperToMethod.Confidence != domain.ConfidenceDirect {
		t.Errorf("wrapper hop confidence = %s, want %s: a concrete method value has exactly one callee",
			wrapperToMethod.Confidence, domain.ConfidenceDirect)
	}
}

// TestAnalyse_InterfaceMethodValueWrapperIsNotRecordedAsExact is the case the
// ticket's "known exactly and by construction" does not cover. A method value
// taken on an INTERFACE wraps a method nobody wrote a single body for; the
// callee set is whatever implements it. Recording that as Direct would launder
// a class-hierarchy over-approximation into the one confidence rank that means
// "measured, not guessed".
func TestAnalyse_InterfaceMethodValueWrapperIsNotRecordedAsExact(t *testing.T) {
	rec := analyseWrapModule(t)
	const wrapper = "(example.com/wrapmod.Store).Save$bound"

	var targets []string
	for _, e := range rec.Edges {
		if e.FromID != wrapper || e.Kind.IsReference() {
			continue
		}
		targets = append(targets, e.ToID)
		if e.Confidence != domain.ConfidenceCHAOverapprox {
			t.Errorf("%s -> %s confidence = %s, want %s: an interface method value has no single callee",
				wrapper, e.ToID, e.Confidence, domain.ConfidenceCHAOverapprox)
		}
	}
	// Both implementations, because the fan-out IS the over-approximation. One
	// edge here would read as a resolved dispatch and would be a stronger claim
	// than the analysis can make.
	sort.Strings(targets)
	want := []string{
		"example.com/wrapmod.(*fileStore).Save",
		"example.com/wrapmod.(*memStore).Save",
	}
	if !reflect.DeepEqual(targets, want) {
		t.Errorf("interface wrapper callees = %v, want %v", targets, want)
	}
}

// TestAnalyse_ExistingEdgesAreUnchanged is the adjacent control for the widened
// caller set: admitting wrappers must not admit anything else. The type-only
// dependency tier carries an object and a signature and no body, and it stays
// out; nothing acquires a caller it did not have.
func TestAnalyse_ExistingEdgesAreUnchanged(t *testing.T) {
	rec := analyseRefModule(t)

	// The reference fixture's control still holds: a function neither called
	// nor referenced has no in-edge, so widening the caller set did not connect
	// everything to everything.
	if dead := inEdges(rec, ".trulyDead"); len(dead) != 0 {
		t.Errorf("trulyDead acquired %d in-edge(s) from the widened caller set: %v", len(dead), dead)
	}

	// And every recorded edge still starts somewhere the analysis is entitled to
	// record: a module function, or a wrapper one of them reaches.
	for _, e := range rec.Edges {
		if isWrapperID(e.FromID) {
			continue
		}
		if !strings.HasPrefix(e.FromID, refCoord.Path()) {
			t.Errorf("edge from %s: caller is outside the analysed module and is not a wrapper", e.FromID)
		}
	}
}

// TestAnalyse_AWrapperTheGraphResolvesThroughGetsNoEdges is the other side of
// the admission rule. Late.Only is registered as a method value and never
// invoked through a matching dynamic call. The reference to it resolves through
// to the method, so the graph already names what the reader asked about and the
// wrapper is not in the answer. Giving it edges anyway would add a node with
// callees and no callers, which is noise dressed as a measurement.
func TestAnalyse_AWrapperTheGraphResolvesThroughGetsNoEdges(t *testing.T) {
	rec := analyseWrapModule(t)
	const wrapper = "(*example.com/wrapmod.Late).Only$bound"

	for _, n := range rec.Nodes {
		if n.ID == wrapper {
			t.Errorf("%s is a node: a wrapper the reference resolved through was recorded anyway", wrapper)
		}
	}
	for _, e := range rec.Edges {
		if e.FromID == wrapper || e.ToID == wrapper {
			t.Errorf("edge touches %s: %s -> %s", wrapper, e.FromID, e.ToID)
		}
	}
	// The control: the method itself IS named, by the registration.
	var named bool
	for _, e := range rec.Edges {
		if e.Kind.IsReference() && e.ToID == "example.com/wrapmod.(*Late).Only" {
			named = true
		}
	}
	if !named {
		t.Error("the registration of Late.Only names neither the method nor the wrapper")
	}
}
