package staticcha_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

var refCoord, _ = coordinate.NewModuleCoordinate("example.com/refmod", "v1.0.0")

// refModuleFiles is the shape the blind spot was found in: a router that stores
// handlers, a type whose methods ARE the handlers, and a registrar that hands
// them over as method values. Nothing calls confirmEmail; an HTTP request
// would, on every hit.
//
// It carries the neighbouring forms of the same idiom deliberately — a method
// expression, a plain function used as a value, and a function that is only ever
// called — so a fix that sees one and not the others fails here rather than in a
// user's graph.
var refModuleFiles = map[string]string{
	"go.mod": "module example.com/refmod\n\ngo 1.21\n",
	"refmod.go": `package refmod

type Router struct{ routes map[string]func(int) }

func NewRouter() *Router { return &Router{routes: map[string]func(int){}} }

func (r *Router) Get(path string, h func(int)) { r.routes[path] = h }

func (r *Router) Serve(path string) {
	if h, ok := r.routes[path]; ok {
		h(1)
	}
}

type Handlers struct{}

// confirmEmail is registered as a METHOD VALUE and never called.
func (h *Handlers) confirmEmail(int) {}

// resetPassword is registered through a METHOD EXPRESSION and never called.
func (h *Handlers) resetPassword(int) {}

// freeHandler is registered as a plain FUNCTION VALUE and never called.
func freeHandler(int) {}

// calledDirectly is called and never taken as a value.
func calledDirectly(int) {}

// trulyDead is neither called nor referenced anywhere. Its signature is its
// own so that CHA's over-approximation of the dynamic call in Serve cannot
// bind it: the control has to be genuinely unreached, not merely unwritten.
func trulyDead(string, bool) {}

// MountRoutes is the registration site: every reference below names it.
func MountRoutes(r *Router, h *Handlers) {
	r.Get("/confirm", h.confirmEmail)
	viaExpression := (*Handlers).resetPassword
	r.Get("/reset", func(i int) { viaExpression(h, i) })
	r.Get("/free", freeHandler)
	calledDirectly(0)
}
`,
}

func analyseRefModule(t *testing.T) domain.CallGraphRecord {
	t.Helper()
	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, makeZip(t, refCoord, refModuleFiles))
	rec, err := a.Analyse(context.Background(), zipPath, refCoord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %v (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
	return rec
}

// inEdges returns the edges into a node whose ID ends in symbol.
func inEdges(rec domain.CallGraphRecord, symbol string) []domain.CallEdge {
	var out []domain.CallEdge
	for _, e := range rec.Edges {
		if strings.HasSuffix(e.ToID, symbol) {
			out = append(out, e)
		}
	}
	return out
}

func TestAnalyse_MethodValueRegistrationIsRecordedAsAReference(t *testing.T) {
	rec := analyseRefModule(t)

	for _, sym := range []string{".confirmEmail", ".resetPassword", ".freeHandler"} {
		edges := inEdges(rec, sym)
		if len(edges) == 0 {
			t.Errorf("%s has no in-edge at all: the registration is still invisible", sym)
			continue
		}
		var fromRegistrar bool
		for _, e := range edges {
			if !e.Kind.IsReference() {
				continue
			}
			if strings.HasSuffix(e.FromID, ".MountRoutes") ||
				strings.Contains(e.FromID, ".MountRoutes$") {
				fromRegistrar = true
			}
		}
		if !fromRegistrar {
			t.Errorf("%s: no reference edge from the registration site; edges: %v", sym, edges)
		}
	}
}

func TestAnalyse_AReferenceIsNeverRecordedAsACall(t *testing.T) {
	rec := analyseRefModule(t)

	// The control that keeps the reference kind meaningful: a function that is
	// genuinely called keeps a call edge, and nothing turns it into a reference.
	called := inEdges(rec, ".calledDirectly")
	if len(called) == 0 {
		t.Fatal("calledDirectly has no in-edge: the call graph itself is broken")
	}
	for _, e := range called {
		if e.Kind.IsReference() {
			t.Errorf("calledDirectly's call edge from %s is tagged a reference", e.FromID)
		}
	}

	// And the zero's control: a function neither called nor referenced still has
	// no in-edge, so the change did not simply connect everything to everything.
	if dead := inEdges(rec, ".trulyDead"); len(dead) != 0 {
		t.Errorf("trulyDead acquired %d in-edge(s): %v", len(dead), dead)
	}
}

func TestAnalyse_ReferenceScopeIsRecorded(t *testing.T) {
	rec := analyseRefModule(t)
	if !rec.ReferenceScope.IsMeasured() {
		t.Errorf("ReferenceScope = %q, want Analysed: a record that measured the axis must say so", rec.ReferenceScope)
	}
}

func TestAnalyse_ReferenceEdgesResolveThroughTheSyntheticWrapper(t *testing.T) {
	rec := analyseRefModule(t)
	// The method value materialises as a "$bound" wrapper nobody wrote. The
	// answer must name the method, not the wrapper.
	for _, e := range rec.Edges {
		if e.Kind.IsReference() && strings.Contains(e.ToID, "$bound") {
			t.Errorf("reference edge names the synthetic wrapper %s rather than the method it wraps", e.ToID)
		}
	}
}
