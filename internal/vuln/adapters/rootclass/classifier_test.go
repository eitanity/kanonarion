package rootclass_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/rootclass"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

const pipelineVersion = "0.3.0"

// fakeGraphs serves one record per coordinate and counts the reads, so a test
// can assert both what was classified and how often the store was asked.
type fakeGraphs struct {
	records map[string]cgdomain.CallGraphRecord
	err     error
	reads   int
}

func (f *fakeGraphs) GetCallGraphRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (cgdomain.CallGraphRecord, bool, error) {
	f.reads++
	if f.err != nil {
		return cgdomain.CallGraphRecord{}, false, f.err
	}
	rec, ok := f.records[coord.String()]
	return rec, ok, nil
}

func appCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	return coordinatetest.MustNew("example.com/app", "local")
}

func targetRooted(t *testing.T) vuldomain.Rooting {
	t.Helper()
	return vuldomain.TargetRootedAt(appCoord(t))
}

// handlerFrame is the route's entry point: a method in the application module,
// carrying no version because a main module has none in a Go build.
func handlerFrame(symbol, receiver string) vuldomain.ReachabilityFrame {
	return vuldomain.ReachabilityFrame{
		ModulePath: "example.com/app",
		Package:    "example.com/app/handlers",
		Receiver:   receiver,
		Symbol:     symbol,
	}
}

func routeFrom(entry vuldomain.ReachabilityFrame) vuldomain.ReachabilityRoute {
	return vuldomain.ReachabilityRoute{
		entry,
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
	}
}

// appRecord builds a call graph for the application module containing the named
// nodes and edges.
func appRecord(nodes []cgdomain.CallNode, edges []cgdomain.CallEdge) cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		Completeness: cgdomain.CompletenessBuiltWithBodies,
		Nodes:        nodes,
		Edges:        edges,
	}
}

func node(id, receiver, symbol string, opts ...func(*cgdomain.CallNode)) cgdomain.CallNode {
	n := cgdomain.CallNode{
		ID:       id,
		Module:   "example.com/app",
		Package:  "example.com/app/handlers",
		Receiver: receiver,
		Symbol:   symbol,
	}
	for _, o := range opts {
		o(&n)
	}
	return n
}

func exported(n *cgdomain.CallNode)   { n.IsExportedAPI = true }
func testScope(n *cgdomain.CallNode)  { n.IsTest = true }
func externalTo(n *cgdomain.CallNode) { n.IsExternal = true; n.Module = "example.com/dep" }

// TestClassify_ReadsTheNodeFactsOffTheServedGraph is the adapter's core claim:
// the kind comes from the call graph the coordinate serves, not from anything
// the route itself carries.
func TestClassify_ReadsTheNodeFactsOffTheServedGraph(t *testing.T) {
	tests := []struct {
		name     string
		entry    vuldomain.ReachabilityFrame
		record   cgdomain.CallGraphRecord
		wantKind vuldomain.RootKind
		wantIn   string
	}{
		{
			name:  "a ServeHTTP method is an http.Handler implementation",
			entry: handlerFrame("ServeHTTP", "*Server"),
			record: appRecord([]cgdomain.CallNode{
				node("example.com/app/handlers.(*Server).ServeHTTP", "*Server", "ServeHTTP", exported),
			}, nil),
			wantKind: vuldomain.RootIngress,
			wantIn:   "http.Handler",
		},
		{
			name:  "package init is an entry point the runtime drives",
			entry: handlerFrame("init", ""),
			record: appRecord([]cgdomain.CallNode{
				node("example.com/app/handlers.init", "", "init"),
			}, nil),
			wantKind: vuldomain.RootIngress,
			wantIn:   "package initialisation",
		},
		{
			name:  "a test declaration is test scope however exported it looks",
			entry: handlerFrame("Helper", "*Fixture"),
			record: appRecord([]cgdomain.CallNode{
				node("example.com/app/handlers.(*Fixture).Helper", "*Fixture", "Helper", exported, testScope),
			}, nil),
			wantKind: vuldomain.RootTest,
			wantIn:   "test scope",
		},
		{
			name:  "an exported symbol nothing in the project calls",
			entry: handlerFrame("Decode", ""),
			record: appRecord([]cgdomain.CallNode{
				node("example.com/app/handlers.Decode", "", "Decode", exported),
			}, nil),
			wantKind: vuldomain.RootExportedAPI,
			wantIn:   "a consumer could drive it",
		},
		{
			name:  "an owned caller makes it internal",
			entry: handlerFrame("Decode", ""),
			record: appRecord([]cgdomain.CallNode{
				node("example.com/app/handlers.Decode", "", "Decode", exported),
				node("example.com/app/handlers.run", "", "run"),
			}, []cgdomain.CallEdge{
				{FromID: "example.com/app/handlers.run", ToID: "example.com/app/handlers.Decode"},
			}),
			wantKind: vuldomain.RootInternal,
			wantIn:   "1 caller",
		},
		{
			name:  "a dependency calling back in is an external invocation",
			entry: handlerFrame("Callback", ""),
			record: appRecord([]cgdomain.CallNode{
				node("example.com/app/handlers.Callback", "", "Callback", exported),
				node("example.com/dep.dispatch", "", "dispatch", externalTo),
			}, []cgdomain.CallEdge{
				{FromID: "example.com/dep.dispatch", ToID: "example.com/app/handlers.Callback"},
			}),
			wantKind: vuldomain.RootIngress,
			wantIn:   "a dependency invokes it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{
				appCoord(t).String(): tt.record,
			}}
			got := rootclass.New(graphs, pipelineVersion).
				Classify(context.Background(), targetRooted(t), appCoord(t), routeFrom(tt.entry))
			if got.Kind != tt.wantKind {
				t.Fatalf("Kind = %q (reason %q), want %q", got.Kind, got.Reason, tt.wantKind)
			}
			if !strings.Contains(got.Reason, tt.wantIn) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tt.wantIn)
			}
			if got.NodeID == "" {
				t.Error("a resolved classification must name the node it was read off, so it can be re-run")
			}
		})
	}
}

// TestClassify_ExternalNodeDoesNotAnswerForTheProject pins the reason external
// nodes are kept out of the frame index: a dependency with an identically named
// method in an identically named package would otherwise be classified as the
// project's own.
func TestClassify_ExternalNodeDoesNotAnswerForTheProject(t *testing.T) {
	graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{
		appCoord(t).String(): appRecord([]cgdomain.CallNode{
			node("example.com/dep/handlers.(*Server).ServeHTTP", "*Server", "ServeHTTP", exported, externalTo),
		}, nil),
	}}
	got := rootclass.New(graphs, pipelineVersion).
		Classify(context.Background(), targetRooted(t), appCoord(t), routeFrom(handlerFrame("ServeHTTP", "*Server")))
	if got.Kind != vuldomain.RootUnrooted {
		t.Fatalf("Kind = %q, want unrooted — an external node must not answer for the analysed module", got.Kind)
	}
}

// TestClassify_UnavailableGraphIsAMeasurement covers the three ways the graph
// can fail to answer. Each must name what happened; an unrooted answer with no
// reason is the silent negative this whole classification exists to prevent.
func TestClassify_UnavailableGraphIsAMeasurement(t *testing.T) {
	tests := []struct {
		name       string
		graphs     *fakeGraphs
		wantIn     string
		wantRemedy bool
	}{
		{
			name:       "no record for the module",
			graphs:     &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{}},
			wantIn:     "no call graph is stored",
			wantRemedy: true,
		},
		{
			name: "a record analysed at a fidelity that holds no nodes",
			graphs: &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{
				"example.com/app@local": {Completeness: cgdomain.CompletenessMetadataOnly},
			}},
			wantIn:     "METADATA_ONLY",
			wantRemedy: true,
		},
		{
			name:   "the store could not be read",
			graphs: &fakeGraphs{err: errors.New("content hash mismatch")},
			wantIn: "content hash mismatch",
		},
		{
			name: "the entry point is not a node in the graph",
			graphs: &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{
				"example.com/app@local": appRecord([]cgdomain.CallNode{
					node("example.com/app/handlers.other", "", "other"),
				}, nil),
			}},
			wantIn:     "is not a node in",
			wantRemedy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rootclass.New(tt.graphs, pipelineVersion).
				Classify(context.Background(), targetRooted(t), appCoord(t), routeFrom(handlerFrame("ServeHTTP", "*Server")))
			if got.Kind != vuldomain.RootUnrooted {
				t.Fatalf("Kind = %q, want unrooted", got.Kind)
			}
			if !strings.Contains(got.Reason, tt.wantIn) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tt.wantIn)
			}
			if tt.wantRemedy && got.Remedy == "" {
				t.Error("a gap a command would close must name that command")
			}
		})
	}
}

// TestClassify_RootCoordinateResolution checks which module's graph is consulted.
// Getting this wrong is not a missing answer but a wrong one: a frame's symbol
// looked up in the wrong module's graph can match a different function entirely.
func TestClassify_RootCoordinateResolution(t *testing.T) {
	depGraph := cgdomain.CallGraphRecord{
		Completeness: cgdomain.CompletenessBuiltWithBodies,
		Nodes: []cgdomain.CallNode{{
			ID: "example.com/dep.Parse", Module: "example.com/dep",
			Package: "example.com/dep", Symbol: "Parse", IsExportedAPI: true,
		}},
	}
	graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{
		"example.com/dep@v1.2.0": depGraph,
	}}
	// An isolated record whose route starts in the dependency: the frame carries
	// a version, so that is the coordinate to read.
	route := vuldomain.ReachabilityRoute{
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
		{ModulePath: "example.com/other", ModuleVersion: "v0.1.0", Package: "example.com/other", Symbol: "Read"},
	}
	got := rootclass.New(graphs, pipelineVersion).
		Classify(context.Background(), vuldomain.RootingIsolated, coordinatetest.MustNew("example.com/dep", "v1.2.0"), route)
	if got.Kind != vuldomain.RootExportedAPI {
		t.Fatalf("Kind = %q (reason %q), want exported-api read from the dependency's own graph", got.Kind, got.Reason)
	}
	if !got.ClosureRooted {
		t.Error("an isolated scan analysed no application, so its route is closure-rooted")
	}
}

// TestClassify_UnlocatableRootSaysSo covers the frame that names neither a
// version nor a module any frame identifies: there is no coordinate to read, and
// guessing one would classify against an unrelated graph.
func TestClassify_UnlocatableRootSaysSo(t *testing.T) {
	graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{}}
	route := vuldomain.ReachabilityRoute{
		{ModulePath: "example.com/unknown", Package: "example.com/unknown", Symbol: "Run"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
	}
	got := rootclass.New(graphs, pipelineVersion).
		Classify(context.Background(), targetRooted(t), appCoord(t), route)
	if got.Kind != vuldomain.RootUnrooted {
		t.Fatalf("Kind = %q, want unrooted", got.Kind)
	}
	if graphs.reads != 0 {
		t.Errorf("store read %d time(s) for a route no coordinate could be resolved for", graphs.reads)
	}
	if !strings.Contains(got.Reason, "example.com/unknown") {
		t.Errorf("Reason = %q, want the module it could not locate named", got.Reason)
	}
}

// TestClassify_GraphIsReadOncePerCoordinate matters because a record with forty
// findings asks the same question of the same module forty times, and a call
// graph is a large object to decode. A cached MISS is asserted alongside a
// cached hit: re-asking for a module the store does not hold is the same answer
// at forty times the cost.
func TestClassify_GraphIsReadOncePerCoordinate(t *testing.T) {
	graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{}}
	c := rootclass.New(graphs, pipelineVersion)
	for range 4 {
		c.Classify(context.Background(), targetRooted(t), appCoord(t), routeFrom(handlerFrame("ServeHTTP", "*Server")))
	}
	if graphs.reads != 1 {
		t.Fatalf("store read %d times, want 1", graphs.reads)
	}
}

// TestClassify_EmptyRouteIsNotClassified mirrors the domain rule at the adapter
// boundary, and asserts it costs no store read: there is nothing to classify.
func TestClassify_EmptyRouteIsNotClassified(t *testing.T) {
	graphs := &fakeGraphs{records: map[string]cgdomain.CallGraphRecord{}}
	got := rootclass.New(graphs, pipelineVersion).
		Classify(context.Background(), targetRooted(t), appCoord(t), nil)
	if got.IsRecorded() {
		t.Fatalf("an empty route was classified as %q", got.Kind)
	}
	if graphs.reads != 0 {
		t.Errorf("store read %d time(s) for an empty route", graphs.reads)
	}
}

// A remedy is only a remedy if the coordinate it names can be handed to the
// command it names. A project module carries the synthetic "local" version, and
// "kanonarion callgraph <path>@local" exits non-zero — the coordinate names no
// published artefact, so no fetch can ever satisfy it and the operator's next
// step is a second dead end. Every unavailable branch is covered because they
// built the string independently and fixing one left the others impossible.
func TestClassify_RemedyNamesACommandTheCoordinateCanRun(t *testing.T) {
	depCoord := coordinatetest.MustNew("example.com/dep", "v1.2.0")
	depRoute := vuldomain.ReachabilityRoute{
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
		{ModulePath: "example.com/other", ModuleVersion: "v0.1.0", Package: "example.com/other", Symbol: "Read"},
	}
	otherNode := []cgdomain.CallNode{node("example.com/app/handlers.other", "", "other")}

	// gap names the three ways a graph can be unavailable, keyed by the record
	// the store serves for the coordinate under test.
	gaps := map[string]func(coord string) map[string]cgdomain.CallGraphRecord{
		"no record for the module": func(string) map[string]cgdomain.CallGraphRecord {
			return map[string]cgdomain.CallGraphRecord{}
		},
		"a record that holds no nodes": func(coord string) map[string]cgdomain.CallGraphRecord {
			return map[string]cgdomain.CallGraphRecord{coord: {Completeness: cgdomain.CompletenessMetadataOnly}}
		},
		"the entry point is not a node": func(coord string) map[string]cgdomain.CallGraphRecord {
			return map[string]cgdomain.CallGraphRecord{coord: appRecord(otherNode, nil)}
		},
	}

	kinds := []struct {
		name       string
		coordKey   string
		rooting    vuldomain.Rooting
		record     coordinate.ModuleCoordinate
		route      vuldomain.ReachabilityRoute
		wantPrefix string
	}{
		{
			name:       "a project coordinate is re-derived by 'local'",
			coordKey:   "example.com/app@local",
			rooting:    vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
			record:     coordinatetest.MustNew("example.com/app", "local"),
			route:      routeFrom(handlerFrame("ServeHTTP", "*Server")),
			wantPrefix: "kanonarion local ",
		},
		{
			name:       "a published coordinate is re-derived by 'callgraph'",
			coordKey:   "example.com/dep@v1.2.0",
			rooting:    vuldomain.RootingIsolated,
			record:     depCoord,
			route:      depRoute,
			wantPrefix: "kanonarion callgraph example.com/dep@v1.2.0",
		},
	}

	for _, k := range kinds {
		for gapName, build := range gaps {
			t.Run(k.name+"/"+gapName, func(t *testing.T) {
				graphs := &fakeGraphs{records: build(k.coordKey)}
				got := rootclass.New(graphs, pipelineVersion).
					Classify(context.Background(), k.rooting, k.record, k.route)
				if got.Kind != vuldomain.RootUnrooted {
					t.Fatalf("Kind = %q (reason %q), want unrooted", got.Kind, got.Reason)
				}
				if !strings.HasPrefix(got.Remedy, k.wantPrefix) {
					t.Fatalf("Remedy = %q, want it to begin %q", got.Remedy, k.wantPrefix)
				}
				if strings.Contains(got.Remedy, "callgraph") && strings.Contains(got.Remedy, "@local") {
					t.Errorf("Remedy = %q hands a project coordinate to a command that fetches", got.Remedy)
				}
			})
		}
	}
}
