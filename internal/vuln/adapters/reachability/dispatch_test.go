package reachability_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// fakeCallSiteReader answers from a fixture, and records what it was asked, so
// a test can assert both the annotation and the reads behind it.
type fakeCallSiteReader struct {
	answers map[string]ports.CallSiteAnswer
	fail    map[string]error
	reads   []string
	asked   map[string][]string
}

func (f *fakeCallSiteReader) ReadCallSites(
	_ context.Context, coord coordinate.ModuleCoordinate, fromIDs []string,
) (ports.CallSiteAnswer, error) {
	key := coord.String()
	f.reads = append(f.reads, key)
	if f.asked == nil {
		f.asked = map[string][]string{}
	}
	f.asked[key] = append(f.asked[key], fromIDs...)
	if err := f.fail[key]; err != nil {
		return ports.CallSiteAnswer{}, err
	}
	return f.answers[key], nil
}

// theRoute is the shape the ticket is about, reproduced from a real store: a
// project's own code, two hops inside a dependency, an interface dispatch into a
// second dependency, and a final hop into the standard library — which is a
// module the call-graph stage does not analyse at all.
//
// The module is spelt example.com/mod rather than the measured project's path,
// because a fixture is not the measurement.
func theRoute() domain.ReachabilityRoute {
	return domain.ReachabilityRoute{
		{ModulePath: "example.com/mod", Package: "example.com/mod/internal/backup", Symbol: "Start"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/auto", Receiver: "*Uploader", Symbol: "upload"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/aws", Receiver: "*S3Client", Symbol: "CurrentID"},
		{ModulePath: "stdlib", ModuleVersion: "v1.26.5", Package: "net/http", Receiver: "*Client", Symbol: "Get"},
	}
}

func recordWithRoute(route domain.ReachabilityRoute) *domain.VulnerabilityRecord {
	coord, err := coordinate.NewModuleCoordinate("example.com/dep", "v1.2.3")
	if err != nil {
		panic(err)
	}
	root, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		panic(err)
	}
	return &domain.VulnerabilityRecord{
		Coordinate: coord,
		Rooting:    domain.TargetRootedAt(root),
		Findings: []domain.VulnerabilityFinding{{
			ID: "GO-2026-5026",
			Reachable: &domain.ReachabilityResult{
				IsReachable: true,
				Confidence:  domain.ConfidenceHigh,
				Routes:      []domain.ReachabilityRoute{route},
			},
		}},
	}
}

// depAnswer is the served graph of example.com/dep: it records the direct call
// inside the module and the interface dispatch out of it, and names both
// callers.
func depAnswer() ports.CallSiteAnswer {
	return ports.CallSiteAnswer{
		Served:       true,
		Completeness: "BUILT_WITH_BODIES",
		KnownCallers: map[string]bool{
			"example.com/dep/auto.(*Uploader).upload":   true,
			"example.com/dep/aws.(*S3Client).CurrentID": true,
		},
		Edges: map[ports.CallSiteKey]ports.CallSiteFact{
			{
				FromID: "example.com/dep/auto.(*Uploader).upload",
				ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
			}: {
				Confidence:           "CHA-overapprox",
				CallSiteFile:         "auto/uploader.go",
				CallSiteLine:         167,
				InterfaceID:          "example.com/dep/auto.StorageClient",
				Implementers:         4,
				ImplementationModule: "example.com/dep",
			},
		},
	}
}

// TestAnnotateRecord_AnnotatesWhatItCanAndSaysWhyForTheRest is the shape of the
// acceptance figure on one route: one entry point, one interface dispatch read
// off the edge, and two hops the graph cannot corroborate — each with the reason
// it could not, and neither of them a direct call.
func TestAnnotateRecord_AnnotatesWhatItCanAndSaysWhyForTheRest(t *testing.T) {
	t.Parallel()

	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{
		"example.com/dep@v1.2.3": depAnswer(),
	}}
	record := recordWithRoute(theRoute())
	tally := reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), record)

	route := record.Findings[0].Reachable.Routes[0]
	if got := route[0].Dispatch.Kind; got != domain.DispatchRouteEntry {
		t.Errorf("the entry point is annotated %q, want the route-entry kind", got)
	}
	// The hop into the dependency: the call site is in the project's own module,
	// which this store holds no graph for.
	if got := route[1].Dispatch.Kind; got != domain.DispatchNotAnnotated {
		t.Errorf("the hop out of the unanalysed root is annotated %q, want not-annotated", got)
	}
	if reason := route[1].Dispatch.Reason; !strings.Contains(reason, "no call graph is held for example.com/mod@local") {
		t.Errorf("the reason is %q, which does not name the module whose graph is missing", reason)
	}
	// The interface dispatch, read off the edge.
	iface := route[2].Dispatch
	if iface.Kind != domain.DispatchInterface {
		t.Fatalf("the interface hop is annotated %q, want interface", iface.Kind)
	}
	if iface.Confidence != "CHA-overapprox" {
		t.Errorf("the edge's own confidence is reported as %q", iface.Confidence)
	}
	if iface.Interface != "example.com/dep/auto.StorageClient" {
		t.Errorf("the interface crossed is reported as %q", iface.Interface)
	}
	if iface.Implementers != 4 {
		t.Errorf("the implementer count is %d, want 4", iface.Implementers)
	}
	if iface.ImplementationModule != "example.com/dep" {
		t.Errorf("the module supplying the implementation is %q", iface.ImplementationModule)
	}
	if !strings.Contains(iface.ImplementersQuery, "implementers") {
		t.Errorf("the interface hop points at no implementers query: %q", iface.ImplementersQuery)
	}
	if iface.CallSite != "auto/uploader.go:167" {
		t.Errorf("the call site is %q", iface.CallSite)
	}
	if iface.GraphCompleteness != "BUILT_WITH_BODIES" {
		t.Errorf("the graph's completeness is %q", iface.GraphCompleteness)
	}
	// The standard-library hop: the call site is in the dependency, whose graph IS
	// held and records no such edge.
	if got := route[3].Dispatch.Kind; got != domain.DispatchNotAnnotated {
		t.Errorf("the stdlib hop is annotated %q, want not-annotated", got)
	}
	if reason := route[3].Dispatch.Reason; !strings.Contains(reason, "records no edge from it to") {
		t.Errorf("the reason is %q, which does not distinguish a missing edge from a missing graph", reason)
	}

	if tally.Hops != 4 {
		t.Errorf("the tally counts %d hops, want 4", tally.Hops)
	}
	if got := tally.Annotated(); got != 1 {
		t.Errorf("the tally reports %d annotated hops, want 1", got)
	}
	if tally.ByKind[domain.DispatchNotAnnotated] != 2 {
		t.Errorf("the tally reports %d unannotated hops, want 2: %v", tally.ByKind[domain.DispatchNotAnnotated], tally.ByKind)
	}
}

// TestAnnotateRecord_NeverRendersAnUnannotatedHopAsADirectCall is the named
// failure, asserted from a route the call graph cannot corroborate at any hop.
//
// It checks every route the record carries, on every path out of the annotator:
// no graph at all, a graph that does not name the caller, a graph that names the
// caller and holds no edge, and a store that could not be read. None of them may
// produce the direct kind, and every one of them must say why.
func TestAnnotateRecord_NeverRendersAnUnannotatedHopAsADirectCall(t *testing.T) {
	t.Parallel()

	reader := &fakeCallSiteReader{
		answers: map[string]ports.CallSiteAnswer{
			// Held, and it names neither caller.
			"example.com/dep@v1.2.3": {Served: true, Completeness: "TYPE_ONLY", KnownCallers: map[string]bool{}},
		},
		fail: map[string]error{
			"example.com/broken@v9.9.9": errors.New("stored hash does not describe its contents"),
		},
	}
	route := theRoute()
	route = append(route, domain.ReachabilityFrame{
		ModulePath: "example.com/broken", ModuleVersion: "v9.9.9",
		Package: "example.com/broken/pkg", Symbol: "Sink",
	})
	// A hop naming no version and not the analysed root, followed by the hop it
	// calls: that second hop's call site cannot be placed in any one module's
	// graph, because the module holding it is not identified.
	route = append(route, domain.ReachabilityFrame{
		ModulePath: "example.com/other", Package: "example.com/other/pkg", Symbol: "Middle",
	})
	route = append(route, domain.ReachabilityFrame{
		ModulePath: "example.com/other", ModuleVersion: "v0.1.0", Package: "example.com/other/pkg", Symbol: "End",
	})
	record := recordWithRoute(route)
	tally := reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), record)

	for i, hop := range record.Findings[0].Reachable.Routes[0] {
		d := hop.Dispatch
		if d.Kind == domain.DispatchDirect {
			t.Errorf("hop %d is reported as a direct call by a graph that recorded no edge for it", i)
		}
		if !d.IsRecorded() {
			t.Errorf("hop %d carries no annotation at all, so a reader cannot tell it from a hop the annotation never ran on", i)
		}
		if d.Kind == domain.DispatchNotAnnotated && d.Reason == "" {
			t.Errorf("hop %d is unannotated and states no reason", i)
		}
	}
	if got := tally.Annotated(); got != 0 {
		t.Errorf("%d hops were counted as annotated over a graph that corroborates none of them", got)
	}
	if got := record.Findings[0].Reachable.Routes[0][5].Dispatch.Reason; !strings.Contains(got, "could not be read") {
		t.Errorf("a store read failure is reported as %q, which does not distinguish it from a module with no graph", got)
	}
	if got := record.Findings[0].Reachable.Routes[0][6].Dispatch.Reason; !strings.Contains(got, "names no module version") {
		t.Errorf("an unplaceable call site is reported as %q", got)
	}
	if got := record.Findings[0].Reachable.Routes[0][2].Dispatch.Reason; !strings.Contains(got, "does not name") {
		t.Errorf("a caller the graph does not name is reported as %q", got)
	}
}

// TestAnnotateRecord_LeavesTheHopSequenceByteIdentical asserts the route is
// enriched and never edited: same routes, same hops, same order, and every
// identity field unchanged.
//
// It is asserted on the serialised hops rather than on a count, because a count
// survives a swap and a reorder is exactly what a reader would never see.
func TestAnnotateRecord_LeavesTheHopSequenceByteIdentical(t *testing.T) {
	t.Parallel()

	before, err := json.Marshal(theRoute())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{
		"example.com/dep@v1.2.3": depAnswer(),
	}}
	record := recordWithRoute(theRoute())
	reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), record)

	routes := record.Findings[0].Reachable.Routes
	if len(routes) != 1 {
		t.Fatalf("the record carries %d routes, want the 1 it was given", len(routes))
	}
	stripped := make(domain.ReachabilityRoute, 0, len(routes[0]))
	for _, hop := range routes[0] {
		hop.Dispatch = domain.HopDispatch{}
		stripped = append(stripped, hop)
	}
	after, err := json.Marshal(stripped)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("the hop sequence changed under annotation:\nbefore %s\nafter  %s", before, after)
	}
}

// TestAnnotateRecord_ServesEachModuleOnce pins the memo. Serving a graph is a
// blob decode and an edge reconstruction, and a walk's records share their
// routes, so reading once per record instead of once per run is the difference
// between an annotation and a friction bug.
func TestAnnotateRecord_ServesEachModuleOnce(t *testing.T) {
	t.Parallel()

	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{
		"example.com/dep@v1.2.3": depAnswer(),
	}}
	annotator := reachability.NewDispatchAnnotator(reader, nil)
	for range 5 {
		annotator.AnnotateRecord(t.Context(), recordWithRoute(theRoute()))
	}
	reads := map[string]int{}
	for _, r := range reader.reads {
		reads[r]++
	}
	if reads["example.com/dep@v1.2.3"] != 1 {
		t.Errorf("the dependency's graph was served %d times over 5 records, want 1", reads["example.com/dep@v1.2.3"])
	}
	if reads["example.com/mod@local"] != 1 {
		t.Errorf("the unanalysed root was asked for %d times over 5 records, want 1 — an absence is memoised too",
			reads["example.com/mod@local"])
	}
	if reads["stdlib@v1.26.5"] != 0 {
		t.Errorf("the standard library was read %d times, and it is a callee on this route and never a caller",
			reads["stdlib@v1.26.5"])
	}
}

// TestAnnotateRecord_ReReadsAModuleForACallerItNeverAsked checks the memo does
// not answer a question it was never asked. A later record naming a caller the
// held answer did not cover must re-read, or the site is reported absent from a
// query that never looked for it.
func TestAnnotateRecord_ReReadsAModuleForACallerItNeverAsked(t *testing.T) {
	t.Parallel()

	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{
		"example.com/dep@v1.2.3": depAnswer(),
	}}
	annotator := reachability.NewDispatchAnnotator(reader, nil)
	annotator.AnnotateRecord(t.Context(), recordWithRoute(theRoute()))

	other := domain.ReachabilityRoute{
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/other", Symbol: "Elsewhere"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/other", Symbol: "Callee"},
	}
	annotator.AnnotateRecord(t.Context(), recordWithRoute(other))

	reads := 0
	for _, r := range reader.reads {
		if r == "example.com/dep@v1.2.3" {
			reads++
		}
	}
	if reads != 2 {
		t.Errorf("the dependency was served %d times, want 2 — a caller the first read never covered must be asked for", reads)
	}
	second := reader.asked["example.com/dep@v1.2.3"]
	if !containsAll(second, "example.com/dep/auto.(*Uploader).upload", "example.com/dep/other.Elsewhere") {
		t.Errorf("the re-read asked for %v, which does not carry both the old callers and the new one", second)
	}
}

func containsAll(list []string, want ...string) bool {
	seen := map[string]bool{}
	for _, s := range list {
		seen[s] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

// TestAnnotateRecord_HandlesTheAbsences checks the annotator is safe to call
// where there is nothing to do: a nil annotator, a nil record, a record with no
// findings, and a finding with no reachability answer.
func TestAnnotateRecord_HandlesTheAbsences(t *testing.T) {
	t.Parallel()

	var nilAnnotator *reachability.DispatchAnnotator
	if got := nilAnnotator.AnnotateRecord(t.Context(), recordWithRoute(theRoute())); got.Hops != 0 {
		t.Errorf("a nil annotator reported %d hops", got.Hops)
	}
	annotator := reachability.NewDispatchAnnotator(&fakeCallSiteReader{}, nil)
	if got := annotator.AnnotateRecord(t.Context(), nil); got.Hops != 0 {
		t.Errorf("a nil record reported %d hops", got.Hops)
	}
	if got := annotator.AnnotateRecord(t.Context(), &domain.VulnerabilityRecord{}); got.Hops != 0 {
		t.Errorf("an empty record reported %d hops", got.Hops)
	}
	routeless := &domain.VulnerabilityRecord{Findings: []domain.VulnerabilityFinding{
		{ID: "GO-0000-0000"},
		{ID: "GO-0000-0001", Reachable: &domain.ReachabilityResult{}},
	}}
	if got := annotator.AnnotateRecord(t.Context(), routeless); got.Hops != 0 {
		t.Errorf("a record with no routes reported %d hops", got.Hops)
	}
}

// TestAnnotateRecord_AnInterfaceHopTheGraphCannotAttributeSaysSo covers the
// measured cross-module case: the edge records an interface dispatch, and the
// implementation relation of the module holding the call site covers only its
// own declarations, so the interface crossed is not recoverable. The dispatch is
// still stated; the interface is not invented.
func TestAnnotateRecord_AnInterfaceHopTheGraphCannotAttributeSaysSo(t *testing.T) {
	t.Parallel()

	answer := depAnswer()
	fact := answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
	}]
	fact.InterfaceID = ""
	fact.Implementers = 0
	answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
	}] = fact

	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{"example.com/dep@v1.2.3": answer}}
	record := recordWithRoute(theRoute())
	reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), record)

	hop := record.Findings[0].Reachable.Routes[0][2].Dispatch
	if hop.Kind != domain.DispatchInterface {
		t.Errorf("the hop is annotated %q, want interface — the edge said so", hop.Kind)
	}
	if hop.Interface != "" {
		t.Errorf("an interface was named as %q where the graph attributes none", hop.Interface)
	}
	if !strings.Contains(hop.Reason, "not recoverable") {
		t.Errorf("the unattributed interface is explained as %q", hop.Reason)
	}
	if hop.ImplementersQuery != "" {
		t.Errorf("a query was offered for an interface that was never named: %q", hop.ImplementersQuery)
	}
}

// TestAnnotateRecord_DirectCallStatesNoImplementationModule checks the
// annotation answers only the question its hop raises: a caller that named its
// callee raises no question about which module supplied an implementation.
func TestAnnotateRecord_DirectCallStatesNoImplementationModule(t *testing.T) {
	t.Parallel()

	answer := ports.CallSiteAnswer{
		Served:       true,
		Completeness: "BUILT_WITH_BODIES",
		KnownCallers: map[string]bool{"example.com/dep/auto.(*Uploader).upload": true},
		Edges: map[ports.CallSiteKey]ports.CallSiteFact{
			{
				FromID: "example.com/dep/auto.(*Uploader).upload",
				ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
			}: {Confidence: "Direct", ImplementationModule: "example.com/dep", CallSiteFile: "auto/uploader.go", CallSiteLine: 167},
		},
	}
	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{"example.com/dep@v1.2.3": answer}}
	record := recordWithRoute(theRoute())
	reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), record)

	hop := record.Findings[0].Reachable.Routes[0][2].Dispatch
	if hop.Kind != domain.DispatchDirect {
		t.Fatalf("the hop is annotated %q, want direct", hop.Kind)
	}
	if hop.ImplementationModule != "" {
		t.Errorf("a direct call names an implementation module %q", hop.ImplementationModule)
	}
	if hop.CallSite != "auto/uploader.go:167" {
		t.Errorf("the call site is %q", hop.CallSite)
	}
}

// TestImplementersQuery renders the remedy a counted interface points at, and
// nothing at all for an interface that was never named.
func TestImplementersQuery(t *testing.T) {
	t.Parallel()

	if got := reachability.ImplementersQuery(""); got != "" {
		t.Errorf("a query was offered for no interface: %q", got)
	}
	got := reachability.ImplementersQuery("example.com/mod/auto.StorageClient")
	if got != "kanonarion implementers 'example.com/mod/auto.StorageClient'" {
		t.Errorf("ImplementersQuery = %q", got)
	}
	if strings.Contains(reachability.ImplementersQuery("weird'id"), "'weird'id'") {
		t.Errorf("a quote in an interface id reached the rendered command unescaped")
	}
}

// TestAnnotateRecord_PlacesVersionlessHopsInTheAnalysedRoot pins where a hop
// that names no version is looked up.
//
// A main module has no version in a Go build, so a versionless frame is the
// analysed root and only the analysed root. An isolated record names that root
// with its own coordinate; a target-rooted one names it in the frame, and reading
// the coordinate there would place the target's frames in the wrong graph.
func TestAnnotateRecord_PlacesVersionlessHopsInTheAnalysedRoot(t *testing.T) {
	t.Parallel()

	isolatedCoord := coordinatetest.MustNew("example.com/dep", "v1.2.3")
	isolated := &domain.VulnerabilityRecord{
		Coordinate: isolatedCoord,
		Rooting:    domain.RootingIsolated,
		Findings: []domain.VulnerabilityFinding{{
			ID: "GO-0000-0001",
			Reachable: &domain.ReachabilityResult{Routes: []domain.ReachabilityRoute{{
				{ModulePath: "example.com/dep", Package: "example.com/dep/auto", Symbol: "Entry"},
				{ModulePath: "example.com/dep", Package: "example.com/dep/auto", Symbol: "Next"},
			}}},
		}},
	}
	reader := &fakeCallSiteReader{}
	reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), isolated)
	if len(reader.reads) != 1 || reader.reads[0] != "example.com/dep@v1.2.3" {
		t.Errorf("an isolated record's versionless hops were looked up in %v, want the record's own coordinate", reader.reads)
	}

	// A frame naming no module at all, and one whose version is not a version:
	// neither can be placed, and neither is guessed at.
	unplaceable := &domain.VulnerabilityRecord{
		Coordinate: isolatedCoord,
		Rooting:    domain.Rooting("target-rooted:not a coordinate"),
		Findings: []domain.VulnerabilityFinding{{
			ID: "GO-0000-0002",
			Reachable: &domain.ReachabilityResult{Routes: []domain.ReachabilityRoute{{
				{Package: "example.com/dep/auto", Symbol: "Nameless"},
				{ModulePath: "example.com/dep", ModuleVersion: "not-a-version", Package: "example.com/dep/auto", Symbol: "Odd"},
				{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/auto", Symbol: "End"},
			}}},
		}},
	}
	second := &fakeCallSiteReader{}
	reachability.NewDispatchAnnotator(second, nil).AnnotateRecord(t.Context(), unplaceable)
	route := unplaceable.Findings[0].Reachable.Routes[0]
	if got := route[1].Dispatch.Kind; got != domain.DispatchNotAnnotated {
		t.Errorf("a hop above which no module is named is annotated %q", got)
	}
	if got := route[2].Dispatch.Kind; got != domain.DispatchNotAnnotated {
		t.Errorf("a hop above which the version is not a version is annotated %q", got)
	}
	// The unparsable frame fell back to the record's own coordinate, which is what
	// the malformed-version hop is NOT looked up under.
	for _, r := range second.reads {
		if r == "example.com/dep@not-a-version" {
			t.Errorf("a malformed version was carried into a coordinate lookup: %v", second.reads)
		}
	}
}

// TestAnnotateRecord_RendersACallSiteWithoutALine covers the edge whose position
// the graph recorded partially, or not at all. A missing line must not render as
// ":0", which reads as the top of the file.
func TestAnnotateRecord_RendersACallSiteWithoutALine(t *testing.T) {
	t.Parallel()

	answer := ports.CallSiteAnswer{
		Served:       true,
		KnownCallers: map[string]bool{"example.com/dep/auto.(*Uploader).upload": true},
		Edges: map[ports.CallSiteKey]ports.CallSiteFact{
			{
				FromID: "example.com/dep/auto.(*Uploader).upload",
				ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
			}: {Confidence: "Direct", CallSiteFile: "auto/uploader.go"},
		},
	}
	reader := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{"example.com/dep@v1.2.3": answer}}
	record := recordWithRoute(theRoute())
	reachability.NewDispatchAnnotator(reader, nil).AnnotateRecord(t.Context(), record)
	if got := record.Findings[0].Reachable.Routes[0][2].Dispatch.CallSite; got != "auto/uploader.go" {
		t.Errorf("an edge with a file and no line renders its call site as %q", got)
	}

	delete(answer.Edges, ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
	})
	answer.Edges[ports.CallSiteKey{
		FromID: "example.com/dep/auto.(*Uploader).upload",
		ToID:   "example.com/dep/aws.(*S3Client).CurrentID",
	}] = ports.CallSiteFact{Confidence: "Direct"}
	positionless := &fakeCallSiteReader{answers: map[string]ports.CallSiteAnswer{"example.com/dep@v1.2.3": answer}}
	other := recordWithRoute(theRoute())
	reachability.NewDispatchAnnotator(positionless, nil).AnnotateRecord(t.Context(), other)
	if got := other.Findings[0].Reachable.Routes[0][2].Dispatch.CallSite; got != "" {
		t.Errorf("an edge with no position renders its call site as %q", got)
	}
}
