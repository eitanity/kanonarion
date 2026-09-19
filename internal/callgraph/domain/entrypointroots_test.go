package domain_test

import (
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// appCandidates is one module's nodes: a command's main, a package initialiser,
// an exported API function, an http.Handler method, an unexported helper that
// nothing outside the module can name, a test declaration, the main the go
// command synthesises for a test binary, and a node from another module.
func appCandidates() []domain.RootCandidate {
	return []domain.RootCandidate{
		{ID: "main", Package: "example.com/mod/cmd/tool", Symbol: "main"},
		{ID: "init", Package: "example.com/mod", Symbol: "init"},
		{ID: "api", Package: "example.com/mod", Symbol: "Serve", IsExportedAPI: true},
		{ID: "handler", Package: "example.com/mod", Symbol: "ServeHTTP", Receiver: "*H"},
		{ID: "helper", Package: "example.com/mod", Symbol: "helper"},
		{ID: "testfunc", Package: "example.com/mod", Symbol: "TestThing", IsExportedAPI: true, IsTest: true},
		{ID: "testmain", Package: "example.com/mod.test", Symbol: "main"},
		{ID: "external", Package: "other.example/dep", Symbol: "Exported", IsExportedAPI: true, IsExternal: true},
	}
}

// TestSelectEntryPointRoots_IsNarrowerThanTheWholeGraph is the ceiling this
// selector exists to lift. The whole-graph rule roots an application at every
// function it owns, so a vulnerable symbol is itself a root and no absence can
// ever be certified over it. The entry-point rule roots only at what can be
// entered from outside, which leaves the helper unrooted — and a search for the
// helper can therefore come back empty.
func TestSelectEntryPointRoots_IsNarrowerThanTheWholeGraph(t *testing.T) {
	candidates := appCandidates()

	whole := domain.SelectReachabilityRoots(candidates, domain.ArtifactApplication, domain.RootScopeProduction)
	entry := domain.SelectEntryPointRoots(candidates, domain.RootScopeProduction)

	if !slices.Contains(whole, "helper") {
		t.Fatal("the whole-graph rule stopped rooting at every owned node; this test no longer measures the ceiling")
	}
	if slices.Contains(entry, "helper") {
		t.Error("an unexported helper nothing enters is an entry-point root, so a negative about it can still never be confirmed")
	}
	if len(entry) >= len(whole) {
		t.Errorf("entry-point roots (%d) are not narrower than whole-graph roots (%d)", len(entry), len(whole))
	}
}

// TestSelectEntryPointRoots_KeepsEveryWayIn pins the generosity. Every root here
// can only turn a confirmed absence back into a found path, so a missing one is
// a false negative — the failure direction that matters.
func TestSelectEntryPointRoots_KeepsEveryWayIn(t *testing.T) {
	got := domain.SelectEntryPointRoots(appCandidates(), domain.RootScopeProduction)

	for _, want := range []string{"main", "init", "api", "handler"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q is a way into the module and is not a root: %v", want, got)
		}
	}
	if slices.Contains(got, "external") {
		t.Error("a node from another module is a root; the traversal would start outside the analysed code")
	}
	if !slices.IsSorted(got) {
		t.Errorf("roots are not sorted, so two runs can disagree: %v", got)
	}
}

// TestSelectEntryPointRoots_ExcludesSyntheticTestMains is the hygiene item,
// asserted on its own because it is not the fix. The go command writes this main
// to run a test binary; no source declares it, no consumer ships it, and it is
// not covered by the IsTest axis — so a production-scope selection keeps it
// unless it is excluded by name.
func TestSelectEntryPointRoots_ExcludesSyntheticTestMains(t *testing.T) {
	candidates := appCandidates()

	for _, scope := range []domain.RootScope{domain.RootScopeProduction, domain.RootScopeWithTests} {
		got := domain.SelectEntryPointRoots(candidates, scope)
		if slices.Contains(got, "testmain") {
			t.Errorf("scope %v roots at the synthesised test main", scope)
		}
	}

	// The control: the exclusion is by identity, not by the test axis, because the
	// axis does not cover it. Measured on kanonarion's own graph: 138 of its 140
	// main nodes are synthesised test mains and every one carries IsTest false.
	for _, c := range candidates {
		if c.ID == "testmain" && c.IsTest {
			t.Fatal("the fixture marks the synthesised main as a test declaration; it does not in a real graph")
		}
	}
	if !domain.IsSyntheticTestMain("example.com/mod.test", "main", "") {
		t.Error("the synthesised test main is not recognised")
	}
	if domain.IsSyntheticTestMain("example.com/mod/cmd/tool", "main", "") {
		t.Error("a real command's main is recognised as a synthesised one")
	}
}

// TestSelectEntryPointRoots_TestScopeIsSeparateFromTheSyntheticMain keeps the two
// exclusions apart: a test DECLARATION is code somebody wrote and an answer may
// name it, so the scope decides; the synthesised main is excluded either way.
func TestSelectEntryPointRoots_TestScopeIsSeparateFromTheSyntheticMain(t *testing.T) {
	candidates := appCandidates()

	production := domain.SelectEntryPointRoots(candidates, domain.RootScopeProduction)
	withTests := domain.SelectEntryPointRoots(candidates, domain.RootScopeWithTests)

	if slices.Contains(production, "testfunc") {
		t.Error("a consumer compiles no _test.go file of a dependency, so a test declaration must not root the production question")
	}
	if !slices.Contains(withTests, "testfunc") {
		t.Error("the with-tests scope dropped a test declaration, which is the scope that exists to keep it")
	}
}

// TestSelectEntryPointRoots_NoEntryPointsIsAnAnswer pins the absence of a
// fallback. SelectReachabilityRoots falls back to every owned node when nothing
// qualifies, so the traversal still reasons about something; here that would
// hand a caller the whole graph under the name "entry points" and let an absence
// be certified against roots nothing established are entered.
func TestSelectEntryPointRoots_NoEntryPointsIsAnAnswer(t *testing.T) {
	unreachable := []domain.RootCandidate{
		{ID: "helper", Package: "example.com/mod", Symbol: "helper"},
		{ID: "other", Package: "example.com/mod", Symbol: "another"},
	}

	if got := domain.SelectEntryPointRoots(unreachable, domain.RootScopeProduction); len(got) != 0 {
		t.Errorf("a graph naming no entry point produced roots: %v", got)
	}
	// The control: the whole-graph rule DOES fall back, and that difference is the
	// point of having two selectors.
	if got := domain.SelectReachabilityRoots(unreachable, domain.ArtifactLibrary, domain.RootScopeProduction); len(got) == 0 {
		t.Error("the whole-graph rule stopped falling back to every owned node")
	}
}

// TestArtifactKindString_NamesTheZeroValue: the library kind's stored form is
// the empty string, so every surface rendering the raw field published a
// measured library as a blank. It is a FINDING — every package loaded and none
// builds a command — and must never render as an absence.
func TestArtifactKindString_NamesTheZeroValue(t *testing.T) {
	for kind, want := range map[domain.ArtifactKind]string{
		domain.ArtifactLibrary:        "Library",
		domain.ArtifactApplication:    "Application",
		domain.ArtifactNotEstablished: "NotEstablished",
		// A value this build does not know is rendered as it stands; inventing a
		// name for it would hide the disagreement.
		domain.ArtifactKind("Plugin"): "Plugin",
	} {
		if got := kind.String(); got != want {
			t.Errorf("ArtifactKind(%q).String() = %q, want %q", string(kind), got, want)
		}
	}
}
