package domain_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
)

// hostStdlibIdentity is the identity of hostStdlibOutcome as the build before
// the TinyGo split computed it. A host walk's stdlib node must keep it.
const hostStdlibIdentity = "sha256:ea803c305c1a1a75ff9fd2856703ccc6d0e69724550387a5d684a68142498571"

func hostStdlibOutcome(t *testing.T) domain3.WalkOutcome {
	t.Helper()
	outcome := buildOutcome(t)
	std, ok := domain3.StdlibNode("go1.27.2")
	if !ok {
		t.Fatal("StdlibNode refused go1.27.2")
	}
	outcome.Graph.Nodes = append(outcome.Graph.Nodes, std)
	outcome.Graph.Edges = append(outcome.Graph.Edges, domain3.GraphEdge{From: outcome.Graph.Target, To: std.Coordinate})
	outcome.Graph.BuildEnv = domain3.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.27.2"}
	outcome.Graph.Sort()
	return outcome
}

func tinyGoFacts() domain3.TinyGoFacts {
	return domain3.TinyGoFacts{Target: "wasip1", Packages: []string{"os", "runtime", "sync"},
		Mixed: map[string][]string{"sync": {"once.go"}}}
}

func TestWalkIdentity_AHostWalkHashesAsBeforeTheSplit(t *testing.T) {
	outcome := hostStdlibOutcome(t)
	if got := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", outcome); got != hostStdlibIdentity {
		t.Errorf("a host walk changed identity: %s, want %s", got, hostStdlibIdentity)
	}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	data, err := domain3.WalkRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{`"packages"`, `"tinygo"`} {
		if bytes.Contains(data, []byte(key)) {
			t.Errorf("a host walk marshals the %s key:\n%s", key, data)
		}
	}
}

func tinyGoOutcome(t *testing.T) domain3.WalkOutcome {
	t.Helper()
	outcome := hostStdlibOutcome(t)
	node, ok := domain3.TinyGoNode("0.42.0", tinyGoFacts())
	if !ok {
		t.Fatal("TinyGoNode refused 0.42.0")
	}
	outcome.Graph.Nodes = append(outcome.Graph.Nodes, node)
	for i := range outcome.Graph.Nodes {
		if outcome.Graph.Nodes[i].ResolutionSource == domain3.ResolutionStdlib {
			outcome.Graph.Nodes[i].Packages = []string{"io", "strconv"}
		}
	}
	outcome.Graph.Sort()
	return outcome
}

func roundTrip(t *testing.T, outcome domain3.WalkOutcome) domain3.WalkRecord {
	t.Helper()
	hasher := domain3.WalkRecordHasher{}
	rec := domain3.NewWalkRecord("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ci-bot", "0.2.0", domain3.WalkScopeCode, domain3.WalkDepthFull, outcome, domain3.DefaultDepthPolicy(), "")
	rec, err := hasher.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := hasher.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := hasher.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if verr := hasher.VerifyContentHash(back); verr != nil {
		t.Fatalf("VerifyContentHash after the round trip: %v", verr)
	}
	return back
}

func TestWalkRecordHasher_TinyGoSplitRoundTrips(t *testing.T) {
	p, ok := roundTrip(t, tinyGoOutcome(t)).Graph.TinyGoPartition()
	if !ok {
		t.Fatal("the TinyGo split was lost in the round trip")
	}
	want := tinyGoFacts()
	if p.Target != want.Target || !reflect.DeepEqual(p.TinyGo, want.Packages) || !reflect.DeepEqual(p.Mixed, want.Mixed) ||
		!reflect.DeepEqual(p.Go, []string{"io", "strconv"}) || p.Version != "v0.42.0" || p.Total() != 5 {
		t.Errorf("partition after round trip = %+v", p)
	}
	if !p.SuppliesTinyGo("os") || p.SuppliesTinyGo("io") || !p.SuppliesGo("strconv") || p.SuppliesGo("os") {
		t.Errorf("supplier lookups disagree with the split %+v", p)
	}
}

func TestWalkIdentity_CoversTheTinyGoSplit(t *testing.T) {
	host := identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", hostStdlibOutcome(t))
	if host == identityOf(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice", tinyGoOutcome(t)) {
		t.Error("the TinyGo node and the stdlib split are outside the identity")
	}
}

func TestTinyGoNode(t *testing.T) {
	n, ok := domain3.TinyGoNode("0.42.0", tinyGoFacts())
	if !ok {
		t.Fatal("TinyGoNode refused 0.42.0")
	}
	if n.Coordinate.String() != "github.com/tinygo-org/tinygo@v0.42.0" || n.ResolutionSource != domain3.ResolutionTinyGo ||
		n.DirectDependency || n.TinyGo == nil {
		t.Errorf("node = %+v", n)
	}
	if v, _ := domain3.TinyGoNode("v0.42.0", tinyGoFacts()); v.Coordinate != n.Coordinate {
		t.Errorf("a v-prefixed release named %s, want %s", v.Coordinate, n.Coordinate)
	}
	for _, bad := range []string{"", "  ", "not a version"} {
		if _, ok := domain3.TinyGoNode(bad, tinyGoFacts()); ok {
			t.Errorf("TinyGoNode(%q) built a node", bad)
		}
	}
}

func TestTinyGoPartition_AbsentOnAHostWalk(t *testing.T) {
	if _, ok := hostStdlibOutcome(t).Graph.TinyGoPartition(); ok {
		t.Error("a host walk reports a TinyGo split")
	}
}

func TestTinyGoNode_IsToolchainProvided(t *testing.T) {
	if domain3.ResolutionTinyGo.HasFetchedArtefact() {
		t.Error("the TinyGo node owes a fetched artefact")
	}
	if noun := domain3.ResolutionTinyGo.ArtefactAbsenceNoun(); noun != "TinyGo toolchain" {
		t.Errorf("absence noun = %q", noun)
	}
	n, _ := domain3.TinyGoNode("0.42.0", tinyGoFacts())
	g := domain3.Graph{Nodes: []domain3.GraphNode{n}}
	if _, selected := g.SelectedVersions()[n.Coordinate]; selected {
		t.Error("the TinyGo node is a version the scan cache must resolve")
	}
	dep, err := coordinate.NewModuleCoordinate(domain3.TinyGoModulePath, "v0.42.0")
	if err != nil {
		t.Fatal(err)
	}
	rec := domain3.WalkRecord{Graph: domain3.Graph{Nodes: []domain3.GraphNode{n}}}
	if _, named := domain3.NamedVersions(rec)[dep.Path()]; named {
		t.Error("the TinyGo node reads as a require line of the manifest")
	}
}
