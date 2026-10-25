package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

var errInjected = errors.New("injected failure")

// failMarshalAfter makes canonicalMarshal fail from call n+1 on.
func failMarshalAfter(t *testing.T, n int) {
	t.Helper()
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	calls := 0
	canonicalMarshal = func(v any) ([]byte, error) {
		calls++
		if calls > n {
			return nil, errInjected
		}
		return original(v)
	}
}

// failEdgeEncoding makes every edge chunk fail to encode.
func failEdgeEncoding(t *testing.T) {
	t.Helper()
	original := encodeEdgeChunk
	t.Cleanup(func() { encodeEdgeChunk = original })
	encodeEdgeChunk = func(*json.Encoder, []canonicalEdge) error { return errInjected }
}

func TestHasher_EdgeEncodingFailureIsReported(t *testing.T) {
	failEdgeEncoding(t)
	r := CallGraphRecord{Edges: []CallEdge{{FromID: "a", ToID: "b"}}}
	if _, err := hashCanonical(r); !errors.Is(err, errInjected) {
		t.Errorf("hashCanonical: %v", err)
	}
	if _, err := (CallGraphRecordHasher{}).StoredDigest([]byte(`{"edges":[]}`), r.Edges); !errors.Is(err, errInjected) {
		t.Errorf("StoredDigest: %v", err)
	}
	if _, err := graphClaimDigest(r, []string{edgesFieldName}); !errors.Is(err, errInjected) {
		t.Errorf("graphClaimDigest: %v", err)
	}
}

func TestMarshalCanonical_WrapsTheMarshalFailure(t *testing.T) {
	failMarshalAfter(t, 0)
	if _, err := marshalCanonical(CallGraphRecord{}); !errors.Is(err, errInjected) {
		t.Errorf("marshalCanonical: %v", err)
	}
}

func TestDomainRequires_ReadsEachDirective(t *testing.T) {
	got := domainRequires([]canonicalRequire{{Path: "a", Version: "v1"}})
	if len(got) != 1 || got[0] != (SynthesisedRequire{Path: "a", Version: "v1"}) {
		t.Errorf("domainRequires = %v", got)
	}
}

func TestGraphClaimDigest_UnreadableShellIsReported(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	canonicalMarshal = func(any) ([]byte, error) { return []byte(`[]`), nil }
	if _, err := graphClaimDigest(CallGraphRecord{}, nil); err == nil {
		t.Error("graphClaimDigest read a shell that is not an object")
	}
}

func TestCanonicalFields_GuardsTheDecoder(t *testing.T) {
	if err := canonicalFields([]byte(`{1:2}`), func(string, []byte) {}); err == nil {
		t.Error("a non-string member name was read")
	}

	key := canonicalKey
	t.Cleanup(func() { canonicalKey = key })
	canonicalKey = func(*json.Decoder) (json.Token, error) { return json.Delim('['), nil }
	if err := canonicalFields([]byte(`{"a":1}`), func(string, []byte) {}); err == nil || !strings.Contains(err.Error(), "want a string") {
		t.Errorf("non-string key: %v", err)
	}
	canonicalKey = key

	end := canonicalValueEnd
	t.Cleanup(func() { canonicalValueEnd = end })
	canonicalValueEnd = func(*json.Decoder) int64 { return 1 << 20 }
	if err := canonicalFields([]byte(`{"a":1}`), func(string, []byte) {}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Errorf("out-of-range value: %v", err)
	}
}

// The field names read, then the claim digest failing, is still no agreement.
func TestGraphComparisons_ClaimDigestFailureIsNotAgreement(t *testing.T) {
	records := []CallGraphRecord{
		{ContentHash: "sha256:a", Completeness: CompletenessBuiltWithBodies, Toolchain: "go1.26.1"},
		{ContentHash: "sha256:b", Completeness: CompletenessBuiltWithBodies, Toolchain: "go1.27.1"},
	}
	t.Run("graph disagreement", func(t *testing.T) {
		failMarshalAfter(t, len(records))
		if c := graphDisagreement(records); c == nil || !strings.Contains(c.Values[0], "unmeasurable") {
			t.Errorf("graphDisagreement = %+v", c)
		}
	})
	t.Run("toolchain, claim digest", func(t *testing.T) {
		failMarshalAfter(t, len(records))
		if c := toolchainExplainedGraphDifference(records); c != nil {
			t.Errorf("toolchainExplainedGraphDifference attributed an unmeasured difference: %+v", c)
		}
	})
	t.Run("toolchain, field names", func(t *testing.T) {
		failMarshalAfter(t, 0)
		if c := toolchainExplainedGraphDifference(records); c != nil {
			t.Errorf("toolchainExplainedGraphDifference read no field names and still attributed: %+v", c)
		}
	})
}

func TestAgreedAnalysisRoot_TwoRootsAgreeOnNone(t *testing.T) {
	if got := agreedAnalysisRoot([]CallGraphRecord{{AnalysisRoot: "/a"}, {}, {AnalysisRoot: "/b"}}); got != "" {
		t.Errorf("agreedAnalysisRoot = %q", got)
	}
	if got := agreedAnalysisRoot([]CallGraphRecord{{AnalysisRoot: "/a"}, {AnalysisRoot: "/a"}}); got != "/a" {
		t.Errorf("agreedAnalysisRoot = %q", got)
	}
}

func TestDescribingTheDifference_LeavesWhatItCannotValidate(t *testing.T) {
	if describingTheDifference(nil, nil) != nil {
		t.Error("a nil conflict gained a value")
	}
	one := &CallGraphConflict{ContentHashes: []string{"sha256:a"}}
	if describingTheDifference(one, nil).Difference != nil {
		t.Error("a single-hash conflict gained a difference")
	}
	two := &CallGraphConflict{ContentHashes: []string{"sha256:a", "sha256:b"}}
	if describingTheDifference(two, nil).Difference != nil {
		t.Error("generations the list does not hold were described")
	}
	records := []CallGraphRecord{{ContentHash: "sha256:a"}, {ContentHash: "sha256:b"}}
	if describingTheDifference(two, records).Difference != nil {
		t.Error("unverifiable generations were described")
	}
}

func TestReportedAsWholeDigests_TiesOrderOnTheHash(t *testing.T) {
	c := &CallGraphConflict{ContentHashes: []string{"sha256:b", "sha256:a"}, Values: []string{"v", "v"}}
	c = reportedAsWholeDigests(c, nil)
	if c.ContentHashes[0] != "sha256:a" {
		t.Errorf("ties ordered %v", c.ContentHashes)
	}
}

func TestPreferredToolchain_TheNarrowedGroupMustCompose(t *testing.T) {
	records := []CallGraphRecord{
		{Toolchain: "go1.26.1", ArtefactIdentity: "zip:a"},
		{Toolchain: "go1.26.1", ArtefactIdentity: "zip:b"},
	}
	if _, ok := preferredToolchain(records, &CallGraphConflict{Field: ConflictFieldToolchain}, "go1.26.1"); ok {
		t.Error("a preference served a group that still disagrees")
	}
}

func TestToolchainIdentity_StringAndPathElement(t *testing.T) {
	if got := (ToolchainIdentity{Version: "go1.26.1", Derived: true}).String(); got != "go1.26.1 (from the recorded stdlib path)" {
		t.Errorf("derived: %s", got)
	}
	if got := (ToolchainIdentity{Version: "go1.26.1"}).String(); got != "go1.26.1" {
		t.Errorf("recorded: %s", got)
	}
	if got := firstPathElement("encoding/json"); got != "encoding" {
		t.Errorf("firstPathElement = %s", got)
	}
}

func TestCompareFrames_EqualFramesCompareEqual(t *testing.T) {
	f := BuildFrame{GOOS: "linux", GOARCH: "amd64"}
	if compareFrames(f, f) != 0 {
		t.Error("a frame differs from itself")
	}
}

func TestCandidateVersions_DropsTheModuleItself(t *testing.T) {
	self, err := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	dep, err := coordinate.NewModuleCoordinate("example.com/d", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	got := candidateVersions(self, map[coordinate.ModuleCoordinate]struct{}{self: {}, dep: {}})
	if len(got) != 1 || got["example.com/d"] != "v1.0.0" {
		t.Errorf("candidateVersions = %v", got)
	}
}

// ---- generation diff ----

func TestGenerationDiff_EmptyAndSummary(t *testing.T) {
	if !(GenerationDiff{}).Empty() {
		t.Error("a diff of nothing is not empty")
	}
	d := GenerationDiff{Left: "L", Right: "R", Edges: CollectionDiff{
		Kind: "edge", OnlyRight: []string{"x", "y"}, Changed: []MemberChange{{ID: "z"}},
	}}
	if d.Empty() {
		t.Error("a diff with edges only on the right is empty")
	}
	if got := d.Summary(); got != "2 edges only in R, 1 edge described differently" {
		t.Errorf("Summary = %q", got)
	}
}

func TestIdentityComparators(t *testing.T) {
	edges := []CallEdge{
		{FromID: "a"}, {FromID: "b"},
	}
	if !edgeIdentityLess(edges[0], edges[1]) {
		t.Error("from")
	}
	for _, tc := range []struct{ lo, hi CallEdge }{
		{CallEdge{ToID: "a"}, CallEdge{ToID: "b"}},
		{CallEdge{CallSite: SourcePosition{File: "a"}}, CallEdge{CallSite: SourcePosition{File: "b"}}},
		{CallEdge{CallSite: SourcePosition{Line: 1}}, CallEdge{CallSite: SourcePosition{Line: 2}}},
		{CallEdge{Kind: "a"}, CallEdge{Kind: "b"}},
	} {
		if !edgeIdentityLess(tc.lo, tc.hi) || edgeIdentityLess(tc.hi, tc.lo) {
			t.Errorf("edgeIdentityLess(%+v, %+v)", tc.lo, tc.hi)
		}
	}
	if !interfaceIdentityLess(InterfaceType{ID: "a"}, InterfaceType{ID: "b"}) {
		t.Error("interface")
	}
	if !implementationIdentityLess(InterfaceImplementation{InterfaceID: "a"}, InterfaceImplementation{InterfaceID: "b"}) ||
		!implementationIdentityLess(InterfaceImplementation{TypeID: "a"}, InterfaceImplementation{TypeID: "b"}) {
		t.Error("implementation")
	}
}

// diffGenerationsPair is two sealed generations differing in every collection.
func diffGenerationsPair(t *testing.T) (CallGraphRecord, CallGraphRecord) {
	t.Helper()
	var h CallGraphRecordHasher
	left, err := h.SetContentHash(CallGraphRecord{
		Nodes:           []CallNode{{ID: "n1"}, {ID: "n2", Symbol: "s"}},
		Edges:           []CallEdge{{FromID: "n1", ToID: "n2"}},
		Interfaces:      []InterfaceType{{ID: "i1", Methods: []string{"b", "a"}}},
		Implementations: []InterfaceImplementation{{InterfaceID: "i1", TypeID: "t1", Methods: []ImplementedMethod{{Method: "b"}, {Method: "a"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := h.SetContentHash(CallGraphRecord{
		Nodes:           []CallNode{{ID: "n2", Symbol: "t"}, {ID: "n3"}},
		Edges:           []CallEdge{{FromID: "n2", ToID: "n3"}},
		Interfaces:      []InterfaceType{{ID: "i2"}},
		Implementations: []InterfaceImplementation{{InterfaceID: "i2", TypeID: "t2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return left, right
}

func TestDiffGenerations_EveryCollectionIsCompared(t *testing.T) {
	left, right := diffGenerationsPair(t)
	d, err := DiffGenerations(left, right)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Nodes.Changed) != 1 || len(d.Edges.OnlyLeft) != 1 || len(d.Interfaces.OnlyRight) != 1 || len(d.Implementations.OnlyLeft) != 1 {
		t.Errorf("diff = %+v", d)
	}
}

// Every marshal DiffGenerations makes, failing in turn, fails the diff.
func TestDiffGenerations_EveryMarshalFailureIsReported(t *testing.T) {
	left, right := diffGenerationsPair(t)
	original := canonicalMarshal
	calls := 0
	canonicalMarshal = func(v any) ([]byte, error) { calls++; return original(v) }
	if _, err := DiffGenerations(left, right); err != nil {
		t.Fatal(err)
	}
	canonicalMarshal = original
	for n := range calls {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			failMarshalAfter(t, n)
			if _, err := DiffGenerations(left, right); err == nil {
				t.Errorf("marshal %d failing went unreported", n+1)
			}
		})
	}
}

func TestDiffMembers_DescribeFailuresAreReported(t *testing.T) {
	describe := func(n CallNode) (map[string]json.RawMessage, error) {
		if n.Symbol == "bad" {
			return nil, errInjected
		}
		return describeNode(n)
	}
	bad := func(id string) CallNode { return CallNode{ID: id, Symbol: "bad"} }
	good := func(id string) CallNode { return CallNode{ID: id} }
	for _, tc := range []struct {
		name        string
		left, right []CallNode
	}{
		{"only left", []CallNode{bad("a")}, []CallNode{good("b")}},
		{"only right", []CallNode{good("b")}, []CallNode{bad("a")}},
		{"changed, left side", []CallNode{bad("a")}, []CallNode{{ID: "a", Symbol: "x"}}},
		{"changed, right side", []CallNode{{ID: "a", Symbol: "c"}}, []CallNode{bad("a")}},
		{"left tail", []CallNode{good("a"), bad("b")}, []CallNode{good("a")}},
		{"right tail", []CallNode{good("a")}, []CallNode{good("a"), bad("b")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := diffMembers("nodes", "node", tc.left, tc.right, nodeIdentityLess, CallNodeLess, describe); !errors.Is(err, errInjected) {
				t.Errorf("diffMembers: %v", err)
			}
		})
	}
}

func TestDiffMembers_ARunOfOneIdentityIsOneMember(t *testing.T) {
	left := []CallNode{{ID: "a"}, {ID: "a", Symbol: "s"}}
	d, err := diffMembers("nodes", "node", left, nil, nodeIdentityLess, CallNodeLess, describeNode)
	if err != nil || len(d.OnlyLeft) != 1 {
		t.Errorf("diffMembers = %+v, %v", d, err)
	}
}

// An order that separates two members the canonical form cannot is named, not
// read as agreement.
func TestMemberDifference_IndistinguishableMembersAreNamed(t *testing.T) {
	same := func(CallNode) (map[string]json.RawMessage, error) {
		return map[string]json.RawMessage{"id": json.RawMessage(`"a"`)}, nil
	}
	got, err := memberDifference("nodes", CallNode{ID: "a"}, CallNode{ID: "a", Symbol: "s"}, same)
	if err != nil || got.Field != "canonical form" {
		t.Errorf("memberDifference = %+v, %v", got, err)
	}
}

func TestCanonicalMember_RefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, out string }{
		{"not JSON", `x`},
		{"collection not an array", `{"nodes":1}`},
		{"two members", `{"nodes":[{},{}]}`},
		{"member not an object", `{"nodes":[1]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := canonicalMarshal
			t.Cleanup(func() { canonicalMarshal = original })
			canonicalMarshal = func(any) ([]byte, error) { return []byte(tc.out), nil }
			if _, err := canonicalMember("nodes", CallGraphRecord{}); err == nil {
				t.Errorf("canonicalMember read %s", tc.out)
			}
		})
	}
	failMarshalAfter(t, 0)
	if _, err := canonicalMember("nodes", CallGraphRecord{}); !errors.Is(err, errInjected) {
		t.Errorf("canonicalMember: %v", err)
	}
}

func TestRecordFields_RefusesWhatItCannotRead(t *testing.T) {
	original := canonicalMarshal
	t.Cleanup(func() { canonicalMarshal = original })
	canonicalMarshal = func(any) ([]byte, error) { return []byte(`x`), nil }
	if _, err := recordFields(CallGraphRecord{}); err == nil {
		t.Error("recordFields read bytes that are not JSON")
	}
}

func TestFirstDifference_EqualMembersHaveNone(t *testing.T) {
	m := map[string]json.RawMessage{"id": json.RawMessage(`"a"`)}
	if _, differs := firstDifference("a", m, m); differs {
		t.Error("equal members differ")
	}
}

// ---- remedies and answers ----

func TestAnalyserLimitCaveat(t *testing.T) {
	if _, _, ok := AnalyserLimitCaveat("no limit here"); ok {
		t.Error("a detail with no limit has a caveat")
	}
	detail := "package requires newer Go version go1.99 (application built with go1.26)"
	restore := gotoolchain.SetAnalysingGo("go1.26.1")
	clause, remedy, ok := AnalyserLimitCaveat(detail)
	restore()
	if !ok || clause == "" || remedy == "" {
		t.Errorf("binding limit: %q %q %v", clause, remedy, ok)
	}
	restore = gotoolchain.SetAnalysingGo("go1.99.1")
	defer restore()
	if _, remedy, ok := AnalyserLimitCaveat(detail); !ok || remedy != "" {
		t.Errorf("cleared limit: remedy %q, ok %v", remedy, ok)
	}
}

func TestIncompleteGraphRemedy_EveryCauseAndKind(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	dep, err := coordinate.NewModuleCoordinate("example.com/dep", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		coord coordinate.ModuleCoordinate
		cause FailureCause
		want  string
	}{
		{local, FailureCauseEnvironment, ColdModuleCacheRemedy},
		{local, FailureCauseModule, "Fix the package so it compiles"},
		{dep, FailureCauseModule, "is a fetched dependency, so the failure is in its own sources"},
		{dep, FailureCauseEnvironment, "the gap is in the environment and not in what it published"},
	} {
		if got := IncompleteGraphRemedy(tc.coord, tc.cause, "x", "/work"); !strings.Contains(got, tc.want) {
			t.Errorf("%s/%s:\n%s", tc.coord, tc.cause, got)
		}
	}
}

func TestClassifyNegativeAnswer_DroppedPackageAndHarness(t *testing.T) {
	a := ClassifyNegativeAnswer(NegativeAnswerInputs{MethodName: "M", DroppedEdgePackage: "p", DroppedEdgeDetail: "x"})
	if len(a.Sinks) == 0 || a.Sinks[0].Kind != SinkDroppedPackageEdges || a.Sinks[0].Site != "M" {
		t.Errorf("dropped package: %+v", a.Sinks)
	}
	b := ClassifyNegativeAnswer(NegativeAnswerInputs{
		Found: true, QueriedNode: CallNode{ID: "p.TestX", Symbol: "TestX", Package: "p", IsTest: true},
	})
	found := false
	for _, s := range b.Sinks {
		found = found || s.Kind == SinkTestHarnessEntry
	}
	if !found {
		t.Errorf("test entry: %+v", b.Sinks)
	}
}

func TestGenerationDiff_SameRecordAndSeveralChanges(t *testing.T) {
	if got := (GenerationDiff{}).Summary(); got != "the two generations state the same record" {
		t.Errorf("Summary = %q", got)
	}
	left := []CallNode{{ID: "b", Symbol: "x"}, {ID: "a", Symbol: "x"}}
	right := []CallNode{{ID: "b", Symbol: "y"}, {ID: "a", Symbol: "y"}}
	d, err := diffMembers("nodes", "node", orderedBy(left, CallNodeLess), orderedBy(right, CallNodeLess), nodeIdentityLess, CallNodeLess, describeNode)
	if err != nil || len(d.Changed) != 2 || d.Changed[0].ID > d.Changed[1].ID {
		t.Errorf("diffMembers = %+v, %v", d, err)
	}
}

func TestWorktreeRecordAnswersFor_EachMismatchRefuses(t *testing.T) {
	id := WorktreeIdentity{Root: "/r", ScanDigest: "scan:1"}
	held := CallGraphRecord{AnalysisSource: AnalysisSourceWorktree, AnalysisRoot: "/r", WorktreeScanDigest: "scan:1"}
	for name, tc := range map[string]struct {
		rec CallGraphRecord
		id  WorktreeIdentity
	}{
		"no identity":    {held, WorktreeIdentity{}},
		"another source": {func() CallGraphRecord { r := held; r.AnalysisSource = AnalysisSourceModuleZip; return r }(), id},
		"another root":   {func() CallGraphRecord { r := held; r.AnalysisRoot = "/other"; return r }(), id},
		"another digest": {func() CallGraphRecord { r := held; r.WorktreeScanDigest = "scan:2"; return r }(), id},
		"another frame":  {held, WorktreeIdentity{Root: "/r", ScanDigest: "scan:1", Frame: BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}}},
	} {
		if WorktreeRecordAnswersFor(tc.rec, tc.id) {
			t.Errorf("%s: the held record answered", name)
		}
	}
}

func TestLatestObservation_AnotherRootIsAnotherCheckout(t *testing.T) {
	records := []CallGraphRecord{
		{WorktreeScanDigest: "scan:1", AnalysisRoot: "/other", ContentHash: "sha256:a"},
		{WorktreeScanDigest: "scan:1", AnalysisRoot: "/r", ContentHash: "sha256:b"},
	}
	if got := LatestObservation(records); got.ContentHash != "sha256:b" {
		t.Errorf("LatestObservation served %s", got.ContentHash)
	}
}

func TestConflictRemedy_AWorkingTreeReadsItsWorktree(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	r := CallGraphConflict{Coordinate: local, Field: ConflictFieldAnalysisSource}.Remedy()
	if !strings.Contains(r.String(), string(AnalysisSourceWorktree)) {
		t.Errorf("remedy for a project coordinate:\n%s", r.String())
	}
}
