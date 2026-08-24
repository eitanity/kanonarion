package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// TestToolchain_IsHashTransparentForRecordsThatPredateIt is the falsifying test
// for the whole field: a record sealed before the toolchain existed must still
// verify, because its canonical bytes must not have moved.
//
// It is asserted against the SEAL rather than against the golden shape, because
// they answer different questions: the golden pins the bytes one record encodes
// to, and this pins that a record sealed WITHOUT the field is still readable by
// a build that has it. A field added without omitempty passes neither, but a
// field whose omission is conditional on something other than emptiness would
// pass the golden and fail here.
func TestToolchain_IsHashTransparentForRecordsThatPredateIt(t *testing.T) {
	t.Parallel()
	var h domain.CallGraphRecordHasher

	// Sealed with no toolchain: exactly the shape every stored record carries.
	sealed, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealed.Toolchain.Recorded() {
		t.Fatalf("the test record states a toolchain (%q); it must not, or this proves nothing", sealed.Toolchain)
	}
	if verr := h.VerifyContentHash(sealed); verr != nil {
		t.Errorf("a record sealed without a toolchain no longer verifies: %v", verr)
	}

	// And the field is genuinely covered once it IS stated, so the transparency
	// above is omission rather than the field being outside the seal.
	stated := sealed
	stated.Toolchain = "go1.26.6"
	if verr := h.VerifyContentHash(stated); verr == nil {
		t.Error("adding a toolchain to a sealed record did not break its seal — the field is not hashed")
	}
}

func TestRecordToolchain_PrefersTheRecordedValue(t *testing.T) {
	t.Parallel()
	r := makeTestRecord()
	r.Toolchain = "go1.27.0"
	r.Nodes = append(r.Nodes, stdlibNode("usr/local/go"))

	got := domain.RecordToolchain(r)
	if got.Version != "go1.27.0" || got.Derived {
		t.Errorf("RecordToolchain = %+v, want the recorded go1.27.0 with Derived false", got)
	}
}

// TestRecordToolchain_RecoversAVersionFromAToolchainModuleRoot: a toolchain
// downloaded as a module states its Go version in its own module version, so a
// record that predates the field still shows which toolchain built it.
func TestRecordToolchain_RecoversAVersionFromAToolchainModuleRoot(t *testing.T) {
	t.Parallel()
	r := makeTestRecord()
	r.Nodes = append(r.Nodes,
		stdlibNode("home/mb/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.linux-amd64"))

	got := domain.RecordToolchain(r)
	if got.Version != "go1.26.6" || !got.Derived {
		t.Errorf("RecordToolchain = %+v, want a derived go1.26.6", got)
	}
	if got.Key() != "go1.26.6" {
		t.Errorf("Key = %q, want go1.26.6", got.Key())
	}
}

// TestRecordToolchain_APlainGOROOTNamesNoVersion pins the distinction the whole
// exception rests on. A toolchain installed at /usr/local/go is upgraded in
// place, so the path says WHERE the stdlib came from and never WHICH version it
// was — and the identity must not read as one.
func TestRecordToolchain_APlainGOROOTNamesNoVersion(t *testing.T) {
	t.Parallel()
	r := makeTestRecord()
	r.Nodes = append(r.Nodes, stdlibNode("usr/local/go"))

	got := domain.RecordToolchain(r)
	if got.Version.Recorded() {
		t.Errorf("a plain GOROOT produced version %q; it names no version", got.Version)
	}
	if got.Root != "usr/local/go" {
		t.Errorf("Root = %q, want usr/local/go", got.Root)
	}
	// A GOROOT is not a value. Key is what a record ESTABLISHES, and "the stdlib
	// came from /usr/local/go" establishes no version — the toolchain installed
	// there is upgraded in place. Reading it as a value made it collide with a
	// named toolchain over byte-identical graphs.
	if got.Key() != "" {
		t.Errorf("Key = %q, want empty: an unnamed GOROOT establishes no toolchain", got.Key())
	}
	if got.String() != "unnamed version at GOROOT usr/local/go" {
		t.Errorf("String = %q, want the GOROOT reported without asserting a version", got.String())
	}
}

// TestRecordToolchain_NoStdlibPathEstablishesNothing is the population the
// deliberate exception exists for: a record with no stdlib path at all. It must
// read as "not recorded" and never as the reading host's toolchain.
func TestRecordToolchain_NoStdlibPathEstablishesNothing(t *testing.T) {
	t.Parallel()
	got := domain.RecordToolchain(makeTestRecord())
	if got.Key() != "" {
		t.Errorf("Key = %q, want the empty key that stands for no toolchain", got.Key())
	}
	if got.String() != gotoolchain.Unrecorded.String() {
		t.Errorf("String = %q, want %q", got.String(), gotoolchain.Unrecorded.String())
	}
}

// TestCompose_RefusesTwoToolchainsThatDisagreeAboutTheGraph is the behaviour the
// whole field is for: two toolchains that produced DIFFERENT graphs for one
// coordinate are two answers, and composition names the toolchain rather than
// picking the newer.
//
// The graph difference is what makes it a disagreement. Two toolchains that
// produced the same graph produced the same answer — see the sibling test.
func TestCompose_RefusesTwoToolchainsThatDisagreeAboutTheGraph(t *testing.T) {
	t.Parallel()
	older := recordBuiltBy(t, "go1.26.5", "sha256:aaa")
	newer := recordBuiltBy(t, "go1.26.6", "sha256:bbb")
	newer.Nodes = append(newer.Nodes, domain.CallNode{
		ID: "example.com/mod.OnlyUnderTheNewerToolchain", Module: "example.com/mod",
		Package: "example.com/mod", Symbol: "OnlyUnderTheNewerToolchain",
	})
	newer.NodeCount = len(newer.Nodes)

	_, err := domain.Compose([]domain.CallGraphRecord{older, newer}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !asConflict(err, &conflict) {
		t.Fatalf("Compose = %v, want a CallGraphConflict", err)
	}
	if conflict.Field != domain.ConflictFieldToolchain {
		t.Errorf("conflict field = %q, want %q", conflict.Field, domain.ConflictFieldToolchain)
	}
	if len(conflict.Values) != 2 || conflict.Values[0] != "go1.26.5" || conflict.Values[1] != "go1.26.6" {
		t.Errorf("conflict values = %v, want both toolchains named", conflict.Values)
	}
	// The refusal has to name a way out the CLI accepts; the remedy contract test
	// in internal/cli parses every line.
	if len(conflict.Remedy().Lines) == 0 {
		t.Error("a toolchain refusal printed no invocation")
	}
}

// TestCompose_OneToolchainStillComposes is the control. Two generations from one
// toolchain are two measurements of one thing and the ladder still orders them.
func TestCompose_OneToolchainStillComposes(t *testing.T) {
	t.Parallel()
	older := recordBuiltBy(t, "go1.26.6", "sha256:aaa")
	newer := recordBuiltBy(t, "go1.26.6", "sha256:bbb")

	got, err := domain.Compose([]domain.CallGraphRecord{older, newer}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose refused two generations from ONE toolchain: %v", err)
	}
	if got.Toolchain != "go1.26.6" {
		t.Errorf("composed toolchain = %q, want go1.26.6", got.Toolchain)
	}
}

// TestCompose_ARecordEstablishingNoToolchainTakesNoPart pins the deliberate
// exception, and its exact width.
//
// A record that establishes no toolchain neither conflicts with one that names a
// toolchain nor counts as a toolchain of its own — there is nothing to ladder it
// to and the reading host's would be fabrication. What it must NOT do is drop out
// of the graph comparison: filtering such records out of the group silenced a
// real disagreement between a run that reached an external symbol and one that
// did not, which is why the exception lives in the comparison and not in a
// filter.
func TestCompose_ARecordEstablishingNoToolchainTakesNoPart(t *testing.T) {
	t.Parallel()
	silent := recordBuiltBy(t, "", "sha256:aaa")
	named := recordBuiltBy(t, "go1.26.6", "sha256:bbb")

	if _, err := domain.Compose([]domain.CallGraphRecord{silent, named}, domain.ComposeRequest{}); err != nil {
		t.Fatalf("a record stating no toolchain conflicted with one that names a toolchain: %v", err)
	}

	// The same pair, disagreeing about the graph, is still a graph conflict.
	silent.Nodes = nil
	silent.NodeCount = 0
	_, err := domain.Compose([]domain.CallGraphRecord{silent, named}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !asConflict(err, &conflict) {
		t.Fatalf("Compose = %v, want the graph disagreement still reported", err)
	}
	if conflict.Field != domain.ConflictFieldCallGraph {
		t.Errorf("conflict field = %q, want %q", conflict.Field, domain.ConflictFieldCallGraph)
	}
}

// TestCompose_ToolchainSelectorAnswersFromOneOfThem: the remedy the refusal
// prints has to work, or the refusal is a dead end.
func TestCompose_ToolchainSelectorAnswersFromOneOfThem(t *testing.T) {
	t.Parallel()
	older := recordBuiltBy(t, "go1.26.5", "sha256:aaa")
	newer := recordBuiltBy(t, "go1.26.6", "sha256:bbb")
	records := []domain.CallGraphRecord{older, newer}

	got, err := domain.Compose(records, domain.ComposeRequest{Toolchain: "go1.26.5"})
	if err != nil {
		t.Fatalf("Compose with a named toolchain: %v", err)
	}
	if got.ContentHash != older.ContentHash {
		t.Errorf("served %q, want the go1.26.5 record", got.ContentHash)
	}
	if _, err := domain.Compose(records, domain.ComposeRequest{Toolchain: "go1.99.0"}); err == nil {
		t.Error("a toolchain the ledger does not hold was answered from anyway")
	}
}

// stdlibNode is an external node whose position sits under root's stdlib tree,
// which is how a stored record carries the GOROOT that built it.
func stdlibNode(root string) domain.CallNode {
	return domain.CallNode{
		ID:         "bufio.NewReader",
		Package:    "bufio",
		Symbol:     "NewReader",
		IsExternal: true,
		Position:   domain.SourcePosition{File: root + "/src/bufio/bufio.go", Line: 10},
	}
}

// recordBuiltBy is a sealed, artefact-identified record stating one toolchain.
func recordBuiltBy(t *testing.T, toolchain gotoolchain.Version, artefact string) domain.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	r := makeTestRecord()
	r.Coordinate = coord
	r.Completeness = domain.CompletenessBuiltWithBodies
	r.AnalysisSource = domain.AnalysisSourceModuleZip
	r.ArtefactIdentity = "zip:h1:same"
	r.Toolchain = toolchain
	r.ContentHash = artefact
	return r
}

// asConflict unwraps err into a CallGraphConflict.
func asConflict(err error, out *domain.CallGraphConflict) bool {
	c, ok := err.(domain.CallGraphConflict) //nolint:errorlint // the domain returns the value, never a wrapper
	if ok {
		*out = c
	}
	return ok
}

// TestCompose_TwoToolchainsThatAgreeAboutTheGraphAreNotADisagreement is the other
// half, and it is what stops the dimension refusing reads it has nothing to say
// about. Where the records describe the same nodes and edges there is nothing to
// choose between, and the served record still names its own toolchain.
func TestCompose_TwoToolchainsThatAgreeAboutTheGraphAreNotADisagreement(t *testing.T) {
	t.Parallel()
	older := recordBuiltBy(t, "go1.26.5", "sha256:aaa")
	newer := recordBuiltBy(t, "go1.26.6", "sha256:bbb")

	got, err := domain.Compose([]domain.CallGraphRecord{older, newer}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("two toolchains holding one graph refused: %v", err)
	}
	if !got.Toolchain.Recorded() {
		t.Error("the served record does not name the toolchain that produced it")
	}
}

// TestCompose_ToolchainPreferenceResolvesARefusalWithoutNarrowingTheRead pins the
// distinction between the two request fields.
//
// A store-wide read spans hundreds of modules of which almost none state a
// toolchain. Restricting such a read would answer "no record" for every one of
// them, turning a disambiguation into a silently short answer — so a preference
// is consulted only where the records for a coordinate actually disagree.
func TestCompose_ToolchainPreferenceResolvesARefusalWithoutNarrowingTheRead(t *testing.T) {
	t.Parallel()
	older := recordBuiltBy(t, "go1.26.5", "sha256:aaa")
	newer := recordBuiltBy(t, "go1.26.6", "sha256:bbb")
	newer.Nodes = append(newer.Nodes, domain.CallNode{
		ID: "example.com/mod.Extra", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Extra",
	})
	newer.NodeCount = len(newer.Nodes)
	both := []domain.CallGraphRecord{older, newer}

	got, err := domain.Compose(both, domain.ComposeRequest{ToolchainPreference: "go1.26.5"})
	if err != nil {
		t.Fatalf("the preference did not resolve the refusal: %v", err)
	}
	if got.ContentHash != older.ContentHash {
		t.Errorf("served %q, want the go1.26.5 record", got.ContentHash)
	}

	// A coordinate that holds nothing of the named toolchain keeps its refusal
	// rather than being answered from some other generation.
	if _, err := domain.Compose(both, domain.ComposeRequest{ToolchainPreference: "go1.99.0"}); err == nil {
		t.Error("a preference naming a toolchain the coordinate does not hold silenced the refusal")
	}

	// And a coordinate with no disagreement at all is served exactly as it would
	// be with no preference: the preference must not narrow anything.
	solo := []domain.CallGraphRecord{recordBuiltBy(t, "", "sha256:ccc")}
	if _, err := domain.Compose(solo, domain.ComposeRequest{ToolchainPreference: "go1.26.6"}); err != nil {
		t.Errorf("a preference narrowed a read that had nothing to disambiguate: %v", err)
	}
}
