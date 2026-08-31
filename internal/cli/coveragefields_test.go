package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
)

// A coverage limit is a field, and "not recorded" is a value.
//
// Three read surfaces qualified their answer in prose only. `implementers`
// printed one English sentence saying the count covered the types declared in
// ONE module and whether tests were dropped; `callgraph-show` and
// `interface-show` printed "not recorded" to a person and "" to a machine.
// Both are the same defect: a fact a person is told and a machine has to parse
// English for, or cannot recover at all.
//
// Everything here is about the DOCUMENT. Nothing below touches a record, a
// ladder or a comparison — see TestToCallGraphJSON_LeavesTheRecordUntouched,
// which is the boundary this whole change rests on.

// implDoc runs the implementers query and decodes the document.
func implDoc(t *testing.T, opts cgports.EdgeQueryOptions) map[string]any {
	t.Helper()
	out := runImpl(t, implPortID, true, implRecord(), opts)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("decoding implementers document: %v\n%s", err, out)
	}
	return doc
}

// TestImplementersJSON_StatesWhatWasSearchedWithoutTestsExcluded is the live
// case: the count reads as "the implementers", and only the prose said it was
// the implementers DECLARED IN ONE MODULE.
func TestImplementersJSON_StatesWhatWasSearchedWithoutTestsExcluded(t *testing.T) {
	doc := implDoc(t, cgports.EdgeQueryOptions{})

	if got := doc["searched_module"]; got != implModule {
		t.Errorf("searched_module = %v, want %q", got, implModule)
	}
	if got := doc["cross_module_types_measured"]; got != false {
		t.Errorf("cross_module_types_measured = %v, want false — types in other modules were never looked at", got)
	}
	if got := doc["tests_excluded"]; got != false {
		t.Errorf("tests_excluded = %v, want false", got)
	}
	if got := doc["tests_exclude_flag"]; got != "--"+testScopeFlagName {
		t.Errorf("tests_exclude_flag = %v, want %q", got, "--"+testScopeFlagName)
	}
	// The sentence stays: it is what the text renders, and removing it would be a
	// break with no benefit.
	if s, _ := doc["scope"].(string); !strings.Contains(s, implModule) {
		t.Errorf("scope sentence lost the module it names: %q", s)
	}
}

// TestImplementersJSON_StatesTheTestExclusion is the other direction. Without
// it the count is the answer to a narrower question with nothing in the
// document saying so — --exclude-tests was fielded NOWHERE.
func TestImplementersJSON_StatesTheTestExclusion(t *testing.T) {
	doc := implDoc(t, cgports.EdgeQueryOptions{ExcludeTests: true})

	if got := doc["tests_excluded"]; got != true {
		t.Errorf("tests_excluded = %v, want true", got)
	}
	if got := doc["tests_exclude_flag"]; got != "--"+testScopeFlagName {
		t.Errorf("tests_exclude_flag = %v, want %q", got, "--"+testScopeFlagName)
	}
	if got := doc["searched_module"]; got != implModule {
		t.Errorf("searched_module = %v, want %q", got, implModule)
	}
	// The exclusion changed the count, which is the whole reason the state has to
	// be readable: 2 implementers unexcluded, 1 with the flag.
	if got := doc["count"]; got != float64(1) {
		t.Errorf("count = %v, want 1 — the fixture's only production implementer", got)
	}
}

// TestImplementersJSON_EveryScopeFieldIsPresent is the falsification harness for
// the four fields: delete one from the struct and this names it.
func TestImplementersJSON_EveryScopeFieldIsPresent(t *testing.T) {
	for _, opts := range []cgports.EdgeQueryOptions{{}, {ExcludeTests: true}} {
		doc := implDoc(t, opts)
		for _, field := range []string{
			"searched_module", "cross_module_types_measured", "tests_excluded", "tests_exclude_flag",
		} {
			if _, ok := doc[field]; !ok {
				t.Errorf("exclude-tests=%v: %s absent — the limit is back in the prose only", opts.ExcludeTests, field)
			}
		}
	}
}

// unrecordedGraphRecord states none of the three axes: no test scope, no
// reference scope, and no toolchain either recorded or recoverable from a
// stdlib position. It is what a store holding records from an older binary
// serves, which is the state this store cannot reach.
func unrecordedGraphRecord() cgdomain.CallGraphRecord {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.TestScope = cgdomain.TestScopeUnknown
	rec.ReferenceScope = cgdomain.ReferenceScopeUnknown
	rec.Toolchain = gotoolchain.Unrecorded
	rec.NodeCount = len(rec.Nodes)
	return rec
}

// TestCallGraphShowJSON_UnrecordedAxesAreNamed: the three axes name the state
// they are in.
//
// The reference axis is the worst of the three, and the text says so in as many
// words: an empty callers answer over a record that never looked for references
// is UNRESOLVED, not a measured absence. Spelling that state "" hands a machine
// the shape of an answer that was never given.
func TestCallGraphShowJSON_UnrecordedAxesAreNamed(t *testing.T) {
	out := toCallGraphJSON(unrecordedGraphRecord())
	for _, c := range []struct{ field, got string }{
		{"test_scope", out.TestScope},
		{"reference_scope", out.ReferenceScope},
		{"toolchain", out.Toolchain},
	} {
		if c.got != jsonNotRecorded {
			t.Errorf("%s = %q, want %q", c.field, c.got, jsonNotRecorded)
		}
	}
}

// TestCallGraphShowJSON_RecordedAxesKeepTheirValue is the other direction: the
// token replaces an absence and never a measurement.
func TestCallGraphShowJSON_RecordedAxesKeepTheirValue(t *testing.T) {
	rec := unrecordedGraphRecord()
	rec.TestScope = cgdomain.TestScopeAnalysed
	rec.ReferenceScope = cgdomain.ReferenceScopeAnalysed
	rec.Toolchain = "go1.26.6"

	out := toCallGraphJSON(rec)
	for _, c := range []struct{ field, got, want string }{
		{"test_scope", out.TestScope, string(cgdomain.TestScopeAnalysed)},
		{"reference_scope", out.ReferenceScope, string(cgdomain.ReferenceScopeAnalysed)},
		{"toolchain", out.Toolchain, "go1.26.6"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
	// An excluded test scope is a RECORDED state, not an absent one, and must
	// survive the same way a measured one does.
	rec.TestScope = cgdomain.TestScopeExcluded
	if got := toCallGraphJSON(rec).TestScope; got != string(cgdomain.TestScopeExcluded) {
		t.Errorf("test_scope = %q, want %q — an exclusion is a measurement", got, cgdomain.TestScopeExcluded)
	}
}

// TestInterfaceRecordJSON_UnrecordedFrameAndToolchainAreNamed: the frame field
// the document did not have.
//
// A record written before extraction evaluated build constraints holds every
// platform's declarations at once. The text said so; the document simply
// omitted build_frame, which a reader cannot tell from a frame the encoder
// dropped.
func TestInterfaceRecordJSON_UnrecordedFrameAndToolchainAreNamed(t *testing.T) {
	r := embeddingRecord()
	r.BuildFrame = ifacedomain.BuildFrame{}
	r.Toolchain = gotoolchain.Unrecorded

	wantFrame := (ifacedomain.BuildFrame{}).String()
	out := toInterfaceRecordJSON(r)
	if out.BuildFrameStated != wantFrame {
		t.Errorf("build_frame_stated = %q, want %q", out.BuildFrameStated, wantFrame)
	}
	if out.Toolchain != jsonNotRecorded {
		t.Errorf("toolchain = %q, want %q", out.Toolchain, jsonNotRecorded)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshalling record: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding record: %v", err)
	}
	if _, ok := doc["build_frame_stated"]; !ok {
		t.Error("build_frame_stated absent — the document still states no frame at all")
	}
	if _, ok := doc["toolchain"]; !ok {
		t.Error("toolchain absent")
	}
}

// TestInterfaceRecordJSON_RecordedFrameAndToolchain is the other direction: a
// measured frame is named, and the components stay beside it.
func TestInterfaceRecordJSON_RecordedFrameAndToolchain(t *testing.T) {
	r := embeddingRecord()
	r.BuildFrame = ifacedomain.BuildFrame{GOOS: "linux", GOARCH: "amd64", CgoEnabled: true}
	r.Toolchain = "go1.26.6"

	out := toInterfaceRecordJSON(r)
	if want := r.BuildFrame.String(); out.BuildFrameStated != want {
		t.Errorf("build_frame_stated = %q, want %q", out.BuildFrameStated, want)
	}
	if out.Toolchain != "go1.26.6" {
		t.Errorf("toolchain = %q, want %q", out.Toolchain, "go1.26.6")
	}
	if out.BuildFrame == nil {
		t.Fatal("build_frame components dropped from a framed record")
	}
	if out.BuildFrame.GOOS != "linux" || out.BuildFrame.GOARCH != "amd64" || !out.BuildFrame.CgoEnabled {
		t.Errorf("build_frame components = %+v, want linux/amd64 with cgo on", *out.BuildFrame)
	}
}

// TestUnrecordedTokens_AreWhatTheTextPrints keeps the two renderings from
// drifting apart.
//
// The point of naming the absence is that one fact reads the same to a person
// and to a machine. If somebody reworded one surface, a document and a screen
// would state the same record in two vocabularies and the reader would have to
// learn both.
func TestUnrecordedTokens_AreWhatTheTextPrints(t *testing.T) {
	if jsonNotRecorded != gotoolchain.Unrecorded.String() {
		t.Errorf("the document says %q and the toolchain rendering says %q",
			jsonNotRecorded, gotoolchain.Unrecorded.String())
	}

	r := embeddingRecord()
	r.BuildFrame = ifacedomain.BuildFrame{}
	r.Toolchain = gotoolchain.Unrecorded

	text := renderRecord(t, r)
	if frame := toInterfaceRecordJSON(r).BuildFrameStated; !strings.Contains(text, frame) {
		t.Errorf("the document says the frame is %q and interface-show prints:\n%s", frame, text)
	}
	if !strings.Contains(text, jsonNotRecorded) {
		t.Errorf("interface-show does not print %q for an unrecorded toolchain:\n%s", jsonNotRecorded, text)
	}

	graph := renderGraph(t, unrecordedGraphRecord())
	if !strings.Contains(graph, "test scope: "+jsonNotRecorded) {
		t.Errorf("callgraph-show does not print %q for an unmeasured test scope:\n%s", jsonNotRecorded, graph)
	}
	if !strings.Contains(graph, "reference scope: "+jsonNotRecorded) {
		t.Errorf("callgraph-show does not print %q for an unmeasured reference scope:\n%s", jsonNotRecorded, graph)
	}
	if !strings.Contains(graph, "toolchain: "+jsonNotRecorded) {
		t.Errorf("callgraph-show does not print %q for an unrecorded toolchain:\n%s", jsonNotRecorded, graph)
	}
}

// renderGraph is the call-graph record as callgraph-show prints it.
func renderGraph(t *testing.T, r cgdomain.CallGraphRecord) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printCallGraphRecord(r, 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	return buf.String()
}

// TestToCallGraphJSON_LeavesTheRecordUntouched is the constraint the whole
// change rests on.
//
// A dimension field added to a table with existing rows must not make the zero
// value a third value of the dimension: doing so segregates legacy records from
// the records that should supersede them, and this project has been bitten by
// exactly that and caught it only on real data. The token here is RENDERING. It
// is produced when a document is written and never stored, so it cannot reach a
// ladder or a comparison — and the way to keep that true is to check that
// rendering a record does not change it.
//
// The composition side is unchanged and proved where it lives:
// TestCompose_ARecordEstablishingNoToolchainTakesNoPart,
// TestCompose_ARecordNamingNoSourceIsLadderedNotSegregated and
// TestCompose_RecordPredatingAFieldIsSupersededNotConflicting in
// internal/callgraph/domain, and TestCompose_FramedAndUnframedRecordsConflictOnTheFrame
// in internal/iface/domain.
func TestToCallGraphJSON_LeavesTheRecordUntouched(t *testing.T) {
	rec := unrecordedGraphRecord()
	_ = toCallGraphJSON(rec)

	if rec.TestScope != cgdomain.TestScopeUnknown {
		t.Errorf("rendering wrote a test scope onto the record: %q", rec.TestScope)
	}
	if rec.ReferenceScope != cgdomain.ReferenceScopeUnknown {
		t.Errorf("rendering wrote a reference scope onto the record: %q", rec.ReferenceScope)
	}
	if rec.Toolchain.Recorded() {
		t.Errorf("rendering wrote a toolchain onto the record: %q", rec.Toolchain)
	}
	if key := cgdomain.RecordToolchain(rec).Key(); key != "" {
		t.Errorf("the composition key became %q — the token reached the dimension", key)
	}
	if rec.TestScope.IsMeasured() || rec.ReferenceScope.IsMeasured() {
		t.Error("an unmeasured axis reads as measured after rendering")
	}

	ir := embeddingRecord()
	ir.BuildFrame = ifacedomain.BuildFrame{}
	ir.Toolchain = gotoolchain.Unrecorded
	_ = toInterfaceRecordJSON(ir)
	if !ir.BuildFrame.IsZero() {
		t.Errorf("rendering wrote a build frame onto the record: %+v", ir.BuildFrame)
	}
	if ir.Toolchain.Recorded() {
		t.Errorf("rendering wrote a toolchain onto the record: %q", ir.Toolchain)
	}
}
