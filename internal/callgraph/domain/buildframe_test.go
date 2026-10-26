package domain_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

var (
	hostFrame   = domain.BuildFrame{GOOS: "linux", GOARCH: "amd64"}
	wasip1Frame = domain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
	tinyWasip1  = domain.BuildFrame{
		GOOS: "wasip1", GOARCH: "wasm", GOARM: "6", TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0",
		TinyGoTags: []string{"tinygo.wasm", "tinygo"},
	}
	picoFrame = domain.BuildFrame{
		GOOS: "linux", GOARCH: "arm", GOARM: "6", TinyGoTarget: "pico", TinyGoVersion: "0.42.0",
		TinyGoTags: []string{"cortexm", "baremetal"},
	}
)

// The frame is named in the walk's own spelling, so one platform reads the same
// on a walk and on the graph extracted under it.
func TestBuildFrame_RendersAsTheWalkDoes(t *testing.T) {
	t.Parallel()
	if got, want := picoFrame.String(), walkdomain.TinyGoFrameText("pico", "linux", "arm"); got != want {
		t.Errorf("pico frame = %q, the walk renders %q", got, want)
	}
	env := walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm"}
	if got, want := wasip1Frame.String(), walkdomain.FrameOf(walkdomain.Graph{}.Target, env).Text; got != want {
		t.Errorf("wasip1 frame = %q, the walk renders %q", got, want)
	}
	if got := (domain.BuildFrame{}).String(); got != "unrecorded" {
		t.Errorf("zero frame = %q, want unrecorded", got)
	}
	for f, want := range map[*domain.BuildFrame]string{
		&hostFrame: "--target linux/amd64", &tinyWasip1: "--tinygo wasip1", {}: "",
	} {
		if got := f.FlagSpelling(); got != want {
			t.Errorf("%s spells %q, want %q", f, got, want)
		}
	}
}

// Selection is on the platform and the TinyGo target; the TinyGo release and
// tags are recorded, never selected on.
func TestSameFrame_SelectsOnTheKeyAlone(t *testing.T) {
	t.Parallel()
	other := tinyWasip1
	other.TinyGoVersion, other.TinyGoTags = "0.43.0", []string{"x"}
	if !domain.SameFrame(tinyWasip1, other) {
		t.Error("two TinyGo releases of one target were told apart")
	}
	for _, f := range []domain.BuildFrame{hostFrame, wasip1Frame, picoFrame, {}} {
		if domain.SameFrame(tinyWasip1, f) {
			t.Errorf("tinygo/wasip1 matched %s", f)
		}
	}
	arm7 := domain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "7"}
	arm6 := domain.BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "6"}
	if domain.SameFrame(arm6, arm7) {
		t.Error("GOARM 6 and 7 were selected as one frame")
	}
}

// A framed record carries its frame as one alphabetical object inside the seal;
// a record without one marshals exactly as it did before the field existed.
func TestBuildFrame_WireShapeAndSeal(t *testing.T) {
	t.Parallel()
	var h domain.CallGraphRecordHasher
	plain, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	plainBytes, err := h.Marshal(plain)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(plainBytes, []byte(`"frame"`)) {
		t.Fatalf("a record with no frame carries the key: %s", plainBytes)
	}

	framed := makeTestRecord()
	framed.Frame = picoFrame
	framed, err = h.SetContentHash(framed)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if framed.ContentHash == plain.ContentHash {
		t.Fatal("the frame is outside the seal: a framed record hashes as the same record without it")
	}
	raw, err := h.Marshal(framed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `"frame":{"goarch":"arm","goarm":"6","goos":"linux","tinygo_tags":["baremetal","cortexm"],"tinygo_target":"pico","tinygo_version":"0.42.0"}`
	if !bytes.Contains(raw, []byte(want)) {
		t.Errorf("framed wire shape lacks %s:\n%s", want, raw)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if verr := h.VerifyContentHash(back); verr != nil {
		t.Errorf("a framed record does not verify after a round trip: %v", verr)
	}
	if !reflect.DeepEqual(back.Frame, domain.BuildFrame{
		GOOS: "linux", GOARCH: "arm", GOARM: "6", TinyGoTarget: "pico", TinyGoVersion: "0.42.0",
		TinyGoTags: []string{"baremetal", "cortexm"},
	}) {
		t.Errorf("round-tripped frame = %+v", back.Frame)
	}

	standard := makeTestRecord()
	standard.Frame = wasip1Frame
	raw, err = h.Marshal(standard)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"frame":{"goarch":"wasm","goos":"wasip1"}`)) {
		t.Errorf("a standard frame carries more than its pair: %s", raw)
	}
}

func framedRecord(t *testing.T, f domain.BuildFrame, symbol string) domain.CallGraphRecord {
	t.Helper()
	r := composeRecord(t, composeSpec{
		completeness: domain.CompletenessBuiltWithBodies, source: domain.AnalysisSourceModuleZip,
		artefact: "zip:h1:a", symbol: symbol,
	})
	r.Frame = f
	var h domain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// The frame is selected before the ladder: each read gets its own frame's
// record, and a frame the ledger does not hold is no answer.
func TestCompose_SelectsTheRequestedFrame(t *testing.T) {
	t.Parallel()
	host := framedRecord(t, hostFrame, "Host")
	wasm := framedRecord(t, wasip1Frame, "Wasm")
	tiny := framedRecord(t, tinyWasip1, "Tiny")
	records := []domain.CallGraphRecord{host, wasm, tiny}
	for _, tc := range []struct {
		frame domain.BuildFrame
		want  string
	}{{hostFrame, host.ContentHash}, {wasip1Frame, wasm.ContentHash}, {tinyWasip1, tiny.ContentHash}} {
		got, err := domain.Compose(records, domain.ComposeRequest{Frame: tc.frame})
		if err != nil {
			t.Fatalf("Compose(%s): %v", tc.frame, err)
		}
		if got.ContentHash != tc.want {
			t.Errorf("Compose(%s) served %s, want %s", tc.frame, got.Frame, tc.frame)
		}
	}
	if _, err := domain.Compose(records, domain.ComposeRequest{Frame: picoFrame}); !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Errorf("a frame the ledger does not hold composed: %v", err)
	}
	if got, err := domain.Compose([]domain.CallGraphRecord{host}, domain.ComposeRequest{}); err != nil || got.ContentHash != host.ContentHash {
		t.Errorf("one frame and no request did not serve it: %v", err)
	}
}

// A read naming no frame over records of several is refused by name, and the
// remedy spells the declaration that selects each frame held.
func TestCompose_SeveralFramesAndNoneNamedIsAConflict(t *testing.T) {
	t.Parallel()
	records := []domain.CallGraphRecord{
		framedRecord(t, wasip1Frame, "Wasm"), framedRecord(t, hostFrame, "Host"), framedRecord(t, tinyWasip1, "Tiny"),
	}
	_, err := domain.Compose(records, domain.ComposeRequest{})
	var c domain.CallGraphConflict
	if !errors.As(err, &c) || c.Field != domain.ConflictFieldFrame {
		t.Fatalf("Compose = %v, want a %s conflict", err, domain.ConflictFieldFrame)
	}
	if want := []string{"linux/amd64", "wasip1/wasm", "tinygo/wasip1 (wasip1/wasm)"}; !reflect.DeepEqual(c.Values, want) {
		t.Errorf("Values = %q, want %q", c.Values, want)
	}
	if len(c.ContentHashes) != len(c.Values) {
		t.Errorf("%d hashes for %d values", len(c.ContentHashes), len(c.Values))
	}
	coord := records[0].Coordinate.String()
	for _, line := range []string{
		"kanonarion callgraph-show " + coord + " --history",
		"kanonarion callgraph-show " + coord + " --target linux/amd64",
		"kanonarion callgraph-show " + coord + " --target wasip1/wasm",
		"kanonarion callgraph-show " + coord + " --tinygo wasip1",
	} {
		if !strings.Contains(err.Error(), "\n  "+line) {
			t.Errorf("the refusal does not print %q:\n%s", line, err)
		}
	}
}

// One tree holds a record per frame, and each run reuses only its own.
func TestWorktreeRecordAnswersFor_RequiresTheSameFrame(t *testing.T) {
	t.Parallel()
	held := domain.CallGraphRecord{
		AnalysisSource: domain.AnalysisSourceWorktree, AnalysisRoot: "/src/app",
		WorktreeScanDigest: "scanned-sha256:a", OverallStatus: domain.CallGraphStatusExtracted,
		Completeness: domain.CompletenessBuiltWithBodies, Frame: hostFrame,
	}
	id := domain.WorktreeIdentity{Root: "/src/app", ScanDigest: "scanned-sha256:a", Frame: hostFrame}
	if !domain.WorktreeRecordAnswersFor(held, id) {
		t.Fatal("the host record of an unchanged tree does not answer a host run")
	}
	for _, f := range []domain.BuildFrame{wasip1Frame, tinyWasip1, {}} {
		id.Frame = f
		if domain.WorktreeRecordAnswersFor(held, id) {
			t.Errorf("the host record answers a run under %s", f)
		}
	}
}
