package reachability_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

var (
	scanHost = callgraphdomain.BuildFrame{GOOS: "linux", GOARCH: "amd64"}
	heldWasm = callgraphdomain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
)

// historyStore serves nothing under the scan's frame and lists every frame's
// generations.
type historyStore struct {
	fakeStore
	recs []callgraphdomain.CallGraphRecord
	err  error
}

func (s *historyStore) ListCallGraphRecordsFor(context.Context, coordinate.ModuleCoordinate, string) ([]callgraphdomain.CallGraphRecord, error) {
	return s.recs, s.err
}

func hostReadFrame() (callgraphdomain.BuildFrame, string) { return scanHost, "" }

// A graph held only under another frame is a frame miss on the answer, and the
// hop says so; with nothing to list, or no frame to compare, it stays a miss.
func TestReadCallSites_FrameMiss(t *testing.T) {
	t.Parallel()
	held := &historyStore{recs: []callgraphdomain.CallGraphRecord{{Frame: heldWasm, AnalysisRoot: "/src/dep"}}}
	answer, err := reachability.NewCallSiteStoreReader(held, "p1").WithReadFrame(hostReadFrame).
		ReadCallSites(t.Context(), callSiteCoord, []string{"x"})
	if err != nil || answer.Served {
		t.Fatalf("answer = %+v, %v", answer, err)
	}
	if !strings.Contains(answer.FrameMiss, "held under wasip1/wasm, not under this scan's frame linux/amd64; read it with --target wasip1/wasm") ||
		answer.FrameMissRemedy != "kanonarion fetch example.com/dep@v1.2.3 && kanonarion callgraph example.com/dep@v1.2.3" {
		t.Errorf("answer = %+v", answer)
	}

	for name, r := range map[string]*reachability.CallSiteStoreReader{
		"no frame":        reachability.NewCallSiteStoreReader(held, "p1"),
		"no history":      reachability.NewCallSiteStoreReader(&fakeStore{}, "p1").WithReadFrame(hostReadFrame),
		"history fails":   reachability.NewCallSiteStoreReader(&historyStore{err: errors.New("boom")}, "p1").WithReadFrame(hostReadFrame),
		"only this frame": reachability.NewCallSiteStoreReader(&historyStore{recs: []callgraphdomain.CallGraphRecord{{Frame: scanHost}}}, "p1").WithReadFrame(hostReadFrame),
	} {
		if a, err := r.ReadCallSites(t.Context(), callSiteCoord, []string{"x"}); err != nil || a.FrameMiss != "" {
			t.Errorf("%s: answer = %+v, %v", name, a, err)
		}
	}
}

// The annotation carries the frame miss and its remedy on the hop.
func TestAnnotateRecord_FrameMissHop(t *testing.T) {
	t.Parallel()
	held := &historyStore{recs: []callgraphdomain.CallGraphRecord{{Frame: heldWasm}}}
	annotator := reachability.NewDispatchAnnotator(reachability.NewCallSiteStoreReader(held, "p1").WithReadFrame(hostReadFrame), nil)
	rec := &domain.VulnerabilityRecord{Coordinate: callSiteCoord, Findings: []domain.VulnerabilityFinding{{
		Reachable: &domain.ReachabilityResult{Routes: []domain.ReachabilityRoute{{
			{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/auto", Receiver: "*Uploader", Symbol: "upload"},
			{ModulePath: "example.com/dep", ModuleVersion: "v1.2.3", Package: "example.com/dep/auto", Symbol: "helper"},
		}}},
	}}}
	annotator.AnnotateRecord(t.Context(), rec)
	hop := rec.Findings[0].Reachable.Routes[0][1].Dispatch
	want := "the call graph of example.com/dep@v1.2.3 is held under wasip1/wasm, not under this scan's frame linux/amd64; " +
		"read it with --target wasip1/wasm, or produce this frame's with: kanonarion fetch example.com/dep@v1.2.3 && " +
		"kanonarion callgraph example.com/dep@v1.2.3; the route stands as the analyser reported it"
	if hop.Kind != domain.DispatchNotAnnotated || hop.Reason != want {
		t.Errorf("hop = %+v\nwant reason %q", hop, want)
	}
}
