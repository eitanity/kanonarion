package domain

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
)

func TestFrameMissReason(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	host := BuildFrame{GOOS: "linux", GOARCH: "amd64"}
	wasm := BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
	pico := BuildFrame{GOOS: "linux", GOARCH: "arm", GOARM: "6", TinyGoTarget: "pico"}
	recs := []CallGraphRecord{
		{Frame: wasm, AnalysisRoot: "/src/app"}, {Frame: wasm, AnalysisRoot: "/src/app"},
		{Frame: pico}, {Frame: host, AnalysisRoot: "/src/app"}, {},
	}

	reason, remedy, ok := FrameMissReason(local, recs, host, "", "this scan's")
	if !ok {
		t.Fatal("other frames held, but no frame miss stated")
	}
	if want := "the call graph of example.com/app@local is held under wasip1/wasm, tinygo/pico (linux/arm), " +
		"not under this scan's frame linux/amd64; read it with --target wasip1/wasm or --tinygo pico"; reason != want {
		t.Errorf("reason = %q\nwant     %q", reason, want)
	}
	if remedy != "kanonarion local /src/app" {
		t.Errorf("remedy = %q", remedy)
	}

	// Generations naming two trees agree on none, so the lead sentence stands.
	recs[1].AnalysisRoot = "/elsewhere"
	if _, remedy, _ = FrameMissReason(local, recs, wasm, " --target wasip1/wasm", "this read's"); remedy != ReanalysisInstruction(local, "") {
		t.Errorf("remedy with no agreed tree = %q", remedy)
	}
	published, err := coordinate.NewModuleCoordinate("example.com/dep", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, remedy, _ = FrameMissReason(published, recs, host, " --target linux/arm64", "this read's"); remedy != "kanonarion fetch example.com/dep@v1.0.0 && kanonarion callgraph example.com/dep@v1.0.0 --target linux/arm64" {
		t.Errorf("published remedy = %q", remedy)
	}

	// Only the read's own frame, or none at all, is not a frame miss.
	for _, held := range [][]CallGraphRecord{nil, {{Frame: host}}, {{}}} {
		if _, _, ok := FrameMissReason(local, held, host, "", "this scan's"); ok {
			t.Errorf("%v reported as a frame miss", held)
		}
	}
}
