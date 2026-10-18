package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func tinyGoRecord() domain.CallGraphRecord {
	return domain.CallGraphRecord{
		Frame: domain.BuildFrame{GOOS: "linux", GOARCH: "arm", TinyGoTarget: "pico", TinyGoVersion: "0.42.0"},
		Nodes: []domain.CallNode{
			{ID: "machine.gpioHandleInterrupt", Symbol: "gpioHandleInterrupt",
				InterruptHandler: domain.InterruptHandler{Kind: domain.HandlerInterruptNew, Site: domain.SourcePosition{File: "src/machine/machine_rp2_gpio.go", Line: 246}}},
			{ID: "example.com/devarm.main", Symbol: "main"},
		},
		Edges: []domain.CallEdge{
			{FromID: "example.com/devarm.main", ToID: "runtime.alloc", Confidence: domain.ConfidenceDirect, Kind: domain.EdgeKindCompilerInserted},
			{FromID: "runtime.callMain", ToID: "example.com/devarm.main", Confidence: domain.ConfidenceDirect, Kind: domain.EdgeKindLinkname},
			{FromID: "example.com/devarm.main", ToID: "machine.Pin.Configure", Confidence: domain.ConfidenceDirect},
			{FromID: "example.com/devarm.main", ToID: "example.com/devarm.onPin", Confidence: domain.ConfidenceDirect, Kind: domain.EdgeKindReference},
		},
	}
}

func TestCallGraphJSON_TinyGoKindsAndHandler(t *testing.T) {
	b, err := json.Marshal(toCallGraphJSON(tinyGoRecord()))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{
		`"kind":"compiler-inserted"`, `"kind":"linkname"`, `"kind":"Call"`, `"kind":"Reference"`,
		`"interrupt_handler":{"kind":"interrupt.New","site_file":"src/machine/machine_rp2_gpio.go","site_line":246}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "interrupt_handler"); n != 1 {
		t.Errorf("interrupt_handler appears %d times, want 1: a node without one leaves the key out", n)
	}
}

// The two TinyGo kinds are calls with their own names, said beside the edge.
func TestEdgeKindLabelAndTag(t *testing.T) {
	for k, want := range map[domain.EdgeKind][2]string{
		domain.EdgeKindCall:             {"call", ""},
		domain.EdgeKindReference:        {"reference", "  [reference — the symbol's value is taken here, not called]"},
		domain.EdgeKindCompilerInserted: {"compiler-inserted", "  [compiler-inserted — TinyGo's compiler emits this call]"},
		domain.EdgeKindLinkname:         {"linkname", "  [linkname — //go:linkname supplies this body]"},
	} {
		if got := edgeKindLabel(k); got != want[0] {
			t.Errorf("edgeKindLabel(%q) = %q, want %q", k, got, want[0])
		}
		if got := edgeKindTag(k); got != want[1] {
			t.Errorf("edgeKindTag(%q) = %q, want %q", k, got, want[1])
		}
	}
}

func TestCallGraphShowText_CountsAndTagsTheTinyGoKinds(t *testing.T) {
	r := tinyGoRecord()
	r.NodeCount, r.EdgeCount = len(r.Nodes), len(r.Edges)
	var buf bytes.Buffer
	if err := printCallGraphRecord(r, 0, 0, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"— 1 compiler-inserted and 1 linkname edges",
		"example.com/devarm.main → runtime.alloc  [Direct] [compiler-inserted]",
		"runtime.callMain → example.com/devarm.main  [Direct] [linkname]",
		"example.com/devarm.main → machine.Pin.Configure  [Direct]\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	var none bytes.Buffer
	if err := writeFrameLine(&none, domain.CallGraphRecord{Frame: r.Frame}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(none.String(), "compiler-inserted") {
		t.Errorf("a record without TinyGo edges states a count: %q", none.String())
	}
}
