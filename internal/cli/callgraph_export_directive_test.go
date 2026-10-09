package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func TestCallGraphJSON_NodeStatesItsExportDirective(t *testing.T) {
	r := domain.CallGraphRecord{Nodes: []domain.CallNode{
		{ID: "example.com/wvuln.parse", Symbol: "parse",
			ExportDirective: domain.ExportDirective{Kind: domain.ExportWasm, Name: "parse"}},
		{ID: "example.com/wvuln.irq", Symbol: "irq",
			ExportDirective: domain.ExportDirective{Kind: domain.ExportInterrupt}},
		{ID: "example.com/wvuln.main", Symbol: "main"},
	}}
	b, err := json.Marshal(toCallGraphJSON(r))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{
		`"export_directive":{"kind":"wasmexport","name":"parse"}`,
		`"export_directive":{"kind":"interrupt"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "export_directive"); n != 2 {
		t.Errorf("export_directive appears %d times, want 2: a node without one leaves the key out", n)
	}
}
