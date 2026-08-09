package cli

import (
	"bytes"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestCallGraphShow_NamesPrefixAttributedPackages: where membership was
// reconstructed from a path prefix rather than taken from the toolchain, the
// record dump says so, and names the packages.
//
// The silent version is the failure this closes. "In module" decided by the
// build and "in module" decided by a string prefix read identically, and only
// one of them is a measurement.
func TestCallGraphShow_NamesPrefixAttributedPackages(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.NodeCount = len(rec.Nodes)
	rec.PrefixAttributedPackages = []string{"example.com/m/legacy"}

	var buf bytes.Buffer
	if err := printCallGraphRecord(rec, 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"module membership:", "PATH PREFIX", "example.com/m/legacy"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestCallGraphShow_SaysNothingWhenTheToolchainPlacedEveryPackage is the
// control: the line is a report of a reconstruction, so a record with none must
// not carry it. A line on every record would be noise, and noise is what stops
// the exceptional case being read.
func TestCallGraphShow_SaysNothingWhenTheToolchainPlacedEveryPackage(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.NodeCount = len(rec.Nodes)

	var buf bytes.Buffer
	if err := printCallGraphRecord(rec, 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	if strings.Contains(buf.String(), "module membership:") {
		t.Errorf("record with no prefix attribution still reported one:\n%s", buf.String())
	}
}
