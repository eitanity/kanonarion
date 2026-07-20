package cli

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestBuildProvenance_ForkShapedPath(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "github.com/someuser/cobra", Version: "v1.0.0"}

	got := buildProvenance(coord)

	fh := got.ForkHeuristic
	if fh.Status != forkStatusPathMatch {
		t.Fatalf("Status = %q, want %q", fh.Status, forkStatusPathMatch)
	}
	if fh.CatalogueVersion != fetchdomain.ForkCatalogueVersion {
		t.Errorf("CatalogueVersion = %q, want %q", fh.CatalogueVersion, fetchdomain.ForkCatalogueVersion)
	}
	if len(fh.ForkIndicators) != 1 {
		t.Fatalf("ForkIndicators = %v, want exactly one", fh.ForkIndicators)
	}
	if fh.ForkIndicators[0].Canonical != "github.com/spf13/cobra" {
		t.Errorf("Canonical = %q, want %q", fh.ForkIndicators[0].Canonical, "github.com/spf13/cobra")
	}
	if !strings.Contains(fh.ForkIndicators[0].Statement, "verify") {
		t.Errorf("Statement %q lacks the verify caveat", fh.ForkIndicators[0].Statement)
	}
}

func TestBuildProvenance_UnrelatedPathIsAnalysedNone(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "example.com/some/app", Version: "v1.0.0"}

	got := buildProvenance(coord)

	fh := got.ForkHeuristic
	if fh.Status != forkStatusNone {
		t.Fatalf("Status = %q, want %q", fh.Status, forkStatusNone)
	}
	if fh.Status == fetchdomain.ForkProvenanceNotAnalysed.String() {
		t.Fatal("analysed-no-fork must be distinguishable from not-analysed")
	}
	if len(fh.ForkIndicators) != 0 {
		t.Errorf("ForkIndicators = %v, want none", fh.ForkIndicators)
	}
	if fh.CatalogueVersion == "" {
		t.Error("CatalogueVersion is empty; analysed sections must carry the catalogue version")
	}
}

func TestPrintContextSummary_ProvenancePathMatch(t *testing.T) {
	out := makeNotRunOutput(contextCommands{})
	out.Provenance = buildProvenance(coordinate.ModuleCoordinate{Path: "github.com/someuser/cobra", Version: "v1.0.0"})

	var buf strings.Builder
	if err := printContextText(out, true, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "Provenance:      path suggests a fork of github.com/spf13/cobra") {
		t.Errorf("summary missing fork statement\ngot:\n%s", got)
	}
}

func TestPrintContextSummary_ProvenanceNone(t *testing.T) {
	out := makeNotRunOutput(contextCommands{})
	out.Provenance = buildProvenance(coordinate.ModuleCoordinate{Path: "example.com/some/app", Version: "v1.0.0"})

	var buf strings.Builder
	if err := printContextText(out, true, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "Provenance:      no fork indicators") {
		t.Errorf("summary missing analysed-no-fork line\ngot:\n%s", got)
	}
}

func TestPrintContextSummary_ProvenanceNotAnalysedZeroValue(t *testing.T) {
	// An output assembled without buildProvenance must read as uncertainty,
	// never as a confident "no fork indicators".
	out := makeNotRunOutput(contextCommands{})

	var buf strings.Builder
	if err := printContextText(out, true, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "Provenance:      (not analysed)") {
		t.Errorf("summary missing not-analysed line\ngot:\n%s", got)
	}
	if strings.Contains(got, "no fork indicators") {
		t.Errorf("not-analysed output must not claim no fork indicators\ngot:\n%s", got)
	}
}

func TestPrintContextFull_ProvenanceSection(t *testing.T) {
	out := makeNotRunOutput(contextCommands{})
	out.Provenance = buildProvenance(coordinate.ModuleCoordinate{Path: "gitlab.com/mirrors/logrus", Version: "v1.0.0"})

	var buf strings.Builder
	if err := printContextFull(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{
		"=== Provenance ===",
		"Fork Heuristic: path_match",
		"path suggests a fork of github.com/sirupsen/logrus",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("full output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestPrintContextFull_ProvenanceNotAnalysedZeroValue(t *testing.T) {
	out := makeNotRunOutput(contextCommands{})

	var buf strings.Builder
	if err := printContextFull(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "Fork Heuristic: (not analysed)") {
		t.Errorf("full output missing not-analysed line\ngot:\n%s", got)
	}
}
