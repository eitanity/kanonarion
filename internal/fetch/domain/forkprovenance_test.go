package domain

import (
	"strings"
	"testing"
)

func TestInferForkProvenance_ForkShapedPathYieldsCaveatedIndicator(t *testing.T) {
	got := InferForkProvenance("github.com/someuser/cobra")

	if got.Status != ForkProvenancePathMatch {
		t.Fatalf("Status = %v, want %v", got.Status, ForkProvenancePathMatch)
	}
	if len(got.Indicators) != 1 {
		t.Fatalf("Indicators = %v, want exactly one", got.Indicators)
	}
	ind := got.Indicators[0]
	if ind.Canonical != "github.com/spf13/cobra" {
		t.Errorf("Canonical = %q, want %q", ind.Canonical, "github.com/spf13/cobra")
	}
	if !strings.Contains(ind.Statement, "suggests a fork of github.com/spf13/cobra") {
		t.Errorf("Statement %q does not phrase the finding as a suggestion", ind.Statement)
	}
	if !strings.Contains(ind.Statement, "verify") {
		t.Errorf("Statement %q lacks the verify caveat", ind.Statement)
	}
	if got.CatalogueVersion != ForkCatalogueVersion {
		t.Errorf("CatalogueVersion = %q, want %q", got.CatalogueVersion, ForkCatalogueVersion)
	}
}

func TestInferForkProvenance_UnrelatedPathYieldsNoneDistinctFromNotAnalysed(t *testing.T) {
	got := InferForkProvenance("github.com/eitanity/kanonarion")

	if got.Status != ForkProvenanceNone {
		t.Fatalf("Status = %v, want %v", got.Status, ForkProvenanceNone)
	}
	if len(got.Indicators) != 0 {
		t.Fatalf("Indicators = %v, want none", got.Indicators)
	}
	if got.Status == ForkProvenanceNotAnalysed {
		t.Fatal("analysed-no-fork must be distinguishable from not-analysed")
	}
	if got.CatalogueVersion != ForkCatalogueVersion {
		t.Errorf("CatalogueVersion = %q, want %q", got.CatalogueVersion, ForkCatalogueVersion)
	}
}

func TestForkProvenance_ZeroValueReadsAsNotAnalysed(t *testing.T) {
	var zero ForkProvenance
	if zero.Status != ForkProvenanceNotAnalysed {
		t.Fatalf("zero-value Status = %v, want %v", zero.Status, ForkProvenanceNotAnalysed)
	}
}

func TestInferForkProvenance_CanonicalItselfIsNotAFork(t *testing.T) {
	for _, path := range []string{
		"github.com/spf13/cobra",
		"go.uber.org/zap",
		"gopkg.in/yaml.v3",
		"github.com/labstack/echo/v4",
	} {
		got := InferForkProvenance(path)
		if got.Status != ForkProvenanceNone {
			t.Errorf("InferForkProvenance(%q).Status = %v, want %v", path, got.Status, ForkProvenanceNone)
		}
	}
}

func TestInferForkProvenance_OtherMajorVersionOfCanonicalIsNotAFork(t *testing.T) {
	for _, path := range []string{
		"github.com/labstack/echo",     // pre-/v4 era path of the catalogued canonical
		"github.com/spf13/cobra/v2",    // hypothetical future major of a canonical
		"gopkg.in/yaml.v2",             // earlier gopkg.in major of the catalogued yaml.v3
		"github.com/golang-jwt/jwt/v4", // earlier major of the catalogued jwt/v5
	} {
		got := InferForkProvenance(path)
		if got.Status != ForkProvenanceNone {
			t.Errorf("InferForkProvenance(%q).Status = %v, want %v", path, got.Status, ForkProvenanceNone)
		}
	}
}

func TestInferForkProvenance_MatchesAcrossHostOwnerAndVersionMarkers(t *testing.T) {
	cases := []struct {
		path      string
		canonical string
	}{
		{"gitlab.com/mirrors/logrus", "github.com/sirupsen/logrus"},
		{"github.com/someuser/cobra/v3", "github.com/spf13/cobra"},
		{"github.com/SomeUser/Cobra", "github.com/spf13/cobra"},
		{"example.org/forks/yaml.v3", "gopkg.in/yaml.v3"},
		{"github.com/someuser/echo", "github.com/labstack/echo/v4"},
		{"github.com/someuser/jwt", "github.com/golang-jwt/jwt/v5"},
	}
	for _, tc := range cases {
		got := InferForkProvenance(tc.path)
		if got.Status != ForkProvenancePathMatch {
			t.Errorf("InferForkProvenance(%q).Status = %v, want %v", tc.path, got.Status, ForkProvenancePathMatch)
			continue
		}
		if len(got.Indicators) != 1 || got.Indicators[0].Canonical != tc.canonical {
			t.Errorf("InferForkProvenance(%q).Indicators = %v, want one indicator for %q", tc.path, got.Indicators, tc.canonical)
		}
	}
}

func TestInferForkProvenance_NameMustMatchExactly(t *testing.T) {
	// Affix variants ("jwt-go" vs "jwt") are below the cheap tier's bar: only
	// an identical trailing element is a signal.
	for _, path := range []string{
		"github.com/someuser/jwt-go",
		"github.com/someuser/cobras",
		"github.com/someuser/go-cobra",
	} {
		got := InferForkProvenance(path)
		if got.Status != ForkProvenanceNone {
			t.Errorf("InferForkProvenance(%q).Status = %v, want %v", path, got.Status, ForkProvenanceNone)
		}
	}
}

func TestInferForkProvenance_DegenerateInputsDoNotPanic(t *testing.T) {
	for _, path := range []string{"", "cobra", "v2", "/", "gopkg.in/"} {
		got := InferForkProvenance(path)
		if got.Status == ForkProvenanceNotAnalysed {
			t.Errorf("InferForkProvenance(%q) returned not-analysed; the function always analyses", path)
		}
	}
}

func TestInferForkProvenance_BareNameMatchesCanonical(t *testing.T) {
	// A single-element path is its own trailing element.
	got := InferForkProvenance("cobra")
	if got.Status != ForkProvenancePathMatch {
		t.Fatalf("Status = %v, want %v", got.Status, ForkProvenancePathMatch)
	}
}

func TestInferForkProvenance_MultipleMatchesAreSortedByCanonical(t *testing.T) {
	catalogue := []string{
		"gitlab.com/zzz/widget",
		"github.com/aaa/widget",
	}
	got := inferForkProvenance("example.com/forks/widget", catalogue)
	if len(got.Indicators) != 2 {
		t.Fatalf("Indicators = %v, want two", got.Indicators)
	}
	if got.Indicators[0].Canonical != "github.com/aaa/widget" || got.Indicators[1].Canonical != "gitlab.com/zzz/widget" {
		t.Errorf("Indicators not sorted by canonical: %v", got.Indicators)
	}
}

func TestInferForkProvenance_CanonicalIdentityWinsOverSharedName(t *testing.T) {
	// When the candidate is itself catalogued, another entry sharing its
	// trailing element must not turn it into a fork suggestion.
	catalogue := []string{
		"github.com/aaa/widget",
		"gitlab.com/zzz/widget",
	}
	got := inferForkProvenance("gitlab.com/zzz/widget", catalogue)
	if got.Status != ForkProvenanceNone {
		t.Fatalf("Status = %v, want %v", got.Status, ForkProvenanceNone)
	}
}

func TestForkProvenanceStatus_StringValuesAreStable(t *testing.T) {
	cases := map[ForkProvenanceStatus]string{
		ForkProvenanceNotAnalysed: "not_analysed",
		ForkProvenanceNone:        "none",
		ForkProvenancePathMatch:   "path_match",
	}
	for status, want := range cases {
		if got := status.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", status, got, want)
		}
	}
}

func TestInferForkProvenance_IsDeterministic(t *testing.T) {
	first := InferForkProvenance("github.com/someuser/cobra")
	for range 10 {
		again := InferForkProvenance("github.com/someuser/cobra")
		if len(again.Indicators) != len(first.Indicators) {
			t.Fatalf("indicator count varies between runs")
		}
		for i := range again.Indicators {
			if again.Indicators[i] != first.Indicators[i] {
				t.Fatalf("indicator %d varies between runs: %v vs %v", i, again.Indicators[i], first.Indicators[i])
			}
		}
	}
}
