package cli

import (
	"encoding/json"
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func setJSONOut(t *testing.T, v bool) {
	t.Helper()
	prev := jsonOut
	jsonOut = v
	t.Cleanup(func() { jsonOut = prev })
}

func TestRunProvenance_JSONForkShapedPath(t *testing.T) {
	setJSONOut(t, true)

	var buf strings.Builder
	if err := runProvenance("github.com/someuser/cobra", "v1.0.0", &buf); err != nil {
		t.Fatal(err)
	}

	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	if out.Module != "github.com/someuser/cobra" || out.Version != "v1.0.0" {
		t.Errorf("module/version = %q/%q, want echo of input", out.Module, out.Version)
	}
	if out.ForkHeuristic.Status != forkStatusPathMatch {
		t.Errorf("status = %q, want %q", out.ForkHeuristic.Status, forkStatusPathMatch)
	}
	if out.ForkHeuristic.CatalogueVersion != fetchdomain.ForkCatalogueVersion {
		t.Errorf("catalogue_version = %q, want %q", out.ForkHeuristic.CatalogueVersion, fetchdomain.ForkCatalogueVersion)
	}
	if len(out.ForkHeuristic.ForkIndicators) != 1 ||
		out.ForkHeuristic.ForkIndicators[0].Canonical != "github.com/spf13/cobra" {
		t.Errorf("fork_indicators = %v, want one for github.com/spf13/cobra", out.ForkHeuristic.ForkIndicators)
	}
}

func TestRunProvenance_JSONUnrelatedPathIsAnalysedNone(t *testing.T) {
	setJSONOut(t, true)

	var buf strings.Builder
	if err := runProvenance("example.com/some/app", "", &buf); err != nil {
		t.Fatal(err)
	}

	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	if out.ForkHeuristic.Status != forkStatusNone {
		t.Errorf("status = %q, want %q (analysed, no indicators)", out.ForkHeuristic.Status, forkStatusNone)
	}
	if out.ForkHeuristic.Status == fetchdomain.ForkProvenanceNotAnalysed.String() {
		t.Error("analysed-no-fork must be distinguishable from not-analysed")
	}
	if len(out.ForkHeuristic.ForkIndicators) != 0 {
		t.Errorf("fork_indicators = %v, want none", out.ForkHeuristic.ForkIndicators)
	}
	if strings.Contains(buf.String(), `"version"`) {
		t.Errorf("version should be omitted when not supplied\ngot:\n%s", buf.String())
	}
}

func TestRunProvenance_TextForkShapedPath(t *testing.T) {
	setJSONOut(t, false)

	var buf strings.Builder
	if err := runProvenance("gitlab.com/mirrors/logrus", "", &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{
		"gitlab.com/mirrors/logrus",
		"Fork Heuristic: path_match",
		"path suggests a fork of github.com/sirupsen/logrus",
		"verify",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestRunProvenance_TextUnrelatedPath(t *testing.T) {
	setJSONOut(t, false)

	var buf strings.Builder
	if err := runProvenance("example.com/some/app", "v2.3.4", &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "example.com/some/app@v2.3.4") {
		t.Errorf("text output missing module header\ngot:\n%s", got)
	}
	if !strings.Contains(got, "no fork indicators") {
		t.Errorf("text output missing analysed-no-fork line\ngot:\n%s", got)
	}
}

func TestProvenanceCmd_RejectsEmptyModulePath(t *testing.T) {
	var stdout, stderr strings.Builder
	root := newRootCmd(&stdout, &stderr)
	root.SetArgs([]string{"provenance", "@v1.0.0"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected usage error for empty module path")
	}
}

func TestProvenanceCmd_ExitsZeroOnPathMatch(t *testing.T) {
	// A fork indicator is a fact view, not a policy gate: the command must
	// succeed even when the heuristic fires.
	setJSONOut(t, false)
	var stdout, stderr strings.Builder
	root := newRootCmd(&stdout, &stderr)
	root.SetArgs([]string{"provenance", "github.com/someuser/cobra"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() = %v, want nil", err)
	}
	if !strings.Contains(stdout.String(), "path suggests a fork of github.com/spf13/cobra") {
		t.Errorf("stdout missing fork statement\ngot:\n%s", stdout.String())
	}
}
