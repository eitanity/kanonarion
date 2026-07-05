package cli

import (
	"encoding/json"
	"strings"
	"testing"

	dirdomain "github.com/eitanity/kanonarion/internal/directive/domain"
)

// toDirectivesDiffJSON projects a domain DirectiveDiff into the JSON
// shape consumed by `directives diff --json`. The CLI promises the same
// directiveResult shape that `directives` emits, plus the diff envelope —
// this test pins that contract.
func TestToDirectivesDiffJSON_Shape(t *testing.T) {
	added := dirdomain.Directive{
		Kind: dirdomain.KindReplace, Source: "go.mod", Line: 7,
		OldPath: "example.com/foo", NewPath: "example.com/fork", NewVersion: "v2.0.0",
		Applied: true, Class: dirdomain.RiskHigh,
		ReachabilityTarget: "example.com/fork",
		PolicyOutcome:      "warn", PolicyBlocking: true,
	}
	removed := dirdomain.Directive{
		Kind: dirdomain.KindExclude, Source: "go.mod", Line: 9,
		OldPath: "example.com/legacy", OldVersion: "v0.1.0",
		Class: dirdomain.RiskLow, PolicyOutcome: "allow",
	}
	before := dirdomain.Directive{
		Kind: dirdomain.KindReplace, Source: "go.mod", Line: 11,
		OldPath: "example.com/baz", NewPath: "example.com/baz-fork", NewVersion: "v1",
		Class: dirdomain.RiskMedium, PolicyOutcome: "allow",
	}
	after := before
	after.Class = dirdomain.RiskHigh
	after.PolicyOutcome = "warn"
	after.PolicyBlocking = true

	diff := dirdomain.DirectiveDiff{
		ScanA:        dirdomain.Record{ID: "01A", ProjectModulePath: "example.com/proj"},
		ScanB:        dirdomain.Record{ID: "01B", ProjectModulePath: "example.com/proj"},
		Added:        []dirdomain.Directive{added},
		Removed:      []dirdomain.Directive{removed},
		Reclassified: []dirdomain.Reclassification{{Before: before, After: after}},
	}

	got := toDirectivesDiffJSON(diff)

	if got.Project != "example.com/proj" {
		t.Errorf("Project = %q, want example.com/proj", got.Project)
	}
	if got.ScanA != "01A" || got.ScanB != "01B" {
		t.Errorf("scan IDs = %q,%q want 01A,01B", got.ScanA, got.ScanB)
	}
	if len(got.Added) != 1 || got.Added[0].Directive.OldPath != "example.com/foo" {
		t.Errorf("Added projection wrong: %+v", got.Added)
	}
	if got.Added[0].Directive.Classification != "high" {
		t.Errorf("Classification not serialised: %q", got.Added[0].Directive.Classification)
	}
	if !got.Added[0].Directive.PolicyBlocking {
		t.Errorf("PolicyBlocking lost in projection")
	}
	if got.Reclassified[0].Before.Classification != "medium" || got.Reclassified[0].After.Classification != "high" {
		t.Errorf("Reclassified before/after classification incorrect: %+v", got.Reclassified[0])
	}

	// JSON-marshal the projection and assert the externally-promised key names
	// (snake_case, mirroring the `directives` command output).
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	for _, key := range []string{
		`"project"`, `"scan_a"`, `"scan_b"`,
		`"added"`, `"removed"`, `"reclassified"`,
		`"directive"`, `"before"`, `"after"`,
		`"classification"`, `"policy_outcome"`,
	} {
		if !strings.Contains(s, key) {
			t.Errorf("JSON missing key %s\nfull payload:\n%s", key, s)
		}
	}
}

// TestDirectiveLeftHandSide: the helper formats the old-path coordinate for
// diff output — with a version when present, plain path otherwise.
func TestDirectiveLeftHandSide(t *testing.T) {
	cases := []struct {
		d    dirdomain.Directive
		want string
	}{
		{dirdomain.Directive{OldPath: "example.com/foo", OldVersion: "v1.2.3"}, "example.com/foo@v1.2.3"},
		{dirdomain.Directive{OldPath: "example.com/bar"}, "example.com/bar"},
	}
	for _, c := range cases {
		if got := directiveLeftHandSide(c.d); got != c.want {
			t.Errorf("directiveLeftHandSide(%+v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// an empty diff (identical scans) projects to empty slices, not nil,
// so `directives diff --json` always emits a parseable [] for callers.
func TestToDirectivesDiffJSON_EmptyDiffEmitsEmptyArrays(t *testing.T) {
	diff := dirdomain.DirectiveDiff{
		ScanA: dirdomain.Record{ID: "X", ProjectModulePath: "p"},
		ScanB: dirdomain.Record{ID: "Y", ProjectModulePath: "p"},
	}
	got := toDirectivesDiffJSON(diff)

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"added":[]`, `"removed":[]`, `"reclassified":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("empty diff JSON missing %q\nfull payload: %s", want, string(raw))
		}
	}
}
