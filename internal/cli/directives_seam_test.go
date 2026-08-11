package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	dirapp "github.com/eitanity/kanonarion/internal/directive/application"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
)

// A missing scan is surfaced as ExitNotFound, never an empty success.
func TestDirectivesShowWith_NotFound(t *testing.T) {
	ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{Found: false}}
	var out bytes.Buffer
	err := directivesShowWith(context.Background(), ctr, "missing-scan", &out, io.Discard)
	requireExit(t, err, ExitNotFound)
}

// A found scan renders its header and table (text mode).
func TestDirectivesShowWith_Renders(t *testing.T) {
	ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{
		Found: true,
		Scan:  directivedomain.Record{ID: "SCAN-1", ProjectModulePath: "example.com/proj"},
	}}
	var out bytes.Buffer
	if err := directivesShowWith(context.Background(), ctr, "SCAN-1", &out, io.Discard); err != nil {
		t.Fatalf("directivesShowWith: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "SCAN-1") || !strings.Contains(got, "example.com/proj") {
		t.Errorf("rendered scan missing header fields:\n%s", got)
	}
}

// A missing scan on either side of a diff is surfaced as ExitNotFound.
func TestDirectivesDiffWith_ScanNotFound(t *testing.T) {
	ctr := &Container{DiffDirectives: &testfakes.FakeDiffDirectives{
		Err: &dirapp.ErrScanNotFound{ScanID: "SCAN-X"},
	}}
	var out bytes.Buffer
	err := directivesDiffWith(context.Background(), ctr, "SCAN-A", "SCAN-X", &out)
	requireExit(t, err, ExitNotFound)
}

// A diff with no changes reports that explicitly (text mode).
func TestDirectivesDiffWith_NoChanges(t *testing.T) {
	scan := directivedomain.Record{Directives: []directivedomain.Directive{{}, {}}}
	ctr := &Container{DiffDirectives: &testfakes.FakeDiffDirectives{
		Result: directivedomain.DirectiveDiff{ScanA: scan, ScanB: scan},
	}}
	var out bytes.Buffer
	if err := directivesDiffWith(context.Background(), ctr, "SCAN-A", "SCAN-B", &out); err != nil {
		t.Fatalf("directivesDiffWith: %v", err)
	}
	// The population is stated with the zero: two scans agreeing on two
	// directives and two scans that each found none are different findings.
	for _, want := range []string{"No directive changes", "the same 2 directives"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("expected %q, got:\n%s", want, out.String())
		}
	}
}

// An empty scan list reports the empty set explicitly.
func TestDirectivesListWith_Empty(t *testing.T) {
	ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{Scans: nil}}
	var out bytes.Buffer
	if err := directivesListWith(context.Background(), ctr, "example.com/proj", 10, 0, &out, io.Discard); err != nil {
		t.Fatalf("directivesListWith: %v", err)
	}
	if !strings.Contains(out.String(), `the store holds no directive scan at all, so project "example.com/proj" is not what made this empty`) {
		t.Errorf("expected empty-set notice, got:\n%s", out.String())
	}
}

// A populated scan list renders the table.
func TestDirectivesListWith_Renders(t *testing.T) {
	ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{
		Scans: []directivedomain.Record{{ID: "SCAN-1", ProjectModulePath: "example.com/proj"}},
	}}
	var out bytes.Buffer
	if err := directivesListWith(context.Background(), ctr, "example.com/proj", 10, 0, &out, io.Discard); err != nil {
		t.Fatalf("directivesListWith: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "SCAN ID") || !strings.Contains(got, "SCAN-1") {
		t.Errorf("expected a scan table, got:\n%s", got)
	}
}

// A populated scan list with --json emits snake_case keys, not PascalCase.
func TestDirectivesListWith_SnakeCaseJSON(t *testing.T) {
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{
		Scans: []directivedomain.Record{{ID: "SCAN-1", ProjectModulePath: "example.com/proj"}},
	}}
	var out bytes.Buffer
	if err := directivesListWith(context.Background(), ctr, "example.com/proj", 10, 0, &out, io.Discard); err != nil {
		t.Fatalf("directivesListWith: %v", err)
	}
	got := out.String()
	for _, pascal := range []string{`"ID"`, `"CompletedAt"`, `"ContentHash"`, `"Directives"`} {
		if strings.Contains(got, pascal) {
			t.Errorf("PascalCase key %s found in --json output: %s", pascal, got)
		}
	}
	if !strings.Contains(got, `"id"`) || !strings.Contains(got, `"completed_at"`) {
		t.Errorf("expected snake_case keys in --json output: %s", got)
	}
}
