package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestAuditDependencyNodes_ExcludesLocalRoot guards the shape audit now derives
// its rows from: a single project walk whose graph holds the local root plus
// every scoped dependency. Audit must report one row per dependency and never
// a row for the local main module, and it must carry each node's own direct-vs-
// transitive flag rather than marking every row direct.
func TestAuditDependencyNodes_ExcludesLocalRoot(t *testing.T) {
	local := fetchdomain.ModuleCoordinate{Path: "example.com/app", Version: fetchdomain.LocalVersion}
	direct := fetchdomain.ModuleCoordinate{Path: "example.com/direct", Version: "v1.0.0"}
	transitive := fetchdomain.ModuleCoordinate{Path: "example.com/transitive", Version: "v2.0.0"}

	rec := walkdomain.WalkRecord{
		Target: local,
		Graph: walkdomain.Graph{
			Target: local,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: local, DirectDependency: false},
				{Coordinate: direct, DirectDependency: true},
				{Coordinate: transitive, DirectDependency: false},
			},
		},
	}

	nodes := auditDependencyNodes(rec, local)

	if len(nodes) != 2 {
		t.Fatalf("want 2 dependency nodes (local root excluded), got %d", len(nodes))
	}
	if nodes[0].Coordinate != direct {
		t.Errorf("want first row %s, got %s", direct, nodes[0].Coordinate)
	}
	if !nodes[0].DirectDependency {
		t.Errorf("direct dependency %s must keep its direct flag", direct)
	}
	if nodes[1].Coordinate != transitive {
		t.Errorf("want second row %s, got %s", transitive, nodes[1].Coordinate)
	}
	if nodes[1].DirectDependency {
		t.Errorf("transitive dependency %s must not be marked direct", transitive)
	}
	for _, n := range nodes {
		if n.Coordinate == local {
			t.Fatalf("local root %s must never appear as an audit row", local)
		}
	}
}

// A walk with only the local root (an empty dependency set) yields no rows.
func TestAuditDependencyNodes_RootOnly(t *testing.T) {
	local := fetchdomain.ModuleCoordinate{Path: "example.com/app", Version: fetchdomain.LocalVersion}
	rec := walkdomain.WalkRecord{
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: local}}},
	}
	if nodes := auditDependencyNodes(rec, local); len(nodes) != 0 {
		t.Errorf("want no dependency rows for a root-only walk, got %d", len(nodes))
	}
}

// TestAuditBlockingErr guards audit must exit non-zero when any
// result is a hard compliance block (undetermined license under
// unknown_license=block), and stay nil otherwise.
func TestAuditBlockingErr(t *testing.T) {
	clean := []auditModuleResult{
		{Coordinate: "ok/a@v1", LicenseResolved: true},
		{Coordinate: "ok/b@v1", LicenseResolved: false, PolicyBlocking: false}, // uncertain but not blocking
	}
	if err := auditBlockingErr(clean); err != nil {
		t.Errorf("non-blocking results returned error: %v", err)
	}
	blocked := []auditModuleResult{
		{Coordinate: "ok/a@v1", LicenseResolved: true},
		{Coordinate: "ok/b@v1", LicenseResolved: false, PolicyBlocking: false},
		{Coordinate: "risk/c@v1", LicenseResolved: false, PolicyBlocking: true},
	}
	err := auditBlockingErr(blocked)
	if err == nil {
		t.Fatal("blocking result did not produce a non-zero exit error")
	}
	if !strings.Contains(err.Error(), "risk/c@v1") {
		t.Errorf("error should name the blocked module, got: %v", err)
	}
}

func TestAuditCmd_ToolAndProjectMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"audit", "--gomod", path, "--tool", "--project"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when both --tool and --project given")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestPrintAuditTable_ScopeColumn(t *testing.T) {
	results := []auditModuleResult{
		{
			Coordinate:    "github.com/foo/bar@v1.0.0",
			Scope:         "production",
			Verification:  "Verified",
			License:       "MIT",
			LicenseStatus: "Detected",
			VulnStatus:    "Clean",
			IsLatest:      true,
		},
		{
			Coordinate:    "golang.org/x/tools@v0.30.0",
			Scope:         "tool",
			Verification:  "Verified",
			License:       "BSD-3-Clause",
			LicenseStatus: "Detected",
			VulnStatus:    "Clean",
			IsLatest:      true,
		},
	}
	var buf strings.Builder
	if err := printAuditTable(&buf, results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "production") {
		t.Errorf("expected 'production' scope label in output:\n%s", out)
	}
	if !strings.Contains(out, "tool") {
		t.Errorf("expected 'tool' scope label in output:\n%s", out)
	}
}

func TestPrintAuditTable_NoScopeColumn(t *testing.T) {
	// When no results have a Scope set, the scope column must not appear.
	results := []auditModuleResult{
		{
			Coordinate:    "github.com/foo/bar@v1.0.0",
			Verification:  "Verified",
			License:       "MIT",
			LicenseStatus: "Detected",
			VulnStatus:    "Clean",
			IsLatest:      true,
		},
	}
	var buf strings.Builder
	if err := printAuditTable(&buf, results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// "production" and "tool" must not appear as column values when scope is empty.
	if strings.Contains(out, "production") || strings.Contains(out, "  tool  ") {
		t.Errorf("unexpected scope column in output when scope is empty:\n%s", out)
	}
}

func TestPrintAuditTable(t *testing.T) {
	tests := []struct {
		name    string
		results []auditModuleResult
		checks  []string
		absent  []string
	}{
		{
			name: "clean detected license current version",
			results: []auditModuleResult{
				{
					Coordinate:    "github.com/foo/bar@v1.0.0",
					Verification:  "Verified",
					License:       "MIT",
					LicenseStatus: "Detected",
					VulnStatus:    "Clean",
					IsLatest:      true,
				},
			},
			checks: []string{"github.com/foo/bar@v1.0.0", "Verified", "MIT", "Clean", "current"},
			// Detected license shows no status annotation
			absent: []string{"[Detected]", "latest:"},
		},
		{
			name: "ambiguous license shows status annotation",
			results: []auditModuleResult{
				{
					Coordinate:    "github.com/foo/bar@v1.0.0",
					Verification:  "Verified",
					License:       "Apache-2.0",
					LicenseStatus: "Ambiguous",
					VulnStatus:    "Clean",
					IsLatest:      true,
				},
			},
			checks: []string{"Apache-2.0 [Ambiguous]"},
		},
		{
			name: "affected with findings count",
			results: []auditModuleResult{
				{
					Coordinate:    "github.com/foo/bar@v1.0.0",
					Verification:  "Verified",
					License:       "MIT",
					LicenseStatus: "Detected",
					VulnStatus:    "Affected",
					VulnFindings:  3,
					IsLatest:      true,
				},
			},
			checks: []string{"Affected (3 findings)"},
		},
		{
			name: "stale dep shows latest version",
			results: []auditModuleResult{
				{
					Coordinate:    "github.com/foo/bar@v1.0.0",
					Verification:  "Verified",
					License:       "MIT",
					LicenseStatus: "Detected",
					VulnStatus:    "Clean",
					IsLatest:      false,
					LatestVersion: "v1.5.0",
					DaysBehind:    45,
				},
			},
			checks: []string{"latest: v1.5.0", "45 days ago"},
			absent: []string{"current"},
		},
		{
			name: "stale dep released today",
			results: []auditModuleResult{
				{
					Coordinate:    "github.com/foo/bar@v1.0.0",
					Verification:  "Verified",
					License:       "MIT",
					LicenseStatus: "Detected",
					VulnStatus:    "Clean",
					IsLatest:      false,
					LatestVersion: "v1.1.0",
					DaysBehind:    0,
				},
			},
			checks: []string{"latest: v1.1.0", "today"},
		},
		{
			name: "walk failed module",
			results: []auditModuleResult{
				{
					Coordinate:    "github.com/foo/bar@v1.0.0",
					Verification:  "(walk failed)",
					License:       "(not run)",
					LicenseStatus: "(not run)",
					VulnStatus:    "(not run)",
					IsLatest:      true,
				},
			},
			checks: []string{"github.com/foo/bar@v1.0.0", "(walk failed)", "(not run)"},
		},
		{
			name:    "empty results",
			results: []auditModuleResult{},
			checks:  []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			if err := printAuditTable(&buf, tc.results); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := buf.String()
			for _, want := range tc.checks {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in output:\n%s", want, got)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("unexpected %q in output:\n%s", absent, got)
				}
			}
		})
	}
}

func TestAuditCmd_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"audit", "--help"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	for _, flag := range []string{"--gomod", "--force", "--fresh", "--goproxy", "--skip-vcs-verify"} {
		if !strings.Contains(out, flag) {
			t.Errorf("expected %q in help output, got: %q", flag, out)
		}
	}
}

// TestAuditCmd_SkipVCSVerifyFlagRegistered guards the parity gap that made
// audit reject --skip-vcs-verify as an unknown flag even though every other
// go.mod command (fetch/walk/inspect) accepts it. The flag must be registered
// on the command and bound to the audit flag set.
func TestAuditCmd_SkipVCSVerifyFlagRegistered(t *testing.T) {
	cmd := newAuditCmd(io.Discard, io.Discard)
	flag := cmd.Flags().Lookup("skip-vcs-verify")
	if flag == nil {
		t.Fatal("audit must register --skip-vcs-verify")
	}
	if flag.DefValue != "false" {
		t.Errorf("--skip-vcs-verify default = %q, want false", flag.DefValue)
	}
}

// TestAuditCmd_SkipVCSVerifyAccepted confirms the flag parses end-to-end: an
// empty-scope go.mod returns before any network call, so this exercises flag
// acceptance without a fetch. Before the fix this failed with
// "unknown flag: --skip-vcs-verify".
func TestAuditCmd_SkipVCSVerifyAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"audit", "--gomod", path, "--skip-vcs-verify"}, &stdout, &stderr); err != nil {
		t.Fatalf("audit --skip-vcs-verify should be accepted, got: %v", err)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected empty-scope message, got: %q", stdout.String())
	}
}

func TestAuditCmd_GomodDefault_NotFound(t *testing.T) {
	// Run from a temp dir that has no go.mod so the auto-detect fails.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	var stdout, stderr bytes.Buffer
	runErr := Run([]string{"audit"}, &stdout, &stderr)
	if runErr == nil {
		t.Fatal("expected error when no go.mod present")
	}
	if !strings.Contains(runErr.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", runErr)
	}
}

func TestAuditCmd_GomodDefault_Found(t *testing.T) {
	// Run from a temp dir that has a go.mod with no require directives.
	// Verifies auto-detection without making network calls.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/myapp\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	var stdout, stderr bytes.Buffer
	runErr := Run([]string{"audit"}, &stdout, &stderr)
	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected empty-scope message, got: %q", stdout.String())
	}
}

func TestAuditCmd_GomodMissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"audit", "--gomod", "/nonexistent/go.mod"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing go.mod")
	}
	// The shared scope resolver shells out to the Go toolchain in the go.mod's
	// directory; a missing path surfaces as a resolution error.
	if !strings.Contains(err.Error(), "resolving code scope") {
		t.Errorf("expected 'resolving code scope' in error, got: %v", err)
	}
}

// A module with no Go packages has an empty code scope; audit reports that
// rather than walking anything.
func TestAuditCmd_EmptyCodeScope(t *testing.T) {
	gomod := "module example.com/myapp\n\ngo 1.21\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run([]string{"audit", "--gomod", path}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no code dependencies found") {
		t.Errorf("expected empty-scope message, got: %q", stdout.String())
	}
}
