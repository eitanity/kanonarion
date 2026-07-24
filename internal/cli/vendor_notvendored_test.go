package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeUnvendoredProject creates a go.mod with no vendor/ directory beside it,
// which is what makes the scanner return ErrNotVendored.
func writeUnvendoredProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/myapp\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestVendorCmd_NotVendoredJSON guards that an unvendored project is reported
// to a --json caller as a section, not as prose. The not-vendored branch used
// to return above the jsonOut check, so it wrote a human sentence onto the
// data channel and exited 0 — leaving a parse error as the caller's only
// signal that anything was unusual.
func TestVendorCmd_NotVendoredJSON(t *testing.T) {
	gomod := writeUnvendoredProject(t)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"vendor", "--gomod", gomod, "--json", "--store-root", t.TempDir()},
		&stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v (stderr=%q)", err, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	var got vendorSection
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json did not emit JSON: %q", out)
	}

	// The status must distinguish "no vendor tree" from a reconciliation that
	// ran and found nothing. Reporting this as clean would present an absent
	// vendor tree as a verified one.
	if got.OverallStatus != vendorStatusNotVendored {
		t.Errorf("overall_status = %q, want %q", got.OverallStatus, vendorStatusNotVendored)
	}
	if got.Modules == nil {
		t.Error("modules decoded as null, want an empty array")
	}
	if got.Findings == nil {
		t.Error("findings decoded as null, want an empty array")
	}
	if len(got.Modules) != 0 || len(got.Findings) != 0 {
		t.Errorf("expected no modules or findings, got %d/%d", len(got.Modules), len(got.Findings))
	}
}

// TestVendorCmd_NotVendoredTextKeepsProse guards that routing the not-vendored
// case to JSON did not silently drop the human answer on the text path.
func TestVendorCmd_NotVendoredText(t *testing.T) {
	gomod := writeUnvendoredProject(t)

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"vendor", "--gomod", gomod, "--store-root", t.TempDir()},
		&stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v (stderr=%q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "project is not vendored") {
		t.Errorf("expected the not-vendored sentence, got: %q", stdout.String())
	}
}
