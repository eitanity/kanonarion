package localfs_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/adapters/scanner/localfs"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
)

const corpus = "../../../../../test/fixtures/supplychain/vendor"

func scan(t *testing.T, leaf string) domain.ParseResult {
	t.Helper()
	res, err := localfs.New().ScanProject(filepath.Join(corpus, leaf, "go.mod"), true)
	if err != nil {
		t.Fatalf("ScanProject(%s): %v", leaf, err)
	}
	return res
}

// TestScan_MatchingClean: a pristine vendored tree recomputes to the go.sum
// checksum, so domain reconciliation yields zero findings — and the airgapped
// (vendor-only) scan completes with no network (cases 1 & 5).
func TestScan_MatchingClean(t *testing.T) {
	res := scan(t, "matching")
	if !res.VendorOnly {
		t.Error("vendor-only flag not recorded")
	}
	if res.ComputedHashes["example.com/dep"] != res.GoSum["example.com/dep@v1.2.0"] {
		t.Errorf("pristine tree must match go.sum: computed=%q expected=%q",
			res.ComputedHashes["example.com/dep"], res.GoSum["example.com/dep@v1.2.0"])
	}
	_, findings := domain.Aggregate(res)
	if len(findings) != 0 {
		t.Errorf("matching fixture must be clean, got %+v", findings)
	}
}

// TestScan_Drift: one altered vendored file changes the recomputed hash so it
// no longer matches go.sum — drift with both hashes reported (case 2).
func TestScan_Drift(t *testing.T) {
	res := scan(t, "drift")
	if res.ComputedHashes["example.com/dep"] == res.GoSum["example.com/dep@v1.2.0"] {
		t.Fatal("drift fixture must not match the expected checksum")
	}
	_, findings := domain.Aggregate(res)
	var drift *domain.Finding
	for i := range findings {
		if findings[i].Kind == domain.FindingDrift {
			drift = &findings[i]
		}
	}
	if drift == nil {
		t.Fatalf("want drift finding, got %+v", findings)
	}
	if drift.Expected == "" || drift.Actual == "" || drift.Expected == drift.Actual {
		t.Errorf("drift must report both hashes: %+v", drift)
	}
}

// TestScan_MissingModule: modules.txt references a module with no files under
// vendor/ → missing-from-vendor inconsistency (case 3).
func TestScan_MissingModule(t *testing.T) {
	res := scan(t, "missing-module")
	_, findings := domain.Aggregate(res)
	found := false
	for _, f := range findings {
		if f.Kind == domain.FindingMissingFromVendor && f.Module == "example.com/dep" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want missing-from-vendor for example.com/dep, got %+v", findings)
	}
}

// TestScan_NotVendored: a project with no vendor/modules.txt yields the
// distinct ErrNotVendored sentinel, not a misleading empty-clean result.
func TestScan_NotVendored(t *testing.T) {
	_, err := localfs.New().ScanProject(
		filepath.Join("../../../../../test/fixtures/supplychain/godebug/clean", "go.mod"), false)
	if !errors.Is(err, ports.ErrNotVendored) {
		t.Fatalf("want ErrNotVendored, got %v", err)
	}
}
