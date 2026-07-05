package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
)

func TestEcosystemOrDefault(t *testing.T) {
	if got := ecosystemOrDefault(""); got != domain.EcosystemGo {
		t.Errorf("empty ecosystem => %q, want %q", got, domain.EcosystemGo)
	}
	if got := ecosystemOrDefault("go"); got != "go" {
		t.Errorf("non-empty ecosystem => %q, want go", got)
	}
}

// errScanner always fails, exercising scanRecord's Scan-error path.
type errScanner struct{}

func (errScanner) Scan(...any) error { return errors.New("scan boom") }

func TestScanRecordScanError(t *testing.T) {
	if _, err := scanRecord(errScanner{}); err == nil || !strings.Contains(err.Error(), "scanning sbom record") {
		t.Fatalf("want scan error, got: %v", err)
	}
}

// A stored row whose generated_at is not RFC3339 must fail the scan loudly on
// both the single-row (Get) and multi-row (List) read paths, rather than
// yielding a zero time.
func TestScanRecordRejectsUnparseableTimestamp(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Insert directly, bypassing PutSBOMRecord's RFC3339 formatting, to plant a
	// corrupted timestamp.
	if _, err := s.db.DB().ExecContext(context.Background(), `
INSERT INTO sbom_records
    (id, ecosystem, walk_id, walk_scan_run_id, format, pipeline_version,
     generated_at, content_hash, content, operator, licenses_incomplete)
VALUES ('bad', 'go', 'walk-1', NULL, 'cyclonedx-1.5', '0.3.0',
        'not-a-timestamp', 'h', 'x', 'op', 0)`); err != nil {
		t.Fatalf("raw insert: %v", err)
	}

	if _, err := s.GetSBOMRecord(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "generated_at") {
		t.Fatalf("Get: want generated_at parse error, got: %v", err)
	}
	if _, err := s.ListSBOMRecords(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "generated_at") {
		t.Fatalf("List: want generated_at parse error, got: %v", err)
	}
}
