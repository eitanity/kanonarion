package application

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// snapshotBlobStore answers the snapshot read with a blob the test built, so the
// pre-extraction runs for real: the ZIP is extracted to a temp dir and the
// advisories in it are counted from the filesystem, which is the seam under
// test. The embedded nil port supplies the rest of the interface — nothing else
// may be reached before the run decides what the database is worth.
type snapshotBlobStore struct {
	ports.VulnerabilityStore
	blob []byte
}

func (s *snapshotBlobStore) GetDatabaseSnapshot(context.Context, domain.DatabaseSnapshot) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.blob)), nil
}

// vulnDBZip builds a govulncheck file:// database archive holding the named
// advisories. Passing none produces the empty database this whole guard exists
// for: index/db.json and index/modules.json are present and well-formed, the
// archive extracts cleanly, and it holds nothing.
func vulnDBZip(t *testing.T, advisoryIDs ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("creating %s in the archive: %v", name, err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatalf("writing %s in the archive: %v", name, err)
		}
	}
	add("index/db.json", `{"modified":"2026-07-30T00:00:00Z"}`)
	add("index/modules.json", `[]`)
	for _, id := range advisoryIDs {
		add("ID/"+id+".json", `{"id":"`+id+`"}`)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the archive: %v", err)
	}
	return buf.Bytes()
}

func emptySnapshotUseCase(blob []byte) *ScanWalkUseCase {
	return &ScanWalkUseCase{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		vulnStore: &snapshotBlobStore{blob: blob},
	}
}

// govulncheck answers a database holding no advisories with "No vulnerabilities
// found." and exit 0, so a run against one would seal a Clean verdict for every
// module while consulting nothing. The refusal and the recorded count are
// asserted as one relation rather than as two independent facts: before this
// change both databases produced the same silent extraction, so either
// assertion alone would have held while the distinction did not exist.
func TestPreExtractVulnDB_RefusesAnEmptyDatabaseAndCountsAPopulatedOne(t *testing.T) {
	t.Run("an empty database refuses the scan and names the count", func(t *testing.T) {
		snapshot := testSnapshot()
		uc := emptySnapshotUseCase(vulnDBZip(t))

		dir, cleanup, err := uc.preExtractVulnDB(context.Background(), &snapshot)
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatal("a database holding no advisories must fail the scan: every module would come back Clean having consulted nothing")
		}
		if !errors.Is(err, ports.ErrSnapshotEmpty) {
			t.Errorf("the sentinel must survive wrapping so a caller can route on it, got: %v", err)
		}
		// An empty database is not a tampered one, and a caller that would
		// preserve the blob as evidence on one and re-fetch on the other must not
		// be told they are the same failure.
		if errors.Is(err, ports.ErrSnapshotIntegrity) {
			t.Errorf("an empty database is not an integrity failure: nothing changed the bytes, got: %v", err)
		}
		if dir != "" {
			t.Errorf("no extraction directory may be offered after a refusal, got %q", dir)
		}
		// The count is the whole content of the finding: it is what separates an
		// empty database from a small one.
		for _, want := range []string{"0 advisories", snapshot.Source(), snapshot.Version(), "--fresh"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal must name %q: %v", want, err)
			}
		}
		if snapshot.AdvisoryCount() != 0 {
			t.Errorf("a refused snapshot must carry no count, got %d", snapshot.AdvisoryCount())
		}
	})

	// The test that makes this real: a populated database scans as it always did
	// AND leaves the count on the snapshot every record in the run names, so a
	// later reader can tell this scan from one against three advisories.
	t.Run("a populated database scans and records its count", func(t *testing.T) {
		snapshot := testSnapshot()
		uc := emptySnapshotUseCase(vulnDBZip(t, "GO-2026-0001", "GO-2026-0002", "GO-2026-0003"))

		dir, cleanup, err := uc.preExtractVulnDB(context.Background(), &snapshot)
		defer cleanup()
		if err != nil {
			t.Fatalf("a populated database must scan unchanged, got: %v", err)
		}
		if dir == "" {
			t.Fatal("a populated database must still yield the shared extraction directory")
		}
		if got := snapshot.AdvisoryCount(); got != 3 {
			t.Errorf("the count must reach the snapshot the run's records name, got %d", got)
		}
	})
}
