package govulncheck

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// snapshotBlobStore answers the snapshot read with a blob the test built, so the
// extraction and the count both run for real against the filesystem.
type snapshotBlobStore struct {
	ports.VulnerabilityStore
	blob []byte
}

func (s *snapshotBlobStore) GetDatabaseSnapshot(context.Context, domain.DatabaseSnapshot) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.blob)), nil
}

// vulnDBZip builds a govulncheck file:// database archive holding the named
// advisories; none produces the well-formed empty database under test.
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

// preExtractedDirAt writes the one file a pre-extracted advisory database is
// asked to show for itself: the index/db.json stating which generation it is.
// A directory that cannot answer that question is refused, so a test that wants
// the shared-extraction path taken has to build one that can.
func preExtractedDirAt(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "index"), 0o750); err != nil {
		t.Fatalf("creating the index dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index", "db.json"), []byte(`{"modified":"`+version+`"}`), 0o600); err != nil {
		t.Fatalf("writing index/db.json: %v", err)
	}
	return dir
}

// This path extracts a database of its own, so it owes the same refusal the
// walk's shared pre-extraction owes. The two reach a database independently, and
// a decision enforced at only one of them is enforced only while the other stays
// unused.
//
// The live-database fallback is the specific failure to guard against here: it
// would answer a scan whose record names an empty snapshot with a different
// advisory set entirely.
func TestPrepareDBArg_RefusesAnEmptyDatabase(t *testing.T) {
	snapshot := vulntest.MustNew("vuln.go.dev", "2026-07-30T00:00:00Z")

	newScanner := func(blob []byte) *Scanner {
		return &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotBlobStore{blob: blob},
		}
	}

	t.Run("an empty database fails the scan", func(t *testing.T) {
		arg, _, cleanup, err := newScanner(vulnDBZip(t)).prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatal("a database holding no advisories must fail the scan: govulncheck clears every module against one at exit 0")
		}
		if !errors.Is(err, ports.ErrSnapshotEmpty) {
			t.Errorf("the sentinel must survive wrapping, got: %v", err)
		}
		if arg == "https://vuln.go.dev" {
			t.Error("the live database must never be offered: it is a different advisory set from the one the record names")
		}
		if arg != "" {
			t.Errorf("no database argument may be returned after a refusal, got %q", arg)
		}
		for _, want := range []string{"0 advisories", snapshot.Version()} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal must name %q: %v", want, err)
			}
		}
	})

	t.Run("a populated database is used unchanged", func(t *testing.T) {
		arg, _, cleanup, err := newScanner(vulnDBZip(t, "GO-2026-0001")).prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("a populated database must be used as before, got: %v", err)
		}
		if !strings.HasPrefix(arg, "file://") {
			t.Errorf("expected the extracted local database, got %q", arg)
		}
	})
}

// TestPrepareDBArg_ReportsTheAdvisoryCountItMeasured pins the reading this seam
// takes and hands back.
//
// The walk's shared pre-extraction counts the database once and every record in
// the run names it. A scan that extracts its own database — because the shared
// extraction could not run — was counting the same thing and dropping it on the
// floor, so its records carried a snapshot with no count: indistinguishable from
// a row written before the field existed, and unable to tell a clean verdict
// reached against four thousand advisories from one reached against three.
//
// Zero is reserved for unmeasured. A pre-extracted directory was counted by
// whoever extracted it, and the live database is a set nothing here opened;
// reporting a count for either would be an assertion this seam cannot support.
func TestPrepareDBArg_ReportsTheAdvisoryCountItMeasured(t *testing.T) {
	snapshot := vulntest.MustNew("vuln.go.dev", "2026-07-30T00:00:00Z")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("a database it extracted is counted", func(t *testing.T) {
		s := &Scanner{
			logger:    logger,
			vulnStore: &snapshotBlobStore{blob: vulnDBZip(t, "GO-2026-0001", "GO-2026-0002", "GO-2026-0003")},
		}
		arg, count, cleanup, err := s.prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("a populated database must be prepared, got: %v", err)
		}
		if !strings.HasPrefix(arg, "file://") {
			t.Fatalf("expected the extracted local database, got %q", arg)
		}
		if count != 3 {
			t.Errorf("advisory count = %d, want 3 — the record must be able to name what was consulted", count)
		}

		// And the count reaches the snapshot the record will name.
		counted, cerr := snapshotCountingAdvisories(snapshot, count)
		if cerr != nil {
			t.Fatalf("carrying the count onto the snapshot: %v", cerr)
		}
		if counted.AdvisoryCount() != 3 {
			t.Errorf("snapshot advisory count = %d, want 3", counted.AdvisoryCount())
		}
	})

	t.Run("a pre-extracted directory reports no count of its own", func(t *testing.T) {
		s := &Scanner{logger: logger, vulnStore: &snapshotBlobStore{blob: vulnDBZip(t, "GO-2026-0001")}}
		_, count, cleanup, err := s.prepareDBArg(context.Background(), snapshot, preExtractedDirAt(t, snapshot.Version()))
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("the shared extraction path must be used as before, got: %v", err)
		}
		if count != 0 {
			t.Errorf("advisory count = %d, want 0: this seam did not open that database", count)
		}
		// An unmeasured reading must leave the snapshot alone rather than being
		// pushed through the domain's positive-only guard as an error.
		counted, cerr := snapshotCountingAdvisories(snapshot, count)
		if cerr != nil {
			t.Fatalf("an unmeasured count must not be an error: %v", cerr)
		}
		if counted.AdvisoryCount() != 0 {
			t.Errorf("snapshot advisory count = %d, want 0", counted.AdvisoryCount())
		}
	})

	// There is no third outcome. A scanner with no store cannot read the pinned
	// database, and the answer to that is a refusal rather than the live service:
	// the count it would report is zero either way, but the record it would let be
	// written names a snapshot nothing opened.
	t.Run("a scanner with no store refuses rather than going live", func(t *testing.T) {
		s := &Scanner{logger: logger}
		arg, count, cleanup, err := s.prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatal("a scan that cannot reach its pinned database must refuse, not answer from another one")
		}
		if !errors.Is(err, ports.ErrSnapshotUnavailable) {
			t.Errorf("the sentinel must survive wrapping, got: %v", err)
		}
		if arg != "" {
			t.Errorf("no database argument may be returned after a refusal, got %q", arg)
		}
		if count != 0 {
			t.Errorf("advisory count = %d, want 0: nothing was opened", count)
		}
	})
}
