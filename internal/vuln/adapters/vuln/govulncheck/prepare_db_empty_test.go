package govulncheck

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
		arg, cleanup, err := newScanner(vulnDBZip(t)).prepareDBArg(context.Background(), snapshot, "")
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
		arg, cleanup, err := newScanner(vulnDBZip(t, "GO-2026-0001")).prepareDBArg(context.Background(), snapshot, "")
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
