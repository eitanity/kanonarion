package sqlite

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/blobstore/localfs"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
)

// A record whose hash does not parse cannot have its legacy blob re-addressed.
// That is counted and logged, never passed over as a record with no blob; a
// recorded absence or a record with no legacy handle stays silent.
func TestAdoptRowBlobs_AHashThatDoesNotParseIsCountedAndLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	blobs := localfs.New(t.TempDir())

	adopted, skipped := adoptRowBlobs(blobs, logger, "notahash", ":", "sha256:legacy-zip", "")
	if adopted != 0 || skipped != 1 {
		t.Errorf("adopted=%d skipped=%d, want 0 and 1", adopted, skipped)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN msg=blob_readdress_failed") || !strings.Contains(out, "legacy-zip") || !strings.Contains(out, `invalid module hash \"notahash\"`) {
		t.Errorf("log = %q, want a warn naming the legacy handle and the parse error", out)
	}

	buf.Reset()
	adopted, skipped = adoptRowBlobs(blobs, logger, ":", "notahash", "", "")
	if adopted != 0 || skipped != 0 || buf.Len() != 0 {
		t.Errorf("control: adopted=%d skipped=%d log=%q, want a silent no-op for an absence and an empty handle", adopted, skipped, buf.String())
	}
}

const legacyHandle = "sha256:ab0123456789"

// legacyDB is a database holding only a fetch_records relation built by ddl,
// so each read failure of the adoption pass can be produced on purpose.
func legacyDB(t *testing.T, root, ddl string) sqlitestore.DB {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if ddl != "" {
		if _, err := db.DB().Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func bufLogger() (*bytes.Buffer, *slog.Logger) {
	var buf bytes.Buffer
	return &buf, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func writeLegacyBlob(t *testing.T, root string) {
	t.Helper()
	path, ok := localfs.New(root).LegacyPath(legacyHandle)
	if !ok {
		t.Fatal("legacy handle has no path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAdoptLegacyBlobs_ReAddressesOnceThenStops(t *testing.T) {
	root := t.TempDir()
	db := legacyDB(t, root, `CREATE TABLE fetch_records (module_hash TEXT, go_mod_hash TEXT, content_location TEXT, go_mod_location TEXT);
		INSERT INTO fetch_records VALUES ('h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=', ':', '`+legacyHandle+`', '')`)
	writeLegacyBlob(t, root)
	buf, logger := bufLogger()

	if err := adoptLegacyBlobs(db, localfs.New(root), root, logger); err != nil {
		t.Fatalf("adoptLegacyBlobs: %v", err)
	}
	if !strings.Contains(buf.String(), "msg=blobs_readdressed_by_artefact_identity adopted=1 skipped=0") {
		t.Errorf("log = %q, want one adopted blob reported", buf.String())
	}
	if _, err := os.Stat(filepath.Join(root, blobAdoptionMarker)); err != nil {
		t.Fatalf("marker: %v", err)
	}

	// With the marker present the pass reads nothing, so a store whose records
	// can no longer be read is not even asked.
	if _, err := db.DB().Exec(`DROP TABLE fetch_records`); err != nil {
		t.Fatal(err)
	}
	if err := adoptLegacyBlobs(db, localfs.New(root), root, logger); err != nil {
		t.Errorf("second pass = %v, want nil once the marker exists", err)
	}
}

func TestAdoptLegacyBlobs_ReportsEachFailure(t *testing.T) {
	cases := []struct {
		name, ddl, root, want string
	}{
		{"no records table", "", "", "reading fetch records to re-address blobs: "},
		{"a record that does not scan", `CREATE TABLE fetch_records (module_hash TEXT, go_mod_hash TEXT, content_location TEXT, go_mod_location TEXT);
			INSERT INTO fetch_records VALUES (NULL, ':', '', '')`, "", "scanning fetch record to re-address blobs: "},
		// abs() of the smallest integer overflows, so the second row fails to step.
		{"a read that fails mid-way", `CREATE VIEW fetch_records AS
			SELECT ':' AS module_hash, ':' AS go_mod_hash, '' AS content_location, CAST(abs(CASE WHEN n = 2 THEN -9223372036854775808 ELSE 0 END) AS TEXT) AS go_mod_location
			FROM (SELECT 1 AS n UNION ALL SELECT 2 AS n)`, "", "iterating fetch records to re-address blobs: "},
		{"an unwritable marker", `CREATE TABLE fetch_records (module_hash TEXT, go_mod_hash TEXT, content_location TEXT, go_mod_location TEXT)`,
			"missing", "recording blob re-addressing marker: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			db := legacyDB(t, root, tc.ddl)
			markerRoot := root
			if tc.root != "" {
				markerRoot = filepath.Join(root, tc.root)
			}
			_, logger := bufLogger()
			err := adoptLegacyBlobs(db, localfs.New(root), markerRoot, logger)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("adoptLegacyBlobs = %v, want an error starting %q", err, tc.want)
			}
		})
	}
}

func TestAdoptRowBlobs_ARecordedAbsenceIsSilentAndAnUnreadableBlobIsCounted(t *testing.T) {
	root := t.TempDir()
	buf, logger := bufLogger()
	blobs := localfs.New(root)

	if adopted, skipped := adoptRowBlobs(blobs, logger, ":", ":", legacyHandle, legacyHandle); adopted != 0 || skipped != 0 || buf.Len() != 0 {
		t.Errorf("zero hashes: adopted=%d skipped=%d log=%q, want a silent no-op", adopted, skipped, buf.String())
	}

	// The legacy blob's directory is a file, so the blob cannot even be stat'd.
	path, _ := blobs.LegacyPath(legacyHandle)
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(path)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(path), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	adopted, skipped := adoptRowBlobs(blobs, logger, "h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", ":", legacyHandle, "")
	if adopted != 0 || skipped != 1 || !strings.Contains(buf.String(), "level=WARN msg=blob_readdress_failed") {
		t.Errorf("adopted=%d skipped=%d log=%q, want one skipped blob with a warning", adopted, skipped, buf.String())
	}
}

func TestCleanOrphanedBlobTemps_RemovesTempsAndWarnsOnAnUnreadableDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "blobs", ".tmp-killed"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf, logger := bufLogger()
	cleanOrphanedBlobTemps(localfs.New(root), logger)
	if !strings.Contains(buf.String(), "msg=\"cleaned orphaned blob temp files\" count=1 bytes=1") {
		t.Errorf("log = %q, want one removed temp reported", buf.String())
	}

	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "blobs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	cleanOrphanedBlobTemps(localfs.New(other), logger)
	if !strings.Contains(buf.String(), "level=WARN msg=\"failed to clean orphaned blob temp files\"") {
		t.Errorf("log = %q, want a warning for an unreadable blob directory", buf.String())
	}
}
