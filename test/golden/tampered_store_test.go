package golden_test

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/cli"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// The module every tampered case alters, and the remedy its refusal must name.
const (
	tamperedModule = "example.com/mod"
	tamperedRemedy = "re-fetch it with kanonarion fetch example.com/mod@v1.2.0 --force"
)

// derivedTables are the records a reader derives from a module's bytes, each
// with the filter that selects the altered module's rows; the run-wide records
// are counted whole, since a run that refused an artefact writes none. The other
// module's records are its own and may be written.
var derivedTables = map[string]string{
	"licence_records":       "module_path = '" + tamperedModule + "'",
	"interface_records":     "module_path = '" + tamperedModule + "'",
	"interface_symbols":     "module_path = '" + tamperedModule + "'",
	"callgraph_records":     "module_path = '" + tamperedModule + "'",
	"example_records":       "module_path = '" + tamperedModule + "'",
	"native_records":        "module_path = '" + tamperedModule + "'",
	"vulnerability_records": "module_path = '" + tamperedModule + "'",
	"walk_scan_runs":        "1",
	"vendor_records":        "1",
}

// Every command that reads a stored module zip refuses one that no longer
// hashes to its identity: exit 10, the one sentence naming the re-fetch, no
// record derived from the bytes, and one verification_failed event. The store
// is altered two ways — a valid zip of other content, and one corrupted byte —
// because the second was the one a reader used to turn into a sealed parse
// failure.
func TestTamperedStore_EveryReaderRefusesAndDerivesNothing(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	vendored := vendoredCopy(t, fx)

	readers := []struct {
		name  string
		args  func(walkID, scratch string) []string
		dir   string
		prime []string
	}{
		{name: "extract", args: func(w, _ string) []string { return []string{"extract", w} }},
		{name: "license", args: func(string, string) []string { return []string{"license", tamperedModule + "@v1.2.0"} }},
		{name: "interface", args: func(string, string) []string { return []string{"interface", tamperedModule + "@v1.2.0"} }},
		{name: "callgraph", args: func(string, string) []string { return []string{"callgraph", tamperedModule + "@v1.2.0"} }},
		{name: "native", args: func(string, string) []string { return []string{"native", tamperedModule + "@v1.2.0"} }},
		{name: "examples", args: func(string, string) []string { return []string{"examples", tamperedModule + "@v1.2.0"} }},
		{name: "vuln-scan", args: func(string, string) []string { return []string{"vuln-scan", "--gomod", fx.gomod()} }},
		{name: "audit", args: func(string, string) []string { return []string{"audit", "--gomod", fx.gomod(), "--from-modcache"} }},
		{name: "vendor", dir: vendored, args: func(string, string) []string { return []string{"vendor"} }},
		{
			name:  "notice",
			prime: []string{"extract", "--stages", "license"},
			args:  func(string, string) []string { return []string{"notice"} },
		},
		{name: "use", args: func(w, scratch string) []string {
			return []string{"use", "example.com/app@local", "--recursive", "--walk-id", w, "--mod-cache", scratch}
		}},
	}

	for _, alteration := range []string{"rezip", "flip"} {
		for _, r := range readers {
			t.Run(alteration+"/"+r.name, func(t *testing.T) {
				for k, v := range fx.env() {
					t.Setenv(k, v)
				}
				store := fx.newStore(t)
				t.Setenv("KANONARION_STORE", store)
				walkID := primeWalk(t, fx)
				if r.prime != nil {
					mustRun(t, append(r.prime, walkID)...)
				}
				alterStoredZip(t, store, fx, alteration)

				before, events := tableCounts(t, store), auditLines(t, store)
				if r.dir != "" {
					t.Chdir(r.dir)
				}
				scratch := t.TempDir()
				var stdout, stderr bytes.Buffer
				err := cli.Run(r.args(walkID, scratch), &stdout, &stderr)

				assertRefusedAndNothingDerived(t, err, stderr.String(), store, before, len(events))
				if r.name == "use" {
					if n := countFiles(t, filepath.Join(scratch, "cache", "download", tamperedModule)); n != 0 {
						t.Errorf("use wrote %d file(s) of the altered module into the module cache", n)
					}
				}
			})
		}
	}
}

// assertRefusedAndNothingDerived checks one reader's run against the refusal's
// contract: exit 10, the one sentence, no record for the altered module, and
// exactly one verification_failed event after the first eventsBefore lines.
func assertRefusedAndNothingDerived(t *testing.T, err error, stderr, store string, before map[string]int, eventsBefore int) {
	t.Helper()
	if got := cli.ExitCodeForError(err); got != cli.ExitIntegrity {
		t.Fatalf("exit %d, want %d: %v\nstderr:\n%s", got, cli.ExitIntegrity, err, stderr)
	}
	if !errors.Is(err, fetchports.ErrBlobTampered) {
		t.Errorf("error does not carry the refusal: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, tamperedRemedy) || strings.Count(msg, fetchports.BlobTamperedMarker) != 1 {
		t.Errorf("message is not the one refusal sentence: %q", msg)
	}
	after := tableCounts(t, store)
	for table := range derivedTables {
		if after[table] != before[table] {
			t.Errorf("%s: %d rows before, %d after; a record was derived from refused bytes", table, before[table], after[table])
		}
	}
	refusals := 0
	for _, line := range auditLines(t, store)[eventsBefore:] {
		if strings.Contains(line, `"event_type":"verification_failed"`) {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("%d verification_failed events appended, want 1", refusals)
	}
}

// A blob the store does not hold is still absence, not a refusal.
func TestTamperedStore_AMissingArtefactIsStillAbsence(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	for k, v := range fx.env() {
		t.Setenv(k, v)
	}
	store := fx.newStore(t)
	t.Setenv("KANONARION_STORE", store)
	primeWalk(t, fx)
	if err := os.Remove(storedZipPath(t, store, fx)); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := cli.Run([]string{"license", tamperedModule + "@v1.2.0"}, &stdout, &stderr)
	if errors.Is(err, fetchports.ErrBlobTampered) || cli.ExitCodeForError(err) == cli.ExitIntegrity {
		t.Errorf("an absent blob was reported as altered: %v", err)
	}
}

func primeWalk(t *testing.T, fx *auditFixture) string {
	t.Helper()
	out := mustRun(t, "walk", "--gomod", fx.gomod(), "--from-modcache")
	m := regexp.MustCompile(`walk (\w+): succeeded`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no walk id in %q", out)
	}
	return m[1]
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := cli.Run(args, &stdout, &stderr); err != nil {
		t.Fatalf("kanonarion %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

// storedZipPath is where the store holds the module's zip, from the h1 the
// project's go.sum records for it.
func storedZipPath(t *testing.T, store string, fx *auditFixture) string {
	t.Helper()
	f, err := os.Open(filepath.Join(fx.project, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 3 && fields[0] == tamperedModule && fields[1] == "v1.2.0" {
			sum := sha256.Sum256([]byte("zip:" + fields[2]))
			addr := hex.EncodeToString(sum[:])
			return filepath.Join(store, "blobs", addr[:2], addr)
		}
	}
	t.Fatalf("go.sum names no zip for %s", tamperedModule)
	return ""
}

// alterStoredZip replaces the stored zip with a different file rather than
// writing through it: in module-cache mode the blob is a hard link to the
// fixture cache every case shares.
func alterStoredZip(t *testing.T, store string, fx *auditFixture, how string) {
	t.Helper()
	path := storedZipPath(t, store, fx)
	intact, err := os.ReadFile(path) // #nosec G304 -- the store's own blob
	if err != nil {
		t.Fatalf("reading the stored zip: %v", err)
	}
	var altered []byte
	switch how {
	case "rezip":
		altered = rezipWithBackdoor(t, intact)
	case "flip":
		altered = bytes.Clone(intact)
		zr, zerr := zip.NewReader(bytes.NewReader(intact), int64(len(intact)))
		if zerr != nil {
			t.Fatal(zerr)
		}
		offset, oerr := zr.File[0].DataOffset()
		if oerr != nil {
			t.Fatal(oerr)
		}
		altered[offset+2] ^= 0xff
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rezipWithBackdoor is a valid module zip of other content: the licence swapped
// and a function appended.
func rezipWithBackdoor(t *testing.T, intact []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(intact), int64(len(intact)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatal(oerr)
		}
		body, rerr := io.ReadAll(rc)
		_ = rc.Close()
		if rerr != nil {
			t.Fatal(rerr)
		}
		switch {
		case strings.HasSuffix(f.Name, "/LICENSE"):
			body = []byte("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n")
		case strings.HasSuffix(f.Name, ".go"):
			body = append(body, []byte("\nfunc Backdoor() string { return \"\" }\n")...)
		}
		w, cerr := fixtureZipEntry(zw, f.Name)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if _, werr := w.Write(body); werr != nil {
			t.Fatal(werr)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tableCounts(t *testing.T, store string) map[string]int {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	out := map[string]int{}
	for table, where := range derivedTables {
		var n int
		if qerr := db.DB().QueryRow(`SELECT count(*) FROM "` + table + `" WHERE ` + where).Scan(&n); qerr != nil {
			t.Fatalf("counting %s: %v", table, qerr)
		}
		out[table] = n
	}
	return out
}

func auditLines(t *testing.T, store string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store, "audit.jsonl")) // #nosec G304 -- the store's own log
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" && json.Valid([]byte(l)) {
			lines = append(lines, l)
		}
	}
	return lines
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return 0
	}
	err := filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// vendoredCopy is the fixture project with a vendor/ tree, for the vendor reader.
func vendoredCopy(t *testing.T, fx *auditFixture) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum", "main.go"} {
		data, err := os.ReadFile(filepath.Join(fx.project, name)) // #nosec G304 -- fixture file
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil { // #nosec G703 -- a fixed name under this test's own temp dir
			t.Fatal(err)
		}
	}
	env := make([]string, 0, len(fx.env()))
	for k, v := range fx.env() {
		env = append(env, k+"="+v)
	}
	runGo(t, dir, env, "mod", "vendor")
	t.Cleanup(func() { makeWritable(dir) })
	return dir
}
