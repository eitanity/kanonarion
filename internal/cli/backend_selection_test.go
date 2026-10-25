package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// backendRun is what one pass of the acceptance sequence observed.
type backendRun struct {
	exits        []int
	events       map[string]int
	attestations int
	storeInfo    string
}

// The same project, walked, extracted with every stage, audited and inspected
// through Run, once per backend. The configured backend must receive every
// event the SQLite backend records, and the store root must hold nothing of
// the SQLite layout.
func TestStorageBackend_TheConfiguredBackendReceivesEveryRecord(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	proj := writeBothPathsProject(t)

	sqliteRoot := t.TempDir()
	sq := runBackendSequence(t, sqliteRoot, proj, "", false)
	sq.events = mustEventCounts(t, filepath.Join(sqliteRoot, "audit.jsonl"))
	sq.attestations = sqliteAttestationCount(t, filepath.Join(sqliteRoot, "mirror.db"))
	for _, name := range []string{"mirror.db", "blobs", "audit.jsonl"} {
		if _, err := os.Stat(filepath.Join(sqliteRoot, name)); err != nil {
			t.Errorf("SQLite backend left no %s: %v", name, err)
		}
	}

	filesRoot, filesDir := t.TempDir(), t.TempDir()
	tf := runBackendSequence(t, filesRoot, proj, filesDir, false)
	tf.events = mustEventCounts(t, filepath.Join(filesDir, testFilesEvents))
	tf.attestations = jsonAttestationCount(t, filepath.Join(filesDir, testFilesAttestations))
	compareBackendRuns(t, sq, tf)
	assertNoSQLiteLayout(t, filesRoot)
	if want := "store schema: the storage backend reports no schema state\n"; tf.storeInfo != want {
		t.Errorf("store info on testfiles = %q, want %q", tf.storeInfo, want)
	}

	// The same backend named by --config, with nothing in the root: the
	// callgraph child must be handed the file too, or it writes to SQLite there.
	flagRoot, flagDir := t.TempDir(), t.TempDir()
	tc := runBackendSequence(t, flagRoot, proj, flagDir, true)
	tc.events = mustEventCounts(t, filepath.Join(flagDir, testFilesEvents))
	tc.attestations = jsonAttestationCount(t, filepath.Join(flagDir, testFilesAttestations))
	compareBackendRuns(t, sq, tc)
	assertNoSQLiteLayout(t, flagRoot)
}

// compareBackendRuns asserts got received, event type for event type, what
// the SQLite run recorded, with the same exit codes.
func compareBackendRuns(t *testing.T, sq, tf backendRun) {
	t.Helper()

	t.Logf("sqlite: exits %v events %v attestations %d", sq.exits, sq.events, sq.attestations)
	t.Logf("testfiles: exits %v events %v attestations %d", tf.exits, tf.events, tf.attestations)
	if !slices.Equal(tf.exits, sq.exits) {
		t.Errorf("exit codes: testfiles %v, sqlite %v", tf.exits, sq.exits)
	}
	for _, et := range sortedEventTypes(sq.events) {
		if tf.events[et] != sq.events[et] {
			t.Errorf("event %q: sqlite recorded %d, testfiles received %d", et, sq.events[et], tf.events[et])
		}
	}
	for _, et := range sortedEventTypes(tf.events) {
		if _, ok := sq.events[et]; !ok {
			t.Errorf("event %q: testfiles received %d, sqlite recorded none", et, tf.events[et])
		}
	}
	for _, et := range []string{"walk_completed", "fact_record_written", "license_extracted", "interface_extracted",
		"examples_extracted", "callgraph_extracted", "extraction_run_completed"} {
		if sq.events[et] == 0 {
			t.Errorf("sqlite recorded no %q; the comparison is vacuous for it", et)
		}
	}
	if tf.attestations != sq.attestations {
		t.Errorf("attestations: sqlite %d, testfiles %d", sq.attestations, tf.attestations)
	}
}

// assertNoSQLiteLayout fails for any SQLite backend file under root.
func assertNoSQLiteLayout(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch d.Name() {
		case "mirror.db", "blobs", "audit.jsonl":
			t.Errorf("the testfiles store root holds %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// runBackendSequence writes a config.yaml (selecting testfiles when dir is
// set) into root, or beside it for --config when viaFlag, and runs the
// acceptance sequence, recording each exit code.
func runBackendSequence(t *testing.T, root, proj, dir string, viaFlag bool) backendRun {
	t.Helper()
	cfg := "version: \"3\"\nstorage:\n  backend: sqlite\n"
	if dir != "" {
		cfg = "version: \"3\"\nstorage:\n  backend: testfiles\ntestfiles:\n  dir: " + dir + "\n"
	}
	path := filepath.Join(root, "config.yaml")
	extra := []string{"--store-root", root}
	if viaFlag {
		path = filepath.Join(t.TempDir(), "elsewhere.yaml")
		extra = append(extra, "--config", path)
	}
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var run backendRun
	exec := func(args ...string) string {
		var stdout, stderr bytes.Buffer
		err := Run(append(args, extra...), &stdout, &stderr)
		run.exits = append(run.exits, ExitCodeForError(err))
		if err != nil {
			t.Logf("%v: %v\n%s", args, err, stderr.String())
		}
		return stdout.String()
	}
	gomod := filepath.Join(proj, "go.mod")
	exec("walk", "--gomod", gomod, "--analyse-root", "--no-progress")
	var list struct {
		Records []struct {
			ID string `json:"id"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(exec("walk-list", "--json")), &list); err != nil || len(list.Records) != 1 {
		t.Fatalf("walk-list: %v, %d records", err, len(list.Records))
	}
	exec("extract", "--no-progress", "--stages", "license,interface,example,callgraph", list.Records[0].ID)
	exec("audit", "--gomod", gomod, "--no-progress")
	run.storeInfo = exec("store", "info")
	return run
}

func mustEventCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	counts, err := eventTypeCounts(path)
	if err != nil {
		t.Fatal(err)
	}
	return counts
}

func sqliteAttestationCount(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fetch_attestations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func jsonAttestationCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var all []jsonAttestation
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatal(err)
	}
	return len(all)
}

// A configuration naming a backend this binary did not register refuses with
// ExitConfig before anything is created.
func TestStorageBackend_AnUnregisteredBackendIsAConfigRefusal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("version: \"3\"\nstorage:\n  backend: postgres\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"walk-list"}, {"store", "info"}} {
		var stdout, stderr bytes.Buffer
		err := Run(append(args, "--store-root", root), &stdout, &stderr)
		const want = `backend "postgres" is not registered in this binary (registered: sqlite, testfiles, testsink)`
		if err == nil || !strings.Contains(err.Error(), want) || ExitCodeForError(err) != ExitConfig {
			t.Errorf("%v: err = %v (exit %d), want %q with ExitConfig", args, err, ExitCodeForError(err), want)
		}
		if code, ok := ExitCodeFromError(err); !ok || code != ExitConfig {
			t.Errorf("%v: exit code not carried: %d %v", args, code, ok)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the refusal left %v", entries)
	}
}

// --config names the file, then KANONARION_CONFIG, then <store-root>/config.yaml.
func TestConfigFile_FlagThenEnvironmentThenStoreRoot(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	write := func(path, backend string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("version: \"3\"\nstorage:\n  backend: "+backend+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "config.yaml"), "from-root")
	flagFile, envFile := filepath.Join(other, "flag.yaml"), filepath.Join(other, "env.yaml")
	write(flagFile, "from-flag")
	write(envFile, "from-env")
	get := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := Run(append([]string{"config", "get", "storage.backend", "--store-root", root}, args...), &stdout, &stderr); err != nil {
			t.Fatalf("config get: %v", err)
		}
		return strings.TrimSpace(stdout.String())
	}
	if got := get(); got != "from-root" {
		t.Errorf("no flag, no env: %q", got)
	}
	t.Setenv(configEnv, envFile)
	if got := get(); got != "from-env" {
		t.Errorf("env: %q", got)
	}
	if got := get("--config", flagFile); got != "from-flag" {
		t.Errorf("flag beside env: %q", got)
	}
	if got := get(); got != "from-env" {
		t.Errorf("the flag outlived its invocation: %q", got)
	}
}

func TestConfigSet_StorageKeys(t *testing.T) {
	root := t.TempDir()
	for _, kv := range [][2]string{{"storage.backend", "testfiles"}, {"storage.sumdb_cache", "/var/cache/sumdb"}} {
		var stdout, stderr bytes.Buffer
		if err := Run([]string{"config", "set", kv[0], kv[1], "--store-root", root}, &stdout, &stderr); err != nil {
			t.Fatalf("config set %s: %v", kv[0], err)
		}
	}
	cfg, err := loadStoreConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Backend != "testfiles" || cfg.Storage.SumDBCache != "/var/cache/sumdb" {
		t.Errorf("Storage = %+v", cfg.Storage)
	}
	for _, bad := range [][2]string{{"storage.backend", "''"}, {"storage.backend", "[a]"}, {"storage.sumdb_cache", "{a: b}"}} {
		var stdout, stderr bytes.Buffer
		err := Run([]string{"config", "set", bad[0], bad[1], "--store-root", root}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), bad[0]+" requires a string") {
			t.Errorf("config set %s %s = %v", bad[0], bad[1], err)
		}
	}
}

// store ledger and store clean read the SQLite layout under the root, so a
// store configured for another backend is refused and left as it was.
func TestStorageBackend_SQLiteLayoutCommandsRefuseAnotherBackend(t *testing.T) {
	root, dir, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	// store clean also sweeps the system temp directory; point it at an empty one.
	t.Setenv("TMPDIR", tmp)
	cfg := "version: \"3\"\nstorage:\n  backend: testfiles\ntestfiles:\n  dir: " + dir + "\n"
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"store", "ledger"}, `store ledger reads the sqlite backend's ledger; this store is configured for backend "testfiles"`},
		{[]string{"store", "clean"}, `store clean cleans the sqlite backend's blob directory; this store is configured for backend "testfiles"`},
	} {
		var stdout, stderr bytes.Buffer
		err := Run(append(tc.args, "--store-root", root), &stdout, &stderr)
		code, carried := ExitCodeFromError(err)
		t.Logf("%v: exit %d, %v", tc.args, ExitCodeForError(err), err)
		if err == nil || !strings.HasSuffix(err.Error(), tc.want) || !carried || code != ExitConfig {
			t.Errorf("%v = %v (exit %d, carried %v), want %q with ExitConfig", tc.args, err, code, carried, tc.want)
		}
		if stdout.Len() != 0 {
			t.Errorf("%v wrote %q", tc.args, stdout.String())
		}
	}
	for _, d := range []string{root, dir, tmp} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if d == root {
			want = 1
		}
		if len(entries) != want {
			t.Errorf("%s holds %v after the refusals", d, entries)
		}
	}
}
