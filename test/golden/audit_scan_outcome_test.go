package golden_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/blobcodec"
	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/cli"
)

// auditScanRun is one audit invocation's whole answer.
type auditScanRun struct {
	stdout, stderr string
	exit           int
	err            error
}

// runAuditOn runs audit against store with the fixture's environment.
func runAuditOn(t *testing.T, fx *auditFixture, store, gomod string, extra ...string) auditScanRun {
	t.Helper()
	for k, v := range fx.env() {
		t.Setenv(k, v)
	}
	t.Setenv("KANONARION_STORE", store)
	var stdout, stderr bytes.Buffer
	err := cli.Run(append([]string{"audit", "--gomod", gomod, "--from-modcache", "--no-progress"}, extra...), &stdout, &stderr)
	return auditScanRun{stdout: stdout.String(), stderr: stderr.String(), exit: cli.ExitCodeForError(err), err: err}
}

// vulnScan is the run-level vulnerability_scan object, beside the scan's run id.
type vulnScan struct {
	Status  string `json:"status"`
	Run     string `json:"run"`
	Reason  string `json:"reason"`
	Partial *struct {
		Analysed int `json:"analysed"`
		Modules  int `json:"modules"`
	} `json:"partial"`
	scanRunID string
}

// vulnScanField decodes the run-level vulnerability_scan object.
func vulnScanField(t *testing.T, stdout string) vulnScan {
	t.Helper()
	var doc struct {
		VulnerabilityScan *vulnScan `json:"vulnerability_scan"`
		Scan              struct {
			RunID string `json:"run_id"`
		} `json:"scan"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decoding audit --json: %v\n%s", err, stdout)
	}
	if doc.VulnerabilityScan == nil {
		t.Fatalf("no vulnerability_scan object in:\n%s", stdout)
	}
	doc.VulnerabilityScan.scanRunID = doc.Scan.RunID
	return *doc.VulnerabilityScan
}

// execStore runs one statement against the fixture store.
func execStore(t *testing.T, store, stmt string, args ...any) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.DB().Exec(stmt, args...); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

// alterVulnRecord rewrites the advisory id inside example.com/mod's stored
// vulnerability record, leaving its content hash as it was.
func alterVulnRecord(t *testing.T, store string) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	var blob []byte
	if qerr := db.DB().QueryRow(`SELECT serialised FROM vulnerability_records WHERE module_path = ?`, tamperedModule).Scan(&blob); qerr != nil {
		t.Fatalf("reading the record: %v", qerr)
	}
	_ = db.Close()
	raw, err := blobcodec.Decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(raw, []byte(auditAdvisoryID), []byte("GO-2026-0002"), 1)
	if bytes.Equal(altered, raw) {
		t.Fatalf("the record does not carry %s", auditAdvisoryID)
	}
	execStore(t, store, `UPDATE vulnerability_records SET serialised = ? WHERE module_path = ?`, altered, tamperedModule)
}

// A store holding no advisory snapshot, offline: the scan cannot start. The
// table is printed, the line says why, and the run exits 1.
func TestAuditScan_NoSnapshotIsAFailedScan(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	for _, asJSON := range []bool{false, true} {
		store := fx.newStore(t)
		execStore(t, store, `DELETE FROM vulnerability_snapshots`)
		var extra []string
		if asJSON {
			extra = []string{"--json"}
		}
		got := runAuditOn(t, fx, store, fx.gomod(), extra...)

		if got.exit != cli.ExitPartial {
			t.Errorf("json=%v: exit %d, want %d: %v\n%s", asJSON, got.exit, cli.ExitPartial, got.err, got.stderr)
		}
		if !strings.Contains(got.stderr, "vulnerability scan: failed — ") || strings.Contains(got.stderr, "vulnerability scan: derived") {
			t.Errorf("json=%v: the derivation does not state the failure:\n%s", asJSON, got.stderr)
		}
		if !strings.Contains(got.stdout, tamperedModule+"@v1.2.0") {
			t.Errorf("json=%v: the table was not printed:\n%s", asJSON, got.stdout)
		}
		if asJSON {
			vs := vulnScanField(t, got.stdout)
			if vs.Status != "failed" || !strings.Contains(vs.Reason, "snapshot") {
				t.Errorf("vulnerability_scan = %v, want failed with the snapshot reason", vs)
			}
		}
	}
}

// One altered vulnerability record: the scan refuses it, the run exits 10 after
// printing the table, and only that module's row says its check failed. Primed
// two ways: a walk and scan audit does not reuse (the scan collides on the
// altered record), and an audit it does reuse (the served run reads it).
func TestAuditScan_AlteredRecordExitsIntegrity(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	primes := map[string]func(t *testing.T, store string){
		"rescanned": func(t *testing.T, _ string) {
			primeWalk(t, fx)
			mustRun(t, "vuln-scan", "--gomod", fx.gomod())
		},
		"reused": func(t *testing.T, store string) {
			if got := runAuditOn(t, fx, store, fx.gomod()); got.exit != cli.ExitOK {
				t.Fatalf("priming audit: exit %d: %v", got.exit, got.err)
			}
		},
	}
	for name, prime := range primes {
		for _, asJSON := range []bool{false, true} {
			store := fx.newStore(t)
			for k, v := range fx.env() {
				t.Setenv(k, v)
			}
			t.Setenv("KANONARION_STORE", store)
			prime(t, store)
			alterVulnRecord(t, store)
			var extra []string
			if asJSON {
				extra = []string{"--json"}
			}
			got := runAuditOn(t, fx, store, fx.gomod(), extra...)

			if got.exit != cli.ExitIntegrity {
				t.Errorf("%s json=%v: exit %d, want %d: %v\n%s", name, asJSON, got.exit, cli.ExitIntegrity, got.err, got.stderr)
			}
			if got.err == nil || !strings.Contains(got.err.Error(), tamperedModule+"@v1.2.0") {
				t.Errorf("%s json=%v: the refusal does not name the record: %v", name, asJSON, got.err)
			}
			if !strings.Contains(got.stderr, "vulnerability scan: failed — ") {
				t.Errorf("%s json=%v: the derivation does not state the failure:\n%s", name, asJSON, got.stderr)
			}
			assertOnlyAlteredRowMarked(t, name, got.stdout, asJSON)
		}
	}
}

func assertOnlyAlteredRowMarked(t *testing.T, name, stdout string, asJSON bool) {
	t.Helper()
	marked := map[string]bool{}
	if asJSON {
		var doc struct {
			Modules []struct {
				Coordinate string `json:"coordinate"`
				VulnStatus string `json:"vuln_status"`
			} `json:"modules"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		for _, m := range doc.Modules {
			marked[m.Coordinate] = m.VulnStatus == "(integrity check failed)"
		}
	} else {
		for _, line := range strings.Split(stdout, "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				marked[f[0]] = strings.Contains(line, "(integrity check failed)")
			}
		}
	}
	if !marked[tamperedModule+"@v1.2.0"] || marked["example.com/clean@v1.0.0"] {
		t.Errorf("%s json=%v: rows marked %v, want only %s:\n%s", name, asJSON, marked, tamperedModule, stdout)
	}
}

// A vendored tree without a module the code scope includes (here imported only
// by a test): that module is unscannable and the rest analysed, so the run is
// partial, exits 1 and the derivation counts what was analysed.
func TestAuditScan_PartialScanSaysHowMuch(t *testing.T) {
	fx := buildAuditFixture(t)
	const mainOnlyMod = "package main\n\nimport \"example.com/mod\"\n\nfunc main() { mod.Handle() }\n"
	const testOnlyClean = "package main\n\nimport (\n\t\"testing\"\n\n\t\"example.com/clean\"\n)\n\nfunc TestPing(*testing.T) { clean.Ping() }\n"
	writeFile(t, filepath.Join(fx.project, "main.go"), mainOnlyMod)
	project := vendoredCopy(t, fx)
	writeFile(t, filepath.Join(project, "main_test.go"), testOnlyClean)
	if err := os.RemoveAll(filepath.Join(project, "vendor", "example.com", "clean")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	for _, asJSON := range []bool{false, true} {
		var extra []string
		if asJSON {
			extra = []string{"--json"}
		}
		got := runAuditOn(t, fx, fx.newStore(t), filepath.Join(project, "go.mod"), extra...)
		if got.exit != cli.ExitPartial {
			t.Errorf("json=%v: exit %d, want %d: %v\n%s", asJSON, got.exit, cli.ExitPartial, got.err, got.stderr)
		}
		if !strings.Contains(got.stderr, "vulnerability scan: derived by this run; it analysed 3 of 4 modules") {
			t.Errorf("json=%v: the derivation does not count the partial run:\n%s", asJSON, got.stderr)
		}
		if asJSON {
			vs := vulnScanField(t, got.stdout)
			if vs.Status != "derived" || vs.Partial == nil || vs.Partial.Analysed != 3 || vs.Partial.Modules != 4 {
				t.Errorf("vulnerability_scan = %v, want derived with 3 of 4 analysed", vs)
			}
		}
	}
}

// The control: a warm re-run serves the stored scan, says so, and exits 0.
func TestAuditScan_ReusedRunIsUnchanged(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	store := fx.newStore(t)
	if got := runAuditOn(t, fx, store, fx.gomod()); got.exit != cli.ExitOK || !strings.Contains(got.stderr, "vulnerability scan: derived by this run\n") {
		t.Fatalf("first audit: exit %d: %v\n%s", got.exit, got.err, got.stderr)
	}
	got := runAuditOn(t, fx, store, fx.gomod(), "--json")
	if got.exit != cli.ExitOK {
		t.Fatalf("reused audit: exit %d: %v\n%s", got.exit, got.err, got.stderr)
	}
	if vs := vulnScanField(t, got.stdout); vs.Status != "reused" || vs.Run != vs.scanRunID || vs.Run == "" {
		t.Errorf("vulnerability_scan = %+v; want reused naming the scan's run", vs)
	}
}

// The same vendored tree without a module the main package imports: the build
// fails, nothing is analysed, and that is a failed scan, not a partial one.
func TestAuditScan_NothingAnalysedIsAFailedScan(t *testing.T) {
	fx := buildAuditFixture(t)
	project := vendoredCopy(t, fx)
	if err := os.RemoveAll(filepath.Join(project, "vendor", "example.com", "clean")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	got := runAuditOn(t, fx, fx.newStore(t), filepath.Join(project, "go.mod"), "--json")
	if got.exit != cli.ExitPartial {
		t.Errorf("exit %d, want %d: %v\n%s", got.exit, cli.ExitPartial, got.err, got.stderr)
	}
	if !strings.Contains(got.stderr, "vulnerability scan: failed — no module in the walk was analysed (4 of 4 unanalysed)") {
		t.Errorf("the derivation does not state the failure:\n%s", got.stderr)
	}
	if vs := vulnScanField(t, got.stdout); vs.Status != "failed" || vs.Partial != nil {
		t.Errorf("vulnerability_scan = %v, want failed", vs)
	}
}
