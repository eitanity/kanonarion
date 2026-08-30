package cli

import (
	"bytes"
	"context"
	"testing"

	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// fixedRescan hands back one completed run, so the assertions are about what the
// command renders and not about what a scanner decided.
type fixedRescan struct{ run vuldomain.WalkScanRun }

func (r fixedRescan) Rescan(_ context.Context, req vulnapp.RescanRequest) (vuldomain.WalkScanRun, error) {
	r.run.WalkID = req.WalkID
	return r.run, nil
}

// rescanFixtureRun is a run with something to say on both axes: part of the
// build list went unanalysed and part of what was analysed is affected. A run
// that was Complete and Clean would render two default statuses and prove
// nothing about either field.
func rescanFixtureRun() vuldomain.WalkScanRun {
	return vuldomain.WalkScanRun{
		ID:             "01RESCANDOC0000000000000",
		Snapshot:       vulntest.MustNew("vuln.go.dev", "2026-08-01T00:00:00Z"),
		OverallStatus:  vuldomain.WalkStatusAffected,
		CoverageStatus: vuldomain.CoveragePartial,
		FindingsStatus: vuldomain.FindingsAffected,
		Counts:         vuldomain.WalkScanCounts{Total: 12, Analysed: 9, Affected: 2, Unscannable: 2, Failed: 1},
	}
}

// runRescanJSON drives the command's own writer under --json and hands back what
// each stream received.
func runRescanJSON(t *testing.T, run vuldomain.WalkScanRun) (map[string]any, string) {
	t.Helper()
	prev := jsonOut
	t.Cleanup(func() { jsonOut = prev })
	jsonOut = true

	var stdout, stderr bytes.Buffer
	req := vulnapp.RescanRequest{WalkID: "01KQDBVW092ER1HNXZ60X27CMD"}
	// The error is the coverage exit code, which a Partial run owes; the
	// document is written before it and is what is measured here.
	_ = rescanWith(context.Background(), fixedRescan{run: run}, req, "", true, &stdout, &stderr)
	return assertSingleJSONDocument(t, "vuln-scan-rescan --json", stdout.Bytes()), stderr.String()
}

// The three lines this command prints are already the shape a consumer wants —
// what the run concluded, which run it was, which database it was measured
// against. Under --json they are fields, and the counts behind the sentence come
// with them so nobody has to parse it.
func TestRescanJSON_StatesRunSnapshotAndCompletion(t *testing.T) {
	run := rescanFixtureRun()
	doc, _ := runRescanJSON(t, run)

	if got := doc["run_id"]; got != run.ID {
		t.Errorf("run_id %v, want %s", got, run.ID)
	}
	if got := doc["walk_id"]; got != "01KQDBVW092ER1HNXZ60X27CMD" {
		t.Errorf("walk_id %v: a re-scan re-evaluates one recorded build and must name it", got)
	}
	if got := doc["completion"]; got != scanCompletionSummary(run) {
		t.Errorf("completion %v, want the same sentence the text prints: %q", got, scanCompletionSummary(run))
	}
	if got := doc["coverage_status"]; got != string(run.CoverageStatus) {
		t.Errorf("coverage_status %v, want %s — the sentence is not a machine-readable answer on its own",
			got, run.CoverageStatus)
	}
	if got := doc["findings_status"]; got != string(run.FindingsStatus) {
		t.Errorf("findings_status %v, want %s", got, run.FindingsStatus)
	}

	snapshot, ok := doc["snapshot"].(map[string]any)
	if !ok {
		t.Fatalf("the document carries no snapshot object: %v", doc["snapshot"])
	}
	if snapshot["source"] != run.Snapshot.Source() || snapshot["version"] != run.Snapshot.Version() {
		t.Errorf("snapshot %v, want %s@%s — the advisory set a verdict rests on is part of the verdict",
			snapshot, run.Snapshot.Source(), run.Snapshot.Version())
	}
}

// The counts are the run's own, and the unanalysed number is the one the
// completion sentence and the exit code are both stated in. A document whose
// counts disagreed with the run would be a second answer.
func TestRescanJSON_CountsAgreeWithTheRun(t *testing.T) {
	run := rescanFixtureRun()
	doc, _ := runRescanJSON(t, run)

	counts, ok := doc["counts"].(map[string]any)
	if !ok {
		t.Fatalf("the document carries no counts object: %v", doc["counts"])
	}
	for key, want := range map[string]int{
		"total": run.Counts.Total, "analysed": run.Counts.Analysed, "affected": run.Counts.Affected,
		"unscannable": run.Counts.Unscannable, "failed": run.Counts.Failed,
	} {
		got, isNumber := counts[key].(float64)
		if !isNumber || int(got) != want {
			t.Errorf("counts.%s is %v, want %d", key, counts[key], want)
		}
	}
	if got, isNumber := doc["unanalysed"].(float64); !isNumber || int(got) != run.Counts.Unscannable+run.Counts.Failed {
		t.Errorf("unanalysed is %v, want %d — unscannable and failed together are what the run did not analyse",
			doc["unanalysed"], run.Counts.Unscannable+run.Counts.Failed)
	}
}

// A document on stdout does not silence the run's statements. The pre-flight and
// the per-module stream stay on stderr in both modes, which is where a consumer
// reading the document expects to find them.
func TestRescanJSON_StderrStatementsAreUnchanged(t *testing.T) {
	prev := jsonOut
	t.Cleanup(func() { jsonOut = prev })

	req := vulnapp.RescanRequest{WalkID: "01KQDBVW092ER1HNXZ60X27CMD"}
	var textOut, textErr, docOut, docErr bytes.Buffer
	jsonOut = false
	_ = rescanWith(context.Background(), fixedRescan{run: rescanFixtureRun()}, req, "", false, &textOut, &textErr)
	jsonOut = true
	_ = rescanWith(context.Background(), fixedRescan{run: rescanFixtureRun()}, req, "", false, &docOut, &docErr)

	if textErr.String() != docErr.String() {
		t.Errorf("stderr differs between the two modes:\ntext:\n%s\njson:\n%s", textErr.String(), docErr.String())
	}
	if textOut.String() == docOut.String() {
		t.Fatal("stdout is the same in both modes, so --json rendered no document")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(docOut.Bytes()), []byte("{")) {
		t.Errorf("stdout under --json must be the document and nothing before it, got:\n%s", docOut.String())
	}
}
