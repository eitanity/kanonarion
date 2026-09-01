package govulncheck

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/local/localtest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// govulncheckRefusingUntilEscalated is the analyser meeting the wall this scan
// environment builds: it pins the toolchain so no scan child can download one,
// and the module asks for a Go newer than the installed toolchain. It clears
// once the scan is running under a toolchain already unpacked on this host.
//
// The refusal is the real one, verbatim — govulncheck loads packages by running
// the go command and hands its sentence back on stderr, which is the only place
// this class exists.
const govulncheckRefusingUntilEscalated = `echo "KANONARION_CHILD=govulncheck" >> "$f"
if [ "$GOTOOLCHAIN" = path ]; then
  echo '{"osv": {"id": "GO-2026-0001", "summary": "fixture advisory"}}'
  echo '{"finding": {"osv": "GO-2026-0001", "fixed_version": "v1.1.0", "trace": [{"module": "example.com/mod", "version": "v1.0.0", "package": "example.com/mod", "function": "Vulnerable"}]}}'
  exit 0
fi
echo 'govulncheck: loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.99.0 (running go 1.26.5; GOTOOLCHAIN=local)' >&2
exit 1
`

// govulncheckAlwaysAnalyses is the control analyser: it never refuses, so any
// escalation a scan takes came from another child of the same scan.
const govulncheckAlwaysAnalyses = `echo "KANONARION_CHILD=govulncheck" >> "$f"
echo '{"osv": {"id": "GO-2026-0001", "summary": "fixture advisory"}}'
echo '{"finding": {"osv": "GO-2026-0001", "fixed_version": "v1.1.0", "trace": [{"module": "example.com/mod", "version": "v1.0.0", "package": "example.com/mod", "function": "Vulnerable"}]}}'
exit 0
`

// scanHost fabricates the one host condition this class needs — an installed Go
// older than the module being scanned, with a newer one unpacked where the
// analysis is allowed to look — and puts a recording go and a recording
// govulncheck in front of the scan.
//
// Both go through localtest.Host's own shim, so every child of the scan records
// the environment it was handed and one set of assertions reads them all. PATH
// is what selects them: the scanner resolves both commands against this
// process's PATH, which is also why prepending the toolchain to a CHILD's PATH
// could never have worked.
func scanHost(t *testing.T, onDisk bool, govulncheckBody string) *localtest.Host {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fabricated children are POSIX shell scripts")
	}
	h := localtest.NewHost(t, onDisk)
	dir := t.TempDir()
	h.Shim(t, filepath.Join(dir, "govulncheck"), govulncheckBody)
	t.Setenv("PATH", strings.Join(
		[]string{dir, filepath.Dir(h.GoBinary), os.Getenv("PATH")},
		string(os.PathListSeparator)))
	return h
}

// scanSubject is a published module declaring goDirective.
//
// The directive is a parameter because the two halves of this class arrive
// differently. A module whose OWN go line is ahead of the installed toolchain is
// refused by the first Go child the scan runs; a module whose go line the host
// satisfies can still be refused by the analyser, because govulncheck loads the
// whole dependency closure and any module in it can raise the requirement. Both
// have to reach the same decision, so both are exercised.
func scanSubject(t *testing.T, goDirective string) []byte {
	t.Helper()
	return makeModuleZip(t, map[string]string{
		"example.com/mod@v1.0.0/go.mod": "module example.com/mod\n\ngo " + goDirective + "\n",
		"example.com/mod@v1.0.0/mod.go": "package mod\n\nfunc Vulnerable() {}\n",
	})
}

// govulncheckChildren is every recorded child that was the analyser rather than
// a go command, read from the marker its shim writes beside the environment.
func govulncheckChildren(t *testing.T, h *localtest.Host) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, env := range h.Children(t) {
		if env["KANONARION_CHILD"] == "govulncheck" {
			out = append(out, env)
		}
	}
	return out
}

// TestScan_UsesAToolchainAlreadyOnThisHost is the defect on the isolated scan:
// the fetched scan environment pins the toolchain so no child can download one,
// which also refused a toolchain unpacked on the same disk. A module needing a Go
// newer than the installed toolchain recorded a failed scan on a host that had
// what it needed.
//
// The analyser is what refuses here, with every go command satisfied, because the
// analyser is the child whose failure becomes the record: a retry anywhere else
// would leave this one still writing the failure.
//
// The verdict is the assertion, not the exit status: a record that measured
// nothing is fast and reads clean, so this requires the finding the analysis
// only produces once it is running under the toolchain on this host.
func TestScan_UsesAToolchainAlreadyOnThisHost(t *testing.T) {
	h := scanHost(t, true, govulncheckRefusingUntilEscalated)
	h.NeverRefuse(t)

	rec, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.21")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	})

	if err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("OverallStatus = %s, want %s; the scan did not reach a verdict under the toolchain on this host: %s",
			rec.OverallStatus, domain.StatusAffected, rec.ErrorDetail)
	}
	if len(rec.Findings) != 1 {
		t.Errorf("findings = %d, want the 1 the analysis reports; a scan that measured nothing also reports none", len(rec.Findings))
	}
	h.AssertEscalated(t)
}

// TestScan_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk. Without this the
// reader is shown GOTOOLCHAIN inside the go command's own sentence and cannot
// tell their own shell from this tool's posture, so they go looking in the wrong
// place. The account has to reach the RECORD, which is where a scan failure is
// read from long after the run.
func TestScan_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk(t *testing.T) {
	h := scanHost(t, false, govulncheckRefusingUntilEscalated)
	h.NeverRefuse(t)

	rec, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.21")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	})

	if err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}
	if rec.OverallStatus == domain.StatusClean {
		t.Fatal("a module no toolchain on this host could load reported Clean")
	}
	for _, want := range []string{"kanonarion pins the toolchain", "go >= 1.99.0", "golang.org/dl/go1.99.0"} {
		if !strings.Contains(rec.ErrorDetail, want) {
			t.Errorf("the recorded reason does not mention %q:\n%s", want, rec.ErrorDetail)
		}
	}
	h.AssertNeverEscalated(t)
}

// TestScan_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheModule is the
// control that must not move. A toolchain is unpacked on this host here too and
// must stay unused, or every host that has ever switched toolchains would start
// measuring its scans under a different Go than the one it measured them under
// yesterday — and a verdict's reachable set is the toolchain's.
func TestScan_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheModule(t *testing.T) {
	h := scanHost(t, true, govulncheckAlwaysAnalyses)
	h.NeverRefuse(t)

	rec, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.21")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	})

	if err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}
	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("OverallStatus = %s, want %s", rec.OverallStatus, domain.StatusAffected)
	}
	h.AssertNeverEscalated(t)
}

// TestScan_DecidesTheToolchainOnceForTheWholeScan. A scan spawns several Go
// children over ONE extracted tree. Deciding per child would make it pay a
// failed first attempt at each of them, and would let two children of one scan
// measure the same tree under different toolchains. Here the module download
// meets the gap first, and the analyser — which never refuses — must already be
// running under the answer rather than discovering it again.
func TestScan_DecidesTheToolchainOnceForTheWholeScan(t *testing.T) {
	h := scanHost(t, true, govulncheckAlwaysAnalyses)

	if _, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.99.0")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	}); err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}

	h.AssertEscalated(t)
	analysers := govulncheckChildren(t, h)
	if len(analysers) != 1 {
		t.Fatalf("the analyser ran %d times; the decision was taken before it started, so it must not pay a "+
			"failed first attempt of its own", len(analysers))
	}
	if got := analysers[0]["GOTOOLCHAIN"]; got != "path" {
		t.Errorf("the analyser was given GOTOOLCHAIN=%q; the decision another child took must reach it", got)
	}
}

// TestScan_RepeatsTheRefusalToEveryChildOfTheScan. A refusal is the operation's
// answer, and the child that carries it into the record is not the one that met
// the gap first — the module download meets it, the analyser writes the record.
// Reporting the go command's own sentence to the second child would leave the
// stored reason naming neither the pinner nor the remedy, which is the whole
// point of having a refusal.
func TestScan_RepeatsTheRefusalToEveryChildOfTheScan(t *testing.T) {
	h := scanHost(t, false, govulncheckRefusingUntilEscalated)

	rec, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).Scan(t.Context(), ports.ScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.99.0")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	})

	if err != nil {
		t.Fatalf("Scan returned a hard error: %v", err)
	}
	if !strings.Contains(rec.ErrorDetail, "kanonarion pins the toolchain") {
		t.Errorf("the analyser's failure was recorded as the go command reported it, not as this tool refused it:\n%s",
			rec.ErrorDetail)
	}
	h.AssertNeverEscalated(t)
}

// TestScanTargetModule_UsesAToolchainAlreadyOnThisHost covers the other pinned
// scan surface, the one a coordinate-keyed walk roots at its target. It is a
// separate analysis over a separate extracted tree, and before the shared
// decision existed each surface would have needed its own copy of it.
func TestScanTargetModule_UsesAToolchainAlreadyOnThisHost(t *testing.T) {
	h := scanHost(t, true, govulncheckRefusingUntilEscalated)
	h.NeverRefuse(t)

	res, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).ScanTargetModule(t.Context(), ports.TargetScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.21")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	})

	if err != nil {
		t.Fatalf("ScanTargetModule returned a hard error: %v", err)
	}
	if res.Status != domain.StatusAffected {
		t.Errorf("Status = %s, want %s; the target was not analysed under the toolchain on this host: %s",
			res.Status, domain.StatusAffected, res.ErrorDetail)
	}
	if len(res.FindingsByModule) != 1 {
		t.Errorf("modules with findings = %d, want 1", len(res.FindingsByModule))
	}
	h.AssertEscalated(t)
}

// TestScanTargetModule_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk. A
// target-rooted scan that cannot load its target fails the whole walk's frame,
// so this is the refusal a reader most needs to be able to act on.
func TestScanTargetModule_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk(t *testing.T) {
	h := scanHost(t, false, govulncheckRefusingUntilEscalated)
	h.NeverRefuse(t)

	res, err := capturingScanner(t, &bytes.Buffer{}, slog.LevelWarn).ScanTargetModule(t.Context(), ports.TargetScanRequest{
		Coordinate:   coordinatetest.MustNew("example.com/mod", "v1.0.0"),
		ModuleSource: bytes.NewReader(scanSubject(t, "1.21")),
		Snapshot:     fixtureSnapshot(t),
		GoModCache:   t.TempDir(),
	})

	if err != nil {
		t.Fatalf("ScanTargetModule returned a hard error: %v", err)
	}
	if res.Status == domain.StatusClean {
		t.Fatal("a target no toolchain on this host could load reported Clean")
	}
	for _, want := range []string{"kanonarion pins the toolchain", "go >= 1.99.0", "golang.org/dl/go1.99.0"} {
		if !strings.Contains(res.ErrorDetail, want) {
			t.Errorf("the recorded reason does not mention %q:\n%s", want, res.ErrorDetail)
		}
	}
	h.AssertNeverEscalated(t)
}
