package govulncheck

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/failurecause"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// theRealRefusal is the message this host produced, verbatim, when a
// govulncheck built with go1.26 was pointed at a project requiring go1.27. Nine
// lines about the project's own files and one parenthetical naming the cause.
const theRealRefusal = `govulncheck: loading packages: There are errors with the provided package patterns:

/home/mb/dev/third-party/victoriametrics/lib/atomicutil/cacheline.go:1:1: package requires newer Go version go1.27 (application built with go1.26)
/home/mb/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.1.linux-amd64/src/math/rand/v2/rand.go:213:17: method must have no type parameters
`

func TestScannerTooOld_ReadsBothVersionsOutOfTheRefusal(t *testing.T) {
	t.Parallel()
	required, built, ok := scannerTooOld(theRealRefusal)
	if !ok {
		t.Fatal("the sentence that names the cause was not recognised")
	}
	if required != "go1.27" {
		t.Errorf("required = %q, want go1.27", required)
	}
	if built != "go1.26" {
		t.Errorf("built = %q, want go1.26", built)
	}
}

// TestScannerTooOld_TakesTheHighestRequirement mirrors goenv's own reader: one
// load can refuse for several packages, and a tool satisfying the largest
// requirement satisfies all of them.
func TestScannerTooOld_TakesTheHighestRequirement(t *testing.T) {
	t.Parallel()
	detail := "a.go:1:1: package requires newer Go version go1.27 (application built with go1.25)\n" +
		"b.go:1:1: package requires newer Go version go1.28 (application built with go1.25)\n"
	required, _, ok := scannerTooOld(detail)
	if !ok || required != "go1.28" {
		t.Errorf("required = %q (ok=%v), want go1.28", required, ok)
	}
}

// TestScannerTooOld_IgnoresProseThatQuotesTheSentence keeps a module's own text
// from being read as a toolchain fact, on the same terms goenv.IsToolchainTooOld
// requires both halves of its sentence.
func TestScannerTooOld_IgnoresProseThatQuotesTheSentence(t *testing.T) {
	t.Parallel()
	if _, _, ok := scannerTooOld("README says: package requires newer Go version go1.27"); ok {
		t.Error("a half-sentence in prose must not be read as the go/types refusal")
	}
}

// TestClassifyScanFailure_NamesTheToolNotTheProject is the defect this closes.
// The operator saw type errors about their own files and concluded the project
// was at fault; what they must see is the tool's build version, the version the
// project needs, and the command that rebuilds it.
func TestClassifyScanFailure_NamesTheToolNotTheProject(t *testing.T) {
	t.Parallel()
	tool := resolvedTool{bin: "/home/op/.local/bin/govulncheck", builtWith: "go1.26.5"}
	f := classifyScanFailure(exec.ErrNotFound, theRealRefusal, tool)

	if f.status != domain.StatusScanFailed {
		t.Errorf("status = %s, want ScanFailed: the scan genuinely could not run", f.status)
	}
	if f.cause != failurecause.Environment {
		t.Fatalf("cause = %q, want environment: the same project scans on this host once the "+
			"tool is rebuilt", f.cause)
	}
	for _, want := range []string{
		"/home/op/.local/bin/govulncheck", // which binary
		"go1.26.5",                        // what built it — the resolved fact, not the message's "go1.26"
		"go1.27",                          // what the project needs
		"go install golang.org/x/vuln/cmd/govulncheck@latest", // what to run
		"GOTOOLCHAIN",
	} {
		if !strings.Contains(f.errorDetail, want) {
			t.Errorf("the refusal does not name %q:\n%s", want, f.errorDetail)
		}
	}
	// GOTOOLCHAIN was measured NOT to help — the type checker is inside the
	// binary — so the refusal must not read as though setting it were the remedy.
	if !strings.Contains(f.errorDetail, "only rebuilding the tool") {
		t.Errorf("the refusal must say that rebuilding is the only remedy:\n%s", f.errorDetail)
	}
}

// TestScannerTooOldRefusal_NamesAToolchainTheGoCommandAccepts closes the trap in
// the remedy: the refusal names a LANGUAGE version ("go1.27"), which GOTOOLCHAIN
// rejects. A remedy that does not run is not a remedy.
func TestScannerTooOldRefusal_NamesAToolchainTheGoCommandAccepts(t *testing.T) {
	t.Parallel()
	for _, required := range []string{"go1.27", "go1.99"} {
		name := rebuildToolchain(required)
		if strings.Count(name, ".") < 2 {
			t.Errorf("rebuildToolchain(%q) = %q, which is a language version rather than a release "+
				"the go command will accept", required, name)
		}
	}
	// A release already on this host is preferred, so the rebuild needs no
	// download. This host has at least the one it is running.
	if name := rebuildToolchain("go1.1"); !strings.HasPrefix(name, "go1.") {
		t.Errorf("rebuildToolchain(go1.1) = %q, want a real toolchain name", name)
	}
}

// TestScannerTooOldRefusal_SurvivesAnUnreadableBuildVersion keeps the probe from
// gating anything: a version that could not be read must still leave a refusal
// that says what to do.
func TestScannerTooOldRefusal_SurvivesAnUnreadableBuildVersion(t *testing.T) {
	t.Parallel()
	msg := scannerTooOldRefusal("/usr/bin/govulncheck", "", "go1.27")
	if !strings.Contains(msg, "go install") {
		t.Errorf("the remedy must survive an unreadable build version:\n%s", msg)
	}
}

// TestBuiltWithGo_ReadsTheStampedRelease asks the question of a real binary: the
// test binary itself, which the go command built and stamped.
func TestBuiltWithGo_ReadsTheStampedRelease(t *testing.T) {
	t.Parallel()
	got := builtWithGo(t.Context(), os.Args[0])
	if !strings.HasPrefix(got, "go1.") {
		t.Fatalf("builtWithGo(this test binary) = %q, want a go1.x release", got)
	}
}

// TestBuiltWithGo_IsNeverAGate pins the other half: a path that is not a Go
// binary answers "", and answering "" must not be an error — the version
// explains a failure, it never decides whether a scan may run.
func TestBuiltWithGo_IsNeverAGate(t *testing.T) {
	t.Parallel()
	if got := builtWithGo(t.Context(), "/dev/null"); got != "" {
		t.Errorf("builtWithGo(/dev/null) = %q, want the empty answer", got)
	}
}
