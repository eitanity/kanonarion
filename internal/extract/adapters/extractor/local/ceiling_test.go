package local

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
)

// TestCallgraphCeiling_AReachedCeilingIsRecordedAsSuchAndNotAsAKill is the
// distinction the status was promised to carry: "the extraction hit the
// configured memory budget and was terminated cleanly".
//
// Both outcomes are OutOfMemory and both are this host rather than the module,
// so asserting the status alone would pass with the mechanism absent. What
// separates them is what a reader does next — raise a number this run chose, or
// find out what else was on the machine — so the record has to say which
// happened.
func TestCallgraphCeiling_AReachedCeilingIsRecordedAsSuchAndNotAsAKill(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building the coordinate: %v", err)
	}

	reached := &fakeSubprocessExecutor{
		stderr: []byte(childproc.MemoryCeilingMarker + "13746540544 bytes in use against a ceiling of 13421772800\n"),
		// The child stopped ITSELF, so what the parent sees is an exit status. A
		// signal here would be the kernel's choice, which is the other case.
		err: fakeExitStatus{code: 2},
	}
	chosen := &fakeSubprocessExecutor{err: errors.New("signal: killed")}

	res, eerr := newCallgraphAdapter(reached, extractedOutcome()).Extract(t.Context(), coord, "callgraph", false, "")
	if eerr != nil {
		t.Fatalf("Extract failed: %v", eerr)
	}
	if res.Status != domain.StageFailed {
		t.Fatalf("Status = %v, want Failed", res.Status)
	}
	if !strings.Contains(res.Error, "status="+cgdomain.CallGraphStatusOutOfMemory.String()) {
		t.Errorf("Error = %q, want it to name status=OutOfMemory", res.Error)
	}
	if res.Cause != failurecause.Environment {
		t.Errorf("Cause = %q, want environment: a ceiling is this host's, never the published bytes", res.Cause)
	}
	if !strings.Contains(res.Error, "stopped itself") {
		t.Errorf("Error = %q, want it to say the analysis stopped itself at the ceiling", res.Error)
	}
	if !strings.Contains(res.Error, "--callgraph-memory-ceiling") {
		t.Errorf("Error = %q, want the number a reader can raise named in it", res.Error)
	}
	if !strings.Contains(res.Error, "13421772800") {
		t.Errorf("Error = %q, want the child's own account of what it reached kept", res.Error)
	}

	// The control that must stay different: the kernel choosing this process is
	// not a ceiling anyone set, and its remedy is not a flag.
	killed, eerr := newCallgraphAdapter(chosen, extractedOutcome()).Extract(t.Context(), coord, "callgraph", false, "")
	if eerr != nil {
		t.Fatalf("Extract failed: %v", eerr)
	}
	if !strings.Contains(killed.Error, "ended by the operating system") {
		t.Errorf("a kernel kill reads %q; it must still say the operating system chose it", killed.Error)
	}
	if strings.Contains(killed.Error, "--callgraph-memory-ceiling") {
		t.Errorf("a kernel kill printed the ceiling remedy: %q", killed.Error)
	}
	if killed.Error == res.Error {
		t.Error("a reached ceiling and a kernel kill record the same sentence; they are different facts")
	}
}

// TestCallgraphCeiling_TheExecutorCarriesItToTheChild: the derivation and the
// classification are both useless if the number never leaves this process.
func TestCallgraphCeiling_TheExecutorCarriesItToTheChild(t *testing.T) {
	const ceiling = 13421772800
	e := NewOsSubprocessExecutor("/nonexistent", 0, nil).WithMemoryCeiling(ceiling)
	if e.bounds.MemoryCeiling != ceiling {
		t.Fatalf("the executor's bounds carry a ceiling of %d, want %d", e.bounds.MemoryCeiling, ceiling)
	}
	if plain := NewOsSubprocessExecutor("/nonexistent", 0, nil); plain.bounds.MemoryCeiling != 0 {
		t.Errorf("an executor given no ceiling carries %d, want none", plain.bounds.MemoryCeiling)
	}
}
