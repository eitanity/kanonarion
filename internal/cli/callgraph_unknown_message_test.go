package cli

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// callgraph-show takes a coordinate. Naming the module path alone printed a line
// that exits 20 — the refusal spending exactly the round trip it existed to save
// — and the version was in the caller's hand throughout: the coordinates the
// lookup iterates carry it.
func TestUnknownNodeMessage_NamesACoordinateAndTheVersionsBehindIt(t *testing.T) {
	coord := mustCoord(t, "github.com/spf13/cobra", "v1.8.1")

	one := unknownNodeMessage("github.com/spf13/cobra.Nope", "github.com/spf13/cobra", []string{"v1.8.1"})
	assertRemedyLine(t, coord, lastLineOf(t, one))
	if strings.Contains(one, "analysed versions in the store") {
		t.Errorf("one analysed version, and the message lists a set:\n%s", one)
	}

	several := unknownNodeMessage("github.com/spf13/cobra.Nope", "github.com/spf13/cobra",
		[]string{"v1.10.2", "v1.8.1", "v1.4.0"})
	if !strings.Contains(several, "analysed versions in the store are v1.10.2, v1.8.1, v1.4.0") {
		t.Errorf("several analysed versions, and the message names none of them:\n%s", several)
	}
	line := lastLineOf(t, several)
	assertRemedyLine(t, coord, line)
	// Newest, not whichever the map iterated first: the line has to name a
	// version, and an arbitrary one reads as a recommendation.
	if !strings.HasSuffix(line, "@v1.10.2") {
		t.Errorf("the line names %q, not the newest analysed version", line)
	}
}

// The implementers refusal owes the same line for the same reason, and it is a
// separate builder — which is why one fix at one site never closed this.
func TestImplementersUnknownError_NamesACoordinate(t *testing.T) {
	coord := mustCoord(t, "github.com/spf13/cobra", "v1.8.1")

	err := implementersUnknownError("github.com/spf13/cobra.Nope", "github.com/spf13/cobra", true,
		[]string{"v1.10.2", "v1.8.1"})
	if err == nil {
		t.Fatal("an undeclared interface resolved")
	}
	if !strings.Contains(err.Error(), "analysed versions in the store are v1.10.2, v1.8.1") {
		t.Errorf("the message names no analysed versions:\n%s", err)
	}
	assertRemedyLine(t, coord, lastLineOf(t, err.Error()))

	// A module with no served version is the never-analysed case, and that
	// refusal already directs the reader at the analysis rather than at a
	// coordinate that does not exist.
	none := implementersUnknownError("example.com/x.Nope", "example.com/x", true, nil)
	if !strings.Contains(none.Error(), "not in the call-graph store") {
		t.Errorf("no analysed version, and the refusal claims one:\n%s", none)
	}
}

// analysedVersionsOf is what puts the version in reach of both builders.
func TestAnalysedVersionsOf_IsNewestFirstAndDeduplicated(t *testing.T) {
	coords := []ports.CallGraphCoordinate{
		{ModulePath: "example.com/a", ModuleVersion: "v1.9.0"},
		{ModulePath: "example.com/b", ModuleVersion: "v2.0.0"},
		{ModulePath: "example.com/a", ModuleVersion: "v1.10.0"},
		{ModulePath: "example.com/a", ModuleVersion: "v1.9.0", PipelineVersion: "0.5.0"},
	}
	got := analysedVersionsOf("example.com/a", coords)
	if len(got) != 2 || got[0] != "v1.10.0" || got[1] != "v1.9.0" {
		t.Errorf("got %v, want [v1.10.0 v1.9.0] — a text sort ranks v1.9.0 above v1.10.0", got)
	}
	if analysedVersionsOf("example.com/absent", coords) != nil {
		t.Error("a module with no analysed version reported one")
	}
}

func lastLineOf(t *testing.T, msg string) string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(msg, "\n"), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
