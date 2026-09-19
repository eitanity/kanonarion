package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/spf13/cobra"
)

// truncatableFake is an analysed module whose transitive caller walk returns two
// nodes. truncated says whether the walk stopped holding an unexpanded frontier
// — the ONE thing that differs between the two cases below, so a difference in
// the rendering can only come from the marker.
func truncatableFake(t *testing.T, truncated bool) *testfakes.FakeQueryCallGraph {
	t.Helper()
	uc := traverseFake(t, false)
	uc.SetTraverseCallers([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target"},
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Outer", ToID: "example.com/m.Caller"},
	}, []string{"example.com/m.Caller", "example.com/m.Outer"})
	uc.SetTraverseCallersTruncated(truncated)
	return uc
}

// runCallersTransitiveFor renders one traversal and returns stdout and the error
// the command ended on.
func runCallersTransitiveFor(t *testing.T, uc *testfakes.FakeQueryCallGraph, depth int, jsonOut bool) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "example.com/m.Target", depth, jsonOut,
		uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}, nil)
	return buf.String(), err
}

// TestTransitiveText_StatesTheBoundOnlyWhenItBit: the text surface, asserted on
// its own.
//
// The two runs return the identical nodes; only the frontier at exit differs. A
// cut answer names the bound and the remedy, and a complete one says nothing —
// silence on the text path already reads as "these are all of them", and the
// point of the change is to make that reading true rather than to add a second
// line that repeats it.
func TestTransitiveText_StatesTheBoundOnlyWhenItBit(t *testing.T) {
	cut, err := runCallersTransitiveFor(t, truncatableFake(t, true), 2, false)
	if err != nil {
		t.Fatalf("a truncated traversal is still an answer and must not carry an exit code: %v", err)
	}
	if !strings.Contains(cut, "showing transitive callers to depth 2") {
		t.Errorf("the truncation notice does not name the bound:\n%s", cut)
	}
	if !strings.Contains(cut, "--depth 0") {
		t.Errorf("the truncation notice does not name the remedy:\n%s", cut)
	}

	whole, err := runCallersTransitiveFor(t, truncatableFake(t, false), 2, false)
	if err != nil {
		t.Fatalf("a complete traversal must not carry an exit code: %v", err)
	}
	if strings.Contains(whole, "showing transitive callers to depth") {
		t.Errorf("a bounded-but-complete answer was marked truncated:\n%s", whole)
	}
	if strings.Contains(whole, "--depth 0") {
		t.Errorf("a complete answer offered a remedy for a gap it does not have:\n%s", whole)
	}
}

// TestTransitiveText_TruncationIsNotThePartialNotice: the bound the READER asked
// for and the packages the ANALYSIS could not build are two different absences,
// and they are stated on two different lines.
//
// The graph here is Partial AND the walk was cut, so both notices are printed.
// The truncation line must carry none of the analysis-gap vocabulary: reusing
// that wording would tell an operator the evidence has a hole when the hole is
// one they asked for, and this tool gives evidence, so a manufactured gap is a
// wrong answer of its own.
func TestTransitiveText_TruncationIsNotThePartialNotice(t *testing.T) {
	uc := traverseFake(t, true)
	uc.SetTraverseCallers([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target"},
	}, []string{"example.com/m.Caller"})
	uc.SetTraverseCallersTruncated(true)

	out, err := runCallersTransitiveFor(t, uc, 2, false)
	if err != nil {
		t.Fatalf("runCallersTransitive: %v", err)
	}

	var truncationLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "showing transitive callers") {
			truncationLine = line
		}
	}
	if truncationLine == "" {
		t.Fatalf("no truncation notice was printed:\n%s", out)
	}
	if !strings.Contains(out, "example.com/m/broken") {
		t.Fatalf("the analysis-gap notice is missing, so this test is not comparing two notices:\n%s", out)
	}
	for _, phrase := range []string{"package", "build", "fail", "drop", "incomplete graph"} {
		if strings.Contains(truncationLine, phrase) {
			t.Errorf("the truncation notice borrowed the analysis-gap wording %q: %q", phrase, truncationLine)
		}
	}
}

// TestTransitiveJSON_StatesTheBoundWhetherOrNotItBit: the JSON surface, asserted
// on its own and not through the text.
//
// Both fields are present on both answers, for the reason listTruncationJSON
// gives: a consumer cannot read a field that is not there, so an absent marker
// cannot be told from a build that does not say.
func TestTransitiveJSON_StatesTheBoundWhetherOrNotItBit(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  bool
	}{{"truncated", true}, {"complete", false}} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCallersTransitiveFor(t, truncatableFake(t, tc.cut), 2, true)
			if err != nil {
				t.Fatalf("runCallersTransitive: %v", err)
			}
			var doc struct {
				MaxDepth  int    `json:"max_depth"`
				Truncated *bool  `json:"truncated"`
				Remedy    string `json:"remedy"`
				NodeCount int    `json:"node_count"`
			}
			if derr := json.Unmarshal([]byte(out), &doc); derr != nil {
				t.Fatalf("decoding the answer: %v\n%s", derr, out)
			}
			if doc.Truncated == nil {
				t.Fatalf("the document carries no truncated field at all:\n%s", out)
			}
			if *doc.Truncated != tc.cut {
				t.Errorf("truncated = %v, want %v", *doc.Truncated, tc.cut)
			}
			if doc.Remedy != "--depth 0" {
				t.Errorf("remedy = %q, want %q", doc.Remedy, "--depth 0")
			}
			if doc.MaxDepth != 2 || doc.NodeCount != 2 {
				t.Errorf("the answer itself moved: max_depth = %d, node_count = %d", doc.MaxDepth, doc.NodeCount)
			}
		})
	}
}

// TestTransitiveJSON_UnboundedIsNeverMarked: --depth 0 expands its last frontier
// and so is always the closure. It is the remedy the other answers name, and a
// remedy that could itself come back marked would be no remedy.
func TestTransitiveJSON_UnboundedIsNeverMarked(t *testing.T) {
	out, err := runCallersTransitiveFor(t, truncatableFake(t, false), 0, true)
	if err != nil {
		t.Fatalf("unbounded traversal: %v", err)
	}
	if !strings.Contains(out, `"truncated": false`) {
		t.Errorf("an unbounded answer did not state truncated: false:\n%s", out)
	}
}

// TestNegativeDepthIsRefusedAtTheFlag.
//
// A negative --depth stops the walk before its first level, so it expands
// nothing and comes back with no nodes and an unexpanded frontier. Rendered, it
// asserted "No transitive callers found" — a measured absence — for a symbol
// with 3,368 transitive callers, at exit 0. A caveat printed under a wrong
// headline does not make it right, so the value is refused where it enters and
// no traversal is attempted at all.
//
// ExitConfig, because nothing was measured: 20 is "never reached an answer".
func TestNegativeDepthIsRefusedAtTheFlag(t *testing.T) {
	for _, depth := range []int{-1, -2, -1000} {
		err := checkDepthFlag(depth)
		if err == nil {
			t.Fatalf("--depth %d was accepted", depth)
		}
		if code := ExitCodeForError(err); code != ExitConfig {
			t.Errorf("--depth %d exits %d, want %d", depth, code, ExitConfig)
		}
		if !strings.Contains(err.Error(), "--depth 0") {
			t.Errorf("--depth %d is refused without naming the remedy: %v", depth, err)
		}
	}
	for _, depth := range []int{0, 1, 2, 18, 1000} {
		if err := checkDepthFlag(depth); err != nil {
			t.Errorf("--depth %d was refused: %v", depth, err)
		}
	}
}

// TestNegativeDepthIsRefusedBeforeTheStoreIsOpened: the refusal is on the
// command, ahead of the container, so a bad invocation costs nothing and cannot
// reach a renderer at all. Asserted through cobra rather than by calling the
// guard, because a guard nothing calls refuses nothing.
func TestNegativeDepthIsRefusedBeforeTheStoreIsOpened(t *testing.T) {
	// If the guard ever stops firing this reaches NewContainer, and a test must
	// not open the operator's own store to find that out.
	prevStore := storeRoot
	t.Cleanup(func() { storeRoot = prevStore })
	storeRoot = t.TempDir()

	for name, build := range map[string]func(stdout, stderr io.Writer) *cobra.Command{
		"callers": newCallersCmd,
		"callees": newCalleesCmd,
	} {
		var stdout, stderr bytes.Buffer
		cmd := build(&stdout, &stderr)
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetArgs([]string{"example.com/m.Target", "--transitive", "--depth=-1"})
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("%s accepted --depth=-1", name)
		}
		if code := ExitCodeForError(err); code != ExitConfig {
			t.Errorf("%s --depth=-1 exits %d, want %d", name, code, ExitConfig)
		}
		if strings.Contains(stdout.String(), "No transitive") {
			t.Errorf("%s rendered an absence for a refused invocation:\n%s", name, stdout.String())
		}
	}
}

// TestTransitiveCallees_StatesTheBound: the other direction has its own renderer
// call and its own exit carrier, so it is asserted rather than assumed.
func TestTransitiveCallees_StatesTheBound(t *testing.T) {
	uc := traverseFake(t, false)
	uc.SetTraverseCallees([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target"},
	}, []string{"example.com/m.Target"})
	uc.SetTraverseCalleesTruncated(true)

	var buf bytes.Buffer
	if err := runCalleesTransitive(context.Background(), "example.com/m.Caller", 1, false,
		uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}, nil); err != nil {
		t.Fatalf("runCalleesTransitive: %v", err)
	}
	if !strings.Contains(buf.String(), "showing transitive callees to depth 1") {
		t.Errorf("the callee notice is missing or misworded:\n%s", buf.String())
	}
}

// TestTraversalTruncationNotice_ReportsFailedWrites: the notice is part of the
// answer, so a stdout that stops accepting bytes must surface as an error rather
// than silently dropping the one line that says the answer is incomplete.
func TestTraversalTruncationNotice_ReportsFailedWrites(t *testing.T) {
	if err := writeTraversalTruncationNotice(&stallingWriter{}, "callers", 3, true); err == nil {
		t.Error("a failed truncation-notice write was swallowed")
	}
	if err := writeTraversalTruncationNotice(&stallingWriter{}, "callers", 3, false); err != nil {
		t.Errorf("a complete answer wrote something: %v", err)
	}
}

// ---- progress -------------------------------------------------------------

// fixedClock advances only when the test says so, so the throttle is exercised
// without sleeping.
type fixedClock struct{ at time.Time }

func (c *fixedClock) now() time.Time { return c.at }

// TestTraversalProgress_NamesDepthAndElapsed: the reporter renders the house
// line for every call it is given, carrying the depth, the visited count and the
// elapsed time.
//
// One line per call and no throttle of its own: the traversal's ticker already
// fires at traversalProgressInterval and is the only caller, so a second gate of
// the same width could only drop a line whose tick arrived a shade early. The
// first line is the one that would go — and a run still inside its first level
// is exactly what this narration exists for.
func TestTraversalProgress_NamesDepthAndElapsed(t *testing.T) {
	var buf bytes.Buffer
	clk := &fixedClock{at: time.Unix(1_700_000_000, 0)}
	r := traversalProgressReporter{p: newStderrProgressReporter(&buf, 0, clk.now,
		"callers progress: depth %d, %d symbols visited (%s elapsed)\n")}

	clk.at = clk.at.Add(5 * time.Second)
	r.Advance(1, 0)
	if want := "callers progress: depth 1, 0 symbols visited (5s elapsed)\n"; buf.String() != want {
		t.Fatalf("first line = %q, want %q", buf.String(), want)
	}

	buf.Reset()
	clk.at = clk.at.Add(5 * time.Second)
	r.Advance(7, 812)
	if want := "callers progress: depth 7, 812 symbols visited (10s elapsed)\n"; buf.String() != want {
		t.Errorf("second line = %q, want %q", buf.String(), want)
	}
}

// TestNewTraversalProgressReporter_FirstCallSpeaks: the production constructor
// builds the unthrottled reporter, so the very first call prints.
//
// The regression this pins was invisible in a unit test of the throttle and cost
// a six-minute silence in the field: the reporter seeded lastEmit to its start,
// the traversal called it once at the top of level 1, and that one call was
// always inside the interval.
func TestNewTraversalProgressReporter_FirstCallSpeaks(t *testing.T) {
	var buf bytes.Buffer
	cfg := configdomain.Config{}
	cfg.Preferences.Progress = true

	r := newTraversalProgressReporter(&buf, false, cfg, "callers")
	if r == nil {
		t.Fatal("an enabled run produced no reporter")
	}
	r.Advance(1, 0)
	if want := "callers progress: depth 1, 0 symbols visited (0s elapsed)\n"; buf.String() != want {
		t.Errorf("first call printed %q, want %q", buf.String(), want)
	}
}

// TestTraversalProgress_IntervalReachesTheTraversal: the cadence is a
// presentation decision, so the command states it; the traversal is what runs a
// ticker on it. A reporter plumbed through without an interval would narrate at
// the application's fallback rather than at the one documented here.
func TestTraversalProgress_IntervalReachesTheTraversal(t *testing.T) {
	cfg := configdomain.Config{}
	cfg.Preferences.Progress = true
	uc := truncatableFake(t, false)
	var stdout bytes.Buffer

	if err := runCallersTransitive(context.Background(), "example.com/m.Target", 2, true,
		uc, &stdout, buildScope{}, cgports.EdgeQueryOptions{},
		newTraversalProgressReporter(&bytes.Buffer{}, false, cfg, "callers")); err != nil {
		t.Fatalf("traversal: %v", err)
	}
	got := uc.TraversalRequests()
	if len(got) != 1 || got[0].ProgressInterval != traversalProgressInterval {
		t.Errorf("the traversal was asked with interval %v, want %v", got, traversalProgressInterval)
	}
}

// TestNewTraversalProgressReporter_Gating: --no-progress and the config
// preference each disable narration, and nothing else does. The log-level gate
// the walk and extract reporters carry is deliberately absent — a traversal
// streams nothing at info or debug, so gating on verbosity would restore the
// silence at exactly the setting an operator raised to see more.
func TestNewTraversalProgressReporter_Gating(t *testing.T) {
	on := configdomain.Config{}
	on.Preferences.Progress = true
	off := configdomain.Config{}

	if r := newTraversalProgressReporter(&bytes.Buffer{}, true, on, "callers"); r != nil {
		t.Error("--no-progress still produced a reporter")
	}
	if r := newTraversalProgressReporter(&bytes.Buffer{}, false, off, "callers"); r != nil {
		t.Error("preferences.progress = false still produced a reporter")
	}
	if r := newTraversalProgressReporter(&bytes.Buffer{}, false, on, "callers"); r == nil {
		t.Error("an enabled run produced no reporter")
	}
}

// TestTraversalProgress_NeverReachesStdout: the narration is proof of life for a
// human, and a --json consumer must get the same bytes whether or not a human
// was watching. The reporter is handed its own writer, and stdout is compared
// byte for byte against a run that had no reporter at all.
func TestTraversalProgress_NeverReachesStdout(t *testing.T) {
	var silent bytes.Buffer
	if err := runCallersTransitive(context.Background(), "example.com/m.Target", 2, true,
		truncatableFake(t, false), &silent, buildScope{}, cgports.EdgeQueryOptions{}, nil); err != nil {
		t.Fatalf("traversal with no reporter: %v", err)
	}

	var narrated, progress bytes.Buffer
	clk := &fixedClock{at: time.Unix(1_700_000_000, 0)}
	reporter := traversalProgressReporter{p: newStderrProgressReporter(&progress, 0, func() time.Time {
		clk.at = clk.at.Add(time.Second)
		return clk.at
	}, "callers progress: depth %d, %d symbols visited (%s elapsed)\n")}
	if err := runCallersTransitive(context.Background(), "example.com/m.Target", 2, true,
		truncatableFake(t, false), &narrated, buildScope{}, cgports.EdgeQueryOptions{}, reporter); err != nil {
		t.Fatalf("traversal with a reporter: %v", err)
	}

	if progress.Len() == 0 {
		t.Fatal("the reporter was plumbed through but never narrated, so this test proves nothing about stdout")
	}
	if !strings.HasPrefix(progress.String(), "callers progress: depth ") {
		t.Errorf("narration is not in the house shape: %q", progress.String())
	}
	if narrated.String() != silent.String() {
		t.Errorf("--json stdout moved when progress was enabled:\n with: %s\n without: %s", narrated.String(), silent.String())
	}
}

// TestTraversalProgress_SuppressedNarratesNothing: --no-progress reaches the
// traversal as a nil reporter, and the answer is unchanged.
func TestTraversalProgress_SuppressedNarratesNothing(t *testing.T) {
	var stderr bytes.Buffer
	cfg := configdomain.Config{}
	cfg.Preferences.Progress = true
	reporter := newTraversalProgressReporter(&stderr, true, cfg, "callers")

	uc := truncatableFake(t, false)
	var stdout bytes.Buffer
	if err := runCallersTransitive(context.Background(), "example.com/m.Target", 2, true,
		uc, &stdout, buildScope{}, cgports.EdgeQueryOptions{}, reporter); err != nil {
		t.Fatalf("suppressed traversal: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("--no-progress narrated anyway: %q", stderr.String())
	}
	if got := uc.TraversalRequests(); len(got) != 1 || got[0].Progress != nil {
		t.Errorf("--no-progress reached the traversal as %#v, want a nil reporter", got)
	}
}

// TestCallersAndCalleesAcceptNoProgress: registerNoProgressFlag's rule runs
// both ways — a command that emits progress must accept the instruction to stop
// it, or a caller who learned the flag elsewhere gets "unknown flag" from the
// command whose output they wanted quiet.
func TestCallersAndCalleesAcceptNoProgress(t *testing.T) {
	for name, build := range map[string]func(stdout, stderr io.Writer) *cobra.Command{
		"callers": newCallersCmd,
		"callees": newCalleesCmd,
	} {
		if build(&bytes.Buffer{}, &bytes.Buffer{}).Flags().Lookup("no-progress") == nil {
			t.Errorf("%s narrates on stderr but does not accept --no-progress", name)
		}
	}
}
