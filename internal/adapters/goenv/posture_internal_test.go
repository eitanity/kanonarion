package goenv

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// TestPostureTableAnswersForEveryVariableOnEverySurface is the table's own gate.
// The per-surface assertions elsewhere each hold one producer to one posture and
// cannot see the shape all four closed defects in this class had: a variable that
// mattered on one surface and was never asked about on another.
func TestPostureTableAnswersForEveryVariableOnEverySurface(t *testing.T) {
	for _, v := range VerifyTable() {
		t.Error(v)
	}
	if len(Variables()) == 0 {
		t.Fatal("the table states no variables at all, so it asserts nothing")
	}
}

// TestVerifyTable_CatchesAVariableStatedOnOneSurfaceOnly plants the defect the
// table exists to catch — a variable added to one posture and to no other — and
// checks the table reports it against every surface that went on saying nothing.
// Without this, the gate above would only be evidence that today's table happens
// to be complete.
func TestVerifyTable_CatchesAVariableStatedOnOneSurfaceOnly(t *testing.T) {
	planted := maps.Clone(postures)
	p := planted["worktree"]
	p.Require = maps.Clone(p.Require)
	p.Require["GOPRIVATE"] = "example.com/*"
	planted["worktree"] = p

	got := verifyTable(planted)

	if len(got) != len(planted)-1 {
		t.Fatalf("planting GOPRIVATE on one posture produced %d complaints, want one for each of the other %d postures:\n%s",
			len(got), len(planted)-1, strings.Join(got, "\n"))
	}
	for _, name := range sortedNames(planted) {
		if name == "worktree" {
			continue
		}
		want := name + ": says nothing about GOPRIVATE"
		if !slices.ContainsFunc(got, func(v string) bool { return strings.HasPrefix(v, want) }) {
			t.Errorf("no complaint that %q leaves the planted GOPRIVATE unstated; got:\n%s", name, strings.Join(got, "\n"))
		}
	}
}

// TestVerifyTable_CatchesAVariableStatedBothWays plants the other misstatement a
// table can carry: one posture demanding a value and forbidding it at once, which
// makes it unverifiable rather than merely incomplete.
func TestVerifyTable_CatchesAVariableStatedBothWays(t *testing.T) {
	planted := maps.Clone(postures)
	p := planted["scan-project"]
	p.Require = maps.Clone(p.Require)
	p.Require["GOWORK"] = "off"
	planted["scan-project"] = p

	got := verifyTable(planted)

	if !slices.ContainsFunc(got, func(v string) bool {
		return strings.HasPrefix(v, "scan-project: states GOWORK both as")
	}) {
		t.Errorf("a posture requiring and forbidding GOWORK at once was not reported; got:\n%s", strings.Join(got, "\n"))
	}
}
