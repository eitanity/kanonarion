package domain

import (
	"encoding/json"
	"testing"
)

// TestDiffMembers_RendersOnlyWhatItReports.
//
// Rendering every member to compare it is what made this unaffordable: on a
// module with four million edges the comparison cost tens of gigabytes, and
// almost all of it was spent rendering members that turned out to be identical.
// A member is now rendered only when it is going to be named in the report, and
// this counts the renders rather than timing them, so the old shape coming back
// fails here rather than being noticed on a big module months later.
func TestDiffMembers_RendersOnlyWhatItReports(t *testing.T) {
	t.Parallel()
	node := func(id, file string) CallNode {
		return CallNode{ID: id, Symbol: id, Position: SourcePosition{File: file, Line: 1}}
	}
	tests := []struct {
		name         string
		left, right  []CallNode
		wantRenders  int
		wantReported int
	}{
		{
			name:  "nothing differs, so nothing is rendered",
			left:  []CallNode{node("a", "a.go"), node("b", "b.go"), node("c", "c.go")},
			right: []CallNode{node("a", "a.go"), node("b", "b.go"), node("c", "c.go")},
		},
		{
			// One changed member: rendered once per side to say what about.
			name:         "one member described differently",
			left:         []CallNode{node("a", "a.go"), node("b", "b.go")},
			right:        []CallNode{node("a", "a.go"), node("b", "moved.go")},
			wantRenders:  2,
			wantReported: 1,
		},
		{
			// One member on one side only: rendered once, to be named.
			name:         "one member only on the left",
			left:         []CallNode{node("a", "a.go"), node("b", "b.go")},
			right:        []CallNode{node("a", "a.go")},
			wantRenders:  1,
			wantReported: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			renders := 0
			counted := func(n CallNode) (map[string]json.RawMessage, error) {
				renders++
				return describeNode(n)
			}
			d, err := diffMembers("nodes", "node", tc.left, tc.right,
				nodeIdentityLess, CallNodeLess, counted)
			if err != nil {
				t.Fatalf("diffMembers: %v", err)
			}
			if renders != tc.wantRenders {
				t.Errorf("rendered %d member(s), want %d — rendering scales with what differs, not with the collection",
					renders, tc.wantRenders)
			}
			reported := len(d.OnlyLeft) + len(d.OnlyRight) + len(d.Changed)
			if reported != tc.wantReported {
				t.Errorf("reported %d member(s), want %d: %+v", reported, tc.wantReported, d)
			}
		})
	}
}

// TestOrderedBy_DoesNotCopyACanonicallyOrderedCollection.
//
// The walk needs canonical order and the store already stores it, so the guard
// has to be a check rather than a defensive sort: copying four million edges to
// re-sort what is already sorted would put back a share of the memory this
// comparison exists to stop spending.
func TestOrderedBy_DoesNotCopyACanonicallyOrderedCollection(t *testing.T) {
	t.Parallel()
	sorted := []CallNode{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	if got := orderedBy(sorted, CallNodeLess); &got[0] != &sorted[0] {
		t.Error("an already-ordered collection was copied")
	}
	unsorted := []CallNode{{ID: "c"}, {ID: "a"}}
	got := orderedBy(unsorted, CallNodeLess)
	if &got[0] == &unsorted[0] {
		t.Fatal("an out-of-order collection was sorted in place, mutating the caller's record")
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("orderedBy returned %v, want canonical order", got)
	}
	if unsorted[0].ID != "c" {
		t.Errorf("the caller's collection was reordered: %v", unsorted)
	}
}
