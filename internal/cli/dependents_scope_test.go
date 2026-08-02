package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// dependentsWalk builds a walk rooted at root whose edges are the given
// (from, to) pairs, so a test can decide exactly whether the root is one of
// the modules depending on the target.
func dependentsWalk(root coordinate.ModuleCoordinate, edges ...[2]coordinate.ModuleCoordinate) walkdomain.WalkRecord {
	graphEdges := make([]walkdomain.GraphEdge, 0, len(edges))
	nodes := make([]walkdomain.GraphNode, 0, len(edges)+1)
	nodes = append(nodes, walkdomain.GraphNode{Coordinate: root})
	for _, e := range edges {
		graphEdges = append(graphEdges, walkdomain.GraphEdge{From: e[0], To: e[1]})
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: e[0]})
	}
	return walkdomain.WalkRecord{
		ID:     "w1",
		Target: root,
		Graph:  walkdomain.Graph{Target: root, Nodes: nodes, Edges: graphEdges},
	}
}

// TestDependentsZeroResult_StatesItsScope covers the three states the empty
// answer can be in. The one that matters is the first: the root depends on the
// target and was dropped, so a bare "no modules depend on it" reads as "this
// module is unused" to anyone — or anything — relaying the line verbatim.
func TestDependentsZeroResult_StatesItsScope(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	cast := coordinatetest.MustNew("example.com/cast", "v1.4.1")
	other := coordinatetest.MustNew("example.com/other", "v1.0.0")

	rootDepends := dependentsWalk(root, [2]coordinate.ModuleCoordinate{root, cast})
	rootDoesNot := dependentsWalk(root, [2]coordinate.ModuleCoordinate{other, cast})

	for _, tc := range []struct {
		name        string
		rec         walkdomain.WalkRecord
		target      coordinate.ModuleCoordinate
		includeRoot bool
		wantSubstr  string
		wantAbsent  string
	}{
		{
			name:       "root is the only dependent and is excluded",
			rec:        rootDepends,
			target:     cast,
			wantSubstr: "(the walk root does; it is excluded by default — pass --include-root)",
		},
		{
			name:       "nothing depends on the target, root included",
			rec:        rootDoesNot,
			target:     other,
			wantSubstr: "(walk root excluded by default)",
			wantAbsent: "--include-root",
		},
		{
			name:        "include-root passed, so no exclusion to disclose",
			rec:         rootDoesNot,
			target:      other,
			includeRoot: true,
			wantSubstr:  "No modules in walk w1 (frame linux/amd64) depend on example.com/other@v1.0.0\n",
			wantAbsent:  "excluded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, rootExcluded := walkDependents(tc.rec, tc.target, tc.includeRoot)
			if len(deps) != 0 {
				t.Fatalf("fixture produced %d dependents, want an empty answer", len(deps))
			}
			var buf bytes.Buffer
			if err := writeDependentsText(&buf, tc.rec.ID, "linux/amd64", tc.target.String(), deps,
				false, rootExcluded, tc.includeRoot); err != nil {
				t.Fatalf("writeDependentsText: %v", err)
			}
			got := buf.String()
			if !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("output %q does not carry %q", got, tc.wantSubstr)
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("output %q carries %q, which does not apply in this state", got, tc.wantAbsent)
			}
		})
	}
}

// TestDependentsNonZeroHeader_StatesTheWithheldRoot pins the other half of the
// decision: the header discloses the exclusion only when the root was actually
// withheld, never as a standing footnote on every answer.
func TestDependentsNonZeroHeader_StatesTheWithheldRoot(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	cast := coordinatetest.MustNew("example.com/cast", "v1.4.1")
	other := coordinatetest.MustNew("example.com/other", "v1.0.0")

	// Both the root and another module depend on cast.
	rec := dependentsWalk(root,
		[2]coordinate.ModuleCoordinate{root, cast},
		[2]coordinate.ModuleCoordinate{other, cast},
	)

	t.Run("root withheld", func(t *testing.T) {
		deps, rootExcluded := walkDependents(rec, cast, false)
		if len(deps) != 1 {
			t.Fatalf("got %d dependents, want 1", len(deps))
		}
		var buf bytes.Buffer
		if err := writeDependentsText(&buf, rec.ID, "linux/amd64", cast.String(), deps, false, rootExcluded, false); err != nil {
			t.Fatalf("writeDependentsText: %v", err)
		}
		if !strings.Contains(buf.String(), "(the walk root does; it is excluded by default — pass --include-root)") {
			t.Errorf("header %q does not disclose the withheld root", buf.String())
		}
	})

	t.Run("root shown, nothing withheld", func(t *testing.T) {
		deps, rootExcluded := walkDependents(rec, cast, true)
		if len(deps) != 2 {
			t.Fatalf("got %d dependents, want 2", len(deps))
		}
		var buf bytes.Buffer
		if err := writeDependentsText(&buf, rec.ID, "linux/amd64", cast.String(), deps, false, rootExcluded, true); err != nil {
			t.Fatalf("writeDependentsText: %v", err)
		}
		if strings.Contains(buf.String(), "excluded") {
			t.Errorf("header %q mentions an exclusion that did not happen", buf.String())
		}
		if !strings.Contains(buf.String(), "[root]") {
			t.Errorf("output %q does not annotate the root entry", buf.String())
		}
	})
}
