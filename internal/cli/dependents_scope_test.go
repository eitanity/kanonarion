package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// linuxAmd64Frame is the frame a project walk on this platform answers in, for
// the text renderers that state it.
var linuxAmd64Frame = walkdomain.WalkFrame{Text: "linux/amd64", Basis: walkdomain.FrameBasisPlatform}

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
			deps, rootScope := walkDependents(tc.rec, tc.target, tc.includeRoot)
			if len(deps) != 0 {
				t.Fatalf("fixture produced %d dependents, want an empty answer", len(deps))
			}
			var buf bytes.Buffer
			if err := writeDependentsText(&buf, tc.rec.ID, linuxAmd64Frame, tc.target.String(), deps,
				false, rootScope.withheld(), tc.includeRoot); err != nil {
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
		deps, rootScope := walkDependents(rec, cast, false)
		if len(deps) != 1 {
			t.Fatalf("got %d dependents, want 1", len(deps))
		}
		var buf bytes.Buffer
		if err := writeDependentsText(&buf, rec.ID, linuxAmd64Frame, cast.String(), deps, false, rootScope.withheld(), false); err != nil {
			t.Fatalf("writeDependentsText: %v", err)
		}
		if !strings.Contains(buf.String(), "(the walk root does; it is excluded by default — pass --include-root)") {
			t.Errorf("header %q does not disclose the withheld root", buf.String())
		}
	})

	t.Run("root shown, nothing withheld", func(t *testing.T) {
		deps, rootScope := walkDependents(rec, cast, true)
		if len(deps) != 2 {
			t.Fatalf("got %d dependents, want 2", len(deps))
		}
		var buf bytes.Buffer
		if err := writeDependentsText(&buf, rec.ID, linuxAmd64Frame, cast.String(), deps, false, rootScope.withheld(), true); err != nil {
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

// TestDependentsJSONStatesTheExclusion is the machine leg of the same decision,
// and it is the one that matters: a person reading "No modules … depend on X"
// gets the exclusion in the same sentence, and a consumer reading
// `"dependents": []` gets nothing at all unless the document says what the
// search covered. An empty list reads as a confirmed negative, and a consumer
// acting on it drops a dependency that is in use.
//
// Both directions are pinned, because a field that only appears when it would
// be alarming is a field nobody can rely on reading: with the root excluded and
// with it included, the document states the scope either way.
func TestDependentsJSONStatesTheExclusion(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	cast := coordinatetest.MustNew("example.com/cast", "v1.4.1")
	other := coordinatetest.MustNew("example.com/other", "v1.0.0")

	rootDepends := dependentsWalk(root, [2]coordinate.ModuleCoordinate{root, cast})
	rootDoesNot := dependentsWalk(root, [2]coordinate.ModuleCoordinate{other, cast})

	type rootScopeDoc struct {
		Root            string `json:"root"`
		Excluded        bool   `json:"excluded"`
		DependsOnTarget bool   `json:"depends_on_target"`
		IncludeFlag     string `json:"include_flag"`
	}

	for _, tc := range []struct {
		name        string
		rec         walkdomain.WalkRecord
		target      coordinate.ModuleCoordinate
		includeRoot bool
		wantDeps    int
		want        rootScopeDoc
	}{
		{
			// The defect: an empty answer that a consumer would read as "nothing
			// uses this, it can be dropped".
			name:     "empty answer, root excluded and depends on the target",
			rec:      rootDepends,
			target:   cast,
			wantDeps: 0,
			want: rootScopeDoc{Root: "example.com/app@v1.0.0", Excluded: true,
				DependsOnTarget: true, IncludeFlag: "--include-root"},
		},
		{
			name:        "the other direction: root included, so it is a row",
			rec:         rootDepends,
			target:      cast,
			includeRoot: true,
			wantDeps:    1,
			want: rootScopeDoc{Root: "example.com/app@v1.0.0", Excluded: false,
				DependsOnTarget: true, IncludeFlag: "--include-root"},
		},
		{
			// The scope is stated even when nothing was withheld, so a consumer
			// can branch on the field on every answer rather than on its absence.
			name:     "empty answer, root excluded and does not depend on the target",
			rec:      rootDoesNot,
			target:   coordinatetest.MustNew("example.com/unused", "v1.0.0"),
			wantDeps: 0,
			want: rootScopeDoc{Root: "example.com/app@v1.0.0", Excluded: true,
				DependsOnTarget: false, IncludeFlag: "--include-root"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, scope := walkDependents(tc.rec, tc.target, tc.includeRoot)
			if len(deps) != tc.wantDeps {
				t.Fatalf("got %d dependents, want %d", len(deps), tc.wantDeps)
			}
			var buf bytes.Buffer
			if err := writeDependentsJSON(&buf, tc.rec.ID, linuxAmd64Frame, pinnedContainment(tc.rec).selection(),
				tc.target.String(), deps, scope, nil); err != nil {
				t.Fatalf("writeDependentsJSON: %v", err)
			}
			var got struct {
				Dependents []map[string]any `json:"dependents"`
				RootScope  *rootScopeDoc    `json:"root_scope"`
			}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("decoding dependents JSON: %v", err)
			}
			if got.RootScope == nil {
				t.Fatalf("the document carries no root_scope, so an empty answer reads as a confirmed negative:\n%s", buf.String())
			}
			if *got.RootScope != tc.want {
				t.Errorf("root_scope = %+v, want %+v", *got.RootScope, tc.want)
			}
		})
	}
}

// TestDependentsRootScopeIsDataNotProse holds the fields to the parity guard's
// prose rule: a sentence pasted into a string value has changed channel, not
// form, and a machine still has to parse it.
func TestDependentsRootScopeIsDataNotProse(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	cast := coordinatetest.MustNew("example.com/cast", "v1.4.1")
	deps, scope := walkDependents(dependentsWalk(root, [2]coordinate.ModuleCoordinate{root, cast}), cast, false)

	var buf bytes.Buffer
	if err := writeDependentsJSON(&buf, "w1", linuxAmd64Frame, walkSelectionJSON{}, cast.String(), deps, scope, nil); err != nil {
		t.Fatalf("writeDependentsJSON: %v", err)
	}
	var doc any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding dependents JSON: %v", err)
	}
	var strs []string
	jsonStrings(doc, &strs)

	words := statementWords(rootDependsSuffix)
	for _, s := range strs {
		if isStatementProse(s, words) {
			t.Errorf("the document carries the text suffix as prose in a scalar (%q); field the facts instead", s)
		}
	}
}
