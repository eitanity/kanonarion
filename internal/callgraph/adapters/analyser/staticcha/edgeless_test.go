package staticcha_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

// edgelessModuleFiles holds functions no edge names, of each scope, and a
// generic type instantiated with a production and with a test type argument.
var edgelessModuleFiles = map[string]string{
	"go.mod": "module example.com/edgeless\n\ngo 1.21\n",
	"leaf.go": `package edgeless

type Framer struct{ err error }

// ErrorDetail calls nothing and nothing here calls it.
func (f *Framer) ErrorDetail() error { return f.err }

func Lonely() {}

func lonely() {}

type Opt[T any] struct{ v T }

func (o *Opt[T]) Set(v T) { o.v = v; touch() }

func touch() {}

func UseInt() { var o Opt[int]; o.Set(1); Apply(1); Apply(map[int]int{}) }

func Apply[T any](v T) { touch() }
`,
	"leaf_test.go": `package edgeless

import "testing"

func testLonely() {}

type ts struct{}

func TestOpt(t *testing.T) { var o Opt[ts]; o.Set(ts{}); Apply(ts{}); Apply(Opt[ts]{}); Apply(map[ts]bool{}); Apply([]*ts{}) }
`,
}

func analyseEdgeless(t *testing.T) map[string]domain.CallNode {
	t.Helper()
	coord := coordinatetest.MustNew("example.com/edgeless", "v1.0.0")
	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, edgelessModuleFiles)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	nodes := map[string]domain.CallNode{}
	for _, n := range rec.Nodes {
		nodes[n.ID] = n
	}
	return nodes
}

// TestAnalyse_AModuleFunctionNoEdgeNamesIsANode: a function built with its body
// is a node of its own module's graph whether or not an edge names it, with the
// same exported-API and test fields as any other node.
func TestAnalyse_AModuleFunctionNoEdgeNamesIsANode(t *testing.T) {
	t.Parallel()

	nodes := analyseEdgeless(t)
	for id, want := range map[string]struct{ api, test bool }{
		"example.com/edgeless.(*Framer).ErrorDetail": {api: true},
		"example.com/edgeless.Lonely":                {api: true},
		"example.com/edgeless.lonely":                {},
		"example.com/edgeless.testLonely":            {test: true},
	} {
		n, ok := nodes[id]
		if !ok {
			t.Errorf("no node %s", id)
			continue
		}
		if n.IsExportedAPI != want.api || n.IsTest != want.test {
			t.Errorf("%s: exported API %t, test %t; want %t, %t", id, n.IsExportedAPI, n.IsTest, want.api, want.test)
		}
	}
}

// TestAnalyse_AGenericInstanceWithATestTypeArgumentIsTestCode: the instance
// exists only in a test build; the production instance does not. Both a method
// of a generic type and a generic function are asked, and a test type nested
// in another type argument counts.
func TestAnalyse_AGenericInstanceWithATestTypeArgumentIsTestCode(t *testing.T) {
	t.Parallel()

	var testInst, prodInst int
	for id, n := range analyseEdgeless(t) {
		if n.Symbol != "Set" && !strings.HasPrefix(n.Symbol, "Apply") {
			continue
		}
		switch {
		case strings.Contains(id, "edgeless.ts"):
			testInst++
			if !n.IsTest {
				t.Errorf("%s is not test code", id)
			}
		case strings.Contains(id, "[int]") || strings.Contains(id, "[map[int]int]"):
			prodInst++
			if n.IsTest {
				t.Errorf("%s is test code", id)
			}
		}
	}
	if testInst != 5 || prodInst != 3 {
		t.Errorf("instances found: test %d, production %d; want 5 and 3", testInst, prodInst)
	}
}
