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

// TestAnalyse_AWrapperOfATestTypeIsTestCode: SSA wraps the method a type
// promotes from an embedded field, and the wrapper's object is the promoted
// method, declared beside the embedded type. A wrapper of a type declared in a
// _test.go file, in package or external, is test code; the embedded type's own
// method and a production type's wrapper of it are not.
func TestAnalyse_AWrapperOfATestTypeIsTestCode(t *testing.T) {
	t.Parallel()

	coord := coordinatetest.MustNew("example.com/twrap", "v1.0.0")
	files := map[string]string{
		"go.mod": "module example.com/twrap\n\ngo 1.21\n",
		"base.go": `package twrap

type Hello interface{ Hello() }

type Base struct{}

func (Base) Hello() { helper() }

func helper() {}

// Prod embeds Base in production code.
type Prod struct{ Base }

func Use(h Hello) { h.Hello() }

func Wire() { Use(&Prod{}) }

// An unnamed struct's wrapper has no declaration to ask, and stays non-test.
func WireAnon() { Use(struct{ Base }{}) }
`,
		"fake_test.go": `package twrap

import "testing"

// Fake embeds Base in a test file.
type Fake struct{ Base }

func TestFake(t *testing.T) { Use(&Fake{}) }
`,
		"ext_test.go": `package twrap_test

import (
	"testing"

	"example.com/twrap"
)

// Ext embeds Base in an external test package.
type Ext struct{ twrap.Base }

func TestExt(t *testing.T) { twrap.Use(&Ext{}) }
`,
	}
	a := staticcha.New("0.1.0", "", slog.Default())
	rec, err := a.Analyse(context.Background(), writeZipToTemp(t, makeZip(t, coord, files)), coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	isTest := map[string]bool{}
	for _, n := range rec.Nodes {
		isTest[n.ID] = n.IsTest
	}
	for _, n := range rec.Nodes {
		if n.Symbol == "Hello" && n.Receiver != "" && n.IsTest && n.Package == "example.com/twrap" && !strings.Contains(n.ID, "Fake") && !strings.Contains(n.ID, "Ext") {
			t.Errorf("%s is test code; only the test types' wrappers are", n.ID)
		}
	}
	for id, want := range map[string]bool{
		"(*example.com/twrap.Fake).Hello":     true,
		"(*example.com/twrap_test.Ext).Hello": true,
		"(*example.com/twrap.Prod).Hello":     false,
		"example.com/twrap.(Base).Hello":      false,
	} {
		got, present := isTest[id]
		if !present {
			t.Errorf("no node %s; nodes: %v", id, isTest)
			continue
		}
		if got != want {
			t.Errorf("%s IsTest = %t, want %t", id, got, want)
		}
	}
}
