package staticcha_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// testScopeFiles is a module in the shape that made the omission expensive: a
// port, its production adapter, a use case dispatching through the port, and a
// test file declaring a fake implementation plus a test that drives it. Before
// test files were analysed, the fake and the test were invisible, so a callers
// query on the adapter method returned a confident RESOLVED-ABSENT for a symbol
// six test sites depended on.
func testScopeFiles() map[string]string {
	return map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"ports/ports.go": `package ports

type Store interface {
	Put(v int) error
}
`,
		"adapter/adapter.go": `package adapter

type Store struct{}

func (s *Store) Put(v int) error { return nil }
`,
		"app/app.go": `package app

import "example.com/cgtestmod/ports"

type UseCase struct{ store ports.Store }

func New(s ports.Store) *UseCase { return &UseCase{store: s} }

func (uc *UseCase) Execute() error { return uc.store.Put(1) }
`,
		"app/app_test.go": `package app

import "testing"

// fakeStore is the test double a port-signature change has to update alongside
// the production adapter.
type fakeStore struct{ calls int }

func (f *fakeStore) Put(v int) error { f.calls++; return nil }

func TestExecute(t *testing.T) {
	f := &fakeStore{}
	if err := New(f).Execute(); err != nil {
		t.Fatal(err)
	}
}
`,
		"adapter/adapter_ext_test.go": `package adapter_test

import (
	"testing"

	"example.com/cgtestmod/adapter"
)

func TestPutDirectly(t *testing.T) {
	s := &adapter.Store{}
	if err := s.Put(1); err != nil {
		t.Fatal(err)
	}
}
`,
	}
}

// TestTestScope_DeclarationsBecomeTaggedNodes is the core rule: test-file
// declarations are in the graph, and they are distinguishable from production
// ones so a query can report them separately rather than hiding either.
func TestTestScope_DeclarationsBecomeTaggedNodes(t *testing.T) {
	rec := analyseFiles(t, testScopeFiles())

	if !rec.TestScope.IsMeasured() {
		t.Fatalf("TestScope = %q, want Analysed (detail: %q)", rec.TestScope, rec.TestScopeDetail)
	}

	fake, ok := nodeByID(rec, "example.com/cgtestmod/app.(*fakeStore).Put")
	if !ok {
		t.Fatal("the test fake's method is not a node in the graph")
	}
	if !fake.IsTest {
		t.Error("the test fake's method is not tagged as test scope")
	}

	extTest, ok := nodeByID(rec, "example.com/cgtestmod/adapter_test.TestPutDirectly")
	if !ok {
		t.Fatal("an external test package's function is not a node in the graph")
	}
	if !extTest.IsTest {
		t.Error("an external test package's function is not tagged as test scope")
	}

	// The production side must keep its role: the point is separability, not
	// relabelling everything the test binary touches.
	prod, ok := nodeByID(rec, "example.com/cgtestmod/adapter.(*Store).Put")
	if !ok {
		t.Fatal("the production adapter method is not a node in the graph")
	}
	if prod.IsTest {
		t.Error("the production adapter method was tagged as test scope")
	}
}

// TestTestScope_TestOnlyCallerIsAnEdge pins the false negative itself: the
// external test calls the adapter method directly, and that call must be an
// edge. Without it, "who calls this" answers RESOLVED-ABSENT for a symbol a
// test would break on.
func TestTestScope_TestOnlyCallerIsAnEdge(t *testing.T) {
	rec := analyseFiles(t, testScopeFiles())
	const adapterPut = "example.com/cgtestmod/adapter.(*Store).Put"
	if _, ok := edgeToExists(rec, "TestPutDirectly", adapterPut); !ok {
		t.Fatalf("no edge from the external test to %s", adapterPut)
	}
}

// TestTestScope_TestBinaryMainDoesNotMakeALibraryAnApplication guards the
// rooting rule. go/packages synthesises a package main for each test binary;
// counting it as the module's own command would reclassify every library and
// silently change how reachability is rooted.
func TestTestScope_TestBinaryMainDoesNotMakeALibraryAnApplication(t *testing.T) {
	rec := analyseFiles(t, testScopeFiles())
	if rec.ArtifactKind != domain.ArtifactLibrary {
		t.Errorf("ArtifactKind = %q, want library: this module ships no command", rec.ArtifactKind)
	}
}
