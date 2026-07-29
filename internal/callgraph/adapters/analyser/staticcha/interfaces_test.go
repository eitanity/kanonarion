package staticcha_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func implementersOf(rec domain.CallGraphRecord, interfaceID string) []domain.InterfaceImplementation {
	impls, _ := domain.ImplementersOf(rec, interfaceID)
	return impls
}

func typeIDs(impls []domain.InterfaceImplementation) map[string]bool {
	out := make(map[string]bool, len(impls))
	for _, im := range impls {
		out[im.TypeID] = true
	}
	return out
}

// TestInterfaces_PortAndItsImplementers is the core rule: the interface is
// addressable, and the concrete types satisfying it — production adapter and
// test fake alike — are recorded against it.
func TestInterfaces_PortAndItsImplementers(t *testing.T) {
	rec := analyseFiles(t, testScopeFiles())

	const portID = "example.com/cgtestmod/ports.Store"
	iface, ok := domain.InterfaceByID(rec, portID)
	if !ok {
		t.Fatalf("interface %s is not recorded", portID)
	}
	if len(iface.Methods) != 1 || iface.Methods[0] != "Put" {
		t.Errorf("interface methods = %v, want [Put]", iface.Methods)
	}

	impls := implementersOf(rec, portID)
	got := typeIDs(impls)
	for _, want := range []string{
		"example.com/cgtestmod/adapter.(*Store)",
		"example.com/cgtestmod/app.(*fakeStore)",
	} {
		if !got[want] {
			t.Errorf("implementer %s missing; got %v", want, got)
		}
	}

	for _, im := range impls {
		wantTest := im.TypeID == "example.com/cgtestmod/app.(*fakeStore)"
		if im.IsTest != wantTest {
			t.Errorf("%s IsTest = %v, want %v", im.TypeID, im.IsTest, wantTest)
		}
		if len(im.Methods) != 1 || im.Methods[0].Method != "Put" {
			t.Fatalf("%s methods = %v, want one Put entry", im.TypeID, im.Methods)
		}
		// The recorded node ID must be one the edge queries also accept, or the
		// per-method form of the query hands back an ID nothing else resolves.
		if _, ok := nodeByID(rec, im.Methods[0].NodeID); !ok {
			t.Errorf("%s implementing method %q is not a node in the graph", im.TypeID, im.Methods[0].NodeID)
		}
	}
}

// TestInterfaces_EmbeddedImplementationIsFound covers the case a grep for the
// method name cannot: the wrapper declares no method of its own and satisfies
// the interface only through the type it embeds.
func TestInterfaces_EmbeddedImplementationIsFound(t *testing.T) {
	files := testScopeFiles()
	files["wrapper/wrapper.go"] = `package wrapper

import "example.com/cgtestmod/adapter"

// Auditing satisfies ports.Store purely by embedding, declaring no Put itself.
type Auditing struct {
	*adapter.Store
}
`
	rec := analyseFiles(t, files)

	impls := implementersOf(rec, "example.com/cgtestmod/ports.Store")
	got := typeIDs(impls)
	// The value form is recorded because embedding a pointer puts Put in both
	// method sets, and the value form is the more general of the two.
	const wrapperID = "example.com/cgtestmod/wrapper.(Auditing)"
	if !got[wrapperID] {
		t.Fatalf("embedded implementer %s not found; got %v", wrapperID, got)
	}
	for _, im := range impls {
		if im.TypeID != wrapperID {
			continue
		}
		// The declaration to change is the embedded one, so that is the node the
		// query must name — pointing at the wrapper would send a reader to a file
		// with nothing to edit.
		if want := "example.com/cgtestmod/adapter.(*Store).Put"; im.Methods[0].NodeID != want {
			t.Errorf("promoted method NodeID = %q, want %q", im.Methods[0].NodeID, want)
		}
	}
}

// TestInterfaces_EmptyInterfaceIsNotRecorded keeps the relation meaningful: a
// method-less interface is satisfied by everything, so its implementer list
// would answer "which types exist", not "what must change together".
func TestInterfaces_EmptyInterfaceIsNotRecorded(t *testing.T) {
	files := testScopeFiles()
	files["ports/any.go"] = "package ports\n\ntype Anything interface{}\n"
	rec := analyseFiles(t, files)

	if _, ok := domain.InterfaceByID(rec, "example.com/cgtestmod/ports.Anything"); ok {
		t.Error("a method-less interface was recorded; every type satisfies it")
	}
}

// TestInterfaces_DeclaredButUnimplemented pins the distinction the verdict
// rests on: an interface with no implementers is a measured empty set, and must
// still be reported as declared rather than as unknown.
func TestInterfaces_DeclaredButUnimplemented(t *testing.T) {
	files := testScopeFiles()
	files["ports/unused.go"] = "package ports\n\ntype Unused interface {\n\tNothingImplementsThis() error\n}\n"
	rec := analyseFiles(t, files)

	const id = "example.com/cgtestmod/ports.Unused"
	impls, declared := domain.ImplementersOf(rec, id)
	if !declared {
		t.Fatalf("interface %s was not recorded as declared", id)
	}
	if len(impls) != 0 {
		t.Errorf("got %d implementers, want none", len(impls))
	}
}
