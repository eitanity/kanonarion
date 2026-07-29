package staticcha_test

import (
	"fmt"
	"testing"
)

// portDispatchFiles builds a module in the shape the missing-edge report was
// measured on: a port interface, a concrete adapter satisfying it, and a use
// case that holds the port as a field and is constructed through a decorator
// (New(...).WithAudit(...)), all in separate packages. filler packages pad the
// target set out past any plausible load batch, which is the condition under
// which the analysis used to hold several copies of each package's types and
// bound the dispatch against the wrong one.
func portDispatchFiles(fillers int) map[string]string {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"ports/ports.go": `package ports

// Store is the port the use case depends on.
type Store interface {
	Put(v int) error
	Get() int
}

// Sink is the optional decorator dependency.
type Sink interface {
	Record(v int)
}
`,
		"adapter/adapter.go": `package adapter

// Store is the sole production implementer of ports.Store.
type Store struct{}

func (s *Store) Put(v int) error { return nil }
func (s *Store) Get() int        { return 0 }
`,
		"app/app.go": `package app

import "example.com/cgtestmod/ports"

// UseCase holds the port as a field, exactly as the license and vuln use cases do.
type UseCase struct {
	store ports.Store
	audit ports.Sink
}

func New(s ports.Store) *UseCase { return &UseCase{store: s} }

// WithAudit is the optional-dependency decorator the use case is constructed
// through at the composition root.
func (uc *UseCase) WithAudit(s ports.Sink) *UseCase {
	uc.audit = s
	return uc
}

// Execute dispatches through the port field.
func (uc *UseCase) Execute() error {
	return uc.store.Put(1)
}
`,
		"wire/wire.go": `package wire

import (
	"example.com/cgtestmod/adapter"
	"example.com/cgtestmod/app"
)

// Build is the composition root: it converts the concrete adapter to the port
// and wraps the use case in its decorator.
func Build() *app.UseCase {
	return app.New(&adapter.Store{}).WithAudit(nil)
}
`,
	}
	for i := range fillers {
		dir := fmt.Sprintf("filler%02d", i)
		files[dir+"/"+dir+".go"] = fmt.Sprintf("package filler%02d\n\n// N is padding so the target package set spans more than one load batch.\nconst N = %d\n", i, i)
	}
	return files
}

// TestPortDispatch_UseCaseFieldReachesAdapter is the regression: a use case
// holding a port interface field, constructed through a decorator, must
// yield a caller edge to the concrete adapter method.
//
// The failure it pins was not a property of this shape — it was that the
// analysis type-checked the target set in several go/packages calls, and
// go/types compares types by pointer identity, so a concrete type from one call
// never satisfied an interface from another. Whether a port method resolved its
// callers came down to which call each package landed in, which is why one
// store-adapter method could report RESOLVED-ABSENT while its sibling on the
// same type resolved.
func TestPortDispatch_UseCaseFieldReachesAdapter(t *testing.T) {
	rec := analyseFiles(t, portDispatchFiles(30))

	const adapterPut = "example.com/cgtestmod/adapter.(*Store).Put"
	if _, ok := nodeByID(rec, adapterPut); !ok {
		t.Fatalf("adapter method %s is not a node in the graph", adapterPut)
	}
	if _, ok := edgeToExists(rec, "Execute", adapterPut); !ok {
		t.Fatalf("no edge from the use case's Execute to %s: the port dispatch was not bound", adapterPut)
	}
}

// TestPortDispatch_SiblingMethodsResolveTogether pins the asymmetry itself. Two
// methods on the same adapter type, reached through the same port field, must
// either both resolve or both not — a graph in which one has a caller and the
// other is absent is the signature of a split type universe, and it is
// indistinguishable, in query output, from a real absence.
func TestPortDispatch_SiblingMethodsResolveTogether(t *testing.T) {
	files := portDispatchFiles(30)
	// Execute now dispatches on both port methods.
	files["app/app.go"] = `package app

import "example.com/cgtestmod/ports"

type UseCase struct {
	store ports.Store
	audit ports.Sink
}

func New(s ports.Store) *UseCase { return &UseCase{store: s} }

func (uc *UseCase) WithAudit(s ports.Sink) *UseCase {
	uc.audit = s
	return uc
}

func (uc *UseCase) Execute() error {
	_ = uc.store.Get()
	return uc.store.Put(1)
}
`
	rec := analyseFiles(t, files)

	for _, method := range []string{"Get", "Put"} {
		id := "example.com/cgtestmod/adapter.(*Store)." + method
		if _, ok := edgeToExists(rec, "Execute", id); !ok {
			t.Errorf("no edge from Execute to %s; sibling port methods must resolve together", id)
		}
	}
}
