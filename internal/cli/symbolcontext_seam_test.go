package cli

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// buildSymbolContextEntries groups refs by module, sorts deterministically,
// and attaches examples. The existing DeterministicSort test could only
// replicate the sort because it lacked a Container; this drives the real
// function through fakes, covering grouping, the method-qualified name, and
// example attachment end-to-end.
func TestBuildSymbolContextEntries_GroupsSortsAndAttachesExamples(t *testing.T) {
	refs := []ifaceports.SymbolRef{
		{ModulePath: "z.io/mod", ModuleVersion: "v1.0.0", PackagePath: "z.io/mod", SymbolKind: "func", SymbolName: "Do"},
		{ModulePath: "a.io/mod", ModuleVersion: "v1.0.0", PackagePath: "a.io/mod", SymbolKind: "method", ParentType: "Client", SymbolName: "Run"},
	}

	examples := testfakes.NewFakeQueryExamples()
	examples.SetRefs([]exports.ExampleRef{{
		ModulePath: "a.io/mod", ModuleVersion: "v1.0.0",
		Package: "a.io/mod", ExampleName: "ExampleClient_Run", Validates: true,
	}})

	ctr := &Container{
		QueryInterface: testfakes.NewFakeQueryInterface(), // no record => empty docs
		QueryExamples:  examples,
	}

	entries, err := buildSymbolContextEntries(context.Background(), ctr, refs, "1.0.0")
	if err != nil {
		t.Fatalf("buildSymbolContextEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}

	// Sorted by module: a.io/mod before z.io/mod regardless of input order.
	if entries[0].Module != "a.io/mod@v1.0.0" {
		t.Errorf("entries not sorted by module: first = %q", entries[0].Module)
	}
	// Method qualified name includes the parent type.
	if entries[0].QualifiedName != "a.io/mod.Client.Run" {
		t.Errorf("method qualified name = %q, want a.io/mod.Client.Run", entries[0].QualifiedName)
	}
	// Example attached to the a.io/mod symbol.
	if len(entries[0].Examples) != 1 || entries[0].Examples[0].Name != "ExampleClient_Run" {
		t.Errorf("expected the matching example attached, got: %+v", entries[0].Examples)
	}
	// z.io/mod symbol has no example (its coordinate did not match).
	if len(entries[1].Examples) != 0 {
		t.Errorf("z.io/mod should have no examples, got: %+v", entries[1].Examples)
	}
}
