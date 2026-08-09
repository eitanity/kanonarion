package staticcha_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// nestedModuleTree writes a parent module that imports a SEPARATE module whose
// path nests under the parent's own — the shape the Go module system permits and
// a path-prefix membership test cannot see.
//
// The child is resolved by a replace directive to a directory outside the parent
// tree, so the analysis needs no network and no module cache. It is a real second
// module either way: it declares its own go.mod, and a replace changes where the
// bytes come from, not which module they are.
//
// The parent also ships a genuine sub-package of its own at a deeper path. That
// is the control: a fix that decides "deeper path means foreign" would satisfy
// the child assertion and silently disown half of every real module.
func nestedModuleTree(t *testing.T) (parentDir string) {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	child := filepath.Join(root, "child")

	writeFile(t, filepath.Join(child, "go.mod"), "module example.com/parent/child\n\ngo 1.21\n")
	writeFile(t, filepath.Join(child, "child.go"), `package child

// ChildExported is exported API of example.com/parent/child, NOT of
// example.com/parent.
func ChildExported() {}

// Speaker is the nested module's interface, and Talker its implementer. Neither
// is a type example.com/parent declares.
type Speaker interface{ Speak() string }

type Talker struct{}

func (Talker) Speak() string { return "" }
`)

	writeFile(t, filepath.Join(parent, "go.mod"), `module example.com/parent

go 1.21

require example.com/parent/child v0.0.0

replace example.com/parent/child => ../child
`)
	writeFile(t, filepath.Join(parent, "go.sum"), "")
	writeFile(t, filepath.Join(parent, "parent.go"), `package parent

import (
	"example.com/parent/child"
	"example.com/parent/sub"
)

// Root calls into both the nested MODULE and the parent's own sub-PACKAGE.
func Root() {
	child.ChildExported()
	sub.SubExported()
}
`)
	writeFile(t, filepath.Join(parent, "sub", "sub.go"), `package sub

// SubExported is a genuine sub-package of example.com/parent: deeper path, same
// module.
func SubExported() {}
`)
	return parent
}

// TestAnalyseDir_NestedModuleIsNotTheParentsCode is the regression: a module
// whose path nests under the analysed module's is a different module, and its
// functions must not be recorded as the analysed module's own code, nor as its
// exported API.
func TestAnalyseDir_NestedModuleIsNotTheParentsCode(t *testing.T) {
	rec := analyseDir(t, nestedModuleTree(t), "example.com/parent")

	const childFn = "example.com/parent/child.ChildExported"
	n, ok := nodeByID(rec, childFn)
	if !ok {
		t.Fatalf("%s is not in the graph at all; the fixture did not build (status %v, detail %q)",
			childFn, rec.OverallStatus, rec.FailureDetail)
	}
	if !n.IsExternal {
		t.Errorf("%s recorded as example.com/parent's own code (is_external=false)", childFn)
	}
	if n.Module != "" {
		t.Errorf("%s recorded under module %q; it belongs to example.com/parent/child", childFn, n.Module)
	}
	if n.IsExportedAPI {
		t.Errorf("%s recorded as example.com/parent's exported API", childFn)
	}
}

// TestAnalyseDir_GenuineSubPackageStaysInModule is the zero-paired control. A
// deeper import path within the SAME module is the analysed module's own code,
// and a membership rule that answers the nested-module case by disowning every
// deeper path fails here.
func TestAnalyseDir_GenuineSubPackageStaysInModule(t *testing.T) {
	rec := analyseDir(t, nestedModuleTree(t), "example.com/parent")

	const subFn = "example.com/parent/sub.SubExported"
	n, ok := nodeByID(rec, subFn)
	if !ok {
		t.Fatalf("%s is not in the graph at all; the fixture did not build (status %v, detail %q)",
			subFn, rec.OverallStatus, rec.FailureDetail)
	}
	if n.IsExternal {
		t.Errorf("%s recorded as foreign; it is a package of example.com/parent", subFn)
	}
	if n.Module != "example.com/parent" {
		t.Errorf("%s recorded under module %q, want example.com/parent", subFn, n.Module)
	}
	if !n.IsExportedAPI {
		t.Errorf("%s is not recorded as exported API of example.com/parent", subFn)
	}
}

// TestAnalyseDir_InterfaceScopeExcludesTheNestedModule pins the fourth call
// site. Interface/implementer extraction is scoped to the analysed module's own
// declarations, and a nested module's types are not that module's.
func TestAnalyseDir_InterfaceScopeExcludesTheNestedModule(t *testing.T) {
	rec := analyseDir(t, nestedModuleTree(t), "example.com/parent")
	for _, it := range rec.Interfaces {
		if strings.HasPrefix(it.Package, "example.com/parent/child") {
			t.Errorf("interface %s from the nested module recorded as example.com/parent's", it.ID)
		}
	}
	for _, im := range rec.Implementations {
		if strings.HasPrefix(im.Package, "example.com/parent/child") {
			t.Errorf("implementation %s from the nested module recorded as example.com/parent's", im.TypeID)
		}
	}
}

// TestAnalyseDir_NamesNoPrefixAttributionWhenTheLoaderPlacedEveryPackage is the
// visibility half. Every package in this fixture is placed in a module by the
// toolchain, so nothing was decided by prefix and the record claims no
// reconstruction. The label is only meaningful if it is absent when nothing was
// reconstructed.
func TestAnalyseDir_NamesNoPrefixAttributionWhenTheLoaderPlacedEveryPackage(t *testing.T) {
	rec := analyseDir(t, nestedModuleTree(t), "example.com/parent")
	if len(rec.PrefixAttributedPackages) != 0 {
		t.Errorf("record claims prefix-attributed packages %v; the loader placed every package in a module",
			rec.PrefixAttributedPackages)
	}
}
