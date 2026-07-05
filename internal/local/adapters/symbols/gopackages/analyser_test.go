package gopackages

import (
	"go/token"
	"go/types"
	"sort"
	"testing"
)

// Tests for unexported helpers: qualifiedName and sortedSet.

// -- sortedSet --

func TestSortedSet_ReturnsSortedSlice(t *testing.T) {
	m := map[string]struct{}{
		"github.com/z": {},
		"github.com/a": {},
		"github.com/m": {},
	}
	got := sortedSet(m)
	if !sort.StringsAreSorted(got) {
		t.Errorf("sortedSet result is not sorted: %v", got)
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

func TestSortedSet_Empty(t *testing.T) {
	got := sortedSet(map[string]struct{}{})
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestSortedSet_SingleElement(t *testing.T) {
	got := sortedSet(map[string]struct{}{"only": {}})
	if len(got) != 1 || got[0] != "only" {
		t.Errorf("got = %v, want [only]", got)
	}
}

func TestSortedSet_NoDuplicates(t *testing.T) {
	// Maps can't have duplicate keys, so this just verifies every key appears once.
	m := map[string]struct{}{
		"a": {},
		"b": {},
	}
	got := sortedSet(m)
	seen := make(map[string]int)
	for _, v := range got {
		seen[v]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("key %q appears %d times, want 1", k, n)
		}
	}
}

// -- qualifiedName --

func makePkg(t *testing.T) *types.Package {
	t.Helper()
	return types.NewPackage("example.com/lib", "lib")
}

func TestQualifiedName_NonFunc_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	v := types.NewVar(token.NoPos, pkg, "MyVar", types.Typ[types.Int])
	got := qualifiedName(v)
	if got != "MyVar" {
		t.Errorf("qualifiedName(Var) = %q, want MyVar", got)
	}
}

func TestQualifiedName_TypeName_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	tn := types.NewTypeName(token.NoPos, pkg, "MyType", nil)
	got := qualifiedName(tn)
	if got != "MyType" {
		t.Errorf("qualifiedName(TypeName) = %q, want MyType", got)
	}
}

func TestQualifiedName_Const_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	c := types.NewConst(token.NoPos, pkg, "MyConst", types.Typ[types.Int], nil)
	got := qualifiedName(c)
	if got != "MyConst" {
		t.Errorf("qualifiedName(Const) = %q, want MyConst", got)
	}
}

func TestQualifiedName_StandaloneFunc_ReturnsName(t *testing.T) {
	pkg := makePkg(t)
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "DoWork", sig)
	got := qualifiedName(fn)
	if got != "DoWork" {
		t.Errorf("qualifiedName(standalone func) = %q, want DoWork", got)
	}
}

func TestQualifiedName_ValueReceiverMethod_ReturnsTypeDotMethod(t *testing.T) {
	pkg := makePkg(t)
	// Build: type MyType struct{}; func (m MyType) Method {}
	typeName := types.NewTypeName(token.NoPos, pkg, "MyType", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, pkg, "m", named)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "Method", sig)

	got := qualifiedName(fn)
	if got != "MyType.Method" {
		t.Errorf("qualifiedName(value receiver) = %q, want MyType.Method", got)
	}
}

func TestQualifiedName_PointerReceiverMethod_ReturnsTypeDotMethod(t *testing.T) {
	pkg := makePkg(t)
	// Build: type MyType struct{}; func (m *MyType) PtrMethod {}
	typeName := types.NewTypeName(token.NoPos, pkg, "MyType", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	ptrType := types.NewPointer(named)
	recv := types.NewVar(token.NoPos, pkg, "m", ptrType)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	fn := types.NewFunc(token.NoPos, pkg, "PtrMethod", sig)

	got := qualifiedName(fn)
	// Pointer is stripped: result should still be "MyType.PtrMethod"
	if got != "MyType.PtrMethod" {
		t.Errorf("qualifiedName(pointer receiver) = %q, want MyType.PtrMethod", got)
	}
}
