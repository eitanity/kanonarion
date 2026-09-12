package staticcha

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// makeNamedMethod builds a *types.Func for a method on a named struct type
// "Client" in pkgPath, with the package name, the method symbol and the
// receiver form chosen.
func makeNamedMethod(pkgPath, pkgName, symbol string, pointerRecv bool) *types.Func {
	pkg := types.NewPackage(pkgPath, pkgName)
	tn := types.NewTypeName(token.NoPos, pkg, "Client", nil)
	named := types.NewNamed(tn, types.NewStruct(nil, nil), nil)

	var recvType types.Type = named
	if pointerRecv {
		recvType = types.NewPointer(named)
	}
	recv := types.NewVar(token.NoPos, pkg, "", recvType)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	return types.NewFunc(token.NoPos, pkg, symbol, sig)
}

// TestLeafNodeFromFunc covers the synthesised-leaf branch used when the
// implementer method has no built SSA function (type-only dep / unbuilt
// package). The ID and metadata must match what buildNode would have produced
// for the same method — IsExportedAPI included, which means the same synthetic
// and package-main guards.
func TestLeafNodeFromFunc(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/analysed", "v1.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}

	tests := []struct {
		name        string
		pkgPath     string
		pkgName     string
		symbol      string
		pointerRecv bool
		wantID      string
		wantRecv    string
		wantExt     bool
		wantAPI     bool
	}{
		{
			name:     "external value receiver",
			pkgPath:  "example.com/dep/proto",
			wantID:   "example.com/dep/proto.(Client).Run",
			wantRecv: "Client",
			wantExt:  true,
			wantAPI:  false,
		},
		{
			name:        "external pointer receiver",
			pkgPath:     "example.com/dep/proto",
			pointerRecv: true,
			wantID:      "example.com/dep/proto.(*Client).Run",
			wantRecv:    "*Client",
			wantExt:     true,
			wantAPI:     false,
		},
		{
			name:     "in-module exported non-internal is API",
			pkgPath:  "example.com/analysed/sub",
			wantID:   "example.com/analysed/sub.(Client).Run",
			wantRecv: "Client",
			wantExt:  false,
			wantAPI:  true,
		},
		{
			name:     "in-module internal package is not API",
			pkgPath:  "example.com/analysed/internal/sub",
			wantID:   "example.com/analysed/internal/sub.(Client).Run",
			wantRecv: "Client",
			wantExt:  false,
			wantAPI:  false,
		},
		{
			// The devirt path must apply the same package-main guard buildNode
			// applies: a main package's exported method is not consumable API,
			// and tagging it makes it a library reachability root that no
			// consumer can reach.
			name:     "in-module main package is not API",
			pkgPath:  "example.com/analysed/cmd/app",
			pkgName:  "main",
			wantID:   "example.com/analysed/cmd/app.(Client).Run",
			wantRecv: "Client",
			wantExt:  false,
			wantAPI:  false,
		},
		{
			// Same for the synthetic guard: a wrapper symbol carries the SSA
			// marker and reads as exported on its first rune alone.
			name:     "in-module wrapper symbol is not API",
			pkgPath:  "example.com/analysed/sub",
			symbol:   "Run$bound",
			wantID:   "example.com/analysed/sub.(Client).Run$bound",
			wantRecv: "Client",
			wantExt:  false,
			wantAPI:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgName := tc.pkgName
			if pkgName == "" {
				pkgName = "pkg"
			}
			symbol := tc.symbol
			if symbol == "" {
				symbol = "Run"
			}
			m := makeNamedMethod(tc.pkgPath, pkgName, symbol, tc.pointerRecv)
			node := leafNodeFromFunc(m, membershipByPrefix(coord), token.NewFileSet(), sourceRoots{})

			if node.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", node.ID, tc.wantID)
			}
			if node.Symbol != symbol {
				t.Errorf("Symbol = %q, want %q", node.Symbol, symbol)
			}
			if node.Receiver != tc.wantRecv {
				t.Errorf("Receiver = %q, want %q", node.Receiver, tc.wantRecv)
			}
			if node.IsExternal != tc.wantExt {
				t.Errorf("IsExternal = %v, want %v", node.IsExternal, tc.wantExt)
			}
			if node.IsExportedAPI != tc.wantAPI {
				t.Errorf("IsExportedAPI = %v, want %v", node.IsExportedAPI, tc.wantAPI)
			}
			if tc.wantExt && node.Module != "" {
				t.Errorf("external node Module = %q, want empty", node.Module)
			}
			if !tc.wantExt && node.Module != coord.Path() {
				t.Errorf("in-module node Module = %q, want %q", node.Module, coord.Path())
			}
		})
	}
}

// edgeKeySink keeps newEdgeKey's result live so the compiler cannot fold the
// call away in the allocation test below.
var edgeKeySink edgeKey

// TestEdgeKeyDistinguishesItsFields pins the deduplication contract the walk
// depends on: two call edges collapse when, and only when, caller, callee, call
// site file and call site line all agree. Nothing here may make two distinct
// edges share a key — an edge dropped as a duplicate it is not is an edge the
// graph never records.
func TestEdgeKeyDistinguishesItsFields(t *testing.T) {
	base := newEdgeKey("pkg.From", "pkg.To", "a.go", 12)

	if base != newEdgeKey("pkg.From", "pkg.To", "a.go", 12) {
		t.Fatal("identical edges produced different keys; duplicates would no longer collapse")
	}

	for _, tc := range []struct {
		name string
		key  edgeKey
	}{
		{"caller", newEdgeKey("pkg.Other", "pkg.To", "a.go", 12)},
		{"callee", newEdgeKey("pkg.From", "pkg.Other", "a.go", 12)},
		{"file", newEdgeKey("pkg.From", "pkg.To", "b.go", 12)},
		{"line", newEdgeKey("pkg.From", "pkg.To", "a.go", 13)},
	} {
		if tc.key == base {
			t.Errorf("edges differing in %s share a key", tc.name)
		}
	}
}

// TestEdgeKeyDoesNotAllocate is the memory property. The walk holds one key per
// resolved edge — tens of millions on a dispatch-heavy module — and every field
// is a string the graph already holds, so forming a key must borrow them rather
// than copy them into a fresh allocation that is freed unread.
func TestEdgeKeyDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(1000, func() {
		edgeKeySink = newEdgeKey(
			"github.com/example/mod/internal/pkg.(*Receiver).Method",
			"github.com/example/mod/internal/other.(*Thing).Handle",
			"internal/pkg/file.go",
			1234,
		)
	})
	if allocs != 0 {
		t.Errorf("newEdgeKey allocated %.1f times per call, want 0", allocs)
	}
}
