package staticcha

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// makeMethod builds a *types.Func for a method "Run" on a named struct type
// "Client" in pkgPath, with a value or pointer receiver.
func makeMethod(pkgPath string, pointerRecv bool) *types.Func {
	pkg := types.NewPackage(pkgPath, "pkg")
	tn := types.NewTypeName(token.NoPos, pkg, "Client", nil)
	named := types.NewNamed(tn, types.NewStruct(nil, nil), nil)

	var recvType types.Type = named
	if pointerRecv {
		recvType = types.NewPointer(named)
	}
	recv := types.NewVar(token.NoPos, pkg, "", recvType)
	sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
	return types.NewFunc(token.NoPos, pkg, "Run", sig)
}

// TestLeafNodeFromFunc covers the synthesised-leaf branch used when the
// implementer method has no built SSA function (type-only dep / unbuilt
// package). The ID and metadata must match what buildNode would have produced
// for the same method.
func TestLeafNodeFromFunc(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/analysed", "v1.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}

	tests := []struct {
		name        string
		pkgPath     string
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := makeMethod(tc.pkgPath, tc.pointerRecv)
			node := leafNodeFromFunc(m, coord, token.NewFileSet(), "")

			if node.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", node.ID, tc.wantID)
			}
			if node.Symbol != "Run" {
				t.Errorf("Symbol = %q, want Run", node.Symbol)
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
			if !tc.wantExt && node.Module != coord.Path {
				t.Errorf("in-module node Module = %q, want %q", node.Module, coord.Path)
			}
		})
	}
}
