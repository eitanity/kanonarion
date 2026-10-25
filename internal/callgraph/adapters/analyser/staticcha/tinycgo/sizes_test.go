package tinycgo

import (
	"go/types"
	"strings"
	"testing"
)

// The sizes follow the triple, not GOARCH: avr reports arm and has 16-bit
// pointers with a 32-bit int.
func TestSizesFor_TheTriplesArchitecture(t *testing.T) {
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	for _, tc := range []struct {
		triple                   string
		ptr, intSize, i64, align int64
	}{
		{"avr", 2, 4, 1, 1},
		{"thumbv6m-unknown-unknown-eabi", 4, 4, 8, 8},
		{"riscv32-unknown-none", 4, 4, 8, 8},
		{"wasm32-unknown-wasi", 4, 4, 8, 8},
		{"i686-unknown-linux", 4, 4, 4, 4},
		{"x86_64-unknown-linux", 8, 8, 8, 8},
		{"aarch64-unknown-linux", 8, 8, 8, 8},
	} {
		s, err := SizesFor(tc.triple)
		if err != nil {
			t.Fatalf("%s: %v", tc.triple, err)
		}
		if got := s.Sizeof(types.Typ[types.UnsafePointer]); got != tc.ptr {
			t.Errorf("%s: pointer %d, want %d", tc.triple, got, tc.ptr)
		}
		if got := s.Sizeof(types.Typ[types.Int]); got != tc.intSize {
			t.Errorf("%s: int %d, want %d", tc.triple, got, tc.intSize)
		}
		if got := s.Alignof(types.Typ[types.Int64]); got != tc.i64 {
			t.Errorf("%s: int64 alignment %d, want %d", tc.triple, got, tc.i64)
		}
		if got := s.Sizeof(sig); got != 2*tc.ptr {
			t.Errorf("%s: a func value is %d bytes, want two pointers", tc.triple, got)
		}
		if got := s.Alignof(types.Typ[types.Complex128]); got != tc.align {
			t.Errorf("%s: complex128 alignment %d, want %d", tc.triple, got, tc.align)
		}
	}
	if _, err := SizesFor("sparc-unknown-none"); err == nil || !strings.Contains(err.Error(), "sparc-unknown-none") {
		t.Errorf("an unknown architecture = %v", err)
	}
}

func TestSizes_CompositeTypesAsTinyGoLaysThemOut(t *testing.T) {
	s, err := SizesFor("avr")
	if err != nil {
		t.Fatal(err)
	}
	str := types.NewStruct([]*types.Var{
		types.NewField(0, nil, "a", types.Typ[types.Uint8], false),
		types.NewField(0, nil, "b", types.Typ[types.Int32], false),
	}, nil)
	for _, tc := range []struct {
		name string
		typ  types.Type
		size int64
	}{
		{"string", types.Typ[types.String], 4},
		{"slice", types.NewSlice(types.Typ[types.Byte]), 6},
		{"interface", types.NewInterfaceType(nil, nil), 4},
		{"array", types.NewArray(types.Typ[types.Uint16], 3), 6},
		{"empty array", types.NewArray(types.Typ[types.Uint16], 0), 0},
		{"struct", str, 5},
		{"empty struct", types.NewStruct(nil, nil), 0},
		{"map", types.NewMap(types.Typ[types.Int], types.Typ[types.Int]), 2},
		{"invalid", types.Typ[types.Invalid], 0},
	} {
		if got := s.Sizeof(tc.typ); got != tc.size {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.size)
		}
	}
	if got := s.Alignof(types.Typ[types.String]); got != 2 {
		t.Errorf("string alignment on avr = %d", got)
	}
	if got := s.Offsetsof([]*types.Var{str.Field(0), str.Field(1)}); got[0] != 0 || got[1] != 1 {
		t.Errorf("offsets on avr = %v, want [0 1]", got)
	}
}
