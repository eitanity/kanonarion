package tinycgo

import (
	"fmt"
	"go/types"
	"slices"
	"strings"
)

// SizesFor is the types.Sizes TinyGo type-checks with for triple. TinyGo reads
// the pointer size and the complex128 alignment from LLVM's target data; the
// table below is those two numbers per architecture, measured with clang's
// data layouts, because GOARCH cannot say them (avr and riscv32 report arm).
func SizesFor(triple string) (types.Sizes, error) {
	arch, _, _ := strings.Cut(triple, "-")
	for _, a := range archSizes {
		if a.match(arch) {
			intSize := int64(4)
			if a.ptr == 8 {
				intSize = 8
			}
			return &stdSizes{IntSize: intSize, PtrSize: a.ptr, MaxAlign: a.maxAlign}, nil
		}
	}
	return nil, fmt.Errorf("the LLVM triple %q names an architecture whose Go type sizes this analysis does not know", triple)
}

// archSize is one architecture's pointer size and complex128 alignment.
type archSize struct {
	names, prefixes []string
	ptr, maxAlign   int64
}

func (a archSize) match(arch string) bool {
	return slices.Contains(a.names, arch) || slices.ContainsFunc(a.prefixes, func(p string) bool { return strings.HasPrefix(arch, p) })
}

var archSizes = []archSize{
	{names: []string{"avr"}, ptr: 2, maxAlign: 1},
	{names: []string{"i386", "i486", "i586", "i686"}, ptr: 4, maxAlign: 4},
	{names: []string{"x86_64", "aarch64", "arm64", "riscv64", "wasm64", "s390x"}, prefixes: []string{"mips64", "powerpc64"}, ptr: 8, maxAlign: 8},
	{names: []string{"riscv32", "wasm32", "mips", "mipsel", "xtensa"}, prefixes: []string{"arm", "thumb"}, ptr: 4, maxAlign: 8},
}

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo cgo transform, target definitions and type sizes
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.42.0, compiler/sizes.go (stdSizes) and compiler/compiler.go (Sizes)

// stdSizes is go/types' StdSizes with the int and pointer sizes allowed to
// differ, and function values two words wide, as TinyGo lays them out.
type stdSizes struct {
	IntSize  int64
	PtrSize  int64
	MaxAlign int64
}

func (s *stdSizes) Alignof(typ types.Type) int64 {
	switch t := typ.Underlying().(type) {
	case *types.Array:
		return s.Alignof(t.Elem())
	case *types.Struct:
		maxA := int64(1)
		for f := range t.Fields() {
			if a := s.Alignof(f.Type()); a > maxA {
				maxA = a
			}
		}
		return maxA
	case *types.Slice, *types.Interface:
		return s.PtrSize
	case *types.Basic:
		if t.Info()&types.IsString != 0 {
			return s.PtrSize
		}
	case *types.Signature:
		return s.PtrSize
	}

	a := s.Sizeof(typ)
	if a < 1 {
		return 1
	}
	if t, ok := typ.Underlying().(*types.Basic); ok && t.Info()&types.IsComplex != 0 {
		a /= 2
	}
	if a > s.MaxAlign {
		return s.MaxAlign
	}
	return a
}

func (s *stdSizes) Offsetsof(fields []*types.Var) []int64 {
	offsets := make([]int64, len(fields))
	var o int64
	for i, f := range fields {
		a := s.Alignof(f.Type())
		o = align(o, a)
		offsets[i] = o
		o += s.Sizeof(f.Type())
	}
	return offsets
}

var basicSizes = [...]byte{
	types.Bool:       1,
	types.Int8:       1,
	types.Int16:      2,
	types.Int32:      4,
	types.Int64:      8,
	types.Uint8:      1,
	types.Uint16:     2,
	types.Uint32:     4,
	types.Uint64:     8,
	types.Float32:    4,
	types.Float64:    8,
	types.Complex64:  8,
	types.Complex128: 16,
}

func (s *stdSizes) Sizeof(typ types.Type) int64 {
	switch t := typ.Underlying().(type) {
	case *types.Basic:
		return s.sizeofBasic(t)
	case *types.Array:
		n := t.Len()
		if n <= 0 {
			return 0
		}
		a := s.Alignof(t.Elem())
		z := s.Sizeof(t.Elem())
		return align(z, a)*(n-1) + z
	case *types.Slice:
		return s.PtrSize * 3
	case *types.Struct:
		n := t.NumFields()
		if n == 0 {
			return 0
		}
		fields := make([]*types.Var, n)
		maxA := int64(1)
		for i := range fields {
			field := t.Field(i)
			fields[i] = field
			if al := s.Alignof(field.Type()); al > maxA {
				maxA = al
			}
		}
		offsets := s.Offsetsof(fields)
		return align(offsets[n-1]+s.Sizeof(fields[n-1].Type()), maxA)
	case *types.Interface:
		return s.PtrSize * 2
	case *types.Pointer, *types.Chan, *types.Map:
		return s.PtrSize
	case *types.Signature:
		return s.PtrSize * 2
	default:
		panic("unknown type: " + t.String())
	}
}

func (s *stdSizes) sizeofBasic(t *types.Basic) int64 {
	k := t.Kind()
	if int(k) < len(basicSizes) {
		if s := basicSizes[k]; s > 0 {
			return int64(s)
		}
	}
	switch k {
	case types.String:
		return s.PtrSize * 2
	case types.Int, types.Uint:
		return s.IntSize
	case types.Uintptr, types.UnsafePointer:
		return s.PtrSize
	case types.Invalid:
		return 0
	}
	panic("unknown basic type: " + t.String())
}

// align returns the smallest y >= x such that y % a == 0.
func align(x, a int64) int64 {
	y := x + a - 1
	return y - y%a
}

// SPDX-SnippetEnd
