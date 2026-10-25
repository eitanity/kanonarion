package tinylower

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
)

type keyClass int

const (
	keyString keyClass = iota
	keyBinary
	keyGeneric
)

// keyOf is a map type's key type, nil for any other type.
func keyOf(m types.Type) types.Type {
	if mt, ok := m.Underlying().(*types.Map); ok {
		return mt.Key()
	}
	return nil
}

func mapKey(m types.Type) keyClass {
	key := m
	if k := keyOf(m); k != nil {
		key = k.Underlying()
	}
	if b, ok := key.(*types.Basic); ok && b.Info()&types.IsString != 0 {
		return keyString
	}
	if isBinaryKey(key) {
		return keyBinary
	}
	return keyGeneric
}

func mapOp(k keyClass, str, binary, generic Op) Op {
	switch k {
	case keyString:
		return str
	case keyBinary:
		return binary
	}
	return generic
}

// isBinaryKey is hashmapIsBinaryKey (map.go:202).
func isBinaryKey(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&(types.IsBoolean|types.IsInteger) != 0 || u.Kind() == types.UnsafePointer
	case *types.Pointer:
		return true
	case *types.Array:
		return isBinaryKey(u.Elem())
	}
	return false
}

// makeMap is createMakeMap (map.go:18). A key that is neither a string nor
// binary gets generated hash and equal functions, whose runtime calls are
// attributed to the make.
func (w *walker) makeMap(v *ssa.MakeMap) {
	w.add(v.Pos(), OpMapMake)
	switch mapKey(v.Type()) {
	case keyString:
		w.add(v.Pos(), OpMapKeyFuncsString)
	case keyBinary:
		w.add(v.Pos(), OpMapKeyFuncsBinary)
	default:
		key := keyOf(v.Type())
		seen := map[Op]bool{}
		for _, op := range append(keyHash(key, nil), keyEqual(key, nil)...) {
			if !seen[op] {
				seen[op] = true
				w.add(v.Pos(), op)
			}
		}
	}
}

// keyHash is generateKeyHash (map.go:341).
func keyHash(t types.Type, out []Op) []Op {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsString != 0:
			return append(out, OpKeyHashString)
		case u.Kind() == types.Float32 || u.Kind() == types.Complex64:
			return append(out, OpKeyHashFloat32)
		case u.Kind() == types.Float64 || u.Kind() == types.Complex128:
			return append(out, OpKeyHashFloat64)
		}
		return append(out, OpKeyHashBinary)
	case *types.Pointer, *types.Chan:
		return append(out, OpKeyHashBinary)
	case *types.Interface:
		return append(out, OpKeyHashInterface)
	case *types.Struct:
		for i := range u.NumFields() {
			out = keyHash(u.Field(i).Type(), out)
		}
	case *types.Array:
		if u.Len() == 0 {
			return out
		}
		if isBinaryKey(u.Elem()) {
			return append(out, OpKeyHashBinary)
		}
		return keyHash(u.Elem(), out)
	}
	return out
}

// keyEqual is generateKeyEqual (map.go:455); floats compare inline.
func keyEqual(t types.Type, out []Op) []Op {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsString != 0:
			return append(out, OpKeyEqualString)
		case u.Info()&(types.IsFloat|types.IsComplex) != 0:
			return out
		}
		return append(out, OpKeyEqualBinary)
	case *types.Pointer, *types.Chan:
		return append(out, OpKeyEqualBinary)
	case *types.Interface:
		return append(out, OpKeyEqualInterface)
	case *types.Struct:
		for i := range u.NumFields() {
			out = keyEqual(u.Field(i).Type(), out)
		}
	case *types.Array:
		if u.Len() == 0 {
			return out
		}
		if isBinaryKey(u.Elem()) {
			return append(out, OpKeyEqualBinary)
		}
		return keyEqual(u.Elem(), out)
	}
	return out
}
