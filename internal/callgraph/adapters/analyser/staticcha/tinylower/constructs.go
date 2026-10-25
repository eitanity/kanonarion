package tinylower

import (
	"go/constant"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/ssa"
)

func (w *walker) sizeof(t types.Type) int64 {
	if w.cfg.Sizes == nil {
		return 1
	}
	return w.cfg.Sizes.Sizeof(t)
}

func (w *walker) heapAlloc(pos token.Pos, zero bool) {
	switch {
	case zero:
		w.add(pos, OpAllocZero) // gc.go:27 overrides gc.go:21
	case w.noHeap:
		w.add(pos, OpAllocNoHeap)
	default:
		w.add(pos, OpAlloc)
	}
}

// alloc is compiler.go:2427: escaping or large locals go to the heap.
func (w *walker) alloc(v *ssa.Alloc) {
	elem := v.Type()
	if p, ok := elem.Underlying().(*types.Pointer); ok {
		elem = p.Elem()
	}
	size := w.sizeof(elem)
	if v.Heap || size > maxStackAlloc {
		w.heapAlloc(v.Pos(), size == 0)
	}
}

// pack is emitPointerPack (llvm.go:57): values that do not fit in a pointer and
// are not all constant are copied to the heap.
func (w *walker) pack(pos token.Pos, ts []types.Type, allConst bool) {
	if len(ts) == 0 || allConst {
		return
	}
	if len(ts) == 1 && pointerShaped(ts[0]) {
		return
	}
	if w.cfg.Sizes == nil {
		w.heapAlloc(pos, false)
		return
	}
	fields := make([]*types.Var, len(ts))
	for i, t := range ts {
		fields[i] = types.NewField(token.NoPos, nil, "f"+strconv.Itoa(i), t, false)
	}
	size := w.sizeof(types.NewStruct(fields, nil))
	if size == 0 || size <= w.sizeof(types.Typ[types.UnsafePointer]) {
		return
	}
	w.heapAlloc(pos, false)
}

func pointerShaped(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Pointer, *types.Map, *types.Chan:
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	}
	return false
}

func valueTypes(vs []ssa.Value) []types.Type {
	out := make([]types.Type, len(vs))
	for i, v := range vs {
		out[i] = v.Type()
	}
	return out
}

// nilCheck is createNilCheck (asserts.go:164), which skips pointers that cannot
// be nil.
func (w *walker) nilCheck(pos token.Pos, ptr ssa.Value) {
	switch p := ptr.(type) {
	case *ssa.Alloc, *ssa.FreeVar, *ssa.IndexAddr, *ssa.Global, *ssa.Function:
		return
	case *ssa.Convert:
		if b, ok := p.X.Type().Underlying().(*types.Basic); ok && b.Kind() == types.UnsafePointer {
			return
		}
	}
	w.add(pos, OpNilPanic)
}

func isConst(v ssa.Value) bool {
	_, ok := v.(*ssa.Const)
	return ok
}

// lookupCheck is createLookupBoundsCheck (asserts.go:19); a constant index into
// a fixed length folds away (asserts.go:236).
func (w *walker) lookupCheck(pos token.Pos, index ssa.Value, fixedLen int64) {
	if w.noBounds {
		return
	}
	if c, ok := index.(*ssa.Const); ok && fixedLen >= 0 && c.Value != nil {
		if i, exact := constant.Int64Val(constant.ToInt(c.Value)); exact && i >= 0 && i < fixedLen {
			return
		}
	}
	w.add(pos, OpLookupPanic)
}

func (w *walker) index(v *ssa.Index) {
	if a, ok := v.X.Type().Underlying().(*types.Array); ok {
		w.lookupCheck(v.Pos(), v.Index, a.Len())
		return
	}
	w.lookupCheck(v.Pos(), v.Index, -1)
}

func (w *walker) indexAddr(v *ssa.IndexAddr) {
	if p, ok := v.X.Type().Underlying().(*types.Pointer); ok {
		w.nilCheck(v.Pos(), v.X)
		if a, ok := p.Elem().Underlying().(*types.Array); ok {
			w.lookupCheck(v.Pos(), v.Index, a.Len())
		}
		return
	}
	w.lookupCheck(v.Pos(), v.Index, -1)
}

func (w *walker) slice(v *ssa.Slice) {
	if _, ok := v.X.Type().Underlying().(*types.Pointer); ok {
		w.nilCheck(v.Pos(), v.X)
	}
	if !w.noBounds && !constantSliceBounds(v) {
		w.add(v.Pos(), OpSlicePanic)
	}
}

// constantSliceBounds reports whether slicing an array of known length with
// constant bounds folds its check away (asserts.go:236).
func constantSliceBounds(v *ssa.Slice) bool {
	t := v.X.Type().Underlying()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem().Underlying()
	}
	a, ok := t.(*types.Array)
	if !ok {
		return false
	}
	bound := func(b ssa.Value, dflt int64) (int64, bool) {
		if b == nil {
			return dflt, true
		}
		c, ok := b.(*ssa.Const)
		if !ok || c.Value == nil {
			return 0, false
		}
		return constant.Int64Val(constant.ToInt(c.Value))
	}
	low, okL := bound(v.Low, 0)
	high, okH := bound(v.High, a.Len())
	maxB, okM := bound(v.Max, a.Len())
	return okL && okH && okM && 0 <= low && low <= high && high <= maxB && maxB <= a.Len()
}

// makeSlice is compiler.go:2656. go/ssa builds a make whose capacity is
// constant as an array allocation, so here the capacity never is.
func (w *walker) makeSlice(v *ssa.MakeSlice) {
	if !w.noBounds {
		w.add(v.Pos(), OpSlicePanic) // compiler.go:2676
	}
	zero := false
	if sl, ok := v.Type().Underlying().(*types.Slice); ok {
		zero = w.sizeof(sl.Elem()) == 0
	}
	w.heapAlloc(v.Pos(), zero)
}

func (w *walker) typeAssert(v *ssa.TypeAssert) {
	if _, ok := v.AssertedType.Underlying().(*types.Interface); !ok {
		w.add(v.Pos(), OpTypeAssert)
	}
	if !v.CommaOk {
		w.add(v.Pos(), OpTypeAssertPanic)
	}
}

func (w *walker) selectStmt(v *ssa.Select) {
	switch {
	case len(v.States) > 0:
		w.add(v.Pos(), OpChanSelect)
	case v.Blocking:
		w.add(v.Pos(), OpDeadlock)
	}
}

func (w *walker) unOp(v *ssa.UnOp) {
	switch v.Op {
	case token.MUL:
		if w.sizeof(v.Type()) != 0 {
			w.nilCheck(v.Pos(), v.X)
		}
	case token.ARROW:
		w.add(v.Pos(), OpChanRecv)
	}
}

func (w *walker) convert(v *ssa.Convert) {
	from, to := v.X.Type().Underlying(), v.Type().Underlying()
	if tb, ok := to.(*types.Basic); ok && tb.Info()&types.IsString != 0 {
		switch f := from.(type) {
		case *types.Basic:
			if f.Info()&types.IsInteger != 0 {
				w.add(v.Pos(), OpStringFromUnicode)
			}
		case *types.Slice:
			if isRune(f.Elem()) {
				w.add(v.Pos(), OpStringFromRunes)
			} else {
				w.add(v.Pos(), OpStringFromBytes)
			}
		}
		return
	}
	if ts, ok := to.(*types.Slice); ok {
		if fb, ok := from.(*types.Basic); ok && fb.Info()&types.IsString != 0 {
			if isRune(ts.Elem()) {
				w.add(v.Pos(), OpStringToRunes)
			} else {
				w.add(v.Pos(), OpStringToBytes)
			}
		}
	}
}

func isRune(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.Int32
}

func (w *walker) binOp(v *ssa.BinOp) {
	switch v.Op {
	case token.QUO, token.REM:
		if isInteger(v.X.Type()) && !w.noBounds && !nonZeroConst(v.Y) {
			w.add(v.Pos(), OpDivideByZeroPanic)
		}
	case token.SHL, token.SHR:
		if b, ok := v.Y.Type().Underlying().(*types.Basic); ok && b.Info()&types.IsUnsigned == 0 && !isConst(v.Y) && !w.noBounds {
			w.add(v.Pos(), OpNegativeShiftPanic)
		}
	}
	w.compare(v.Pos(), v.Op, v.X.Type(), v.X, v.Y)
}

func isInteger(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsInteger != 0
}

func nonZeroConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.Value != nil && constant.Sign(c.Value) != 0
}

// compare is createBinOp (compiler.go:3007) for the operand types that lower to
// runtime calls, recursing through struct and array equality as it does.
func (w *walker) compare(pos token.Pos, op token.Token, t types.Type, x, y ssa.Value) {
	eq := op == token.EQL || op == token.NEQ
	switch u := t.Underlying().(type) {
	case *types.Basic:
		w.compareBasic(pos, op, u)
	case *types.Interface:
		if eq && !isNilConst(x) && !isNilConst(y) {
			w.add(pos, OpInterfaceEqual)
		}
	case *types.Struct:
		for i := range u.NumFields() {
			if eq && u.Field(i).Name() != "_" {
				w.compare(pos, token.EQL, u.Field(i).Type(), nil, nil)
			}
		}
	case *types.Array:
		if eq && u.Len() > 0 {
			w.compare(pos, token.EQL, u.Elem(), nil, nil)
		}
	}
}

func (w *walker) compareBasic(pos token.Pos, op token.Token, u *types.Basic) {
	switch {
	case u.Info()&types.IsString != 0:
		switch op {
		case token.ADD:
			w.add(pos, OpStringConcat)
		case token.EQL, token.NEQ:
			w.add(pos, OpStringEqual)
		case token.LSS, token.LEQ, token.GTR, token.GEQ:
			w.add(pos, OpStringLess)
		}
	case op == token.QUO && u.Kind() == types.Complex64:
		w.add(pos, OpComplex64Div)
	case op == token.QUO && u.Kind() == types.Complex128:
		w.add(pos, OpComplex128Div)
	}
}

func isNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.IsNil()
}

// lookup is a map read; go/ssa spells a string index as Index.
func (w *walker) lookup(v *ssa.Lookup) {
	w.add(v.Pos(), mapOp(mapKey(v.X.Type()), OpMapGetString, OpMapGetBinary, OpMapGetGeneric))
}
