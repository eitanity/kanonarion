package tinylower_test

import (
	"bytes"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinylower"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// fixture holds one function per construct TinyGo lowers to a runtime call.
const fixture = `package fx

import "unsafe"

type pair struct{ s string; e error; f float64 }
type fkey struct{ n int; x float32; y complex128; i interface{}; p *int; a [2]string; b [2]int; z [0]string; c chan int }

var g *int
var sink interface{}

func mapMake() map[string]int  { return make(map[string]int) }
func mapMakeBinary() map[int]int { return make(map[int]int, 4) }
func mapMakeGeneric() map[fkey]int { return make(map[fkey]int) }
func mapGet(m map[string]int) int  { return m["a"] }
func mapGetBinary(m map[int]int) int { return m[1] }
func mapGetGeneric(m map[fkey]int, k fkey) (int, bool) { v, ok := m[k]; return v, ok }
func mapSet(m map[string]int)  { m["a"] = 1 }
func mapSetBinary(m map[int]int) { m[1] = 1 }
func mapSetGeneric(m map[fkey]int, k fkey) { m[k] = 1 }
func mapDelete(m map[string]int) { delete(m, "a") }
func mapDeleteBinary(m map[int]int) { delete(m, 1) }
func mapDeleteGeneric(m map[fkey]int, k fkey) { delete(m, k) }
func mapClear(m map[int]int) { clear(m) }
func mapLen(m map[int]int) int { return len(m) }
func mapRange(m map[int]int) (n int) { for k := range m { n += k }; return }
func sliceClear(s []int) { clear(s) }

func strConcat(a, b string) string { return a + b }
func strEqual(a, b string) bool    { return a == b }
func strLess(a, b string) bool     { return a < b }
func strMin(a, b string) string    { return min(a, b) }
func strFromRune(r rune) string    { return string(r) }
func strFromBytes(b []byte) string { return string(b) }
func strFromRunes(r []rune) string { return string(r) }
func strToBytes(s string) []byte   { return []byte(s) }
func strToRunes(s string) []rune   { return []rune(s) }
func strRange(s string) (n int)    { for _, r := range s { n += int(r) }; return }
func strIndex(s string, i int) byte { return s[i] }
func strSlice(s string, i int) string { return s[i:] }

func ifaceEqual(a, b interface{}) bool { return a == b }
func ifaceNil(a interface{}) bool      { return a == nil }
func structEqual(a, b pair) bool       { return a == b }
func arrayEqual(a, b [2]string) bool   { return a == b }
func assertConcrete(a interface{}) int { return a.(int) }
func assertCommaOk(a interface{}) (int, bool) { v, ok := a.(int); return v, ok }
func assertIface(a interface{}) error  { return a.(error) }

func appendTo(s []int) []int { return append(s, 1) }
func doPanic()               { panic("x") }
func doRecover()             { defer func() { _ = recover() }() }
func deferPanic()            { defer panic("x") }
func deferInLoop(n int)      { for i := 0; i < n; i++ { defer println() } }

func chanMake(n int) chan int { return make(chan int, n) }
func chanMakeConst() chan int { return make(chan int) }
func chanSend(c chan int)    { c <- 1 }
func chanRecv(c chan int) int { return <-c }
func chanClose(c chan int)   { close(c) }
func chanLen(c chan int) int { return len(c) + cap(c) }
func chanSelect(c chan int)  { select { case <-c: default: } }
func selectBlock()           { select {} }
func selectNone()            { select { default: } }

func worker(a, b int64)  {}
func goStmt()            { go worker(1, 2) }
func goSmall(p *int)     { go func() { *p = 1 }() }
func goDynamic(f func()) { go f() }
func goIface(e error)    { go e.Error() }
func goBuiltin()         { go println("x") }

func heapAlloc() *int       { x := 1; return &x }
func heapZero() *struct{}   { x := struct{}{}; return &x }
func bigLocal() int         { var a [300]byte; p := &a; return len(p) }
func makeSlice(n int) []int { return make([]int, n) }
func makeSliceConst() []int { return make([]int, 0) }
func closure(a, b int64) func() int64 { return func() int64 { return a + b } }
func closurePtr(p *int) func() int { return func() int { return *p } }
func boxBig(v pair) interface{} { return v }
func boxConst() interface{}  { return 3 }
func boxPtr(p *int) interface{} { return p }

func lookupSlice(s []int, i int) int { return s[i] }
func lookupArrayConst(a [3]int) int  { return a[1] }
func lookupArrayPtr(a *[3]int, i int) int { return a[i] }
func sliceSlice(s []int) []int      { return s[1:] }
func sliceArrayPtr(a *[3]int) []int { return a[:] }
func sliceToArray(s []int) *[2]int  { return (*[2]int)(s) }
func unsafeSlice(p *byte, n int) []byte { return unsafe.Slice(p, n) }
func nilDeref(p *int) int           { return *p }
func nilStore(p *int)               { *p = 1 }
func nilField(p *pair) string       { return p.s }
func globalDeref() int              { return *g }
func zeroDeref(p *struct{}) struct{} { return *p }
func funcCall(f func())             { f() }
func divide(a, b int) int           { return a / b }
func divideConst(a int) int         { return a % 3 }
func shift(a int, s int) int        { return a << s }
func shiftUnsigned(a int, s uint) int { return a << s }
func complexDiv(a, b complex128) complex128 { return a / b }
func complex64Div(a, b complex64) complex64 { return a / b }
func printAll(i8 int8, i16 int16, i int, u8 uint8, u16 uint16, u32 uint32, u64 uint64, p uintptr, up unsafe.Pointer, b bool, f32 float32, f float64, c64 complex64, c complex128, s string, e error, m map[int]int, ptr *int, sl []int, ch chan int) {
	println(i8, i16, i, u8, u16, u32, u64, p, up, b, f32, f, c64, c, s, e, m, ptr, sl, ch)
}
func printOne() { print("x") }

//go:nobounds
func noBounds(s []int, i int) int { return s[i] / i }

//go:noheap
func noHeap() *int { x := 1; return &x }

//go:wasmexport ext
func wasmExport() {}

//go:noheap
func extern(x int) int

func callStatic()                         { doPanic() }
func goArgs(x, y int64)                   { go worker(x, y) }
func boxSmall(v int32) interface{}        { return v }
func unsafeDeref(p unsafe.Pointer) int    { return *(*int)(p) }
func indexArray(a [3]int, i int) int      { return a[i] }
func sliceArrayDyn(a *[3]int, i int) []int { return a[i:] }
func makeSliceCap(n int) []int            { return make([]int, n, 0) }
func makeSliceCap10(n int) []int          { return make([]int, n, 10) }
func mapPtrKey(m map[*int]int, p *int) int { return m[p] }
func mapArrayKey(m map[[2]int]int) int    { return m[[2]int{}] }

//
//go:nobounds
func bareComment(s []int, i int) int { return s[i] }

func arrVal() [3]int                { return [3]int{} }
func indexCall(i int) int           { return arrVal()[i] }
func indexCallConst() int           { return arrVal()[1] }
`

func build(t *testing.T, sizes types.Sizes) map[string]*ssa.Function {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fx.go", fixture, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	conf := &types.Config{Importer: importer.Default(), Sizes: sizes}
	pkg, _, err := ssautil.BuildPackage(conf, fset, types.NewPackage("fx", "fx"), []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]*ssa.Function)
	for name, m := range pkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			out[name] = fn
		}
	}
	return out
}

func ops(sites []tinylower.Site) []tinylower.Op {
	out := make([]tinylower.Op, len(sites))
	for i, s := range sites {
		out[i] = s.Op
	}
	return out
}

func sorted(o []tinylower.Op) []tinylower.Op {
	o = slices.Clone(o)
	slices.Sort(o)
	return o
}

var thumb = types.SizesFor("gc", "arm")

func TestSites_OnePerLoweredConstruct(t *testing.T) {
	fns := build(t, thumb)
	cfg := tinylower.Config{Sizes: thumb, Scheduler: "tasks", Recover: true}
	tests := map[string][]tinylower.Op{
		"mapMake":          {tinylower.OpMapMake, tinylower.OpMapKeyFuncsString},
		"mapMakeBinary":    {tinylower.OpMapMake, tinylower.OpMapKeyFuncsBinary},
		"mapMakeGeneric":   {tinylower.OpMapMake, tinylower.OpKeyHashFloat32, tinylower.OpKeyHashFloat64, tinylower.OpKeyHashInterface, tinylower.OpKeyHashBinary, tinylower.OpKeyHashString, tinylower.OpKeyEqualInterface, tinylower.OpKeyEqualBinary, tinylower.OpKeyEqualString},
		"mapGet":           {tinylower.OpMapGetString},
		"mapGetBinary":     {tinylower.OpMapGetBinary},
		"mapGetGeneric":    {tinylower.OpMapGetGeneric},
		"mapSet":           {tinylower.OpMapSetString},
		"mapSetBinary":     {tinylower.OpMapSetBinary},
		"mapSetGeneric":    {tinylower.OpMapSetGeneric},
		"mapDelete":        {tinylower.OpMapDeleteString},
		"mapDeleteBinary":  {tinylower.OpMapDeleteBinary},
		"mapDeleteGeneric": {tinylower.OpMapDeleteGeneric},
		"mapClear":         {tinylower.OpMapClear},
		"mapLen":           {tinylower.OpMapLen},
		"mapRange":         {tinylower.OpMapNext},
		"sliceClear":       nil,
		"strConcat":        {tinylower.OpStringConcat},
		"strEqual":         {tinylower.OpStringEqual},
		"strLess":          {tinylower.OpStringLess},
		"strMin":           {tinylower.OpStringLess},
		"strFromRune":      {tinylower.OpStringFromUnicode},
		"strFromBytes":     {tinylower.OpStringFromBytes},
		"strFromRunes":     {tinylower.OpStringFromRunes},
		"strToBytes":       {tinylower.OpStringToBytes},
		"strToRunes":       {tinylower.OpStringToRunes},
		"strRange":         {tinylower.OpStringNext},
		"strIndex":         {tinylower.OpLookupPanic},
		"strSlice":         {tinylower.OpSlicePanic},
		"ifaceEqual":       {tinylower.OpInterfaceEqual},
		"ifaceNil":         nil,
		"structEqual":      {tinylower.OpStringEqual, tinylower.OpInterfaceEqual},
		"arrayEqual":       {tinylower.OpStringEqual},
		"assertConcrete":   {tinylower.OpTypeAssert, tinylower.OpTypeAssertPanic},
		"assertCommaOk":    {tinylower.OpTypeAssert},
		"assertIface":      {tinylower.OpTypeAssertPanic},
		"appendTo":         {tinylower.OpAlloc, tinylower.OpAppend},
		"doPanic":          {tinylower.OpPanic},
		"doRecover":        {tinylower.OpDeferSetup, tinylower.OpDeferDestroy, tinylower.OpDeferDestroy},
		"deferPanic":       {tinylower.OpDeferSetup, tinylower.OpPanic, tinylower.OpDeferDestroy, tinylower.OpDeferDestroy},
		"deferInLoop":      {tinylower.OpDeferSetup, tinylower.OpPrintLock, tinylower.OpPrintNewline, tinylower.OpPrintUnlock, tinylower.OpAlloc, tinylower.OpDeferDestroy, tinylower.OpDeferDestroy},
		"chanMake":         {tinylower.OpChanMake, tinylower.OpChanMakePanic},
		"chanMakeConst":    {tinylower.OpChanMake},
		"chanSend":         {tinylower.OpChanSend},
		"chanRecv":         {tinylower.OpChanRecv},
		"chanClose":        {tinylower.OpChanClose},
		"chanLen":          {tinylower.OpChanLen, tinylower.OpChanCap},
		"chanSelect":       {tinylower.OpChanSelect},
		"selectBlock":      {tinylower.OpDeadlock, tinylower.OpPanic},
		"selectNone":       nil,
		"goStmt":           {tinylower.OpGoStart},
		"goSmall":          {tinylower.OpAlloc, tinylower.OpGoStart},
		"goDynamic":        {tinylower.OpAlloc, tinylower.OpGoStart},
		"goIface":          {tinylower.OpAlloc, tinylower.OpGoStart},
		"goBuiltin":        {tinylower.OpPrintLock, tinylower.OpPrintString, tinylower.OpPrintNewline, tinylower.OpPrintUnlock},
		"heapAlloc":        {tinylower.OpAlloc},
		"heapZero":         {tinylower.OpAllocZero},
		"bigLocal":         {tinylower.OpAlloc},
		"makeSlice":        {tinylower.OpSlicePanic, tinylower.OpAlloc},
		"makeSliceConst":   {tinylower.OpAllocZero},
		"closure":          {tinylower.OpAlloc, tinylower.OpAlloc, tinylower.OpAlloc},
		"closurePtr":       {tinylower.OpAlloc},
		"boxBig":           {tinylower.OpAlloc},
		"boxConst":         nil,
		"boxPtr":           nil,
		"lookupSlice":      {tinylower.OpLookupPanic},
		"lookupArrayConst": nil,
		"lookupArrayPtr":   {tinylower.OpNilPanic, tinylower.OpLookupPanic},
		"sliceSlice":       {tinylower.OpSlicePanic},
		"sliceArrayPtr":    {tinylower.OpNilPanic},
		"sliceToArray":     {tinylower.OpSliceToArrayPanic},
		"unsafeSlice":      {tinylower.OpUnsafeSlicePanic},
		"nilDeref":         {tinylower.OpNilPanic},
		"nilStore":         {tinylower.OpNilPanic},
		"nilField":         {tinylower.OpNilPanic, tinylower.OpNilPanic},
		"globalDeref":      {tinylower.OpNilPanic},
		"zeroDeref":        nil,
		"funcCall":         {tinylower.OpNilPanic},
		"divide":           {tinylower.OpDivideByZeroPanic},
		"divideConst":      nil,
		"shift":            {tinylower.OpNegativeShiftPanic},
		"shiftUnsigned":    nil,
		"complexDiv":       {tinylower.OpComplex128Div},
		"complex64Div":     {tinylower.OpComplex64Div},
		"printOne":         {tinylower.OpPrintLock, tinylower.OpPrintString, tinylower.OpPrintUnlock},
		"noBounds":         nil,
		"callStatic":       nil,
		"goArgs":           {tinylower.OpAlloc, tinylower.OpGoStart},
		"boxSmall":         nil,
		"unsafeDeref":      nil,
		"indexArray":       {tinylower.OpLookupPanic},
		"sliceArrayDyn":    {tinylower.OpNilPanic, tinylower.OpSlicePanic},
		"makeSliceCap":     {tinylower.OpSlicePanic, tinylower.OpAllocZero},
		"makeSliceCap10":   {tinylower.OpSlicePanic, tinylower.OpAlloc},
		"mapPtrKey":        {tinylower.OpMapGetBinary},
		"mapArrayKey":      {tinylower.OpMapGetBinary},
		"bareComment":      nil,
		"arrVal":           nil,
		"indexCall":        {tinylower.OpLookupPanic},
		"indexCallConst":   nil,
		"noHeap":           {tinylower.OpAllocNoHeap},
		"wasmExport":       {tinylower.OpWasmExportCheckRun, tinylower.OpWasmExportRun, tinylower.OpWasmExportExit},
	}
	for name, want := range tests {
		fn := fns[name]
		if fn == nil {
			t.Fatalf("fixture has no function %s", name)
		}
		if got := ops(tinylower.Sites(fn, cfg)); !slices.Equal(sorted(got), sorted(want)) {
			t.Errorf("%s: Sites = %v, want %v\n%s", name, got, want, dump(fn))
		}
	}
}

func dump(fn *ssa.Function) string {
	var b bytes.Buffer
	ssa.WriteFunction(&b, fn)
	return b.String()
}

// The build, not the source, decides three lowerings: the scheduler, whether the
// target supports recover, and the sizes that decide what is boxed.
func TestSites_FollowTheBuild(t *testing.T) {
	fns := build(t, thumb)
	none := tinylower.Config{Sizes: thumb, Scheduler: "none", Recover: false}
	if got := ops(tinylower.Sites(fns["wasmExport"], none)); !slices.Equal(got, []tinylower.Op{tinylower.OpWasmExportCheckRun}) {
		t.Errorf("wasmExport under scheduler none = %v, want only the check", got)
	}
	if got := ops(tinylower.Sites(fns["deferPanic"], none)); !slices.Equal(got, []tinylower.Op{tinylower.OpPanic}) {
		t.Errorf("deferPanic without recover support = %v, want no defer frame", got)
	}
	asyncify := tinylower.Config{Sizes: thumb, Scheduler: "asyncify", Recover: true}
	if got := ops(tinylower.Sites(fns["goSmall"], asyncify)); !slices.Equal(sorted(got), sorted([]tinylower.Op{tinylower.OpAlloc, tinylower.OpGoStart, tinylower.OpGoExit})) {
		t.Errorf("goSmall under asyncify = %v, want the wrapper's exit too", got)
	}
	// Without sizes every value is taken to need a box, and int prints at no size.
	if got := ops(tinylower.Sites(fns["boxPtr"], tinylower.Config{})); len(got) != 0 {
		t.Errorf("boxPtr without sizes = %v, want a pointer never boxed", got)
	}
	if got := ops(tinylower.Sites(fns["boxBig"], tinylower.Config{})); !slices.Equal(got, []tinylower.Op{tinylower.OpAlloc}) {
		t.Errorf("boxBig without sizes = %v, want it boxed", got)
	}
	if got := ops(tinylower.Sites(fns["heapAlloc"], tinylower.Config{})); !slices.Equal(got, []tinylower.Op{tinylower.OpAlloc}) {
		t.Errorf("heapAlloc without sizes = %v", got)
	}
	if got := ops(tinylower.Sites(fns["printOne"], tinylower.Config{})); len(got) != 3 {
		t.Errorf("printOne without sizes = %v", got)
	}
	var rec *ssa.Function
	for _, anon := range fns["doRecover"].AnonFuncs {
		rec = anon
	}
	if got := ops(tinylower.Sites(rec, none)); !slices.Equal(got, []tinylower.Op{tinylower.OpRecover}) {
		t.Errorf("doRecover$1 = %v, want recover", got)
	}
	if got := tinylower.Sites(fns["extern"], none); got != nil {
		t.Errorf("a declaration without a body = %v, want none", got)
	}
}

// print picks the runtime function by the argument's type and, for integers, by
// its size on the target: int is 32 bits on a 32-bit target.
func TestSites_PrintByTypeAndSize(t *testing.T) {
	fns := build(t, thumb)
	got := ops(tinylower.Sites(fns["printAll"], tinylower.Config{Sizes: thumb}))
	want := []tinylower.Op{tinylower.OpPrintLock,
		tinylower.OpPrintInt8, tinylower.OpPrintInt16, tinylower.OpPrintInt32, tinylower.OpPrintUint8, tinylower.OpPrintUint16,
		tinylower.OpPrintUint32, tinylower.OpPrintUint64, tinylower.OpPrintPointer, tinylower.OpPrintPointer, tinylower.OpPrintBool,
		tinylower.OpPrintFloat32, tinylower.OpPrintFloat64, tinylower.OpPrintComplex64, tinylower.OpPrintComplex128,
		tinylower.OpPrintString, tinylower.OpPrintInterface, tinylower.OpPrintMap, tinylower.OpPrintPointer, tinylower.OpPrintSlice,
		tinylower.OpPrintNewline, tinylower.OpPrintUnlock}
	var noSpace []tinylower.Op
	for _, op := range got {
		if op != tinylower.OpPrintSpace {
			noSpace = append(noSpace, op)
		}
	}
	if !slices.Equal(noSpace, want) {
		t.Errorf("printAll = %v\nwant %v", noSpace, want)
	}
	if spaces := len(got) - len(noSpace); spaces != 19 {
		t.Errorf("printAll spaces = %d, want one between each of 20 arguments", spaces)
	}
}

// An instantiation reads its origin's pragmas, as TinyGo does.
func TestSites_InstantiationReadsTheOriginsPragmas(t *testing.T) {
	const src = `package fx

//go:noheap
func box[T any](v T) *T { return &v }

func use() *int { return box(1) }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fx.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, types.NewPackage("fx", "fx"), []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatal(err)
	}
	var inst *ssa.Function
	for _, b := range pkg.Func("use").Blocks {
		for _, in := range b.Instrs {
			if c, ok := in.(*ssa.Call); ok && c.Common().StaticCallee() != nil {
				inst = c.Common().StaticCallee()
			}
		}
	}
	if inst == nil || inst.Origin() == nil {
		t.Fatalf("no instantiation found: %v", inst)
	}
	if got := ops(tinylower.Sites(inst, tinylower.Config{Sizes: thumb})); !slices.Equal(got, []tinylower.Op{tinylower.OpAllocNoHeap}) {
		t.Errorf("box[int] = %v, want the origin's //go:noheap", got)
	}
}

// Every operation the lowering can produce names a runtime function in every
// table, and an unlisted version has no table.
func TestTable_CoversEveryOp(t *testing.T) {
	if got := tinylower.Versions(); !slices.Equal(got, []string{"0.42.0"}) {
		t.Errorf("Versions = %v", got)
	}
	if _, ok := tinylower.ForVersion("0.41.0"); ok {
		t.Error("ForVersion(0.41.0) found a table")
	}
	table, ok := tinylower.ForVersion("0.42.0")
	if !ok || table.Version() != "0.42.0" {
		t.Fatalf("ForVersion(0.42.0) = %v, %v", table, ok)
	}
	for _, op := range allOps {
		cs := table.Callees(op)
		if len(cs) == 0 {
			t.Errorf("op %s names no runtime function", op)
		}
		for _, c := range cs {
			if c.Pkg != "runtime" && c.Pkg != "internal/task" {
				t.Errorf("op %s names %s.%s outside runtime and internal/task", op, c.Pkg, c.Name)
			}
		}
	}
	if got := table.WasmExports(); len(got) != 1 || got[0] != (tinylower.NamedExport{Callee: tinylower.Callee{Pkg: "runtime", Name: "wasmEntryCommand"}, Symbol: "_start"}) {
		t.Errorf("WasmExports = %+v, want only the default build mode's _start", got)
	}
	if table.Callees("no-such-op") != nil {
		t.Error("an unknown op has callees")
	}
}
