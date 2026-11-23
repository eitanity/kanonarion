package staticcha_test

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

var dispatchCoord = coordinatetest.MustNew("example.com/dispmod", "v1.0.0")

// dispatchModuleFiles holds one type per way a module value reaches a
// dependency, and one per way it does not. Only the standard library is
// imported, so every dependency body is type-only, as in a real extraction.
var dispatchModuleFiles = map[string]string{
	"go.mod": "module example.com/dispmod\n\ngo 1.23\n",
	"dispmod.go": `package dispmod

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
)

// Conv is converted to a standard library interface.
type Conv struct{}

func (*Conv) Read([]byte) (int, error) { return 0, io.EOF }

func UseConv() io.Reader { return &Conv{} }

// Wrapped is converted to error; only an inline interface in errors calls Unwrap.
type Wrapped struct{ err error }

func (w *Wrapped) Error() string { return "wrapped" }
func (w *Wrapped) Unwrap() error { return w.err }

func NewWrapped() error { return &Wrapped{} }

// Inner escapes only inside Outer, which embeds it.
type Inner struct{}

func (Inner) LogValue() slog.Value { return slog.StringValue("inner") }

type Outer struct{ Inner }

func LogOuter() any { return Outer{} }

// Gen is only ever a type argument to a standard library generic.
type Gen struct{ n int }

func (Gen) Describe() string { return "gen" }

func FindGen(gs []Gen) bool { return slices.Contains(gs, Gen{n: 1}) }

// Never is called, and never converted.
type Never struct{}

func (Never) Close() error { return nil }

func UseNever() error { return Never{}.Close() }

// Quiet is converted, but one of its methods is unexported.
type Quiet struct{}

func (Quiet) String() string { return "quiet" }
func (Quiet) hidden()        {}

func UseQuiet() fmt.Stringer { Quiet{}.hidden(); return Quiet{} }

// Val escapes as a value, so its pointer-receiver method stays inside.
type Val struct{}

func (Val) Name() string { return "val" }
func (*Val) Reset()      {}

func UseVal() any { (&Val{}).Reset(); return Val{} }

// Redacted is handed over only by a test.
type Redacted struct{}

func (Redacted) LogValue() slog.Value { return slog.StringValue("redacted") }
`,
	"dispmod_test.go": `package dispmod

import "testing"

func TestRedacted(t *testing.T) { t.Log(Redacted{}) }
`,
}

func analyseDispatchModule(t *testing.T) map[string]domain.CallNode {
	t.Helper()
	return analyseDispatchFiles(t, dispatchCoord, dispatchModuleFiles)
}

func analyseDispatchFiles(t *testing.T, coord coordinate.ModuleCoordinate, files map[string]string) map[string]domain.CallNode {
	t.Helper()
	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, makeZip(t, coord, files))
	rec, err := a.Analyse(context.Background(), zipPath, coord, domain.AnalysisInputs{})
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("OverallStatus = %v (%s), want Extracted", rec.OverallStatus, rec.FailureDetail)
	}
	nodes := make(map[string]domain.CallNode, len(rec.Nodes))
	for _, n := range rec.Nodes {
		nodes[n.ID] = n
	}
	return nodes
}

func TestDependencyDispatch_RecordsEachHandOff(t *testing.T) {
	t.Parallel()
	nodes := analyseDispatchModule(t)
	const mod = "example.com/dispmod."

	cases := []struct {
		id, typ, via  string
		kind          domain.EscapeKind
		wantInterface string
		noInterface   bool
	}{
		{id: mod + "(*Conv).Read", typ: "*Conv", via: "io.Reader", kind: domain.EscapeConversion, wantInterface: "io.Reader"},
		{id: mod + "(*Wrapped).Unwrap", typ: "*Wrapped", via: "error", kind: domain.EscapeConversion, noInterface: true},
		{id: mod + "(Inner).LogValue", typ: "Outer", via: "any", kind: domain.EscapeConversion, wantInterface: "log/slog.LogValuer"},
		{id: mod + "(Gen).Describe", typ: "Gen", via: "slices.Contains", kind: domain.EscapeTypeArgument},
		{id: mod + "(Val).Name", typ: "Val", via: "any", kind: domain.EscapeConversion},
	}
	for _, tc := range cases {
		n, ok := nodes[tc.id]
		if !ok {
			t.Errorf("%s is not a node", tc.id)
			continue
		}
		d := n.DependencyDispatch
		if d.Escape.Kind != tc.kind || d.Escape.Type != tc.typ || d.Escape.Via != tc.via {
			t.Errorf("%s: escape = %+v, want %s %s via %s", tc.id, d.Escape, tc.kind, tc.typ, tc.via)
		}
		if d.Escape.Function == "" || d.Escape.Site.File == "" {
			t.Errorf("%s: escape names no site: %+v", tc.id, d.Escape)
		}
		if tc.wantInterface != "" && !slices.Contains(d.Interfaces, tc.wantInterface) {
			t.Errorf("%s: interfaces = %v, want %s among them", tc.id, d.Interfaces, tc.wantInterface)
		}
		if tc.noInterface && len(d.Interfaces) != 0 {
			t.Errorf("%s: interfaces = %v, want none declared", tc.id, d.Interfaces)
		}
		if !d.InProduction() || d.ProductionEscape != d.Escape {
			t.Errorf("%s: production hand-off = %+v, want the production escape %+v", tc.id, d.ProductionEscape, d.Escape)
		}
	}
}

// A hand-off made only in a test is recorded for callers, which cover both
// scopes, and is not a production one.
func TestDependencyDispatch_ATestOnlyHandOffIsNotProduction(t *testing.T) {
	t.Parallel()
	n := analyseDispatchModule(t)["example.com/dispmod.(Redacted).LogValue"]
	d := n.DependencyDispatch
	if d.IsZero() || !slices.Contains(d.Interfaces, "log/slog.LogValuer") {
		t.Fatalf("(Redacted).LogValue carries %+v, want the test's hand-off", d)
	}
	if d.InProduction() || len(d.ProductionInterfaces) != 0 {
		t.Errorf("(Redacted).LogValue production hand-off = %+v %v, want none", d.ProductionEscape, d.ProductionInterfaces)
	}
}

func TestDependencyDispatch_LeavesTheRestUnmarked(t *testing.T) {
	t.Parallel()
	nodes := analyseDispatchModule(t)
	const mod = "example.com/dispmod."

	for _, id := range []string{
		mod + "(Never).Close",  // never converted
		mod + "(Quiet).hidden", // unexported
		mod + "(*Val).Reset",   // outside the method set of the value that escapes
		mod + "UseConv",        // a function, not a method
	} {
		n, ok := nodes[id]
		if !ok {
			t.Errorf("%s is not a node", id)
			continue
		}
		if !n.DependencyDispatch.IsZero() {
			t.Errorf("%s carries %+v, want no fact", id, n.DependencyDispatch)
		}
	}
	if q := nodes[mod+"(Quiet).String"]; q.DependencyDispatch.IsZero() {
		t.Errorf("(Quiet).String carries no fact; the control beside the unexported method must")
	}
}

var genericDispatchCoord = coordinatetest.MustNew("example.com/genmod", "v1.0.0")

// genericDispatchFiles hands module types on only through the module's own
// generics, whose bodies see the type parameter, not the type.
var genericDispatchFiles = map[string]string{
	"go.mod": "module example.com/genmod\n\ngo 1.23\n",
	"genmod.go": `package genmod

import (
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// LogT converts its type parameter itself.
func LogT[T any](v T) { slog.Info("x", "v", v) }

type Direct struct{}

func (Direct) LogValue() slog.Value { return slog.StringValue("direct") }

func UseDirect() { LogT(Direct{}) }

// PrintPtr converts a pointer to its type parameter.
func PrintPtr[T any](v *T) { fmt.Println(v) }

type Ptr struct{}

func (*Ptr) String() string { return "ptr" }

func UsePtr() { PrintPtr(&Ptr{}) }

// Outer hands its parameter to Inner, which converts it.
func Outer[T any](v T) { Inner(v) }
func Inner[T any](v T) { fmt.Println(v) }

type TwoLevels struct{}

func (TwoLevels) String() string { return "two" }

func UseTwoLevels() { Outer(TwoLevels{}) }

// Has hands its parameter to a standard library generic.
func Has[T comparable](xs []T, v T) bool { return slices.Contains(xs, v) }

type Passed struct{ n int }

func (Passed) Describe() string { return "passed" }

func UsePassed() bool { return Has(nil, Passed{}) }

// Box's method converts its type parameter.
type Box[T any] struct{ v T }

func (b Box[T]) Show() { fmt.Println(b.v) }

type Called struct{}

func (Called) String() string { return "called" }

func UseCalled() { Box[Called]{}.Show() }

type Boxed struct{}

func (Boxed) String() string { return "boxed" }

func UseBoxed() any { return Box[Boxed]{} }

// AsGetter converts to an interface written in its type parameter.
type Getter[T any] interface{ Get() T }

func (b Box[T]) Get() T { return b.v }

func AsGetter[T any](v T) any { var g Getter[T] = Box[T]{v}; return g }

type Got struct{}

func (Got) String() string { return "got" }

func UseGot() any { return AsGetter(Got{}) }

// Keep and Str never convert their type parameter: Str calls its method.
func Keep[T any](v T) T            { return v }
func Str[T fmt.Stringer](v T) string { return v.String() }

type Kept struct{}

func (Kept) String() string { return "kept" }

func UseKept() string { return Str(Keep(Kept{})) }

// A type argument the module does not own; its method is a node.
func UseForeign() string { LogT(time.Second); return time.Second.String() }
`,
}

func TestDependencyDispatch_RecordsAnOwnedGenericsHandOff(t *testing.T) {
	t.Parallel()
	nodes := analyseDispatchFiles(t, genericDispatchCoord, genericDispatchFiles)
	const mod = "example.com/genmod."

	cases := []struct {
		name, id, typ, via, fn string
		kind                   domain.EscapeKind
		wantInterface          string
	}{
		{name: "converts T", id: mod + "(Direct).LogValue", typ: "Direct", via: "any", fn: "UseDirect",
			kind: domain.EscapeConversion, wantInterface: "log/slog.LogValuer"},
		{name: "converts *T", id: mod + "(*Ptr).String", typ: "*Ptr", via: "any", fn: "UsePtr",
			kind: domain.EscapeConversion, wantInterface: "fmt.Stringer"},
		{name: "two owned levels", id: mod + "(TwoLevels).String", typ: "TwoLevels", via: mod + "Outer", fn: "UseTwoLevels",
			kind: domain.EscapeTypeArgument, wantInterface: "fmt.Stringer"},
		{name: "outside generic", id: mod + "(Passed).Describe", typ: "Passed", via: mod + "Has", fn: "UsePassed",
			kind: domain.EscapeTypeArgument},
		{name: "generic type's method called", id: mod + "(Called).String", typ: "Called", via: "any", fn: "UseCalled",
			kind: domain.EscapeConversion, wantInterface: "fmt.Stringer"},
		{name: "interface written in T", id: mod + "(Got).String", typ: "Got", via: mod + "Getter[" + mod + "Got]", fn: "UseGot",
			kind: domain.EscapeConversion, wantInterface: "fmt.Stringer"},
		{name: "generic type converted", id: mod + "(Boxed).String", typ: "Boxed", via: "any", fn: "UseBoxed",
			kind: domain.EscapeConversion, wantInterface: "fmt.Stringer"},
	}
	for _, tc := range cases {
		n, ok := nodes[tc.id]
		if !ok {
			t.Errorf("%s: %s is not a node", tc.name, tc.id)
			continue
		}
		e := n.DependencyDispatch.Escape
		if e.Kind != tc.kind || e.Type != tc.typ || e.Via != tc.via || e.Function != mod+tc.fn || e.Site.File == "" {
			t.Errorf("%s: %s escape = %+v, want %s %s via %s at %s", tc.name, tc.id, e, tc.kind, tc.typ, tc.via, mod+tc.fn)
		}
		if tc.wantInterface != "" && !slices.Contains(n.DependencyDispatch.Interfaces, tc.wantInterface) {
			t.Errorf("%s: %s interfaces = %v, want %s", tc.name, tc.id, n.DependencyDispatch.Interfaces, tc.wantInterface)
		}
	}
}

func TestDependencyDispatch_AnOwnedGenericThatKeepsTIsNoHandOff(t *testing.T) {
	t.Parallel()
	nodes := analyseDispatchFiles(t, genericDispatchCoord, genericDispatchFiles)
	if d := nodes["example.com/genmod.(Kept).String"].DependencyDispatch; !d.IsZero() {
		t.Errorf("(Kept).String carries %+v, want no fact", d)
	}
	if _, ok := nodes["time.(Duration).String"]; !ok {
		t.Fatalf("time.(Duration).String is not a node; the negative below would prove nothing")
	}
	for id, n := range nodes {
		if n.DependencyDispatch.Escape.Function == "example.com/genmod.UseForeign" {
			t.Errorf("%s carries the non-module type argument's hand-off %+v", id, n.DependencyDispatch)
		}
	}
}
