package domain_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

var readerEscape = domain.DispatchEscape{
	Kind: domain.EscapeConversion, Type: "*Body", Via: "io.Reader",
	Function: "example.com/m.Upload", Site: domain.SourcePosition{File: "m.go", Line: 7},
}

func TestNewDependencyDispatch_RefusesWhatNoExtractionRecords(t *testing.T) {
	both := domain.DependencyDispatch{Escape: readerEscape, Interfaces: []string{"io.Reader", "io.ByteReader"}}
	d, err := domain.NewDependencyDispatch(both, domain.DependencyDispatch{Escape: readerEscape, Interfaces: []string{"io.Reader"}})
	if err != nil || d.Escape != readerEscape || !d.InProduction() || d.Production().Escape != readerEscape {
		t.Fatalf("NewDependencyDispatch = %+v, %v", d, err)
	}
	testOnly, err := domain.NewDependencyDispatch(both, domain.DependencyDispatch{})
	if err != nil || testOnly.InProduction() || testOnly.Production().Describe() != "" {
		t.Errorf("a test-only fact = %+v, %v; want no production hand-off and no production detail", testOnly, err)
	}
	if got := d.SortedInterfaces(); !slices.Equal(got, []string{"io.ByteReader", "io.Reader"}) {
		t.Errorf("SortedInterfaces = %v", got)
	}
	noSite := readerEscape
	noSite.Site = domain.SourcePosition{}
	if _, err := domain.NewDependencyDispatch(domain.DependencyDispatch{Escape: noSite}, domain.DependencyDispatch{}); err != nil {
		t.Errorf("an escape with no position is one SSA can produce: %v", err)
	}
	with := func(f func(*domain.DispatchEscape)) domain.DispatchEscape {
		e := readerEscape
		f(&e)
		return e
	}
	for name, c := range map[string]struct {
		escape     domain.DispatchEscape
		interfaces []string
		production domain.DependencyDispatch
	}{
		"zero":               {},
		"interfaces alone":   {interfaces: []string{"io.Reader"}},
		"unknown kind":       {escape: with(func(e *domain.DispatchEscape) { e.Kind = "cast" })},
		"no type":            {escape: with(func(e *domain.DispatchEscape) { e.Type = "" })},
		"no via":             {escape: with(func(e *domain.DispatchEscape) { e.Via = "" })},
		"no function":        {escape: with(func(e *domain.DispatchEscape) { e.Function = "" })},
		"file without line":  {escape: with(func(e *domain.DispatchEscape) { e.Site.Line = 0 })},
		"line without file":  {escape: with(func(e *domain.DispatchEscape) { e.Site.File = "" })},
		"negative line":      {escape: with(func(e *domain.DispatchEscape) { e.Site = domain.SourcePosition{Line: -1} })},
		"unnamed interface":  {escape: readerEscape, interfaces: []string{""}},
		"repeated interface": {escape: readerEscape, interfaces: []string{"io.Reader", "io.Reader"}},
		"production alone":   {production: domain.DependencyDispatch{Escape: readerEscape}},
		"production interfaces with no production escape": {escape: readerEscape, interfaces: []string{"io.Reader"},
			production: domain.DependencyDispatch{Interfaces: []string{"io.Reader"}}},
		"invalid production escape": {escape: readerEscape, production: domain.DependencyDispatch{Escape: with(func(e *domain.DispatchEscape) { e.Via = "" })}},
		"production interface not among all": {escape: readerEscape, interfaces: []string{"io.Reader"},
			production: domain.DependencyDispatch{Escape: readerEscape, Interfaces: []string{"io.Writer"}}},
	} {
		if _, err := domain.NewDependencyDispatch(domain.DependencyDispatch{Escape: c.escape, Interfaces: c.interfaces}, c.production); !errors.Is(err, domain.ErrInvalidDependencyDispatch) {
			t.Errorf("%s: err = %v, want ErrInvalidDependencyDispatch", name, err)
		}
	}
}

func TestDependencyDispatch_Describe(t *testing.T) {
	if got := (domain.DependencyDispatch{}).Describe(); got != "" {
		t.Errorf("zero Describe = %q", got)
	}
	declared := domain.DependencyDispatch{Escape: readerEscape, Interfaces: []string{"io.Reader", "io.ByteReader"}}
	if got, want := declared.Describe(), "a dependency can call it through io.ByteReader, io.Reader; *Body converted to io.Reader at example.com/m.Upload (m.go:7)"; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
	generic := domain.DispatchEscape{Kind: domain.EscapeTypeArgument, Type: "Gen", Via: "slices.Contains", Function: "example.com/m.Find"}
	if got, want := (domain.DependencyDispatch{Escape: generic}).Describe(), "Gen passed as a type argument to slices.Contains at example.com/m.Find; a dependency handed the value can call it through an interface it asserts in its own body"; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}

func dispatchedRecord(d domain.DependencyDispatch) domain.CallGraphRecord {
	rec := makeTestRecord()
	rec.Nodes[0].DependencyDispatch = d
	return rec
}

func TestDependencyDispatch_RoundTripsThroughTheSeal(t *testing.T) {
	var h domain.CallGraphRecordHasher
	fact := domain.DependencyDispatch{Escape: readerEscape, Interfaces: []string{"io.Reader", "io.ByteReader"},
		ProductionEscape: readerEscape, ProductionInterfaces: []string{"io.Reader"}}
	sealed, err := h.SetContentHash(dispatchedRecord(fact))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"dependency_dispatch":{"escape":{"function":"example.com/m.Upload","kind":"interface-conversion","site":{"file":"m.go","line":7},"type":"*Body","via":"io.Reader"},"interfaces":["io.ByteReader","io.Reader"],"production":{"escape":{"function":"example.com/m.Upload","kind":"interface-conversion","site":{"file":"m.go","line":7},"type":"*Body","via":"io.Reader"},"interfaces":["io.Reader"]}}`)) {
		t.Errorf("the sealed bytes do not carry the fact in canonical order:\n%s", b)
	}
	back, err := h.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	i := slices.IndexFunc(back.Nodes, func(n domain.CallNode) bool { return n.ID == sealed.Nodes[0].ID })
	if got := back.Nodes[i].DependencyDispatch; got.Escape != fact.Escape || !slices.Equal(got.Interfaces, fact.SortedInterfaces()) ||
		got.ProductionEscape != fact.ProductionEscape || !slices.Equal(got.ProductionInterfaces, fact.ProductionInterfaces) {
		t.Errorf("round trip = %+v, want %+v", got, fact)
	}
	plain, err := h.Marshal(makeTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("dependency_dispatch")) {
		t.Errorf("a record with no fact writes the key:\n%s", plain)
	}
}

func TestDependencyDispatch_RefusedOnBothLegs(t *testing.T) {
	var h domain.CallGraphRecordHasher
	bad := dispatchedRecord(domain.DependencyDispatch{Interfaces: []string{"io.Reader"}})
	if _, err := h.SetContentHash(bad); !errors.Is(err, domain.ErrInvalidDependencyDispatch) {
		t.Errorf("SetContentHash err = %v, want ErrInvalidDependencyDispatch", err)
	}
	good, err := h.Marshal(dispatchedRecord(domain.DependencyDispatch{Escape: readerEscape}))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(good, []byte(`"kind":"interface-conversion"`), []byte(`"kind":"cast"`), 1)
	if bytes.Equal(tampered, good) {
		t.Fatal("the fixture no longer carries the kind this test rewrites")
	}
	if _, err := h.Unmarshal(tampered); !errors.Is(err, domain.ErrInvalidDependencyDispatch) {
		t.Errorf("Unmarshal err = %v, want ErrInvalidDependencyDispatch", err)
	}
}

func TestCallNodeLess_OrdersOnTheDependencyDispatch(t *testing.T) {
	at := func(f func(*domain.DependencyDispatch)) domain.CallNode {
		d := domain.DependencyDispatch{Escape: readerEscape}
		f(&d)
		return domain.CallNode{ID: "x", DependencyDispatch: d}
	}
	for name, pair := range map[string][2]domain.CallNode{
		"kind":       {at(func(d *domain.DependencyDispatch) {}), at(func(d *domain.DependencyDispatch) { d.Escape.Kind = domain.EscapeTypeArgument })},
		"type":       {at(func(d *domain.DependencyDispatch) { d.Escape.Type = "*A" }), at(func(d *domain.DependencyDispatch) { d.Escape.Type = "*B" })},
		"via":        {at(func(d *domain.DependencyDispatch) { d.Escape.Via = "a" }), at(func(d *domain.DependencyDispatch) { d.Escape.Via = "b" })},
		"function":   {at(func(d *domain.DependencyDispatch) { d.Escape.Function = "a" }), at(func(d *domain.DependencyDispatch) { d.Escape.Function = "b" })},
		"file":       {at(func(d *domain.DependencyDispatch) { d.Escape.Site.File = "a.go" }), at(func(d *domain.DependencyDispatch) { d.Escape.Site.File = "b.go" })},
		"line":       {at(func(d *domain.DependencyDispatch) { d.Escape.Site.Line = 1 }), at(func(d *domain.DependencyDispatch) { d.Escape.Site.Line = 2 })},
		"interfaces": {at(func(d *domain.DependencyDispatch) { d.Interfaces = []string{"b", "a"} }), at(func(d *domain.DependencyDispatch) { d.Interfaces = []string{"c"} })},
		"production": {at(func(d *domain.DependencyDispatch) {}), at(func(d *domain.DependencyDispatch) { d.ProductionEscape = readerEscape })},
		"production interfaces": {
			at(func(d *domain.DependencyDispatch) {
				d.ProductionEscape = readerEscape
				d.ProductionInterfaces = []string{"a"}
			}),
			at(func(d *domain.DependencyDispatch) {
				d.ProductionEscape = readerEscape
				d.ProductionInterfaces = []string{"b"}
			})},
	} {
		if !domain.CallNodeLess(pair[0], pair[1]) || domain.CallNodeLess(pair[1], pair[0]) {
			t.Errorf("%s: %+v and %+v do not order", name, pair[0].DependencyDispatch, pair[1].DependencyDispatch)
		}
	}
}

// An empty callers answer over a method carrying the fact is UNRESOLVED with
// the sink at the method; a callees answer over it, which the fact says nothing
// about, is not.
func TestClassifyNegativeAnswer_DependencyDispatch(t *testing.T) {
	node := domain.CallNode{ID: "example.com/m.(*Body).Read", Symbol: "Read", DependencyDispatch: domain.DependencyDispatch{Escape: readerEscape, Interfaces: []string{"io.Reader"}}}
	in := domain.NegativeAnswerInputs{
		MethodName: "Read", QueriedNode: node, Found: true, ScanDispatch: true,
		TestScope: domain.TestScopeAnalysed, ReferenceScope: domain.ReferenceScopeAnalysed,
	}
	got := domain.ClassifyNegativeAnswer(in)
	if got.Outcome != domain.AnswerUnresolved || len(got.Sinks) != 1 ||
		got.Sinks[0].Kind != domain.SinkDependencyDispatchUnmeasured || got.Sinks[0].Site != node.ID ||
		!strings.Contains(got.Sinks[0].Detail, "io.Reader") {
		t.Errorf("callers answer = %+v, want UNRESOLVED with the dispatch sink", got)
	}
	in.ScanDispatch = false
	if got := domain.ClassifyNegativeAnswer(in); got.Outcome != domain.AnswerResolvedAbsent {
		t.Errorf("callees answer = %+v, want RESOLVED-ABSENT", got)
	}
	in.ScanDispatch = true
	in.QueriedNode.DependencyDispatch = domain.DependencyDispatch{}
	if got := domain.ClassifyNegativeAnswer(in); got.Outcome != domain.AnswerResolvedAbsent {
		t.Errorf("answer without the fact = %+v, want RESOLVED-ABSENT", got)
	}
}

// A dispatch root is a second set: a method already an entry point is not in
// it, nor a test or an external node, and a method with no fact is not either.
func TestSelectDependencyDispatchRoots(t *testing.T) {
	const detail = "a dependency can call it through io.Reader"
	got := domain.SelectDependencyDispatchRoots([]domain.RootCandidate{
		{ID: "m.(*b).Read", Symbol: "Read", Receiver: "*b", Dispatch: detail},
		{ID: "m.(*B).Read", Symbol: "Read", Receiver: "*B", IsExportedAPI: true, Dispatch: detail},
		{ID: "m.(*h).ServeHTTP", Symbol: "ServeHTTP", Receiver: "*h", Dispatch: detail},
		{ID: "m.(*f).Read", Symbol: "Read", Receiver: "*f", IsTest: true, Dispatch: detail},
		{ID: "dep.(*x).Read", Symbol: "Read", Receiver: "*x", IsExternal: true, Dispatch: detail},
		{ID: "m.(*c).Read", Symbol: "Read", Receiver: "*c"},
	}, domain.RootScopeProduction)
	if !slices.Equal(got, []string{"m.(*b).Read"}) {
		t.Errorf("SelectDependencyDispatchRoots = %v, want the unexported type's method only", got)
	}
	if got := domain.DependencyDispatchEntryReason(""); got != "" {
		t.Errorf("no detail gives reason %q", got)
	}
	if got := domain.DependencyDispatchEntryReason(detail); !strings.HasSuffix(got, detail) {
		t.Errorf("reason = %q, want it to end with the detail", got)
	}
}
