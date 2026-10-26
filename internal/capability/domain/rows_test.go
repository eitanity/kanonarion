package domain

import (
	"reflect"
	"strconv"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

const (
	direct = cgdomain.ConfidenceDirect
	cha    = cgdomain.ConfidenceCHAOverapprox
)

func ext(id, pkg, recv, sym string) cgdomain.CallNode {
	return cgdomain.CallNode{ID: id, Package: pkg, Receiver: recv, Symbol: sym, IsExternal: true}
}

func analyseAll(rec cgdomain.CallGraphRecord) CapabilityReport {
	rec.OverallStatus = cgdomain.CallGraphStatusExtracted
	return Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction), cgdomain.RootScopeProduction)
}

func sensitiveCallees(r CapabilityReport) []string {
	var out []string
	for _, s := range r.SensitiveCalls {
		out = append(out, string(s.Capability)+" "+s.Callee)
	}
	return out
}

// A member needs a Direct edge: a callee reached only through CHA stays a row,
// labelled with its confidence, and is not a sensitive call. Plumbing and
// Context-tier callees are never members.
func TestSensitiveCalls_NeedADirectEdgeADirectCallAndASensitiveLabel(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.Format", "m", "Format", false, true),
			node("m.run", "m", "run", false, false),
			ext("os/exec.(*ExitError).Error", "os/exec", "*ExitError", "Error"),
			ext("os/exec.Command", "os/exec", "", "Command"),
			ext("net.Dial", "net", "", "Dial"),
			ext("os.(*File).Close", "os", "*File", "Close"),
			ext("os.sigpipe", "os", "", "sigpipe"),
			ext("os/exec.findExecutable", "os/exec", "", "findExecutable"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Format", "os/exec.(*ExitError).Error", cha),
			edge("m.Format", "os/exec.Command", cha),
			edge("m.Format", "net.Dial", cha),
			edge("m.run", "net.Dial", direct),
			edge("m.run", "os.(*File).Close", direct),
			edge("m.run", "os.sigpipe", direct),
			edge("m.run", "os/exec.findExecutable", direct),
		},
	}
	r := analyseAll(rec)
	if got, want := sensitiveCallees(r), []string{"NET_DIAL net.Dial"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sensitive calls = %v, want %v", got, want)
	}
	if got := r.SensitiveCalls[0]; got.Callers != 2 ||
		!reflect.DeepEqual(got.CallerKinds, []CallerKind{CallerExportedAPI, CallerInternal}) {
		t.Errorf("net.Dial member = %+v, want 2 callers from EXPORTED_API and INTERNAL", got)
	}
	if len(r.Rows) != 7 {
		t.Errorf("every classified edge is a row, got %d: %+v", len(r.Rows), r.Rows)
	}
}

// io/ioutil aliases are the os function they forward to, so migrating off the
// deprecated package is no change in the roll-up; the rows still show it.
func TestSensitiveCalls_NormaliseDeprecatedAliases(t *testing.T) {
	from := analyseAll(cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.Load", "m", "Load", false, true),
			ext("io/ioutil.ReadFile", "io/ioutil", "", "ReadFile"),
			ext("io/ioutil.TempDir", "io/ioutil", "", "TempDir"),
			ext("io/ioutil.ReadAll", "io/ioutil", "", "ReadAll"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Load", "io/ioutil.ReadFile", direct),
			edge("m.Load", "io/ioutil.TempDir", direct),
			edge("m.Load", "io/ioutil.ReadAll", direct),
		},
	})
	to := analyseAll(cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.Load", "m", "Load", false, true),
			ext("os.ReadFile", "os", "", "ReadFile"),
			ext("os.MkdirTemp", "os", "", "MkdirTemp"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Load", "os.ReadFile", direct),
			edge("m.Load", "os.MkdirTemp", direct),
		},
	})
	if got, want := sensitiveCallees(from), []string{"FS_READ os.ReadFile", "FS_WRITE os.MkdirTemp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("from sensitive calls = %v, want %v", got, want)
	}
	d := DiffCapabilities(from, to)
	if len(d.SensitiveAdded) != 0 || len(d.SensitiveRemoved) != 0 {
		t.Errorf("an alias migration moved the roll-up: +%v -%v", d.SensitiveAdded, d.SensitiveRemoved)
	}
	if len(d.RowsAdded) != 2 || len(d.RowsRemoved) != 3 {
		t.Errorf("rows +%d -%d, want +2 -3: the rows name the functions as called", len(d.RowsAdded), len(d.RowsRemoved))
	}
	if NormaliseCallee("io/ioutil.TempFile") != "os.CreateTemp" || NormaliseCallee("os.Open") != "os.Open" {
		t.Error("NormaliseCallee maps TempFile onto CreateTemp and leaves everything else")
	}
}

// One function holding a collection and an egress member over Direct edges is
// named; a CHA egress edge does not count.
func TestCollectsAndEgresses(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.Exfil", "m", "Exfil", false, true),
			node("m.Wide", "m", "Wide", false, false),
			node("m.Other", "m", "Other", false, false),
			ext("os.Getenv", "os", "", "Getenv"),
			ext("io/ioutil.ReadFile", "io/ioutil", "", "ReadFile"),
			ext("net.Dial", "net", "", "Dial"),
			ext("net.(*conn).Write", "net", "*conn", "Write"),
			ext("os.ReadFile", "os", "", "ReadFile"),
			ext("net.Listen", "net", "", "Listen"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.Exfil", "os.Getenv", direct),
			edge("m.Exfil", "io/ioutil.ReadFile", direct),
			edge("m.Exfil", "os.ReadFile", direct),
			edge("m.Exfil", "net.Listen", direct),
			edge("m.Exfil", "net.Dial", direct),
			edge("m.Wide", "os.Getenv", direct),
			edge("m.Wide", "net.(*conn).Write", cha),
			edge("m.Other", "net.(*conn).Write", direct),
			edge("m.Other", "os.Getenv", direct),
			edge("m.Wide", "net.Listen", direct),
		},
	}
	r := analyseAll(rec)
	want := []CoLocation{{
		Function: "m.Exfil", CallerKind: CallerExportedAPI,
		Collection: []string{"os.Getenv", "os.ReadFile"}, Egress: []string{"net.Dial"},
	}, {
		Function: "m.Other", CallerKind: CallerInternal,
		Collection: []string{"os.Getenv"}, Egress: []string{"net.(*conn).Write"},
	}}
	if !reflect.DeepEqual(r.CollectsAndEgresses, want) {
		t.Errorf("CollectsAndEgresses = %+v, want %+v", r.CollectsAndEgresses, want)
	}
}

// From each owned initialiser, Direct edges only, no depth bound: the depth is
// where the second of the two first appears.
func TestInitReachesBoth(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.init", "m", "init", false, false),
			node("m.init#1", "m", "init#1", false, false),
			node("m/b.init", "m/b", "init", false, false),
			node("m.load", "m", "load", false, false),
			node("m.cfg", "m", "cfg", false, false),
			ext("os.Getenv", "os", "", "Getenv"),
			ext("os.LookupEnv", "os", "", "LookupEnv"),
			ext("net.Dial", "net", "", "Dial"),
		},
		Edges: []cgdomain.CallEdge{
			// m.init: net.Dial at 1, os.Getenv at 3 through two owned hops.
			edge("m.init", "net.Dial", direct),
			edge("m.init", "m.load", direct),
			edge("m.load", "m.cfg", direct),
			edge("m.cfg", "os.Getenv", direct),
			edge("m.cfg", "os.LookupEnv", direct),
			edge("m.load", "m.load", direct),
			// m.init#1 reaches the egress only through CHA, so not both.
			edge("m.init#1", "os.Getenv", direct),
			edge("m.init#1", "net.Dial", cha),
			// m/b.init reaches nothing sensitive.
			edge("m/b.init", "m.load", cha),
		},
	}
	r := analyseAll(rec)
	want := []InitReach{{
		Init: "m.init", CallerKind: CallerInit, Depth: 3, CollectionDepth: 3, EgressDepth: 1,
		Collection: "os.Getenv", Egress: "net.Dial",
	}}
	if !reflect.DeepEqual(r.InitReachesBoth, want) {
		t.Errorf("InitReachesBoth = %+v, want %+v", r.InitReachesBoth, want)
	}

	// No egress member at all: nothing to search for.
	rec.Edges = rec.Edges[1:]
	rec.Edges = append(rec.Edges[:6], rec.Edges[7:]...)
	if got := analyseAll(rec).InitReachesBoth; got != nil {
		t.Errorf("without an egress member, got %+v", got)
	}
}

// A capability whose only rows are plumbing keeps one, promoted and marked;
// plumbing beside a direct call of the same capability (net.dialSerial and
// net.ParseIP are both NET_INSPECT) is suppressed, and RUNTIME_INTERNAL always is.
func TestPlumbingOnlyPromotion(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.A", "m", "A", false, true),
			node("m.b", "m", "b", false, false),
			ext("runtime/cgo._Cgo_use", "runtime/cgo", "", "_Cgo_use"),
			ext("runtime/cgo.set_crosscall2", "runtime/cgo", "", "set_crosscall2"),
			ext("net.Dial", "net", "", "Dial"),
			ext("net.dialSerial", "net", "", "dialSerial"),
			ext("net.ParseIP", "net", "", "ParseIP"),
			ext("runtime.GC", "runtime", "", "GC"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.A", "runtime/cgo._Cgo_use", direct),
			edge("m.b", "runtime/cgo.set_crosscall2", cha),
			edge("m.A", "net.Dial", direct),
			edge("m.A", "net.dialSerial", direct),
			edge("m.A", "net.ParseIP", direct),
			edge("m.A", "runtime.GC", direct),
		},
	}
	r := analyseAll(rec)
	state := map[string][2]bool{}
	for _, row := range r.Rows {
		state[row.Callee] = [2]bool{row.Suppressed, row.PlumbingOnly}
	}
	want := map[string][2]bool{
		"runtime/cgo._Cgo_use":       {false, true},
		"runtime/cgo.set_crosscall2": {true, false},
		"net.Dial":                   {false, false},
		"net.dialSerial":             {true, false},
		"net.ParseIP":                {false, false},
		"runtime.GC":                 {true, false},
	}
	if !reflect.DeepEqual(state, want) {
		t.Errorf("row (suppressed, plumbing-only) = %v, want %v", state, want)
	}
	cgo, _ := findingFor(r, CapabilityCgoCall)
	if !cgo.PlumbingOnly || cgo.Suppressed() {
		t.Errorf("CGO_CALL finding = %+v, want shown and plumbing-only", cgo)
	}
	dial, _ := findingFor(r, CapabilityNetDial)
	if dial.PlumbingOnly || dial.Reach != ReachDirectCall {
		t.Errorf("NET_DIAL finding = %+v, want the direct witness, not plumbing-only", dial)
	}
	rt, _ := findingFor(r, CapabilityRuntimeInternal)
	if !rt.Suppressed() {
		t.Error("RUNTIME_INTERNAL finding must be suppressed")
	}
}

// A finding prefers a direct call over plumbing over an unanalysed body, ahead
// of confidence, and names the last owned function on its path.
func TestFindingWitnessPreferenceAndCallerKind(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.init", "m", "init", false, false),
			node("m.Get", "m", "Get", false, true),
			ext("syscall.rawSyscall", "syscall", "", "rawSyscall"),
			{ID: "syscall.RawSyscall", Package: "syscall", Symbol: "RawSyscall", IsExternal: true, IsAssemblyOrLinkname: true},
			ext("syscall.Wrapper", "syscall", "", "Wrapper"),
			ext("syscall.Kill", "syscall", "", "Kill"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.init", "syscall.rawSyscall", direct),
			edge("m.init", "syscall.RawSyscall", direct),
			edge("m.Get", "syscall.Wrapper", cha),
			edge("syscall.Wrapper", "syscall.Kill", cha),
		},
	}
	f, _ := findingFor(analyseAll(rec), CapabilitySyscallDirect)
	if f.Reach != ReachDirectCall || f.WeakestConfidence != cha {
		t.Fatalf("witness = %+v, want the CHA direct call over the Direct plumbing", f)
	}
	// Both direct calls tie on reach and confidence; the shorter path wins, and
	// its caller is the exported function, not the init.
	if f.CallerKind != CallerExportedAPI || f.SinkSymbol != "Wrapper" {
		t.Errorf("witness = %+v, want m.Get → syscall.Wrapper", f)
	}
	// Without a direct call, an exported unanalysed body outranks plumbing: it
	// is not plumbing, so the finding is not plumbing-only.
	rec.Edges = rec.Edges[:2]
	f, _ = findingFor(analyseAll(rec), CapabilitySyscallDirect)
	if f.Reach != ReachUnanalyzed || f.SinkSymbol != "RawSyscall" || f.PlumbingOnly {
		t.Errorf("without a direct call the witness = %+v, want the exported UNANALYZED RawSyscall", f)
	}
	// Plumbing alone is plumbing-only.
	rec.Edges = rec.Edges[:1]
	f, _ = findingFor(analyseAll(rec), CapabilitySyscallDirect)
	if f.Reach != ReachRuntimePlumbing || f.CallerKind != CallerInit || !f.PlumbingOnly {
		t.Errorf("plumbing alone = %+v, want plumbing-only from INIT", f)
	}
	// A path through an external node reports the owned caller before it.
	if got := pathCallerKind([]string{"x.Unknown"}, map[string]cgdomain.CallNode{}); got != CallerInternal {
		t.Errorf("a path with no owned node in the graph = %q, want INTERNAL", got)
	}
}

// Several edges for one row collapse to it with the strongest confidence; a
// default-labelled callee is counted per package.
func TestRowsCollapseEdgesAndCountPackageDefaults(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.F", "m", "F", false, true),
			node("m.G", "m", "G", false, false),
			ext("reflect.TypeOf", "reflect", "", "TypeOf"),
			ext("reflect.ValueOf", "reflect", "", "ValueOf"),
			ext("os.IsNotExist", "os", "", "IsNotExist"),
			ext("missing.Node", "", "", ""),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.F", "reflect.TypeOf", cha),
			edge("m.F", "reflect.TypeOf", direct),
			edge("m.F", "reflect.TypeOf", cha),
			edge("m.G", "reflect.TypeOf", direct),
			edge("m.G", "reflect.ValueOf", direct),
			edge("m.G", "os.IsNotExist", direct),
			edge("m.G", "m.F", direct),
			edge("m.G", "absent.Node", direct),
		},
	}
	r := analyseAll(rec)
	if len(r.Rows) != 4 {
		t.Fatalf("rows = %+v, want 4", r.Rows)
	}
	for _, row := range r.Rows {
		if row.Confidence != direct {
			t.Errorf("row %+v should carry the strongest edge, Direct", row)
		}
	}
	want := []PackageDefault{{Package: "os", Callees: 1}, {Package: "reflect", Callees: 2}}
	if !reflect.DeepEqual(r.PackageDefaults, want) {
		t.Errorf("PackageDefaults = %+v, want %+v", r.PackageDefaults, want)
	}
	// A root named twice, or not in the graph, roots nothing extra.
	again := Analyse(rec, []string{"m.G", "m.G", "nope", "reflect.TypeOf"}, cgdomain.RootScopeProduction)
	if len(again.Rows) != 3 {
		t.Errorf("rows from m.G alone = %d, want 3", len(again.Rows))
	}
}

// The diff's ranking: caller kind, then tier, then Direct first, then
// capability, callee and caller; TEST and INTERNAL collapse with a count.
func TestDiffRowsRankAndCollapse(t *testing.T) {
	from := analyseAll(cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{node("m.Old", "m", "Old", false, true), ext("os.Exit", "os", "", "Exit")},
		Edges: []cgdomain.CallEdge{edge("m.Old", "os.Exit", direct)},
	})
	main := node("m/cmd.main", "m/cmd", "main", false, false)
	tst := testNode("m_test.TestA", "m_test", "TestA")
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			main, tst,
			node("m.init", "m", "init", false, false),
			node("m.Pub", "m", "Pub", false, true),
			node("m.a", "m", "a", false, false),
			node("m.b", "m", "b", false, false),
			ext("os.Getenv", "os", "", "Getenv"),
			ext("os.Hostname", "os", "", "Hostname"),
			ext("net.Dial", "net", "", "Dial"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m/cmd.main", "net.Dial", direct),
			edge("m_test.TestA", "net.Dial", direct),
			edge("m.init", "os.Hostname", direct),
			edge("m.init", "net.Dial", cha),
			edge("m.init", "os.Getenv", direct),
			edge("m.Pub", "os.Getenv", direct),
			edge("m.a", "os.Getenv", direct),
			edge("m.b", "os.Getenv", cha),
		},
	}
	to := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeWithTests), cgdomain.RootScopeWithTests)
	d := DiffCapabilities(from, to)
	if len(d.RowsRemoved) != 1 || d.RowsRemoved[0].Caller != "m.Old" {
		t.Errorf("removed = %+v, want the m.Old row", d.RowsRemoved)
	}
	var got []string
	for _, g := range GroupRows(d.RowsAdded) {
		got = append(got, string(g.CallerKind)+" "+string(g.Capability)+" "+g.Callee+" "+string(g.Confidence)+" "+itoa(len(g.Callers)))
	}
	want := []string{
		"INIT ENV_READ os.Getenv Direct 1",
		"INIT NET_DIAL net.Dial CHA-overapprox 1",
		"INIT HOST_IDENTITY os.Hostname Direct 1",
		"EXPORTED_API ENV_READ os.Getenv Direct 1",
		"TEST NET_DIAL net.Dial Direct 1",
		"INTERNAL ENV_READ os.Getenv Direct 2",
		"MAIN NET_DIAL net.Dial Direct 1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("groups =\n%v\nwant\n%v", got, want)
	}
	if d.Unchanged() {
		t.Error("a diff with rows added is not unchanged")
	}
	if !DiffCapabilities(to, to).Unchanged() {
		t.Error("a report diffed with itself is unchanged")
	}
}

// Each fact the diff carries beside the rows is keyed on its own identity.
func TestDiffCarriesRollUpCoLocationAndUnanalysed(t *testing.T) {
	from := CapabilityReport{
		Unanalyzed: []string{"m.asmA"},
		InitReachesBoth: []InitReach{
			{Init: "m.init", Depth: 2, Collection: "os.Getenv", Egress: "net.Dial"},
			{Init: "m/old.init", Depth: 1, Collection: "os.Getenv", Egress: "net.Dial"},
			{Init: "m/c.init", Depth: 3, Collection: "os.Getenv", Egress: "net.Dial"},
		},
		CollectsAndEgresses: []CoLocation{{Function: "m.F"}},
		SensitiveCalls:      []SensitiveCall{{Callee: "net.Dial", Capability: CapabilityNetDial, Callers: 1}},
	}
	to := CapabilityReport{
		Unanalyzed: []string{"m.asmB"},
		InitReachesBoth: []InitReach{
			{Init: "m.init", Depth: 1, Collection: "os.Getenv", Egress: "net.Dial"},
			{Init: "m/new.init", Depth: 4, Collection: "os.Getenv", Egress: "net.Dial"},
			{Init: "m/c.init", Depth: 3, Collection: "os.ReadFile", Egress: "net.Dial"},
		},
		CollectsAndEgresses: []CoLocation{{Function: "m.F", Collection: []string{"os.Getenv"}}},
		SensitiveCalls:      []SensitiveCall{{Callee: "net.Dial", Capability: CapabilityNetDial, Callers: 3}},
	}
	d := DiffCapabilities(from, to)
	if !reflect.DeepEqual(d.UnanalyzedAdded, []string{"m.asmB"}) || !reflect.DeepEqual(d.UnanalyzedRemoved, []string{"m.asmA"}) {
		t.Errorf("unanalysed +%v -%v", d.UnanalyzedAdded, d.UnanalyzedRemoved)
	}
	// A depth move is a change of depth; an init on one side only, or reaching
	// another member, is an add or a remove.
	if len(d.InitReachesBothDepthChanged) != 1 || d.InitReachesBothDepthChanged[0].From.Depth != 2 ||
		d.InitReachesBothDepthChanged[0].To.Depth != 1 {
		t.Errorf("depth changes = %+v, want m.init 2 → 1", d.InitReachesBothDepthChanged)
	}
	added, removed := []string{}, []string{}
	for _, r := range d.InitReachesBothAdded {
		added = append(added, r.Init+" "+r.Collection)
	}
	for _, r := range d.InitReachesBothRemoved {
		removed = append(removed, r.Init+" "+r.Collection)
	}
	if !reflect.DeepEqual(added, []string{"m/new.init os.Getenv", "m/c.init os.ReadFile"}) ||
		!reflect.DeepEqual(removed, []string{"m/old.init os.Getenv", "m/c.init os.Getenv"}) {
		t.Errorf("init reaches both +%v -%v", added, removed)
	}
	moved := DiffCapabilities(CapabilityReport{InitReachesBoth: from.InitReachesBoth[:1]},
		CapabilityReport{InitReachesBoth: to.InitReachesBoth[:1]})
	if moved.Unchanged() {
		t.Error("a depth move alone is not unchanged")
	}
	if len(d.CollectsAndEgressesAdded) != 0 || len(d.SensitiveAdded) != 0 {
		t.Errorf("the same function and the same member are no change: %+v %+v", d.CollectsAndEgressesAdded, d.SensitiveAdded)
	}
	if d.Unchanged() {
		t.Error("unanalysed bodies moved")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// Under the production scope the search does not enter test code: a CHA edge
// from production into a test function carries no test-only sink into the
// report, nor into init_reaches_both. With tests included it does.
func TestAnalyse_ProductionScopeDoesNotEnterTestNodes(t *testing.T) {
	helper := testNode("m_test.appendLine", "m_test", "appendLine")
	helper.IsExportedAPI = false
	rec := cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			node("m.init", "m", "init", false, false),
			node("m.runHandler", "m", "runHandler", false, false),
			helper,
			ext("os.ReadFile", "os", "", "ReadFile"),
			ext("net.Dial", "net", "", "Dial"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.runHandler", "m_test.appendLine", cha),
			edge("m_test.appendLine", "os.ReadFile", direct),
			edge("m.init", "net.Dial", direct),
			edge("m.init", "m_test.appendLine", direct),
			edge("m.init", "os.ReadFile", cha),
			// A Direct production call makes os.ReadFile a member, so only the test
			// node stands between the init and it.
			edge("m.runHandler", "os.ReadFile", direct),
		},
	}
	prod := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction), cgdomain.RootScopeProduction)
	for _, f := range prod.Findings {
		if f.CallerKind == CallerTest || f.CallerKind == CallerTestInit {
			t.Errorf("finding of kind %s under the production scope: %+v", f.CallerKind, f)
		}
	}
	if len(prod.InitReachesBoth) != 0 {
		t.Errorf("init_reaches_both crossed a test node: %+v", prod.InitReachesBoth)
	}
	all := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeWithTests), cgdomain.RootScopeWithTests)
	testRow := false
	for _, r := range all.Rows {
		testRow = testRow || (r.Caller == "m_test.appendLine" && r.CallerKind == CallerTest)
	}
	if !testRow {
		t.Errorf("with tests included the test function's own call is a row, got %+v", all.Rows)
	}
	if len(all.InitReachesBoth) != 1 {
		t.Errorf("with tests included the init reaches both, got %+v", all.InitReachesBoth)
	}
}

// An unexported callee with an assembly or linkname body is plumbing for
// suppression; promotion still applies when it is a capability's only row.
// Findings use the same predicate: a capability witnessed only by an unexported
// unanalysed body, or by that and plumbing, is plumbing-only; an exported
// unanalysed body is a real witness and is the one chosen over plumbing.
func TestFindingsShareThePlumbingPredicate(t *testing.T) {
	asm := func(id, pkg, sym string) cgdomain.CallNode {
		n := ext(id, pkg, "", sym)
		n.IsAssemblyOrLinkname = true
		return n
	}
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.A", "m", "A", false, true),
			asm("runtime/cgo.set_crosscall2", "runtime/cgo", "set_crosscall2"),
			ext("os/signal.loop", "os/signal", "", "loop"),
			asm("os/signal.signal_enable", "os/signal", "signal_enable"),
			ext("syscall.rawVforkSyscall", "syscall", "", "rawVforkSyscall"),
			asm("syscall.RawSyscall", "syscall", "RawSyscall"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.A", "runtime/cgo.set_crosscall2", direct),
			edge("m.A", "os/signal.loop", direct),
			edge("m.A", "os/signal.signal_enable", direct),
			edge("m.A", "syscall.rawVforkSyscall", direct),
			edge("m.A", "syscall.RawSyscall", cha),
		},
	}
	r := analyseAll(rec)
	for c, want := range map[Capability]bool{CapabilityCgoCall: true, CapabilityProcControl: true, CapabilitySyscallDirect: false} {
		f, _ := findingFor(r, c)
		if f.PlumbingOnly != want {
			t.Errorf("%s plumbing-only = %v, want %v (witness %s.%s %s)", c, f.PlumbingOnly, want, f.SinkPackage, f.SinkSymbol, f.Reach)
		}
	}
	if f, _ := findingFor(r, CapabilitySyscallDirect); f.SinkSymbol != "RawSyscall" {
		t.Errorf("the exported unanalysed body outranks the Direct plumbing, got %+v", f)
	}
}

func TestOpaquePlumbingIsSuppressedAndPromoted(t *testing.T) {
	asm := func(id, pkg, sym string) cgdomain.CallNode {
		n := ext(id, pkg, "", sym)
		n.IsAssemblyOrLinkname = true
		return n
	}
	rec := cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{
			node("m.A", "m", "A", false, true),
			asm("syscall.runtime_AfterFork", "syscall", "runtime_AfterFork"),
			asm("syscall.RawSyscall", "syscall", "RawSyscall"),
			asm("reflect.makeFuncStub", "reflect", "makeFuncStub"),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.A", "syscall.runtime_AfterFork", direct),
			edge("m.A", "syscall.RawSyscall", direct),
			edge("m.A", "reflect.makeFuncStub", direct),
		},
	}
	state := map[string][2]bool{}
	for _, row := range analyseAll(rec).Rows {
		if row.Reach != ReachUnanalyzed {
			t.Errorf("%s reach = %s, want UNANALYZED", row.Callee, row.Reach)
		}
		state[row.Callee] = [2]bool{row.Suppressed, row.PlumbingOnly}
	}
	want := map[string][2]bool{
		"syscall.runtime_AfterFork": {true, false},
		"syscall.RawSyscall":        {false, false},
		"reflect.makeFuncStub":      {false, true},
	}
	if !reflect.DeepEqual(state, want) {
		t.Errorf("row (suppressed, plumbing-only) = %v, want %v", state, want)
	}
}
