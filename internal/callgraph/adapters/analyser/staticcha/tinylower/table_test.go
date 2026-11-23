package tinylower_test

import (
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinylower"
)

func rt(names ...string) []tinylower.Callee {
	out := make([]tinylower.Callee, len(names))
	for i, n := range names {
		out[i] = tinylower.Callee{Pkg: "runtime", Name: n}
	}
	return out
}

// Where the releases lower an op differently, each table names its own callees;
// an op a release does not lower to a call names none.
var releaseCallees = map[string]map[tinylower.Op][]tinylower.Callee{
	"0.42.0": {
		tinylower.OpChanTrySend:               rt("chanSelect"),
		tinylower.OpChanTryRecv:               rt("chanSelect"),
		tinylower.OpStringFromBytesComparedTo: rt("stringFromBytes"),
		tinylower.OpStringFromBytesCompared:   rt("stringFromBytes"),
		tinylower.OpArrayEqual:                nil,
		tinylower.OpUnwindCheck:               nil,
		tinylower.OpUnwindClear:               nil,
		tinylower.OpAsyncifyCatch:             nil,
	},
	"0.43.0": {
		tinylower.OpChanTrySend:               rt("chanTrySend"),
		tinylower.OpChanTryRecv:               rt("chanTryRecv"),
		tinylower.OpStringFromBytesComparedTo: nil,
		tinylower.OpStringFromBytesCompared:   rt("stringFromBytes"),
		tinylower.OpArrayEqual:                rt("memequal"),
		tinylower.OpUnwindCheck:               rt("unwindPending"),
		tinylower.OpUnwindClear:               rt("clearUnwind"),
		tinylower.OpAsyncifyCatch:             asyncifyCatch,
	},
	"0.44.0": {
		tinylower.OpChanTrySend:               rt("chanTrySend"),
		tinylower.OpChanTryRecv:               rt("chanTryRecv"),
		tinylower.OpStringFromBytesComparedTo: nil,
		tinylower.OpStringFromBytesCompared:   nil,
		tinylower.OpArrayEqual:                rt("memequal"),
		tinylower.OpUnwindCheck:               rt("unwindPending"),
		tinylower.OpUnwindClear:               rt("clearUnwind"),
		tinylower.OpAsyncifyCatch:             asyncifyCatch,
	},
}

var asyncifyCatch = rt("unwindPending", "asyncifyStopUnwindImport", "savePanicReplay",
	"panicRewindData", "panicRewindStackPointer", "setPanicRewindStackPointer", "asyncifyStartRewindImport")

// Every op names a runtime function in every table, except where a release
// lowers it to no call; every other op is lowered alike by all three releases.
func TestTable_CoversEveryOp(t *testing.T) {
	if got := tinylower.Versions(); !slices.Equal(got, []string{"0.42.0", "0.43.0", "0.44.0"}) {
		t.Errorf("Versions = %v", got)
	}
	for _, v := range []string{"0.41.0", "0.45.0"} {
		if _, ok := tinylower.ForVersion(v); ok {
			t.Errorf("ForVersion(%s) found a table", v)
		}
	}
	base, _ := tinylower.ForVersion("0.42.0")
	for version, differs := range releaseCallees {
		table, ok := tinylower.ForVersion(version)
		if !ok || table.Version() != version {
			t.Fatalf("ForVersion(%s) = %v, %v", version, table, ok)
		}
		checkTable(t, table, base, differs)
	}
}

func checkTable(t *testing.T, table, base *tinylower.Table, differs map[tinylower.Op][]tinylower.Callee) {
	t.Helper()
	version := table.Version()
	for _, op := range allOps {
		cs := table.Callees(op)
		want, listed := differs[op]
		switch {
		case listed && !slices.Equal(cs, want):
			t.Errorf("%s: op %s names %v, want %v", version, op, cs, want)
		case !listed && (len(cs) == 0 || !slices.Equal(cs, base.Callees(op))):
			t.Errorf("%s: op %s names %v, want 0.42.0's %v", version, op, cs, base.Callees(op))
		}
		for _, c := range cs {
			if c.Pkg != "runtime" && c.Pkg != "internal/task" {
				t.Errorf("%s: op %s names %s.%s outside runtime and internal/task", version, op, c.Pkg, c.Name)
			}
		}
	}
	if got := table.WasmExports(); len(got) != 1 || got[0] != (tinylower.NamedExport{Callee: tinylower.Callee{Pkg: "runtime", Name: "wasmEntryCommand"}, Symbol: "_start"}) {
		t.Errorf("%s: WasmExports = %+v, want only the default build mode's _start", version, got)
	}
	if table.Callees("no-such-op") != nil {
		t.Errorf("%s: an unknown op has callees", version)
	}
}
