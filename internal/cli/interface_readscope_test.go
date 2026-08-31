package cli

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// A question about one coordinate must be asked of that coordinate. Answering it
// from an unfiltered listing is correct and unaffordable: the ledger composes
// every multi-generation key on the way to rows the caller then discards, and
// `context --gomod` asks once per module, so the cost is misses x whole store.
//
// These tests assert WHAT was asked, not how much came back. A read that returns
// the right answer from the whole corpus passes every assertion about output.

// ledgerHoldingManyModules returns a fake whose ledger holds three modules,
// exactly one of which is the coordinate under test and is held only under
// extraction logic this build no longer serves.
func ledgerHoldingManyModules(t *testing.T) (*testfakes.FakeQueryInterface, coordinate.ModuleCoordinate) {
	t.Helper()
	coord := supersededCoord(t)
	uc := testfakes.NewFakeQueryInterface()
	uc.SetList([]ifaceports.InterfaceSummary{
		{
			ModulePath: coord.Path(), ModuleVersion: coord.Version(),
			PipelineVersion: supersededPipeline, PackageCount: 2,
			OverallStatus: ifacedomain.InterfaceStatusExtracted,
		},
		{
			ModulePath: "example.com/other", ModuleVersion: "v1.0.0",
			PipelineVersion: supersededPipeline, PackageCount: 1,
			OverallStatus: ifacedomain.InterfaceStatusExtracted,
		},
		{
			ModulePath: "example.com/third", ModuleVersion: "v3.0.0",
			PipelineVersion: ifaceapp.PipelineVersion, PackageCount: 1,
			OverallStatus: ifacedomain.InterfaceStatusExtracted,
		},
	})
	return uc, coord
}

// readScope counts, over every listing the fake was asked for, how many named a
// coordinate and how many asked for the whole corpus.
func readScope(uc *testfakes.FakeQueryInterface, coord coordinate.ModuleCoordinate) (scoped, corpus int, wrong []string) {
	for _, f := range uc.ListFilters {
		switch {
		case f.Coordinate == nil:
			corpus++
		case f.Coordinate.Path() == coord.Path() && f.Coordinate.Version() == coord.Version():
			scoped++
		default:
			wrong = append(wrong, f.Coordinate.String())
		}
	}
	return scoped, corpus, wrong
}

// TestSupersededDiagnostic_AsksTheStoreForOneCoordinate drives every surface
// that tells "never extracted" from "extracted under superseded logic" and
// asserts each asked the store about the module it was answering for. Before
// the fix each read the whole ledger and threw away every row but one module's.
func TestSupersededDiagnostic_AsksTheStoreForOneCoordinate(t *testing.T) {
	surfaces := []struct {
		name string
		run  func(t *testing.T, uc *testfakes.FakeQueryInterface, coord coordinate.ModuleCoordinate) string
	}{
		{
			name: "context section",
			run: func(t *testing.T, uc *testfakes.FakeQueryInterface, coord coordinate.ModuleCoordinate) string {
				t.Helper()
				return buildInterface(context.Background(), coord, uc, true, "").Error
			},
		},
		{
			name: "interface record miss",
			run: func(t *testing.T, uc *testfakes.FakeQueryInterface, coord coordinate.ModuleCoordinate) string {
				t.Helper()
				var stderr bytes.Buffer
				err := interfaceRecordMiss(context.Background(), uc, coord, false, &stderr)
				if err == nil {
					t.Fatal("a miss must not be reported as success")
				}
				return err.Error()
			},
		},
		{
			name: "interface diff miss",
			run: func(t *testing.T, uc *testfakes.FakeQueryInterface, coord coordinate.ModuleCoordinate) string {
				t.Helper()
				return interfaceMissMessage(context.Background(), uc,
					&ifaceapp.ErrInterfaceRecordNotFound{Coordinate: coord})
			},
		},
		{
			name: "interface history",
			run: func(t *testing.T, uc *testfakes.FakeQueryInterface, coord coordinate.ModuleCoordinate) string {
				t.Helper()
				var stdout bytes.Buffer
				if err := runInterfaceHistory(context.Background(), coord, uc, &stdout); err != nil {
					t.Fatalf("runInterfaceHistory: %v", err)
				}
				return stdout.String()
			},
		},
	}

	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			uc, coord := ledgerHoldingManyModules(t)
			msg := s.run(t, uc, coord)

			// The answer must not change: this is the whole point of the read.
			if !strings.Contains(msg, "superseded extraction logic") {
				t.Fatalf("the superseded statement was lost:\n%s", msg)
			}
			if !strings.Contains(msg, "the store holds this coordinate at pipeline "+supersededPipeline) {
				t.Errorf("the statement no longer names the held pipeline:\n%s", msg)
			}

			scoped, corpus, wrong := readScope(uc, coord)
			if scoped != 1 {
				t.Errorf("the store was asked about %s %d time(s), want exactly 1", coord, scoped)
			}
			if corpus != 0 {
				t.Errorf("a question about %s read the whole ledger %d time(s); the filter exists so it need not",
					coord, corpus)
			}
			if len(wrong) > 0 {
				t.Errorf("the store was asked about coordinates nobody named: %v", wrong)
			}
		})
	}
}

// TestSupersededDiagnostic_CostTracksModulesNotTheStore pins the shape that made
// this cost minutes: the diagnostic runs once per module, so a per-module read
// that is not scoped multiplies the whole store by the module count.
func TestSupersededDiagnostic_CostTracksModulesNotTheStore(t *testing.T) {
	uc, coord := ledgerHoldingManyModules(t)
	const modules = 25
	for range modules {
		buildInterface(context.Background(), coord, uc, true, "")
	}
	scoped, corpus, _ := readScope(uc, coord)
	if scoped != modules {
		t.Errorf("scoped reads = %d, want %d (one per module)", scoped, modules)
	}
	if corpus != 0 {
		t.Errorf("%d whole-ledger reads inside a per-module loop", corpus)
	}
}

// TestInterfaceRecordMiss_CorpusSurveyStillHappensWhenItIsTheQuestion holds the
// other half. The zero-result notice states how many records were considered
// and names one of them; that IS a whole-store question, and scoping the
// coordinate read must not have taken it away.
func TestInterfaceRecordMiss_CorpusSurveyStillHappensWhenItIsTheQuestion(t *testing.T) {
	uc, _ := ledgerHoldingManyModules(t)
	absent, err := coordinate.NewModuleCoordinate("example.com/never", "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	mErr := interfaceRecordMiss(context.Background(), uc, absent, false, &stderr)
	if mErr == nil {
		t.Fatal("a miss must not be reported as success")
	}
	msg := mErr.Error()
	if strings.Contains(msg, "superseded") {
		t.Errorf("a coordinate the store has never held is not superseded:\n%s", msg)
	}
	if !strings.Contains(msg, "3 ") {
		t.Errorf("the notice no longer states the corpus it searched:\n%s", msg)
	}

	scoped, corpus, _ := readScope(uc, absent)
	if scoped != 1 {
		t.Errorf("the coordinate question was asked %d time(s), want 1", scoped)
	}
	if corpus != 1 {
		t.Errorf("the corpus survey ran %d time(s), want 1 — the notice counts the whole store", corpus)
	}
}

// TestSupersededPipelines_AreNotAskedFromAWholeStoreListing is the class guard.
//
// The behavioural tests above reach the surfaces a unit test can drive. This one
// covers the rest — symbol-context among them — structurally: the per-coordinate
// predicate may only be reached through the helper that scopes the read. Passing
// it a listing obtained some other way is the defect, and a hand-kept list of
// known call sites is what let it recur on a third surface.
func TestSupersededPipelines_AreNotAskedFromAWholeStoreListing(t *testing.T) {
	const (
		predicate = "supersededInterfacePipelines"
		scoped    = "supersededInterfaceRecord"
	)
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == scoped {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				ident, isIdent := call.Fun.(*ast.Ident)
				if !isIdent || ident.Name != predicate {
					return true
				}
				t.Errorf("%s calls %s directly, so it decides for itself what the store was asked; "+
					"call %s, which scopes the read to the coordinate (%s)",
					fn.Name.Name, predicate, scoped, fset.Position(call.Pos()))
				return true
			})
		}
	}
}
