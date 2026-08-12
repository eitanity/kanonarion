package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
)

func TestEventType_Known(t *testing.T) {
	known := []audit.EventType{
		audit.EventFactRecordWritten,
		audit.EventFactRecordWriteRefused,
		audit.EventFactRecordDowngraded,
		audit.EventReplaceDirectiveObserved,
		audit.EventExcludeDirectiveObserved,
		audit.EventGoDebugSettingObserved,
		audit.EventVendorTreeGenerated,
		audit.EventFIPSAssessment,
		audit.EventVerificationFailed,
		audit.EventRecordReadVerified,
		audit.EventVulnScanCompleted,
		audit.EventVulnFindingObserved,
		audit.EventLicenseExtracted,
		audit.EventWalkCompleted,
		audit.EventCallGraphExtracted,
		audit.EventInterfaceExtracted,
		audit.EventExamplesExtracted,
		audit.EventExtractionRunCompleted,
		audit.EventStdlibCustodyRecorded,
		audit.EventSBOMGenerated,
		audit.EventSBOMServed,
		audit.EventAdvisorySnapshotRecorded,
		audit.EventVulnScanServed,
	}
	for _, et := range known {
		if !et.Known() {
			t.Errorf("EventType %q should be known", et)
		}
	}
	unknown := []audit.EventType{"", "made_up_type", "FACT_RECORD_WRITTEN"}
	for _, et := range unknown {
		if et.Known() {
			t.Errorf("EventType %q should not be known", et)
		}
	}
}

func TestEvent_Validate_KnownType(t *testing.T) {
	e := audit.Event{Type: audit.EventFactRecordWritten, Payload: map[string]any{"k": "v"}}
	if err := e.Validate(); err != nil {
		t.Errorf("known event type should validate cleanly, got: %v", err)
	}
}

func TestEvent_Validate_UnknownType(t *testing.T) {
	e := audit.Event{Type: "nonexistent_type"}
	if err := e.Validate(); err == nil {
		t.Error("unknown event type must fail Validate")
	}
}

func TestEvent_Validate_EmptyType(t *testing.T) {
	e := audit.Event{Type: ""}
	if err := e.Validate(); err == nil {
		t.Error("empty event type must fail Validate")
	}
}

// TestKnownEventTypes_CoversEveryDeclaredConstant reads this package's own
// source and asserts that every declared EventType constant is in the
// enumeration KnownEventTypes returns.
//
// The enumeration is what the ledger reader offers a caller who mistyped
// --event-type, and what it validates their value against. A constant that was
// declared and never registered would be emittable-looking in code, refused by
// Validate at the emit site, and absent from the list a reader is shown — three
// disagreeing answers about one vocabulary. Reading the constants rather than
// re-listing them is what keeps this test from going stale the same way.
func TestKnownEventTypes_CoversEveryDeclaredConstant(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing the audit package source: %v", err)
	}
	fset := token.NewFileSet()
	declared := map[string]string{} // constant name -> value
	for _, source := range sources {
		file, perr := parser.ParseFile(fset, source, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", source, perr)
		}
		if file.Name.Name != "audit" {
			continue
		}
		for _, decl := range file.Decls {
			gen, isGen := decl.(*ast.GenDecl)
			if !isGen || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, isVS := spec.(*ast.ValueSpec)
				if !isVS {
					continue
				}
				id, isIdent := vs.Type.(*ast.Ident)
				if !isIdent || id.Name != "EventType" || len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, name := range vs.Names {
					lit, isLit := vs.Values[i].(*ast.BasicLit)
					if !isLit || lit.Kind != token.STRING {
						continue
					}
					value, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						t.Fatalf("unquoting %s: %v", name.Name, uerr)
					}
					declared[name.Name] = value
				}
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no EventType constants in the package source; the reader is broken, not the vocabulary")
	}

	enumerated := map[audit.EventType]struct{}{}
	for _, et := range audit.KnownEventTypes() {
		enumerated[et] = struct{}{}
	}
	for name, value := range declared {
		if _, found := enumerated[audit.EventType(value)]; !found {
			t.Errorf("EventType constant %s (%q) is declared but missing from KnownEventTypes()", name, value)
		}
	}
	if len(enumerated) != len(declared) {
		t.Errorf("KnownEventTypes() returned %d type(s), the package declares %d", len(enumerated), len(declared))
	}
}

// TestKnownEventTypes_IsSorted pins the order, because it is printed to a
// reader as the accepted set for --event-type.
func TestKnownEventTypes_IsSorted(t *testing.T) {
	types := audit.KnownEventTypes()
	for i := 1; i < len(types); i++ {
		if types[i-1] >= types[i] {
			t.Fatalf("KnownEventTypes() is not sorted: %q before %q", types[i-1], types[i])
		}
	}
}
