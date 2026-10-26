package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	exampleports "code.eitanity.com/kanonarion/internal/example/ports"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licenceports "code.eitanity.com/kanonarion/internal/license/ports"
)

// Every record store's disagreement sentinel reaches context as the conflict
// status carrying the statement; any other read error stays read_error. The
// capability section follows the call graph.
func TestContextSections_ARecordConflictIsConflict(t *testing.T) {
	ctx := t.Context()
	cases := []struct {
		name     string
		sentinel error
		status   func(err error) (string, string)
	}{
		{"licence", licenceports.ErrLicenceConflict, func(err error) (string, string) {
			uc := testfakes.NewFakeQueryLicense()
			uc.Err = err
			l := buildLicense(ctx, jsonDocDep, uc, nil)
			return l.Status, l.Error
		}},
		{"interface", ifaceports.ErrInterfaceConflict, func(err error) (string, string) {
			uc := testfakes.NewFakeQueryInterface()
			uc.Err = err
			i := buildInterface(ctx, jsonDocDep, uc, false, "")
			return i.Status, i.Error
		}},
		{"call graph", cgports.ErrCallGraphConflict, func(err error) (string, string) {
			uc := testfakes.NewFakeQueryCallGraph()
			uc.Err = err
			cg, capability := buildCallGraph(ctx, jsonDocDep, uc, false, "")
			if capability.Status != cg.Status {
				return "capability " + capability.Status, cg.Error
			}
			return cg.Status, cg.Error
		}},
		{"examples", exampleports.ErrExampleConflict, func(err error) (string, string) {
			uc := testfakes.NewFakeQueryExamples()
			uc.Err = err
			e := buildExamples(ctx, jsonDocDep, uc, false, "")
			return e.Status, e.Error
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conflict := fmt.Errorf("reading the record: %w: two records disagree", tc.sentinel)
			if status, msg := tc.status(conflict); status != sectionStatusConflict || !strings.Contains(msg, "two records disagree") {
				t.Errorf("conflict: status %q, error %q; want %q with the statement", status, msg, sectionStatusConflict)
			}
			if status, _ := tc.status(errors.New("database is locked")); status != sectionStatusReadError {
				t.Errorf("other error: status %q, want %q", status, sectionStatusReadError)
			}
		})
	}
}

// Both text renderings state each section's dispute, not a read failure.
func TestPrintContext_ConflictSections(t *testing.T) {
	out := contextOutput{
		Module:          contextModuleInfo{Path: "example.com/app", Version: "v1.0.0"},
		License:         contextLicense{Status: sectionStatusConflict, Error: "conflicting license records for L"},
		Interface:       contextInterface{Status: sectionStatusConflict, Error: "conflicting interface records for I"},
		CallGraph:       contextCallGraph{Status: sectionStatusConflict, Error: "conflicting call graph records for G"},
		Capability:      contextCapability{Status: sectionStatusConflict},
		Examples:        contextExamples{Status: sectionStatusConflict, Error: "conflicting example records for E"},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusConflict, Error: "conflicting vulnerability records for V"},
	}
	for name, render := range map[string]func(contextOutput, *strings.Builder) error{
		"summary": func(o contextOutput, b *strings.Builder) error { return printContextSummary(o, b) },
		"full":    func(o contextOutput, b *strings.Builder) error { return printContextFull(o, b) },
	} {
		var buf strings.Builder
		if err := render(out, &buf); err != nil {
			t.Fatal(err)
		}
		got := buf.String()
		for _, want := range []string{"(conflicting license records for L)", "(conflicting interface records for I)",
			"(conflicting call graph records for G)", "(conflicting example records for E)",
			"(conflicting vulnerability records for V)", "(conflict — see Call Graph)"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %q:\n%s", name, want, got)
			}
		}
		if strings.Contains(got, "failed:") {
			t.Errorf("%s: a dispute is rendered as a failed read:\n%s", name, got)
		}
	}
}
