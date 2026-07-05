package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// TestSymbolRef_SnakeCaseJSON guards symbol-find serialises
// ifaceports.SymbolRef directly, so the struct's JSON keys must be
// snake_case (matching walk-list/extract/inspect), never PascalCase.
func TestSymbolRef_SnakeCaseJSON(t *testing.T) {
	raw, err := json.Marshal(ifaceports.SymbolRef{
		ModulePath:      "example.com/mod",
		ModuleVersion:   "v1.0.0",
		PipelineVersion: "v1",
		PackagePath:     "example.com/mod/pkg",
		SymbolKind:      "method",
		SymbolName:      "Do",
		ParentType:      "Client",
		Signature:       "func (c *Client) Do() error",
	})
	if err != nil {
		t.Fatalf("marshal SymbolRef: %v", err)
	}
	got := string(raw)
	for _, pascal := range []string{
		`"ModulePath"`, `"ModuleVersion"`, `"SymbolKind"`,
		`"SymbolName"`, `"ParentType"`, `"Signature"`,
	} {
		if strings.Contains(got, pascal) {
			t.Errorf("PascalCase key %s in %s", pascal, got)
		}
	}
	for _, snake := range []string{
		`"module_path"`, `"module_version"`, `"symbol_kind"`,
		`"symbol_name"`, `"parent_type"`, `"signature"`,
	} {
		if !strings.Contains(got, snake) {
			t.Errorf("missing snake_case key %s in %s", snake, got)
		}
	}
}

// TestListCommands_HonourJSON guards every *-list command must emit
// parseable JSON when --json is set, not plain tabular text.
func TestListCommands_HonourJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "callgraph-list", args: []string{"callgraph-list"}},
		{name: "examples-list", args: []string{"examples-list"}},
		{name: "license-list", args: []string{"license-list"}},
		{name: "vuln-scan-list", args: []string{"vuln-scan-list"}},
		{name: "interface-list", args: []string{"interface-list"}},
		{name: "walk-list", args: []string{"walk-list"}},
		{name: "sbom-list", args: []string{"sbom-list"}},
		{name: "extract list", args: []string{"extract", "list"}},
		{name: "directives list", args: []string{"directives", "list", "--project", "example.com/mod"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, tc.args...), "--json", "--store-root", t.TempDir())
			if err := Run(args, &stdout, &stderr); err != nil {
				t.Fatalf("%s --json: unexpected error: %v (stderr=%q)", tc.name, err, stderr.String())
			}
			out := strings.TrimSpace(stdout.String())
			var v any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Errorf("%s --json did not emit JSON: %q", tc.name, out)
			}
		})
	}
}

// TestQueryCommands_EmptyIsArrayNotNull guards list-returning query
// commands must emit "[]" (not "null") under --json when there are no matches.
func TestQueryCommands_EmptyIsArrayNotNull(t *testing.T) {
	// NOTE: callers/callees over an *empty* store are no longer a "[] not
	// null" case — an unresolved symbol is a non-success diagnostic
	// not an empty array. The "[] not null"
	// invariant for callers/callees now only applies to the genuine-zero
	// case (module analysed, no edges); covered at unit level by
	// TestRunCallers_GenuineZeroJSON_IsEmptyArrayNotNull.
	for _, args := range [][]string{
		{"vuln-by-id", "GO-9999-0000"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			full := append(append([]string{}, args...), "--json", "--store-root", t.TempDir())
			if err := Run(full, &stdout, &stderr); err != nil {
				t.Fatalf("%v: unexpected error: %v", args, err)
			}
			out := strings.TrimSpace(stdout.String())
			if out == "null" {
				t.Errorf("%v emitted JSON null instead of []", args)
			}
			var v any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Errorf("%v: not valid JSON: %q", args, out)
			}
		})
	}
}

// TestMissingRequiredArg_NonZeroExit guards commands requiring a
// positional argument must return a non-nil error (non-zero exit) when it is
// missing, instead of printing help and exiting 0.
func TestMissingRequiredArg_NonZeroExit(t *testing.T) {
	for _, cmd := range []string{
		"symbol-find", "symbol-context", "callers", "callees",
		"interface-show", "callgraph-show", "examples-show",
		"dependents", "walk-show",
	} {
		t.Run(cmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run([]string{cmd, "--store-root", t.TempDir()}, &stdout, &stderr)
			if err == nil {
				t.Errorf("%s with no argument returned nil error (exit 0)", cmd)
			}
			if strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("%s dumped cobra usage to stdout", cmd)
			}
		})
	}
}
