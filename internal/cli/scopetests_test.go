package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// goModWithToolDirective writes a go.mod carrying a tool directive, so the tool
// scope resolves to a real `go list` invocation without the toolchain being
// asked to run it.
func goModWithToolDirective(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	const src = "module example.com/myapp\n\ngo 1.24\n\ntool example.com/mod/cmd/gen\n"
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestScopeGoListArgs_EachScopeResolvesItsOwnRootSet pins the axis each scope
// resolves over, and pins it per scope because the right default differs.
//
// `-test` means "include the test dependencies OF THE ROOT SET". On the code
// scope that root set is this project, so -test adds our own test
// infrastructure, which we compile and run: it belongs in the answer, and
// --exclude-tests is how a caller asks for the production-only subset. On the
// tool scope the root set is the tool binaries, so -test would add the test
// frameworks the tool AUTHORS use — nothing we run links them — and the scope
// therefore never passes it. Both are answers to their own question; the defect
// was that neither said which question it had answered.
func TestScopeGoListArgs_EachScopeResolvesItsOwnRootSet(t *testing.T) {
	toolMod := goModWithToolDirective(t)
	plainMod := emptyToolScopeGoMod(t)

	cases := []struct {
		name         string
		gomod        string
		scope        depScope
		excludeTests bool
		wantTest     bool
	}{
		{"code, default", plainMod, scopeCode, false, true},
		{"code, --exclude-tests", plainMod, scopeCode, true, false},
		{"tool, default", toolMod, scopeTool, false, false},
		{"tool, --exclude-tests", toolMod, scopeTool, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := testScopeFor(tc.scope, tc.excludeTests)
			args, err := scopeGoListArgs(tc.gomod, tc.scope, ts)
			if err != nil {
				t.Fatalf("scopeGoListArgs: %v", err)
			}
			if got := slices.Contains(args, "-test"); got != tc.wantTest {
				t.Errorf("go list args %v: -test present = %t, want %t", args, got, tc.wantTest)
			}
		})
	}
}

// TestToolScope_SamePopulationWithAndWithoutTheFlag guards that --exclude-tests
// changes nothing on the tool scope, and that the answer says why rather than
// crediting the flag with an exclusion the scope had already made.
//
// This replaces the assertion that --tool and --tool --exclude-tests must
// differ. They must not: the flag asks for the production-only subset, and on
// this scope that is the whole set. What must never happen is the answer
// reporting a narrowing the flag did not cause.
func TestToolScope_SamePopulationWithAndWithoutTheFlag(t *testing.T) {
	toolMod := goModWithToolDirective(t)

	plain, err := scopeGoListArgs(toolMod, scopeTool, testScopeFor(scopeTool, false))
	if err != nil {
		t.Fatalf("scopeGoListArgs: %v", err)
	}
	narrowed, err := scopeGoListArgs(toolMod, scopeTool, testScopeFor(scopeTool, true))
	if err != nil {
		t.Fatalf("scopeGoListArgs: %v", err)
	}
	if !slices.Equal(plain, narrowed) {
		t.Errorf("--exclude-tests changed the tool scope's resolution:\n  without: %v\n  with:    %v", plain, narrowed)
	}

	stated := newScopeResolution(scopeTool, true).statement()
	if !strings.Contains(stated, "excluded by the scope itself") {
		t.Errorf("the tool scope does not say its exclusion is its own: %q", stated)
	}
	if !strings.Contains(stated, "narrowed nothing") {
		t.Errorf("--exclude-tests on the tool scope does not say it changed nothing: %q", stated)
	}
	if strings.Contains(stated, "was given)") {
		t.Errorf("the tool scope credits --exclude-tests with an exclusion it did not cause: %q", stated)
	}
}

// TestScopeGoListArgs_CompleteScopeAsksNoTestQuestion guards that the complete
// scope keeps resolving through the build list, which carries no test partition:
// slipping -test in there would be a claim the module graph cannot make.
func TestScopeGoListArgs_CompleteScopeAsksNoTestQuestion(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	args, err := scopeGoListArgs(p, scopeComplete, testScopeFor(scopeComplete, false))
	if err != nil {
		t.Fatalf("scopeGoListArgs: %v", err)
	}
	if slices.Contains(args, "-test") || slices.Contains(args, "-deps") {
		t.Errorf("complete scope resolved through a package closure: %v", args)
	}
	if !slices.Contains(args, "all") {
		t.Errorf("complete scope no longer resolves the build list: %v", args)
	}
}

// TestTestScopeFor_CompleteScopeHasNoAxis guards that --project reports the axis
// as unavailable whether or not the flag was given. Reporting "excluded" there
// would publish a narrowing that was never applied, and reporting "included"
// would name a decision the build list never offered.
func TestTestScopeFor_CompleteScopeHasNoAxis(t *testing.T) {
	for _, excludeTests := range []bool{false, true} {
		if got := testScopeFor(scopeComplete, excludeTests); got != testScopeUnavailable {
			t.Errorf("testScopeFor(complete, %t) = %q, want %q", excludeTests, got, testScopeUnavailable)
		}
	}
}

// TestDepScopeNotice_StatesTheAxisOnEveryScope guards that the statement is
// present whether or not anything was excluded, and that the three axes read
// differently: a reader must be able to tell 20-with-tests from 18-without.
func TestDepScopeNotice_StatesTheAxisOnEveryScope(t *testing.T) {
	cases := []struct {
		name         string
		scope        depScope
		excludeTests bool
		offerFlag    bool
		want         []string
		absent       []string
	}{
		{"code default", scopeCode, false, true,
			[]string{"code scope", "20 module(s)", "test-scope dependencies included", "narrow with --exclude-tests"}, nil},
		{"code narrowed", scopeCode, true, true,
			[]string{"code scope", "test-scope dependencies excluded", "--exclude-tests was given"}, []string{"narrow with"}},
		{"tool default", scopeTool, false, true,
			[]string{"tool scope", "excluded by the scope itself", "never reach their authors' test packages"},
			[]string{"narrow with", "was given"}},
		{"tool with the flag", scopeTool, true, true,
			[]string{"tool scope", "excluded by the scope itself", "narrowed nothing"},
			[]string{"narrow with", "was given"}},
		{"complete", scopeComplete, false, false,
			[]string{"complete scope", "no test axis"}, []string{"included", "excluded"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := newScopeResolution(tc.scope, tc.excludeTests)
			if err := writeDepScopeNotice(&buf, r, 20, tc.offerFlag); err != nil {
				t.Fatalf("writeDepScopeNotice: %v", err)
			}
			got := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("notice %q does not state %q", got, want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("notice %q states %q, which does not apply", got, absent)
				}
			}
		})
	}
}

// TestContextGoMod_StatesItsTestScope guards the whole point of the change on the
// surface the defect was found on: an answer must name the axis it was computed
// over, and must do it on both channels. The empty scope is used so no store is
// needed — the statement is written before any module is looked at, which is
// itself the property: which set came back empty is the answer there.
func TestContextGoMod_StatesItsTestScope(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	var stdout, stderr bytes.Buffer
	if err := runContextGoMod(context.Background(), contextFlags{gomodPath: p}, scopeTool, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stderr.String(), "excluded by the scope itself") {
		t.Errorf("context --gomod --tool did not state its test scope: %q", stderr.String())
	}
}

// TestContextGoMod_ExcludeTestsChangesTheStatedScope guards the other half on the
// scope the flag acts on: it must move the stated axis, not only the population,
// or a narrowed answer is indistinguishable from a full one.
func TestContextGoMod_ExcludeTestsChangesTheStatedScope(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	plain := newScopeResolution(scopeCode, false).statement()
	narrowed := newScopeResolution(scopeCode, true).statement()
	if plain == narrowed {
		t.Fatalf("--exclude-tests does not change what the code scope states: %q", plain)
	}

	var stdout, stderr bytes.Buffer
	f := contextFlags{gomodPath: p, excludeTests: true}
	if err := runContextGoMod(context.Background(), f, scopeTool, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The tool scope accepts the flag and must say it narrowed nothing, rather
	// than reporting a narrowing the scope had already made.
	if !strings.Contains(stderr.String(), "narrowed nothing") {
		t.Errorf("--exclude-tests on the tool scope did not say it changed nothing: %q", stderr.String())
	}
}

// TestContextGoMod_CompleteScopeRefusesTheFlag guards that an unavailable axis is
// refused rather than accepted and dropped. Accepting it would emit
// byte-identical output and report a narrowing that never happened.
func TestContextGoMod_CompleteScopeRefusesTheFlag(t *testing.T) {
	p := emptyToolScopeGoMod(t)
	var stdout, stderr bytes.Buffer
	f := contextFlags{gomodPath: p, excludeTests: true}
	err := runContextGoMod(context.Background(), f, scopeComplete, &stdout, &stderr)
	if err == nil {
		t.Fatal("context --gomod --project --exclude-tests was accepted")
	}
	if !strings.Contains(err.Error(), "no test partition") {
		t.Errorf("refusal does not name why the axis is unavailable: %v", err)
	}
}

// TestContextGoMod_JSONCarriesTheAxis guards the machine-readable half. The
// go.mod form emits a sequence of documents with no envelope around it, so the
// field rides on every document: one lifted out of the array or the stream must
// still say which set it came from.
func TestContextGoMod_JSONCarriesTheAxis(t *testing.T) {
	for _, tc := range []struct {
		scope depScope
		ts    testScope
	}{
		{scopeCode, testScopeIncluded},
		{scopeTool, testScopeExcluded},
		{scopeComplete, testScopeUnavailable},
	} {
		out := contextOutput{DependencyScope: &scopeJSON{Scope: string(tc.scope), TestScope: string(tc.ts)}}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded struct {
			DependencyScope *scopeJSON `json:"dependency_scope"`
		}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.DependencyScope == nil {
			t.Fatalf("%s: dependency_scope absent from the document", tc.scope)
		}
		if decoded.DependencyScope.TestScope != string(tc.ts) {
			t.Errorf("%s: test_scope = %q, want %q", tc.scope, decoded.DependencyScope.TestScope, tc.ts)
		}
	}
}

// TestRecordingCommandsRefuseTheFlagByName guards that the commands whose answer
// is a stored walk refuse --exclude-tests and say why. `walks.scope` is inside
// the walk identity hash and names no test axis, so a narrowed walk would be
// stored as indistinguishable from a full one; a silent accept here is the
// falsifying case.
func TestRecordingCommandsRefuseTheFlagByName(t *testing.T) {
	for _, path := range []string{"walk --gomod", "audit", "inspect --gomod", "vuln-scan --gomod/--tool/--project", "fetch --gomod"} {
		err := refuseTestScopeOnRecordingCommand(path, true)
		if err == nil {
			t.Fatalf("%s accepted --exclude-tests", path)
		}
		for _, want := range []string{path, "exclude-tests", "test axis", "latest --gomod"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s refusal %q does not name %q", path, err, want)
			}
		}
	}
	if err := refuseTestScopeOnRecordingCommand("walk --gomod", false); err != nil {
		t.Errorf("refused a run that did not pass the flag: %v", err)
	}
}
