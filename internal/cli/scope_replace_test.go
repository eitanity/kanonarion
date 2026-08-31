package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The defect this file guards: a go.mod `replace` routes the build to a
// different module, and the shared scope resolution reported only the require
// entry. Every answer keyed on that coordinate was then an answer about a module
// the build never compiles — `context` reported a fetched, licensed, scanned
// dependency as not fetched and absent from its own walk, and `latest` offered
// an upgrade to a module the replace directive keeps out of the build.
//
// The three input shapes are exercised together against both surfaces, because
// the fault was never one command's: it was one template, four renderings.

// replacedScopeModules is the input class: an ordinary module, a module replaced
// by another module, and a module replaced by a local directory.
func replacedScopeModules(t *testing.T) []scopeModule {
	t.Helper()
	mods, err := parseGoListModuleRecords([]byte(strings.Join([]string{
		"example.com/plain@v1.0.0\t\t",
		"example.com/fork@v2.0.0\texample.com/upstream@v1.5.0\t",
		"\texample.com/local@v1.0.0\t../localfork",
	}, "\n")))
	if err != nil {
		t.Fatalf("parseGoListModuleRecords: %v", err)
	}
	if len(mods) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(mods))
	}
	return mods
}

// TestScopeModule_CarriesBothCoordinates pins the two projections apart. The
// module an answer is ABOUT is what compiles; the module the build list is keyed
// on is the require entry. Collapsing them either way is the whole defect: one
// direction answers about code that does not ship, the other addresses the
// toolchain with a path it does not know.
func TestScopeModule_CarriesBothCoordinates(t *testing.T) {
	mods := replacedScopeModules(t)
	byRequired := map[string]scopeModule{}
	for _, m := range mods {
		byRequired[m.required()] = m
	}

	cases := []struct {
		required  string
		answering string
		replaced  bool
		localPath string
	}{
		{"example.com/plain@v1.0.0", "example.com/plain@v1.0.0", false, ""},
		{"example.com/upstream@v1.5.0", "example.com/fork@v2.0.0", true, ""},
		{"example.com/local@v1.0.0", "example.com/local@v1.0.0", true, "../localfork"},
	}
	for _, tc := range cases {
		m, ok := byRequired[tc.required]
		if !ok {
			t.Fatalf("no resolved module required at %s", tc.required)
		}
		if got := m.answering().String(); got != tc.answering {
			t.Errorf("%s: answers about %s, want %s", tc.required, got, tc.answering)
		}
		if m.replaced() != tc.replaced {
			t.Errorf("%s: replaced = %t, want %t", tc.required, m.replaced(), tc.replaced)
		}
		if m.localPath != tc.localPath {
			t.Errorf("%s: localPath = %q, want %q", tc.required, m.localPath, tc.localPath)
		}
	}
}

// TestRequiredCoords_KeysOnTheBuildList guards the projection every unchanged
// caller takes — the walk's scope filter, the drift check, the fetch loop and
// the batched latest resolution.
//
// It is the require entry and never the replacement, because `go list -m`
// resolves paths against the build list, where a replaced module is listed under
// the path it was required at. Measured on the road-test subject: `go list -m -u
// -json github.com/cortezaproject/gval` answers "module
// github.com/cortezaproject/gval: not a known dependency" and fails, and the
// batched call answers for the WHOLE scope, so handing it one replacement path
// loses every module's answer.
func TestRequiredCoords_KeysOnTheBuildList(t *testing.T) {
	got := requiredCoords(replacedScopeModules(t))
	// The parser orders on the record, whose first field is what compiles — a
	// local-path replace has none and sorts first. The projection preserves that
	// order and changes only which half of each pair it names; the scope
	// resolution re-orders on the require entry afterwards, which is the order
	// every caller of it has always read.
	want := []string{
		"example.com/local@v1.0.0",
		"example.com/upstream@v1.5.0",
		"example.com/plain@v1.0.0",
	}
	if len(got) != len(want) {
		t.Fatalf("requiredCoords = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("requiredCoords[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

// TestResolveScopeModules_LocalPathReplace resolves a real tree through the Go
// toolchain: `replace X => ../dir` has no version at all, and the record shape
// that carries it is the one no published-module fixture can produce.
//
// It also pins the projection the unchanged callers read: the require entry, the
// same string that resolution produced before the pair existed.
func TestResolveScopeModules_LocalPathReplace(t *testing.T) {
	root := t.TempDir()
	dep := filepath.Join(root, "dep")
	main := filepath.Join(root, "main")
	for _, d := range []string{dep, main} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, content string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dep, "go.mod"), "module example.com/dep\n\ngo 1.24\n")
	write(filepath.Join(dep, "dep.go"), "package dep\n\nfunc D() int { return 1 }\n")
	gomod := filepath.Join(main, "go.mod")
	write(gomod, "module example.com/main\n\ngo 1.24\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ../dep\n")
	write(filepath.Join(main, "main.go"), "package main\n\nimport \"example.com/dep\"\n\nfunc main() { _ = dep.D() }\n")

	mods, _, err := resolveScopeModules(gomod, scopeCode, false)
	if err != nil {
		t.Fatalf("resolveScopeModules: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 module, got %d: %v", len(mods), requiredCoords(mods))
	}
	m := mods[0]
	if !m.coord.IsZero() {
		t.Errorf("a local-path replace has no replacement coordinate, got %s", m.coord)
	}
	if got := m.required(); got != "example.com/dep@v1.0.0" {
		t.Errorf("require entry = %s, want example.com/dep@v1.0.0", got)
	}
	if m.localPath != "../dep" {
		t.Errorf("localPath = %q, want ../dep", m.localPath)
	}
	if r := replaceOf(m); r == nil || r.LocalPath != "../dep" {
		t.Errorf("the directive is not rendered for a local-path replace: %+v", r)
	}
}

// TestLatestTable_ReplacedRowNamesBothCoordinates guards the text rendering of
// the three shapes.
//
// The replaced row must name the module it is about, the require entry it was
// routed away from, and where a bump has to be made. Naming only the version is
// what let a row read as "upgrade available" for a module the replace directive
// keeps out of the build entirely.
func TestLatestTable_ReplacedRowNamesBothCoordinates(t *testing.T) {
	yes, no := true, false
	age := 12
	rows := []latestResult{
		{Module: "example.com/plain", Pinned: "v1.0.0", Latest: "v1.0.0", IsLatest: &yes, PinAheadOfLatest: &no},
		{
			Module: "example.com/fork", Pinned: "v2.0.0", Latest: "v2.1.0",
			IsLatest: &no, PinAheadOfLatest: &no, LatestReleaseAgeDays: &age,
			Replace: &moduleReplace{RequireModule: "example.com/upstream", RequireVersion: "v1.5.0"},
		},
		{
			Module: "example.com/local", Pinned: "v1.0.0",
			StalenessUnmeasured: stalenessLocalReplace,
			Replace:             &moduleReplace{RequireModule: "example.com/local", RequireVersion: "v1.0.0", LocalPath: "../localfork"},
		},
	}
	var buf strings.Builder
	if err := printLatestTable(&buf, rows); err != nil {
		t.Fatalf("printLatestTable: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"example.com/fork@v2.0.0",
		"replaces example.com/upstream@v1.5.0",
		"bumping that require entry cannot take effect while it stands",
		"latest: v2.1.0 (12 days ago)",
		"compiled from ../localfork (go.mod replace)",
		"unmeasured (local replace)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("latest table does not state %q:\n%s", want, out)
		}
	}
	// An unreplaced row is untouched: no clause, no directive, no change of any
	// kind for the projects that have no replace at all.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "example.com/plain@") && strings.Contains(line, "replace") {
			t.Errorf("an unreplaced row carries a replace clause: %q", line)
		}
	}
}

// TestLatestJSON_ReplacedRowCarriesTheRequireEntry guards the machine rendering
// of the same fact. A JSON reader and a text reader learn it or neither does.
func TestLatestJSON_ReplacedRowCarriesTheRequireEntry(t *testing.T) {
	raw, err := json.Marshal(latestResult{
		Module: "example.com/fork", Pinned: "v2.0.0",
		Replace: &moduleReplace{RequireModule: "example.com/upstream", RequireVersion: "v1.5.0"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rep, ok := got["replace"].(map[string]any)
	if !ok {
		t.Fatalf("no replace object in %s", raw)
	}
	if rep["require_module"] != "example.com/upstream" || rep["require_version"] != "v1.5.0" {
		t.Errorf("the require entry is not carried: %v", rep)
	}

	// An unreplaced row emits no key at all, so a consumer cannot read an absent
	// directive as an empty one.
	raw, err = json.Marshal(latestResult{Module: "example.com/plain", Pinned: "v1.0.0"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "replace") {
		t.Errorf("an unreplaced row emits a replace key: %s", raw)
	}
}

// TestContextRenderings_StateTheReplace guards that both of context's text forms
// and its JSON say which module the sections below them describe.
func TestContextRenderings_StateTheReplace(t *testing.T) {
	out := contextOutput{Module: contextModuleInfo{
		Path:    "example.com/fork",
		Version: "v2.0.0",
		Replace: &moduleReplace{RequireModule: "example.com/upstream", RequireVersion: "v1.5.0"},
	}}

	var summary, full strings.Builder
	if err := printContextSummary(out, &summary); err != nil {
		t.Fatalf("printContextSummary: %v", err)
	}
	if err := printContextFull(out, &full); err != nil {
		t.Fatalf("printContextFull: %v", err)
	}
	const want = "replaces example.com/upstream@v1.5.0 under a go.mod replace directive"
	for name, got := range map[string]string{"summary": summary.String(), "full": full.String()} {
		if !strings.Contains(got, "example.com/fork@v2.0.0") {
			t.Errorf("%s does not name the module that compiles:\n%s", name, got)
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s does not state the replace directive:\n%s", name, got)
		}
	}

	raw, err := json.Marshal(out.Module)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"require_module":"example.com/upstream"`) {
		t.Errorf("the JSON module does not carry the require entry: %s", raw)
	}

	// A coordinate named on the command line routes through no manifest, so it
	// carries no directive and its document is unchanged.
	raw, err = json.Marshal(contextModuleInfo{Path: "example.com/plain", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"path":"example.com/plain","version":"v1.0.0"}` {
		t.Errorf("an unreplaced module's JSON changed shape: %s", raw)
	}
}

// TestLocalReplaceStalenessLabel guards that the new unmeasured reason renders
// as words rather than reaching a reader as the machine token, and that it is
// not one of the answers: a directory has no published version, so "current" is
// exactly what must never be printed for it.
func TestLocalReplaceStalenessLabel(t *testing.T) {
	got := stalenessUnmeasuredLabel(stalenessLocalReplace)
	if got != "unmeasured (local replace)" {
		t.Errorf("stalenessUnmeasuredLabel(%q) = %q", stalenessLocalReplace, got)
	}
}
