package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	factsqlite "code.eitanity.com/kanonarion/internal/adapters/factstore/sqlite"
	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	directivedomain "code.eitanity.com/kanonarion/internal/directive/domain"
)

// configEvent is one config_* line of a store's ledger.
type configEvent struct {
	Type    string         `json:"event_type"`
	Payload map[string]any `json:"payload"`
}

// configEvents reads every config_* event the store's ledger holds, in order.
func configEvents(t *testing.T, root string) []configEvent {
	t.Helper()
	f, err := os.Open(factsqlite.AuditLogPath(root))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("opening ledger: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []configEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		var e configEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("ledger line does not parse: %v", err)
		}
		if strings.HasPrefix(e.Type, "config_") {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading ledger: %v", err)
	}
	return out
}

// directivesProject is a go.mod whose one directive resolves to notify under
// the default policy, so `directives` exits 0.
func directivesProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	gomod := "module example.com/app\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep v1.0.0 => example.com/dep v1.0.1\n"
	if err := os.WriteFile(path, []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// configShowHash is the hash `config show --json` reports for the store.
func configShowHash(t *testing.T, root string) string {
	t.Helper()
	out, stderr, code := runCLI(t, "config", "show", "--json", "--store-root", root)
	if code != 0 {
		t.Fatalf("config show exited %d: %s", code, stderr)
	}
	var doc struct {
		ConfigHash string `json:"config_hash"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("config show --json: %v", err)
	}
	if !strings.HasPrefix(doc.ConfigHash, "sha256:") {
		t.Fatalf("config show names no hash: %q", doc.ConfigHash)
	}
	return doc.ConfigHash
}

func runDirectivesJSON(t *testing.T, root, gomod string) directivesSection {
	t.Helper()
	out, stderr, code := runCLI(t, "directives", "--gomod", gomod, "--json", "--store-root", root)
	if code != 0 {
		t.Fatalf("directives exited %d: %s", code, stderr)
	}
	var s directivesSection
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("directives --json: %v\n%s", err, out)
	}
	return s
}

// wantConfigEvents fails unless the ledger holds n config events.
func wantConfigEvents(t *testing.T, root string, n int, why string) {
	t.Helper()
	if got := len(configEvents(t, root)); got != n {
		t.Fatalf("%s: %d config events, want %d", why, got, n)
	}
}

func writeHashedConfig(t *testing.T, root, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSet_AppendsConfigChangedOnlyWhenTheHashMoves(t *testing.T) {
	root := t.TempDir()
	before := configShowHash(t, root)

	if _, stderr, code := runCLI(t, "config", "set", "license_policy.categories.permissive", "[MIT]", "--store-root", root); code != 0 {
		t.Fatalf("config set exited %d: %s", code, stderr)
	}
	after := configShowHash(t, root)
	if after == before {
		t.Fatal("a policy change left the hash where it was")
	}
	events := configEvents(t, root)
	if len(events) != 1 || events[0].Type != "config_changed" {
		t.Fatalf("want one config_changed, got %+v", events)
	}
	p := events[0].Payload
	if p["old_hash"] != before || p["new_hash"] != after || p["key"] != "license_policy.categories.permissive" {
		t.Errorf("config_changed payload = %v, want key, old %s and new %s", p, before, after)
	}

	// The same value again, and a display preference, change nothing the hash covers.
	for _, args := range [][]string{
		{"license_policy.categories.permissive", "[MIT, MIT]"},
		{"preferences.log_level", "debug"},
	} {
		if _, stderr, code := runCLI(t, append([]string{"config", "set"}, append(args, "--store-root", root)...)...); code != 0 {
			t.Fatalf("config set %v exited %d: %s", args, code, stderr)
		}
	}
	wantConfigEvents(t, root, 1, "a set that leaves the hash alone appended")

	// A set is the witnessed change, so the next gate finds nothing to report.
	runDirectivesJSON(t, root, directivesProject(t))
	wantConfigEvents(t, root, 1, "a gate after config set appended drift")
}

func TestDrift_IsObservedOnceByTheFirstGateAfterAHandEdit(t *testing.T) {
	root := t.TempDir()
	gomod := directivesProject(t)

	// A store whose ledger names no hash records the one in use, old empty.
	first := runDirectivesJSON(t, root, gomod)
	events := configEvents(t, root)
	if len(events) != 1 || events[0].Type != "config_drift_observed" ||
		events[0].Payload["old_hash"] != "" || events[0].Payload["new_hash"] != first.ConfigHash {
		t.Fatalf("first gate on a fresh store: got %+v", events)
	}

	writeHashedConfig(t, root, "version: \"3\"\ndirective_policy:\n  version_replace: warn\n")

	// A command that evaluates no gate is a read and appends nothing.
	if _, stderr, code := runCLI(t, "walk-list", "--store-root", root); code != 0 && code != ExitNotFound {
		t.Fatalf("walk-list exited %d: %s", code, stderr)
	}
	configShowHash(t, root)
	wantConfigEvents(t, root, 1, "a non-gate command appended a config event")

	out, stderr, code := runCLI(t, "directives", "--gomod", gomod, "--json", "--store-root", root)
	if code != ExitPolicy {
		t.Fatalf("directives under version_replace: warn exited %d, want %d: %s", code, ExitPolicy, stderr)
	}
	var second directivesSection
	if err := json.Unmarshal([]byte(out), &second); err != nil {
		t.Fatal(err)
	}
	events = configEvents(t, root)
	if len(events) != 2 {
		t.Fatalf("want one drift event for the hand edit, got %+v", events)
	}
	drift := events[1]
	if drift.Type != "config_drift_observed" || drift.Payload["old_hash"] != first.ConfigHash ||
		drift.Payload["new_hash"] != second.ConfigHash || drift.Payload["observed_at"] != "first_use" {
		t.Errorf("drift event = %+v, want old %s new %s observed at first use", drift, first.ConfigHash, second.ConfigHash)
	}

	_, _, _ = runCLI(t, "directives", "--gomod", gomod, "--json", "--store-root", root)
	wantConfigEvents(t, root, 2, "a second gate under the same config appended again")
}

func TestDrift_ASameMeaningRewriteMintsNoHash(t *testing.T) {
	root := t.TempDir()
	gomod := directivesProject(t)
	writeHashedConfig(t, root, "version: \"3\"\ndirective_policy:\n  local_path_replace: allow\n  version_replace: warn\n")
	if _, stderr, code := runCLI(t, "directives", "--gomod", gomod, "--json", "--store-root", root); code != ExitPolicy {
		t.Fatalf("directives exited %d: %s", code, stderr)
	}
	want := configShowHash(t, root)

	for name, body := range map[string]string{
		"reordered keys": "directive_policy:\n  version_replace: warn\n  local_path_replace: allow\nversion: \"3\"\n",
		"comments":       "# pinned\nversion: \"3\"\ndirective_policy:\n  local_path_replace: allow # mine\n  version_replace: warn\n",
		"explicit default": "version: \"3\"\ndirective_policy:\n  local_path_replace: allow\n  version_replace: warn\n" +
			"godebug_policy:\n  red: warn\n  amber: notify\n  green: allow\nstaleness:\n  ttl: 60m\n",
	} {
		writeHashedConfig(t, root, body)
		if _, stderr, code := runCLI(t, "directives", "--gomod", gomod, "--json", "--store-root", root); code != ExitPolicy {
			t.Fatalf("%s: directives exited %d: %s", name, code, stderr)
		}
		if got := configShowHash(t, root); got != want {
			t.Errorf("%s: hash %s, want %s", name, got, want)
		}
	}
	wantConfigEvents(t, root, 1, "a same-meaning rewrite appended drift")
}

func TestGatedAnswers_NameTheirHashInTextAndJSON(t *testing.T) {
	root := t.TempDir()
	gomod := directivesProject(t)
	want := configShowHash(t, root)

	if got := runDirectivesJSON(t, root, gomod).ConfigHash; got != want {
		t.Errorf("directives --json config_hash = %q, want %q", got, want)
	}
	for _, cmd := range []string{"directives", "godebug", "fips"} {
		out, stderr, code := runCLI(t, cmd, "--gomod", gomod, "--store-root", root)
		if code != 0 {
			t.Fatalf("%s exited %d: %s", cmd, code, stderr)
		}
		if !strings.Contains(out, "config: "+want+"\n") {
			t.Errorf("%s text does not name the hash %s:\n%s", cmd, want, out)
		}
	}
	for _, cmd := range []string{"godebug", "fips"} {
		out, _, _ := runCLI(t, cmd, "--gomod", gomod, "--json", "--store-root", root)
		var doc struct {
			ConfigHash string `json:"config_hash"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.ConfigHash != want {
			t.Errorf("%s --json config_hash = %q (%v), want %q", cmd, doc.ConfigHash, err, want)
		}
	}
}

// vendoredProject is a vendored module with nothing vendored: the smallest
// tree the reconciler accepts.
func emptyVendoredProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "modules.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "go.mod")
}

func TestVendorOnly_IsNamedAsAnOverrideAndLedgered(t *testing.T) {
	root := t.TempDir()
	gomod := emptyVendoredProject(t)
	want := configShowHash(t, root)

	out, stderr, code := runCLI(t, "vendor", "--gomod", gomod, "--vendor-only", "--json", "--store-root", root)
	if code != 0 {
		t.Fatalf("vendor exited %d: %s", code, stderr)
	}
	var s vendorSection
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	if s.ConfigHash != want || len(s.ConfigOverrides) != 1 ||
		s.ConfigOverrides[0] != (configOverride{Flag: "--vendor-only", Value: "true"}) {
		t.Errorf("vendor --json: hash %q overrides %+v, want %s and --vendor-only=true", s.ConfigHash, s.ConfigOverrides, want)
	}
	text, _, _ := runCLI(t, "vendor", "--gomod", gomod, "--vendor-only", "--store-root", root)
	if !strings.Contains(text, "config: "+want+" (overridden for this run: --vendor-only=true)\n") {
		t.Errorf("vendor text does not name the override:\n%s", text)
	}

	var overrides []configEvent
	for _, e := range configEvents(t, root) {
		if e.Type == "config_override" {
			overrides = append(overrides, e)
		}
	}
	if len(overrides) != 2 {
		t.Fatalf("want one config_override per run, got %+v", overrides)
	}
	if p := overrides[0].Payload; p["flag"] != "--vendor-only" || p["value"] != "true" || p["config_hash"] != want {
		t.Errorf("config_override payload = %v", p)
	}

	// Where the configuration already asks for it, the flag overrides nothing.
	writeHashedConfig(t, root, "version: \"3\"\nvendor_policy:\n  vendor_only: true\n")
	out, _, _ = runCLI(t, "vendor", "--gomod", gomod, "--vendor-only", "--json", "--store-root", root)
	s = vendorSection{}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.ConfigOverrides) != 0 {
		t.Errorf("--vendor-only under vendor_only: true named an override: %+v", s.ConfigOverrides)
	}
}

func TestDirectivesShow_ARecordWithoutAHashSaysSo(t *testing.T) {
	isolateInvocationState(t)
	jsonOut = false
	rec := directivedomain.Record{ID: "scan-1", ProjectModulePath: "example.com/app"}
	ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{Scan: rec, Found: true}}

	var text bytes.Buffer
	if err := directivesShowWith(context.Background(), ctr, "scan-1", &text, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "config: no config hash recorded\n") {
		t.Errorf("an older record does not read as unrecorded:\n%s", text.String())
	}

	jsonOut = true
	var doc bytes.Buffer
	if err := directivesShowWith(context.Background(), ctr, "scan-1", &doc, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc.String(), "config_hash") {
		t.Errorf("an older record carries a config_hash field:\n%s", doc.String())
	}
}

func TestObserveGateConfig_RefusesWithoutAnAuditSink(t *testing.T) {
	isolateInvocationState(t)
	if _, err := observeGateConfig(&Container{}); err == nil {
		t.Fatal("no audit sink, and the hash was recorded somewhere")
	}
}

func TestVendor_AnUnvendoredProjectRecordsNoDrift(t *testing.T) {
	root := t.TempDir()
	if _, stderr, code := runCLI(t, "vendor", "--gomod", writeUnvendoredProject(t), "--store-root", root); code != 0 {
		t.Fatalf("vendor exited %d: %s", code, stderr)
	}
	wantConfigEvents(t, root, 0, "a vendor run that evaluated no gate")
}
