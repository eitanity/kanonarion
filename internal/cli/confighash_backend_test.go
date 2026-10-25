package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The testsink backend is registered through the public façade, as a
// consumer's main would, over the testfiles stores: its audit events land in
// <dir>/events.jsonl and nothing in the store root.
const testSinkBackendName = "testsink"

type testSinkSettings struct {
	Dir string `yaml:"dir"`
	// KeepsLastHash supplies Storage.ConfigHashes; false leaves it nil.
	KeepsLastHash bool `yaml:"keeps_last_hash"`
	// RefuseWhile names a file whose presence makes Open fail;
	// RefuseEventsWhile, every append; RefuseHashWhile, the before-call;
	// RefuseAfterWhile, the after-call.
	RefuseWhile       string `yaml:"refuse_while"`
	RefuseEventsWhile string `yaml:"refuse_events_while"`
	RefuseHashWhile   string `yaml:"refuse_hash_while"`
	RefuseAfterWhile  string `yaml:"refuse_after_while"`
}

func testSinkBackend() kanonarion.Backend {
	return kanonarion.Backend{
		Name:     testSinkBackendName,
		Section:  testSinkBackendName,
		Defaults: testSinkSettings{},
		Open:     openTestSink,
	}
}

func openTestSink(ctx context.Context, req kanonarion.StorageRequest) (*kanonarion.Storage, error) {
	var s testSinkSettings
	if err := yaml.Unmarshal(req.Section, &s); err != nil {
		return nil, fmt.Errorf("testsink section: %w", err)
	}
	if s.RefuseWhile != "" {
		if _, err := os.Stat(s.RefuseWhile); err == nil {
			return nil, errors.New("testsink: the store is unavailable")
		}
	}
	req.Section = []byte("dir: " + s.Dir + "\n")
	st, err := openTestFiles(ctx, req)
	if err != nil {
		return nil, err
	}
	if s.KeepsLastHash {
		st.ConfigHashes = &fileConfigHashes{
			path: filepath.Join(s.Dir, "last-config-hash"), refuseWhile: s.RefuseHashWhile, refuseAfterWhile: s.RefuseAfterWhile,
		}
	}
	if s.RefuseEventsWhile != "" {
		st.Audit = refusingSink{AuditSink: st.Audit, while: s.RefuseEventsWhile}
	}
	return st, nil
}

// present reports whether the file at path exists; "" never does.
func present(path string) bool {
	_, err := os.Stat(path)
	return path != "" && err == nil
}

// refusingSink fails every append while its file exists.
type refusingSink struct {
	kanonarion.AuditSink
	while string
}

func (r refusingSink) RecordEvent(e kanonarion.AuditEvent) error {
	if present(r.while) {
		return errors.New("testsink: the audit sink refused the event")
	}
	return r.AuditSink.RecordEvent(e) //nolint:wrapcheck // test backend
}

// fileConfigHashes keeps the last hash in a file, cleared before each append.
type fileConfigHashes struct{ path, refuseWhile, refuseAfterWhile string }

func (f *fileConfigHashes) LastConfigHash() (string, bool, error) {
	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading last hash: %w", err)
	}
	return string(data), true, nil
}

func (f *fileConfigHashes) BeforeConfigHashAppend() error {
	if present(f.refuseWhile) {
		return errors.New("testsink: the last hash could not be cleared")
	}
	if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing last hash: %w", err)
	}
	return nil
}

func (f *fileConfigHashes) AfterConfigHashAppend(hash string) error {
	if present(f.refuseAfterWhile) {
		return errors.New("testsink: the last hash could not be kept")
	}
	if err := os.WriteFile(f.path, []byte(hash), 0o600); err != nil {
		return fmt.Errorf("writing last hash: %w", err)
	}
	return nil
}

// testSinkStore writes a store root whose config selects testsink, and
// returns the root and the backend's directory.
func testSinkStore(t *testing.T, s testSinkSettings) (root, dir string) {
	t.Helper()
	root, s.Dir = t.TempDir(), t.TempDir()
	writeHashedConfig(t, root, testSinkConfig(t, s))
	return root, s.Dir
}

func testSinkConfig(t *testing.T, s testSinkSettings) string {
	t.Helper()
	section, err := yaml.Marshal(map[string]testSinkSettings{testSinkBackendName: s})
	if err != nil {
		t.Fatal(err)
	}
	return "version: \"3\"\nstorage:\n  backend: " + testSinkBackendName + "\n" + string(section)
}

// sinkConfigEvents reads every config_* event the testsink backend received.
func sinkConfigEvents(t *testing.T, dir string) []configEvent {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, testFilesEvents))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []configEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		var e configEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("event line does not parse: %v", err)
		}
		if strings.HasPrefix(e.Type, "config_") {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// assertNoLedgerInRoot fails when the store root holds the SQLite backend's
// ledger or its last-hash marker.
func assertNoLedgerInRoot(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{"audit.jsonl", "audit.config-hash"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Errorf("the store root holds %s (%v)", name, err)
		}
	}
}

func wantConfigEvent(t *testing.T, e configEvent, typ string, fields map[string]any) {
	t.Helper()
	if e.Type != typ {
		t.Errorf("event %s, want %s: %+v", e.Type, typ, e)
		return
	}
	for k, v := range fields {
		if e.Payload[k] != v {
			t.Errorf("%s %s = %v, want %v", typ, k, e.Payload[k], v)
		}
	}
}

// config set, a hand edit seen by a gate, and an override each reach the
// registered backend's audit sink, and nothing reaches <store>/audit.jsonl.
func TestConfigEvents_ReachTheRegisteredBackendsAuditSink(t *testing.T) {
	root, dir := testSinkStore(t, testSinkSettings{KeepsLastHash: true})
	gomod := directivesProject(t)

	h0 := runDirectivesJSON(t, root, gomod).ConfigHash
	if _, stderr, code := runCLI(t, "config", "set", "license_policy.categories.permissive", "[MIT]", "--store-root", root); code != 0 || stderr != "" {
		t.Fatalf("config set exited %d: %s", code, stderr)
	}
	h1 := configShowHash(t, root)
	runDirectivesJSON(t, root, gomod) // the set was witnessed, so no drift

	writeHashedConfig(t, root, testSinkConfig(t, testSinkSettings{Dir: dir, KeepsLastHash: true})+
		"license_policy:\n  categories:\n    permissive: [MIT]\ndirective_policy:\n  version_replace: warn\n")
	if _, stderr, code := runCLI(t, "directives", "--gomod", gomod, "--store-root", root); code != ExitPolicy {
		t.Fatalf("directives exited %d: %s", code, stderr)
	}
	h2 := configShowHash(t, root)
	if _, stderr, code := runCLI(t, "vendor", "--gomod", emptyVendoredProject(t), "--vendor-only", "--store-root", root); code != 0 {
		t.Fatalf("vendor exited %d: %s", code, stderr)
	}

	events := sinkConfigEvents(t, dir)
	if len(events) != 4 {
		t.Fatalf("the backend received %d config events, want 4: %+v", len(events), events)
	}
	wantConfigEvent(t, events[0], "config_drift_observed", map[string]any{"old_hash": "", "new_hash": h0, "observed_at": "first_use"})
	wantConfigEvent(t, events[1], "config_changed", map[string]any{"old_hash": h0, "new_hash": h1})
	wantConfigEvent(t, events[2], "config_drift_observed", map[string]any{"old_hash": h1, "new_hash": h2})
	wantConfigEvent(t, events[3], "config_override", map[string]any{"flag": "--vendor-only", "config_hash": h2})
	assertNoLedgerInRoot(t, root)
}

// A backend that keeps no last hash is told the hash in use by every gate,
// with no guess at the previous one.
func TestConfigEvents_ABackendWithoutALastHashRecordsDriftAtEveryGate(t *testing.T) {
	root, dir := testSinkStore(t, testSinkSettings{})
	gomod := directivesProject(t)
	want := configShowHash(t, root)
	for _, args := range [][]string{
		{"directives", "--gomod", gomod},
		{"directives", "--gomod", gomod},
		{"godebug", "--gomod", gomod},
		{"fips", "--gomod", gomod},
		{"vendor", "--gomod", emptyVendoredProject(t)},
	} {
		if _, stderr, code := runCLI(t, append(args, "--store-root", root)...); code != 0 {
			t.Fatalf("%v exited %d: %s", args, code, stderr)
		}
	}
	events := sinkConfigEvents(t, dir)
	if len(events) != 5 {
		t.Fatalf("want one drift event per gate, got %d: %+v", len(events), events)
	}
	for _, e := range events {
		wantConfigEvent(t, e, "config_drift_observed", map[string]any{"old_hash": "", "new_hash": want, "observed_at": "every_gate"})
		if note := fmt.Sprint(e.Payload["note"]); !strings.Contains(note, "keeps no last recorded config hash") {
			t.Errorf("note %q does not say the backend keeps no last hash", note)
		}
	}
	assertNoLedgerInRoot(t, root)
}

// config set over a store that cannot record the change - it cannot be
// opened, refuses the append, or cannot clear its last hash - still writes the
// file and exits 0, says the change went unrecorded, and the next gate
// records it as drift.
func TestConfigSet_AStoreThatCannotRecordLeavesTheChangeToTheNextGate(t *testing.T) {
	for name, tc := range map[string]struct {
		settings func(refuse string) testSinkSettings
		says     string
		// unsure: the refused append came after the last hash was cleared, so
		// the drift names no old hash rather than a guessed one.
		unsure bool
	}{
		"open":   {func(r string) testSinkSettings { return testSinkSettings{KeepsLastHash: true, RefuseWhile: r} }, "the store is unavailable", false},
		"append": {func(r string) testSinkSettings { return testSinkSettings{KeepsLastHash: true, RefuseEventsWhile: r} }, "refused the event", true},
		"marker": {func(r string) testSinkSettings { return testSinkSettings{KeepsLastHash: true, RefuseHashWhile: r} }, "could not be cleared", false},
	} {
		t.Run(name, func(t *testing.T) {
			refuse := filepath.Join(t.TempDir(), "down")
			root, dir := testSinkStore(t, tc.settings(refuse))
			gomod := directivesProject(t)
			h0 := runDirectivesJSON(t, root, gomod).ConfigHash

			if err := os.WriteFile(refuse, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			_, stderr, code := runCLI(t, "config", "set", "license_policy.categories.permissive", "[MIT]", "--store-root", root)
			if code != 0 {
				t.Fatalf("config set exited %d: %s", code, stderr)
			}
			for _, want := range []string{"not recorded in the assurance log", tc.says, "will record it as config drift"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr does not say %q:\n%s", want, stderr)
				}
			}
			data, err := os.ReadFile(filepath.Join(root, "config.yaml"))
			if err != nil || !strings.Contains(string(data), "MIT") {
				t.Fatalf("config.yaml was not written (%v):\n%s", err, data)
			}
			if n := len(sinkConfigEvents(t, dir)); n != 1 {
				t.Fatalf("the backend received %d config events, want only the first drift", n)
			}

			if err := os.Remove(refuse); err != nil {
				t.Fatal(err)
			}
			h1 := runDirectivesJSON(t, root, gomod).ConfigHash
			events := sinkConfigEvents(t, dir)
			if len(events) != 2 {
				t.Fatalf("want the change recorded as drift, got %+v", events)
			}
			wantOld := h0
			if tc.unsure {
				wantOld = ""
			}
			wantConfigEvent(t, events[1], "config_drift_observed", map[string]any{"old_hash": wantOld, "new_hash": h1})
			assertNoLedgerInRoot(t, root)
		})
	}
}

// When only the after-call fails, the change is in the log: config set says
// so, exits 0, and warns only of what the port allows - an unsure backend may
// record the same hash again. This one forgot it, so the next gate does.
func TestConfigSet_ALastHashNotKeptAfterTheAppendIsSaidTruthfully(t *testing.T) {
	refuse := filepath.Join(t.TempDir(), "down")
	root, dir := testSinkStore(t, testSinkSettings{KeepsLastHash: true, RefuseAfterWhile: refuse})
	gomod := directivesProject(t)
	h0 := runDirectivesJSON(t, root, gomod).ConfigHash

	if err := os.WriteFile(refuse, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, "config", "set", "license_policy.categories.permissive", "[MIT]", "--store-root", root)
	if code != 0 {
		t.Fatalf("config set exited %d: %s", code, stderr)
	}
	const want = "config set: the change was recorded, but the backend's last config hash could not be updated: " +
		"testsink: the last hash could not be kept\n" +
		"  the next command that evaluates a gate may record the same hash again as config drift\n"
	if stderr != want {
		t.Errorf("stderr =\n%q\nwant\n%q", stderr, want)
	}
	h1 := configShowHash(t, root)
	events := sinkConfigEvents(t, dir)
	if len(events) != 2 {
		t.Fatalf("want the change in the log, got %+v", events)
	}
	wantConfigEvent(t, events[1], "config_changed", map[string]any{"old_hash": h0, "new_hash": h1})

	if err := os.Remove(refuse); err != nil {
		t.Fatal(err)
	}
	runDirectivesJSON(t, root, gomod)
	events = sinkConfigEvents(t, dir)
	if len(events) != 3 {
		t.Fatalf("want one drift from the unsure backend, got %+v", events)
	}
	wantConfigEvent(t, events[2], "config_drift_observed", map[string]any{"old_hash": "", "new_hash": h1})
	runDirectivesJSON(t, root, gomod)
	if n := len(sinkConfigEvents(t, dir)); n != 3 {
		t.Errorf("the hash was recorded again by a second gate: %d events", n)
	}
	assertNoLedgerInRoot(t, root)
}
