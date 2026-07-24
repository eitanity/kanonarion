package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

func TestRunStoreConfigShow_JSON(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()

	activeConfig = domain.Config{
		Version: "1",
		Preferences: domain.Preferences{
			JSON:     false,
			LogLevel: "info",
		},
		LicensePolicy: domain.LicensePolicy{
			Categories: map[string][]string{
				"permissive": {"MIT", "Apache-2.0"},
			},
			Rules: []domain.LicensePolicyRule{
				{
					Scope:   "production",
					Allow:   []string{"permissive"},
					Notify:  []string{},
					Warn:    []string{},
					Default: domain.PolicyOutcomeAllow,
				},
			},
		},
		LicenseOverrides: map[string]string{},
		Callgraph:        domain.CallgraphConfig{Exclude: []string{}},
	}

	var buf bytes.Buffer
	if err := runStoreConfigShow(t.TempDir(), true, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{`"version"`, `"1"`, `"preferences"`, `"log_level"`, `"license_policy"`, `"rules"`, `"production"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in JSON output, got:\n%s", want, out)
		}
	}
}

func TestRunStoreConfigShow_Text(t *testing.T) {
	dir := t.TempDir()
	configContent := "version: \"1\"\npreferences:\n  log_level: warn\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(configContent), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := buf.String(); got != configContent {
		t.Errorf("text output: got %q, want %q", got, configContent)
	}
}

// TestStoreConfigShow_CoversEveryConfigField is the regression: the
// `store config show --json` view (configShowResult) hand-mirrors
// domain.Config, so a config-schema addition could be silently absent from
// the effective-config contract (absence-as-answer). This guard
// turns that drift into a build failure: every exported field of
// domain.Config must have a same-named field in configShowResult, recursively
// through nested structs and slice/map element structs. When this fails, add
// the missing field to configShowResult (and the runStoreConfigShow mapping)
// rather than weakening the test.
func TestStoreConfigShow_CoversEveryConfigField(t *testing.T) {
	assertStructCovered(t,
		reflect.TypeOf(domain.Config{}),
		reflect.TypeOf(configShowResult{}),
		"Config")
}

// structElem unwraps pointer/slice/array/map(value) layers and reports the
// underlying struct type, if any. A non-struct leaf (string, bool,
// map[string]string, …) returns ok=false and needs no recursion.
func structElem(rt reflect.Type) (reflect.Type, bool) {
	for {
		switch rt.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			rt = rt.Elem()
		case reflect.Map:
			rt = rt.Elem()
		case reflect.Struct:
			return rt, true
		default:
			return nil, false
		}
	}
}

func assertStructCovered(t *testing.T, src, dst reflect.Type, path string) {
	t.Helper()
	if dst.Kind() != reflect.Struct {
		t.Fatalf("%s: view side is %s, not a struct — cannot mirror config", path, dst.Kind())
	}
	for i := 0; i < src.NumField(); i++ {
		sf := src.Field(i)
		if !sf.IsExported() {
			continue
		}
		df, ok := dst.FieldByName(sf.Name)
		if !ok {
			t.Errorf("%s.%s is in domain.Config but missing from the "+
				"`store config show --json` view (configShowResult); "+
				"add it so the effective-config contract stays complete",
				path, sf.Name)
			continue
		}
		srcElem, srcIsStruct := structElem(sf.Type)
		if !srcIsStruct {
			continue // leaf field — presence check above is sufficient
		}
		dstElem, dstIsStruct := structElem(df.Type)
		if !dstIsStruct {
			t.Errorf("%s.%s is a struct in domain.Config but a leaf in the "+
				"view; the nested shape is not surfaced", path, sf.Name)
			continue
		}
		assertStructCovered(t, srcElem, dstElem, path+"."+sf.Name)
	}
}

func TestRunStoreConfigShow_Text_MissingFile(t *testing.T) {
	var buf bytes.Buffer
	err := runStoreConfigShow(t.TempDir(), false, &buf)
	if err == nil {
		t.Fatal("expected error when config.yaml absent")
	}
}

// The clean tests sweep a temp directory of their own, never os.TempDir. The
// sweep deletes by prefix without checking whether an entry is in use, so
// pointing it at the shared system temp directory deletes the working files of
// any kanonarion process scanning on the same machine — a `make test` run then
// corrupts a concurrent scan, which is how a measurement run was lost. Owning
// the directory also lets these assert exactly, instead of accepting any
// outcome because another process might have raced them.

func TestRunStoreClean_NothingToClean(t *testing.T) {
	var buf bytes.Buffer
	if err := runStoreClean(t.TempDir(), t.TempDir(), &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "nothing to clean") {
		t.Errorf("empty store and empty temp dir must report nothing to clean, got: %q", got)
	}
}

func TestRunStoreClean_RemovesTempFiles(t *testing.T) {
	tmpDir := t.TempDir()

	target := filepath.Join(tmpDir, "kanonarion-vuln-scan-test-1")
	if err := os.MkdirAll(filepath.Join(target, "nested"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	var buf bytes.Buffer
	if err := runStoreClean(t.TempDir(), tmpDir, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("kanonarion-owned temp dir survived the clean (stat err = %v)", err)
	}
	if got := buf.String(); !strings.Contains(got, "cleaned 1 item(s)") {
		t.Errorf("clean must report what it removed, got: %q", got)
	}
}

// TestRunStoreClean_LeavesForeignEntries pins the blast radius: the sweep
// removes only kanonarion-owned prefixes, so an unrelated neighbour in the same
// directory survives. Without this the prefix list could widen unnoticed into
// deleting other processes' temp files.
func TestRunStoreClean_LeavesForeignEntries(t *testing.T) {
	tmpDir := t.TempDir()

	foreign := filepath.Join(tmpDir, "someone-elses-work")
	if err := os.MkdirAll(foreign, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	owned := filepath.Join(tmpDir, "kanonarion-cg-1")
	if err := os.MkdirAll(owned, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	var buf bytes.Buffer
	if err := runStoreClean(t.TempDir(), tmpDir, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("clean removed an entry it does not own: %v", err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Errorf("kanonarion-owned entry survived (stat err = %v)", err)
	}
}

func TestLoadStoreConfig_FallsBackOnInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	// Write a file that EnsureConfig will leave untouched (unparseable) but
	// LoadConfig will fail on — triggering the DefaultConfig fallback.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("{invalid yaml"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := loadStoreConfig(dir)
	def := domain.DefaultConfig()
	if cfg.Version != def.Version {
		t.Errorf("version: got %q, want %q", cfg.Version, def.Version)
	}
}
