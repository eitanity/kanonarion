package cli

import (
	"bytes"
	"encoding/json"
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

	got := buf.String()
	if !strings.HasPrefix(got, configContent) {
		t.Errorf("text output does not start with the raw file:\ngot:\n%s\nwant prefix:\n%s", got, configContent)
	}
	if !strings.Contains(got, "# effective configuration") {
		t.Errorf("text output carries no effective-configuration section:\n%s", got)
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
		reflect.TypeFor[domain.Config](),
		reflect.TypeFor[configShowResult](),
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
	for sf := range src.Fields() {
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

// An absent config file is an ordinary state: a store that has never had one
// written is running a full built-in policy, and the text view must report it
// rather than refuse. It also has to say the file is absent, or a reader cannot
// tell a built-in default from a value somebody chose.
func TestRunStoreConfigShow_Text_MissingFileReportsDefaults(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error with no config file: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"no config file at " + filepath.Join(dir, "config.yaml"),
		"built-in default",
		"kanonarion config init",
		"# effective configuration",
		"license_policy.rules[production].unknown_license",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text output missing %q, got:\n%s", want, got)
		}
	}
}

// A file that exists but cannot be read is a different case from one that is
// absent, and stays a refusal on both channels: an all-defaults answer for
// bytes nobody has seen is a guess about the policy in force.
func TestRunStoreConfigShow_UnreadableFileIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file mode does not deny a read")
	}
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	for _, asJSON := range []bool{false, true} {
		var buf bytes.Buffer
		err := runStoreConfigShow(dir, asJSON, &buf)
		if err == nil {
			t.Fatalf("asJSON=%v: expected a refusal for an unreadable config file, got:\n%s", asJSON, buf.String())
		}
		if strings.Contains(err.Error(), "no such file") {
			t.Errorf("asJSON=%v: unreadable file reported as absent: %v", asJSON, err)
		}
	}
}

// The two channels may present the answer differently; they must not disagree
// about whether a config file exists.
func TestRunStoreConfigShow_ChannelsAgreeOnFilePresence(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	for _, tc := range []struct {
		name    string
		write   bool
		present bool
	}{
		{name: "absent", write: false, present: false},
		{name: "present", write: true, present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if tc.write {
				if err := os.WriteFile(path, []byte("version: \"1\"\n"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}

			var text bytes.Buffer
			if err := runStoreConfigShow(dir, false, &text); err != nil {
				t.Fatalf("text: unexpected error: %v", err)
			}
			var jsonBuf bytes.Buffer
			if err := runStoreConfigShow(dir, true, &jsonBuf); err != nil {
				t.Fatalf("json: unexpected error: %v", err)
			}

			var got configShowResult
			if err := json.Unmarshal(jsonBuf.Bytes(), &got); err != nil {
				t.Fatalf("decoding JSON view: %v", err)
			}
			if got.ConfigFile.Present != tc.present {
				t.Errorf("JSON config_file.present = %v, want %v", got.ConfigFile.Present, tc.present)
			}
			if got.ConfigFile.Path != path {
				t.Errorf("JSON config_file.path = %q, want %q", got.ConfigFile.Path, path)
			}
			textSaysAbsent := strings.Contains(text.String(), "no config file at")
			if textSaysAbsent == tc.present {
				t.Errorf("text channel says absent=%v while the file present=%v; the channels disagree:\n%s",
					textSaysAbsent, tc.present, text.String())
			}
		})
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

// TestLoadStoreConfig_ReturnsTheRejectionForAnUnloadableFile replaces a test
// that asserted the opposite — that an unloadable file falls back to
// DefaultConfig and says nothing. That fallback is what let a rejected file run
// as a silent no-op, so the assertion is inverted here rather than dropped.
//
// The built-in defaults are still returned beside the rejection: they are what
// would be in force, and the commands allowed to carry on report them.
func TestLoadStoreConfig_ReturnsTheRejectionForAnUnloadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("{invalid yaml"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := loadStoreConfig(dir)
	if err == nil {
		t.Fatal("unloadable config.yaml returned no error; the file was discarded in silence")
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, "config.yaml")) {
		t.Errorf("rejection does not name the file: %v", err)
	}
	def := domain.DefaultConfig()
	if cfg.Version != def.Version {
		t.Errorf("version: got %q, want the built-in default %q alongside the rejection", cfg.Version, def.Version)
	}
}
