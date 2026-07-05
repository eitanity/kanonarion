package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"gopkg.in/yaml.v3"
)

// TestLoadStoreConfig_DoesNotCreateConfigFile: loading config for a read-only
// command must be side-effect-free — it must never materialise config.yaml in
// an empty store. The built-in defaults still resolve for every key.
func TestLoadStoreConfig_DoesNotCreateConfigFile(t *testing.T) {
	root := t.TempDir()
	cfg := loadStoreConfig(root)
	want := configdomain.DefaultConfig().Preferences.LogLevel
	if cfg.Preferences.LogLevel != want {
		t.Errorf("log_level = %q, want built-in default %q", cfg.Preferences.LogLevel, want)
	}
	if _, err := os.Stat(filepath.Join(root, "config.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("loadStoreConfig created config.yaml as a side effect (stat err=%v); read-only commands must not write config", err)
	}
}

// TestLoadStoreConfig_BuiltInDefaultPropagates: a store whose config.yaml
// exists but never had log_level explicitly set must resolve log_level to the
// live built-in default, not a value frozen to disk on first touch. A
// user-set sibling key is preserved.
func TestLoadStoreConfig_BuiltInDefaultPropagates(t *testing.T) {
	root := t.TempDir()
	existing := []byte("version: \"1\"\npreferences:\n  json: true\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), existing, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadStoreConfig(root)
	want := configdomain.DefaultConfig().Preferences.LogLevel
	if cfg.Preferences.LogLevel != want {
		t.Errorf("log_level = %q, want live built-in default %q (must not be frozen)", cfg.Preferences.LogLevel, want)
	}
	if !cfg.Preferences.JSON {
		t.Error("user-set preferences.json was dropped")
	}
}

// TestLoadStoreConfig_UserSetLogLevelWins: a value the user explicitly wrote
// to config.yaml overrides the built-in default.
func TestLoadStoreConfig_UserSetLogLevelWins(t *testing.T) {
	root := t.TempDir()
	existing := []byte("version: \"1\"\npreferences:\n  log_level: debug\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), existing, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadStoreConfig(root)
	if cfg.Preferences.LogLevel != "debug" {
		t.Errorf("log_level = %q, want user-set debug", cfg.Preferences.LogLevel)
	}
}

// TestRunConfigSet_DoesNotFreezeUnsetSiblings: setting one preferences key
// must not freeze the built-in default for an unset sibling. After setting
// preferences.json, log_level stays absent from disk so it keeps inheriting
// the live built-in default.
func TestRunConfigSet_DoesNotFreezeUnsetSiblings(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	if err := runConfigSet(root, "preferences.json", "true", &buf); err != nil {
		t.Fatalf("runConfigSet: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- test-controlled t.TempDir() path
	if err != nil {
		t.Fatalf("reading written config: %v", err)
	}
	var doc struct {
		Preferences map[string]any `yaml:"preferences"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing written config: %v\n%s", err, data)
	}
	if _, frozen := doc.Preferences["log_level"]; frozen {
		t.Errorf("preferences.log_level was frozen to disk by setting an unrelated key:\n%s", data)
	}
}

// TestRunConfigInit_CreatesTemplate: `config init` writes a config.yaml that
// is a fully-commented template — it parses, contains comments, and freezes no
// values (every section resolves to the live built-in default).
func TestRunConfigInit_CreatesTemplate(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	if err := runConfigInit(root, &buf); err != nil {
		t.Fatalf("runConfigInit: %v", err)
	}
	if !strings.Contains(buf.String(), "wrote") {
		t.Errorf("output = %q, want a 'wrote' confirmation", buf.String())
	}
	data, err := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- test-controlled t.TempDir() path
	if err != nil {
		t.Fatalf("reading written config: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing written config: %v\n%s", err, data)
	}
	for _, section := range []string{"preferences", "license_policy", "callgraph"} {
		if v := doc[section]; v != nil {
			t.Errorf("section %q is frozen to disk by init (%v); template must be fully commented", section, v)
		}
	}
}

// TestRunConfigInit_Idempotent: a second init on an existing file does not
// error and reports the file is already present.
func TestRunConfigInit_Idempotent(t *testing.T) {
	root := t.TempDir()
	var first bytes.Buffer
	if err := runConfigInit(root, &first); err != nil {
		t.Fatalf("first init: %v", err)
	}
	var second bytes.Buffer
	if err := runConfigInit(root, &second); err != nil {
		t.Fatalf("second init: %v", err)
	}
	if !strings.Contains(second.String(), "already present") {
		t.Errorf("second init output = %q, want 'already present'", second.String())
	}
}

// TestRunConfigSet_RoundTrip writes a known key into a fresh store config and
// confirms the value is persisted to config.yaml (git-config-style set).
func TestRunConfigSet_RoundTrip(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	if err := runConfigSet(root, "preferences.json", "true", &buf); err != nil {
		t.Fatalf("runConfigSet: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- test-controlled t.TempDir() path
	if err != nil {
		t.Fatalf("reading written config: %v", err)
	}
	var doc struct {
		Preferences struct {
			JSON bool `yaml:"json"`
		} `yaml:"preferences"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing written config: %v\n%s", err, data)
	}
	if !doc.Preferences.JSON {
		t.Errorf("preferences.json was not persisted as true:\n%s", data)
	}
}

// An unknown key is rejected with an ExitConfig error rather than silently
// writing an unrecognised field.
func TestRunConfigSet_UnknownKey(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	err := runConfigSet(root, "bogus.key", "x", &buf)
	if err == nil {
		t.Fatal("expected an error for an unknown config key")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitConfig {
		t.Errorf("want ExitConfig, got: %v", err)
	}
}

// TestConfigGetValue covers all key branches of configGetValue.
func TestConfigGetValue(t *testing.T) {
	cfg := configdomain.DefaultConfig()
	cfg.Version = "1"
	cfg.Preferences.JSON = true
	cfg.Preferences.LogLevel = "debug"

	cases := []struct {
		key     string
		wantIn  string
		wantErr bool
	}{
		{"version", "1", false},
		{"preferences.json", "true", false},
		{"preferences.log_level", "debug", false},
		{"license_policy.categories", "", false},
		{"license_policy.rules", "", false},
		{"license_overrides", "", false},
		{"callgraph.exclude", "", false},
		{"unknown_key", "", true},
		{"license_policy.categories.nonexistent", "", true},
		{"license_overrides.nonexistent/mod", "", true},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			val, err := configGetValue(cfg, c.key)
			if c.wantErr {
				if err == nil {
					t.Fatalf("key %q: expected error, got %q", c.key, val)
				}
				var xerr *exitError
				if !errors.As(err, &xerr) {
					t.Errorf("key %q: expected exitError, got %T: %v", c.key, err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("key %q: unexpected error: %v", c.key, err)
			}
			if c.wantIn != "" && !strings.Contains(val, c.wantIn) {
				t.Errorf("key %q: value %q missing %q", c.key, val, c.wantIn)
			}
		})
	}
}

// TestConfigGetValue_ExistingCategory: reading a known category and override.
func TestConfigGetValue_ExistingEntries(t *testing.T) {
	cfg := configdomain.DefaultConfig()
	// Ensure at least one override and one category exist.
	cfg.LicenseOverrides = map[string]string{"golang.org/x/mod": "MIT"}
	cfg.LicensePolicy.Categories = map[string][]string{"permissive": {"MIT", "Apache-2.0"}}

	val, err := configGetValue(cfg, "license_overrides.golang.org/x/mod")
	if err != nil || val != "MIT" {
		t.Fatalf("override: err=%v val=%q", err, val)
	}

	val, err = configGetValue(cfg, "license_policy.categories.permissive")
	if err != nil || !strings.Contains(val, "MIT") {
		t.Fatalf("category: err=%v val=%q", err, val)
	}
}

// TestRunConfigGet_WritesValue covers the runConfigGet path.
func TestRunConfigGet_WritesValue(t *testing.T) {
	cfg := configdomain.DefaultConfig()
	cfg.Preferences.LogLevel = "warn"
	var buf bytes.Buffer
	if err := runConfigGet(cfg, "preferences.log_level", &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "warn") {
		t.Errorf("output = %q, want 'warn'", buf.String())
	}
}

// TestParseConfigValue covers the validation branches.
func TestParseConfigValue(t *testing.T) {
	cases := []struct {
		key     string
		value   string
		wantErr bool
	}{
		{"preferences.json", "true", false},
		{"preferences.json", "notabool", true},
		{"preferences.log_level", "debug", false},
		{"preferences.log_level", "info", false},
		{"preferences.log_level", "warn", false},
		{"preferences.log_level", "error", false},
		{"preferences.log_level", "trace", true},
		{"license_policy.categories.permissive", "[MIT, Apache-2.0]", false},
		{"license_policy.categories.permissive", "MIT", true},
		{"callgraph.exclude", "[std, vendor]", false},
		{"callgraph.exclude", "notasequence", true},
		{"license_overrides.example.com/mod", "MIT", false},
		{"license_overrides.example.com/mod", "[MIT]", true},
	}
	for _, c := range cases {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			_, err := parseConfigValue(c.key, c.value)
			if c.wantErr && err == nil {
				t.Fatalf("expected error for key=%q value=%q", c.key, c.value)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error for key=%q value=%q: %v", c.key, c.value, err)
			}
		})
	}
}

// TestConfigSetPath covers the routing in configSetPath.
func TestConfigSetPath(t *testing.T) {
	cases := []struct {
		key     string
		wantLen int
		wantErr bool
	}{
		{"preferences.json", 2, false},
		{"preferences.log_level", 2, false},
		{"license_policy.categories.permissive", 3, false},
		{"license_policy.categories.", 0, true},
		{"license_overrides.example.com/mod", 2, false},
		{"license_overrides.", 0, true},
		{"callgraph.exclude", 2, false},
		{"unknown", 0, true},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			path, err := configSetPath(c.key)
			if c.wantErr {
				if err == nil {
					t.Fatalf("key %q: expected error", c.key)
				}
				return
			}
			if err != nil {
				t.Fatalf("key %q: unexpected error: %v", c.key, err)
			}
			if len(path) != c.wantLen {
				t.Errorf("key %q: path len = %d, want %d", c.key, len(path), c.wantLen)
			}
		})
	}
}

// TestSetYAMLNode_RoundTrip: setting a deep path in a YAML document and
// reading it back produces the expected value.
func TestSetYAMLNode_RoundTrip(t *testing.T) {
	src := "preferences:\n  json: false\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	valueNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}
	if err := setYAMLNode(&doc, []string{"preferences", "json"}, valueNode); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "json: true") {
		t.Errorf("yaml output = %q, expected json: true", out.String())
	}
}

// TestSetYAMLNode_InvalidDocument: non-document node returns error.
func TestSetYAMLNode_InvalidDocument(t *testing.T) {
	var empty yaml.Node
	if err := setYAMLNode(&empty, []string{"key"}, &yaml.Node{}); err == nil {
		t.Fatal("expected error for invalid document node")
	}
}

// TestSetYAMLNode_NewKey: a key absent from the document is appended.
func TestSetYAMLNode_NewKey(t *testing.T) {
	src := "existing: value\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	valueNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "hello"}
	if err := setYAMLNode(&doc, []string{"newkey"}, valueNode); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "newkey: hello") {
		t.Errorf("yaml = %q, expected newkey: hello", out.String())
	}
}
