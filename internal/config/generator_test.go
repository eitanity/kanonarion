package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config"
	configyaml "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	"gopkg.in/yaml.v3"
)

// TestDefaultYAML_PreferencesNotFrozen: the generated template must leave
// preferences keys commented out so they inherit the live built-in default.
// If they were written as concrete values they would freeze on disk and a
// later default change could never propagate to an existing store.
func TestDefaultYAML_PreferencesNotFrozen(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(config.DefaultYAML(), &doc); err != nil {
		t.Fatalf("unmarshal template: %v", err)
	}
	prefs, present := doc["preferences"]
	if !present {
		t.Fatal("preferences section missing from template")
	}
	if prefs != nil {
		t.Errorf("preferences keys are frozen to disk (%v); the template must leave them commented so built-in default changes propagate", prefs)
	}
}

// TestDefaultYAML_PolicyBlocksNotFrozen: the structured policy sections are
// also fully commented in the template, so they resolve to the live built-in
// defaults (and a later default change propagates) rather than freezing on
// disk on first write.
func TestDefaultYAML_PolicyBlocksNotFrozen(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(config.DefaultYAML(), &doc); err != nil {
		t.Fatalf("unmarshal template: %v", err)
	}
	// Every structured schema section must appear in the template (fully
	// commented). The four governance policy blocks are included because they
	// regressed out of the generator once: present in the config schema and the
	// `policy validate` governance markers, but absent from `config init`, so
	// they were undiscoverable and never appended on upgrade.
	for _, section := range []string{
		"license_policy", "callgraph", "license_overrides",
		"directive_policy", "godebug_policy", "vendor_policy", "fips_policy",
	} {
		val, present := doc[section]
		if !present {
			t.Errorf("section %q missing from template", section)
			continue
		}
		if val != nil {
			t.Errorf("section %q is frozen to disk (%v); it must be fully commented", section, val)
		}
	}
}

func TestDefaultYAML_IsValidAndParseable(t *testing.T) {
	data := config.DefaultYAML()
	if len(data) == 0 {
		t.Fatal("DefaultYAML returned empty bytes")
	}
	cfg, err := configyaml.Parse(data)
	if err != nil {
		t.Fatalf("DefaultYAML produced invalid YAML: %v", err)
	}
	if cfg.Version != "1" {
		t.Errorf("version: got %q, want 1", cfg.Version)
	}
	if cfg.Preferences.LogLevel != "warn" {
		t.Errorf("log_level: got %q, want warn", cfg.Preferences.LogLevel)
	}
	if len(cfg.LicensePolicy.Rules) == 0 {
		t.Error("license_policy.rules: expected at least one rule")
	}
}

func TestDefaultYAML_ContainsComments(t *testing.T) {
	data := config.DefaultYAML()
	if !strings.Contains(string(data), "#") {
		t.Error("DefaultYAML should contain comments")
	}
}

// TestDefaultYAML_PreferenceCommentsDescribeKeyNotDefault: preference comments
// must describe the key's meaning and allowed values, never assert that the
// emitted value is the built-in default. `config show` prints the on-disk file
// verbatim, so a "Default log level: ..." comment sitting above a persisted
// override misdescribes that override as the default.
func TestDefaultYAML_PreferenceCommentsDescribeKeyNotDefault(t *testing.T) {
	data := string(config.DefaultYAML())
	for _, mislabel := range []string{"Default log level", "by default"} {
		if strings.Contains(data, mislabel) {
			t.Errorf("preference comment asserts the value is a default (%q); it must describe the key instead", mislabel)
		}
	}
	if !strings.Contains(data, "# Log level: debug | info | warn | error") {
		t.Error("expected the log_level comment to describe the key and its allowed values")
	}
}

func TestEnsureConfig_WritesFile_WhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := config.EnsureConfig(path); err != nil {
		t.Fatalf("EnsureConfig: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatalf("reading written config: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("written config is empty")
	}

	// Must be parseable.
	if _, err := configyaml.Parse(data); err != nil {
		t.Errorf("written config is not valid YAML: %v", err)
	}
}

func TestEnsureConfig_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.yaml")

	if err := config.EnsureConfig(path); err != nil {
		t.Fatalf("EnsureConfig in nested dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestEnsureConfig_Idempotent_WhenFileComplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := config.EnsureConfig(path); err != nil {
		t.Fatalf("first EnsureConfig: %v", err)
	}
	original, _ := os.ReadFile(path) // #nosec G304 -- t.TempDir() path

	if err := config.EnsureConfig(path); err != nil {
		t.Fatalf("second EnsureConfig: %v", err)
	}
	after, _ := os.ReadFile(path) // #nosec G304 -- t.TempDir() path

	if string(original) != string(after) {
		t.Error("EnsureConfig modified a complete config file on second call")
	}
}

func TestEnsureConfig_AppendsMissingSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// Write a minimal config with only preferences.
	minimal := []byte("version: \"1\"\npreferences:\n  json: false\n  log_level: info\n")
	if err := os.WriteFile(path, minimal, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := config.EnsureConfig(path); err != nil {
		t.Fatalf("EnsureConfig: %v", err)
	}

	data, _ := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	content := string(data)

	// Original content preserved.
	if !strings.Contains(content, "log_level: info") {
		t.Error("original content was not preserved")
	}
	// Missing sections appended.
	for _, section := range []string{"license_policy", "license_overrides", "callgraph"} {
		if !strings.Contains(content, section+":") {
			t.Errorf("missing section %q was not appended", section)
		}
	}
	// preferences not duplicated.
	if strings.Count(content, "preferences:") > 1 {
		t.Error("preferences section was duplicated")
	}
}

func TestEnsureConfig_LeavesUnparseableFileUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	garbage := []byte("{not valid yaml")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := config.EnsureConfig(path); err != nil {
		t.Fatalf("EnsureConfig should not error on unparseable file: %v", err)
	}

	after, _ := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if string(after) != string(garbage) {
		t.Error("EnsureConfig modified an unparseable file")
	}
}

func TestEnsureConfig_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()

	err := config.EnsureConfig(path)
	if err == nil {
		t.Fatal("expected error when config file is unreadable")
	}
}
