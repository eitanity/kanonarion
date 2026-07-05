package yaml_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	"github.com/eitanity/kanonarion/internal/config/domain"
)

func TestParse_FullConfig(t *testing.T) {
	input := `
version: "1"
preferences:
  json: true
  log_level: debug
license_policy:
  categories:
    permissive: [MIT, Apache-2.0]
    restricted:  [SSPL-1.0]
  rules:
    - scope: production
      allow:   [permissive]
      notify:  []
      warn:    [restricted]
      default: allow
license_overrides:
  golang.org/x/mod: MIT
callgraph:
  exclude:
    - github.com/some/large/pkg
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Version != "1" {
		t.Errorf("version: got %q, want %q", cfg.Version, "1")
	}
	if !cfg.Preferences.JSON {
		t.Error("preferences.json: want true")
	}
	if cfg.Preferences.LogLevel != "debug" {
		t.Errorf("log_level: got %q, want %q", cfg.Preferences.LogLevel, "debug")
	}
	if got := cfg.LicenseOverrides["golang.org/x/mod"]; got != "MIT" {
		t.Errorf("license_overrides: got %q, want MIT", got)
	}
	if len(cfg.Callgraph.Exclude) != 1 || cfg.Callgraph.Exclude[0] != "github.com/some/large/pkg" {
		t.Errorf("callgraph.exclude: got %v", cfg.Callgraph.Exclude)
	}
	if len(cfg.LicensePolicy.Rules) != 1 {
		t.Fatalf("rules: got %d, want 1", len(cfg.LicensePolicy.Rules))
	}
	r := cfg.LicensePolicy.Rules[0]
	if r.Scope != "production" {
		t.Errorf("rule scope: got %q, want production", r.Scope)
	}
	if len(r.Allow) != 1 || r.Allow[0] != "permissive" {
		t.Errorf("rule allow: got %v", r.Allow)
	}
	if len(r.Warn) != 1 || r.Warn[0] != "restricted" {
		t.Errorf("rule warn: got %v", r.Warn)
	}
	if r.Default != domain.PolicyOutcomeAllow {
		t.Errorf("rule default: got %q, want allow", r.Default)
	}
}

func TestParse_DefaultOutcome_WhenAbsent(t *testing.T) {
	// Omitting the default field should still parse and produce allow.
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
  rules:
    - scope: production
      allow: [permissive]
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LicensePolicy.Rules[0].Default != domain.PolicyOutcomeAllow {
		t.Errorf("default when absent: got %q, want allow", cfg.LicensePolicy.Rules[0].Default)
	}
}

func TestParse_InvalidOutcome(t *testing.T) {
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
  rules:
    - scope: production
      allow:   [permissive]
      default: deny
`
	_, err := yaml.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for invalid outcome 'deny'")
	}
}

func TestParse_Outcome_Notify(t *testing.T) {
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
  rules:
    - scope: production
      allow: [permissive]
      default: notify
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LicensePolicy.Rules[0].Default != domain.PolicyOutcomeNotify {
		t.Errorf("default outcome: got %q, want notify", cfg.LicensePolicy.Rules[0].Default)
	}
}

func TestParse_Outcome_Warn(t *testing.T) {
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
  rules:
    - scope: production
      allow: [permissive]
      default: warn
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LicensePolicy.Rules[0].Default != domain.PolicyOutcomeWarn {
		t.Errorf("default outcome: got %q, want warn", cfg.LicensePolicy.Rules[0].Default)
	}
}

// TestParse_UnknownLicense_RoundTrip guards the per-rule
// unknown_license policy must parse from YAML into the domain.
func TestParse_UnknownLicense_RoundTrip(t *testing.T) {
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
  rules:
    - scope: production
      allow: [permissive]
      unknown_license: block
    - scope: tool
      allow: [permissive]
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.LicensePolicy.Rules[0].UnknownLicense; got != domain.UnknownLicenseBlock {
		t.Errorf("production unknown_license: got %q, want block", got)
	}
	// Unset is preserved as empty; the domain resolves it to a scope
	// default at evaluation time.
	if got := cfg.LicensePolicy.Rules[1].UnknownLicense; got != "" {
		t.Errorf("tool unknown_license: got %q, want empty (scope default applied later)", got)
	}
}

// TestParse_UnknownLicense_Invalid guards that a bad unknown_license value
// is rejected rather than silently ignored.
func TestParse_UnknownLicense_Invalid(t *testing.T) {
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
  rules:
    - scope: production
      unknown_license: maybe
`
	if _, err := yaml.Parse([]byte(input)); err == nil {
		t.Fatal("invalid unknown_license value was accepted")
	}
}

func TestLoadConfig_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Create the file then remove read permission so ReadFile returns a non-ErrNotExist error.
	if err := os.WriteFile(path, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()

	store := yaml.New(path)
	_, err := store.LoadConfig(context.Background())
	if err == nil {
		t.Fatal("expected error when file is unreadable")
	}
}

func TestParse_DefaultsWhenSectionsAbsent(t *testing.T) {
	input := `version: "1"`

	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defaults := domain.DefaultConfig()

	if cfg.Preferences.LogLevel != defaults.Preferences.LogLevel {
		t.Errorf("log_level default: got %q, want %q", cfg.Preferences.LogLevel, defaults.Preferences.LogLevel)
	}
	if cfg.Preferences.JSON != defaults.Preferences.JSON {
		t.Errorf("json default: got %v, want %v", cfg.Preferences.JSON, defaults.Preferences.JSON)
	}
	if len(cfg.LicensePolicy.Categories) != len(defaults.LicensePolicy.Categories) {
		t.Errorf("license_policy.categories default: got %d, want %d",
			len(cfg.LicensePolicy.Categories), len(defaults.LicensePolicy.Categories))
	}
	if len(cfg.LicensePolicy.Rules) != len(defaults.LicensePolicy.Rules) {
		t.Errorf("license_policy.rules default: got %d, want %d",
			len(cfg.LicensePolicy.Rules), len(defaults.LicensePolicy.Rules))
	}
}

// TestParse_CategoryOverlay_KeepsDefaults: a file that sets a single category
// (the shape `config set license_policy.categories.<name>` produces) overrides
// just that category and keeps the other built-in categories. With no rules in
// the file the built-in rules still apply.
func TestParse_CategoryOverlay_KeepsDefaults(t *testing.T) {
	input := `
version: "1"
license_policy:
  categories:
    permissive: [MIT]
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defaults := domain.DefaultConfig()

	// The set category is overridden.
	if got := cfg.LicensePolicy.Categories["permissive"]; len(got) != 1 || got[0] != "MIT" {
		t.Errorf("permissive: got %v, want [MIT]", got)
	}
	// Every other built-in category survives.
	for name := range defaults.LicensePolicy.Categories {
		if name == "permissive" {
			continue
		}
		if _, ok := cfg.LicensePolicy.Categories[name]; !ok {
			t.Errorf("built-in category %q was dropped by an overlay set", name)
		}
	}
	// Rules absent from the file fall back to the built-in rules, not empty.
	if len(cfg.LicensePolicy.Rules) != len(defaults.LicensePolicy.Rules) {
		t.Errorf("rules: got %d, want built-in default %d", len(cfg.LicensePolicy.Rules), len(defaults.LicensePolicy.Rules))
	}
}

// TestParse_RulesReplaceWhenPresent: defining rules in the file replaces the
// built-in rules entirely (they are a scope-keyed whole, not merged).
func TestParse_RulesReplaceWhenPresent(t *testing.T) {
	input := `
version: "1"
license_policy:
  rules:
    - scope: production
      allow: [permissive]
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LicensePolicy.Rules) != 1 || cfg.LicensePolicy.Rules[0].Scope != "production" {
		t.Errorf("rules: got %v, want a single production rule", cfg.LicensePolicy.Rules)
	}
	// Categories absent from the file keep the built-in defaults.
	if len(cfg.LicensePolicy.Categories) != len(domain.DefaultConfig().LicensePolicy.Categories) {
		t.Errorf("categories: got %d, want built-in default count", len(cfg.LicensePolicy.Categories))
	}
}

func TestParse_MissingVersion(t *testing.T) {
	_, err := yaml.Parse([]byte(`preferences:\n  json: true`))
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestParse_FutureVersion(t *testing.T) {
	_, err := yaml.Parse([]byte(`version: "99"`))
	if err == nil {
		t.Fatal("expected error for unsupported future version")
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := yaml.Parse([]byte(`{invalid yaml`))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_FileAbsent_ReturnsDefaults(t *testing.T) {
	store := yaml.New(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	cfg, err := store.LoadConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error for absent file: %v", err)
	}
	defaults := domain.DefaultConfig()
	if cfg.Version != defaults.Version {
		t.Errorf("version: got %q, want %q", cfg.Version, defaults.Version)
	}
}

func TestLoadConfig_FilePresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("version: \"1\"\npreferences:\n  log_level: warn\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	store := yaml.New(path)
	cfg, err := store.LoadConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Preferences.LogLevel != "warn" {
		t.Errorf("log_level: got %q, want %q", cfg.Preferences.LogLevel, "warn")
	}
}

func TestParse_LicensePolicy_RulesWithoutCategories(t *testing.T) {
	// Only rules present (no categories) — should fall back to default categories.
	input := `
version: "1"
license_policy:
  rules:
    - scope: production
      allow: [permissive]
      default: allow
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LicensePolicy.Categories) == 0 {
		t.Error("expected default categories to be used when rules are present but categories absent")
	}
	if len(cfg.LicensePolicy.Rules) != 1 {
		t.Errorf("rules: got %d, want 1", len(cfg.LicensePolicy.Rules))
	}
}
