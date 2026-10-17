package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/config"
)

type commentedDefaults struct {
	URL   string `yaml:"url"`
	Conns int    `yaml:"conns"`
}

func (commentedDefaults) ConfigComment() string { return "First line.\n\nThird line.\n" }

type emptyDefaults struct{}

func TestDefaultYAML_WritesEachSpecCommentedOutAfterTheKnownSections(t *testing.T) {
	data := string(config.DefaultYAML(
		config.ConfigSpec{Section: "postgres", Defaults: commentedDefaults{URL: "postgres://localhost", Conns: 4}},
		config.ConfigSpec{Section: "bare", Defaults: emptyDefaults{}},
		config.ConfigSpec{Section: "nodefaults"},
	))
	want := "\npostgres:\n  # First line.\n  #\n  # Third line.\n  # url: postgres://localhost\n  # conns: 4\n" +
		"\nbare:\n" +
		"\nnodefaults:\n"
	if !strings.HasSuffix(data, want) {
		t.Errorf("generated file ends\n%s\nwant suffix\n%s", data[len(data)-200:], want)
	}
	if strings.Index(data, "\nstorage:\n") > strings.Index(data, "\npostgres:\n") {
		t.Error("a spec section was written before the known sections")
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("generated file does not parse: %v", err)
	}
	if doc["postgres"] != nil {
		t.Errorf("postgres section sets %v, want nothing set", doc["postgres"])
	}
}

// failingDefaults refuses to render, as a Defaults with a broken MarshalYAML
// would.
type failingDefaults struct{}

func (failingDefaults) MarshalYAML() (any, error) { return nil, errors.New("no form") }

// Defaults that YAML cannot render say so in the file instead of vanishing.
func TestDefaultYAML_NamesDefaultsItCannotRender(t *testing.T) {
	data := string(config.DefaultYAML(config.ConfigSpec{Section: "odd", Defaults: failingDefaults{}}))
	if !strings.Contains(data, "\nodd:\n  # defaults could not be rendered: ") {
		t.Errorf("no rendering failure in:\n%s", data[len(data)-120:])
	}
}

func TestEnsureConfig_AppendsAMissingSpecSectionOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.EnsureConfig(path); err != nil {
		t.Fatal(err)
	}
	spec := config.ConfigSpec{Section: "postgres", Defaults: commentedDefaults{}}
	for range 2 {
		if err := config.EnsureConfig(path, spec); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\npostgres:\n"); n != 1 {
		t.Errorf("postgres section written %d times, want once", n)
	}
}

func TestIsKnownSection(t *testing.T) {
	for name, want := range map[string]bool{"version": true, "storage": true, "preferences": true, "sqlite": false, "": false} {
		if got := config.IsKnownSection(name); got != want {
			t.Errorf("IsKnownSection(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestConfigSpec_ValidateRefusesDefaultsYAMLCannotWrite(t *testing.T) {
	if err := (config.ConfigSpec{Section: "ok", Defaults: commentedDefaults{}}).Validate(); err != nil {
		t.Errorf("renderable defaults refused: %v", err)
	}
	for _, d := range []any{failingDefaults{}, struct{ C chan int }{}} {
		err := (config.ConfigSpec{Section: "odd", Defaults: d}).Validate()
		if err == nil || !strings.Contains(err.Error(), "section odd: defaults cannot be written as YAML") {
			t.Errorf("Validate(%T) = %v", d, err)
		}
	}
}
