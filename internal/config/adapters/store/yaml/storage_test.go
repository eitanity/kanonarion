package yaml_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	"github.com/eitanity/kanonarion/internal/config/domain"
)

// A v2 file has no storage section and keeps loading, on the SQLite backend.
func TestParse_AV2FileResolvesToTheDefaultBackend(t *testing.T) {
	cfg, err := yaml.Parse([]byte("version: \"2\"\npreferences:\n  log_level: info\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage != (domain.StorageConfig{Backend: "sqlite"}) || cfg.Sections != nil {
		t.Errorf("Storage = %+v, Sections = %v; want the default and none", cfg.Storage, cfg.Sections)
	}
	if cfg.Preferences.LogLevel != "info" {
		t.Errorf("log_level = %q", cfg.Preferences.LogLevel)
	}
}

func TestParse_StorageSection(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want domain.StorageConfig
	}{
		{"storage:\n", domain.StorageConfig{Backend: "sqlite"}},
		{"storage:\n  backend:\n", domain.StorageConfig{Backend: "sqlite"}},
		{"storage:\n  backend: postgres\n  sumdb_cache: /cache\n", domain.StorageConfig{Backend: "postgres", SumDBCache: "/cache"}},
	} {
		cfg, err := yaml.Parse([]byte("version: \"3\"\n" + tc.in))
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if cfg.Storage != tc.want {
			t.Errorf("%q: Storage = %+v, want %+v", tc.in, cfg.Storage, tc.want)
		}
	}
}

// An explicit empty backend is refused as `config set` refuses it; a key with
// no value keeps the default.
func TestParse_StorageBackendEmptyIsRefused(t *testing.T) {
	_, err := yaml.Parse([]byte("version: \"3\"\nstorage:\n  backend: \"\"\n"))
	if err == nil || err.Error() != `storage.backend requires a string, got ""` {
		t.Fatalf("err = %v, want the config set refusal", err)
	}
}

// Every registered backend's section reaches its owner as raw YAML; a section
// with nothing under it is absent.
func TestParse_KeepsTheSectionsItDoesNotDefine(t *testing.T) {
	cfg, err := yaml.Parse([]byte("version: \"3\"\nstorage:\n  backend: postgres\n"+
		"postgres:\n  url: postgres://db\n  conns: 4\nsqlite:\n  # nothing set\nother: [a, b]\n"),
		"postgres", "sqlite", "other")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"postgres": "url: postgres://db\nconns: 4\n", "other": "[a, b]\n"}
	if len(cfg.Sections) != len(want) {
		t.Fatalf("Sections = %q, want %q", cfg.Sections, want)
	}
	for name, raw := range want {
		if string(cfg.Sections[name]) != raw {
			t.Errorf("Sections[%s] = %q, want %q", name, cfg.Sections[name], raw)
		}
	}
}
