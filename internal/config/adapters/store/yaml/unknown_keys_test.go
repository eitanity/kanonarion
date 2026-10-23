package yaml_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/adapters/yamlkeys"
	"github.com/eitanity/kanonarion/internal/config"
	configyaml "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
)

// A misspelt key in any section is refused with its full path and the key it
// most likely meant, rather than loading and changing nothing.
func TestParse_UnknownKeyInEverySectionIsRefused(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"licence_policy: {default: warn}", `unknown key "licence_policy" (did you mean "license_policy"?)`},
		{"verison: \"3\"", `unknown key "verison" (did you mean "version"?)`},
		{"preferences: {log_levl: debug}", `unknown key "preferences.log_levl" (did you mean "log_level"?)`},
		{"license_policy: {categorys: {a: [MIT]}}", `unknown key "license_policy.categorys" (did you mean "categories"?)`},
		{"license_policy: {default: warn}", `unknown key "license_policy.default"`},
		{"license_policy:\n  rules:\n    - scope: x\n      defualt: warn", `unknown key "license_policy.rules[0].defualt" (did you mean "default"?)`},
		{"license_overrides:\n  example.com/m: {spdx: MIT, declared_by: a, declared_on: \"2026-01-01\", basiss: b}", `unknown key "license_overrides.example.com/m.basiss" (did you mean "basis"?)`},
		{"copyright_declarations:\n  example.com/m: {copyrigt: x}", `unknown key "copyright_declarations.example.com/m.copyrigt" (did you mean "copyright"?)`},
		{"callgraph: {excludes: []}", `unknown key "callgraph.excludes" (did you mean "exclude"?)`},
		{"staleness: {tll: 1h}", `unknown key "staleness.tll" (did you mean "ttl"?)`},
		{"directive_policy: {defualt: warn}", `unknown key "directive_policy.defualt" (did you mean "default"?)`},
		{"godebug_policy: {rd: warn}", `unknown key "godebug_policy.rd" (did you mean "red"?)`},
		{"vendor_policy: {on_drfit: warn}", `unknown key "vendor_policy.on_drfit" (did you mean "on_drift"?)`},
		{"fips_policy: {requird: true}", `unknown key "fips_policy.requird" (did you mean "required"?)`},
		{"fetch_policy: {alowed_vcs_hosts: [example.org]}", `unknown key "fetch_policy.alowed_vcs_hosts" (did you mean "allowed_vcs_hosts"?)`},
		{"storage: {backed: sqlite}", `unknown key "storage.backed" (did you mean "backend"?)`},
		{"vulndb: {ulr: https://mirror.example.com}", `unknown key "vulndb.ulr" (did you mean "url"?)`},
		{"base: &b {jsn: true}\npreferences:\n  <<: *b", `unknown key "base"`},
		{"preferences:\n  <<: {jsn: true}", `unknown key "preferences.jsn" (did you mean "json"?)`},
	} {
		_, err := configyaml.Parse([]byte("version: \"3\"\n"+tc.body+"\n"), "sqlite")
		if err == nil || err.Error() != tc.want {
			t.Errorf("%q:\n got  %v\n want %s", tc.body, err, tc.want)
		}
		if uk, ok := errors.AsType[*yamlkeys.UnknownKeyError](err); !ok || uk.Key == "" {
			t.Errorf("%q: %T is not an UnknownKeyError", tc.body, err)
		}
	}
}

// A top-level section is known when a registered backend owns it, and refused
// when none does.
func TestParse_BackendSectionNeedsARegisteredBackend(t *testing.T) {
	src := []byte("version: \"3\"\nsqlite:\n  # nothing set\npostgres:\n  url: postgres://db\n")
	if _, err := configyaml.Parse(src, "sqlite", "postgres"); err != nil {
		t.Fatalf("registered backend sections refused: %v", err)
	}
	_, err := configyaml.Parse(src, "sqlite")
	if err == nil || err.Error() != `unknown key "postgres"` {
		t.Fatalf("unregistered backend section: err = %v", err)
	}
}

// A newer schema is told to upgrade, not refused for the keys it added.
func TestParse_NewerSchemaIsNotRefusedKeyByKey(t *testing.T) {
	_, err := configyaml.Parse([]byte("version: \"99\"\nnew_section: {a: 1}\n"))
	if err == nil || err.Error() != `config schema version "99" is newer than supported "3"; upgrade kanonarion` {
		t.Fatalf("err = %v", err)
	}
}

// Every value `config set` refuses is refused from the file in the same words.
func TestParse_RefusesWhatConfigSetRefuses(t *testing.T) {
	for _, tc := range []struct{ key, section, field, value string }{
		{"preferences.log_level", "preferences", "log_level", "verbose"},
		{"preferences.log_level", "preferences", "log_level", "[debug]"},
		{"preferences.json", "preferences", "json", "\"yes\""},
		{"preferences.progress", "preferences", "progress", "1"},
		{"license_policy.categories.permissive", "license_policy", "categories", "MIT"},
		{"callgraph.exclude", "callgraph", "exclude", "golang.org/x/tools"},
		{"callgraph.toolchain", "callgraph", "toolchain", "1.26"},
		{"callgraph.toolchain", "callgraph", "toolchain", "[go1.26.6]"},
		{"staleness.ttl", "staleness", "ttl", "soon"},
		{"staleness.ttl", "staleness", "ttl", "-1h"},
		{"staleness.ttl", "staleness", "ttl", "[1h]"},
		{"staleness.probe_concurrency", "staleness", "probe_concurrency", "-1"},
		{"staleness.probe_concurrency", "staleness", "probe_concurrency", "four"},
		{"fetch_policy.allowed_vcs_hosts", "fetch_policy", "allowed_vcs_hosts", "[]"},
		{"fetch_policy.allowed_vcs_hosts", "fetch_policy", "allowed_vcs_hosts", "github.com"},
		{"fetch_policy.allowed_vcs_hosts", "fetch_policy", "allowed_vcs_hosts", "[https://github.com]"},
		{"storage.backend", "storage", "backend", "[sqlite]"},
		{"storage.sumdb_cache", "storage", "sumdb_cache", "{a: b}"},
		{"vulndb.url", "vulndb", "url", "http://mirror.example.com"},
		{"vulndb.url", "vulndb", "url", "ftp://mirror.example.com"},
		{"vulndb.url", "vulndb", "url", "https://"},
		{"vulndb.url", "vulndb", "url", "\"\""},
		{"vulndb.url", "vulndb", "url", "mirror.example.com"},
		{"vulndb.url", "vulndb", "url", "https://user@mirror.example.com"},
		{"vulndb.url", "vulndb", "url", "https://mirror.example.com/?q=1"},
		{"vulndb.url", "vulndb", "url", "[https://mirror.example.com]"},
		{"vulndb.url", "vulndb", "url", "\"https://mirror.example.com/%zz\""},
	} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(tc.value), &doc); err != nil {
			t.Fatal(err)
		}
		want := configyaml.ValidateSetting(tc.key, doc.Content[0])
		if want == nil {
			t.Errorf("%s %s: config set accepts it; the case proves nothing", tc.key, tc.value)
			continue
		}
		body := tc.section + ":\n  " + tc.field + ": " + tc.value + "\n"
		if tc.field == "categories" {
			body = "license_policy:\n  categories:\n    permissive: " + tc.value + "\n"
		}
		_, err := configyaml.Parse([]byte("version: \"3\"\n" + body))
		if err == nil || err.Error() != want.Error() {
			t.Errorf("%s %s:\n file  %v\n set   %v", tc.key, tc.value, err, want)
		}
	}
}

// The file `config init` writes, with every backend section, loads unchanged.
func TestParse_ConfigInitTemplateLoads(t *testing.T) {
	spec := config.ConfigSpec{Section: "sqlite", Defaults: struct{}{}}
	if _, err := configyaml.Parse(config.DefaultYAML(spec), "sqlite"); err != nil {
		t.Fatalf("config init template refused: %v", err)
	}
}

// The store reports the unknown key and leaves naming the file to the caller
// that read it.
func TestLoadConfig_UnknownKeyIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: \"3\"\npostgres: {url: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configyaml.New(path, "postgres").LoadConfig(context.Background()); err != nil {
		t.Fatalf("registered section refused: %v", err)
	}
	_, err := configyaml.New(path).LoadConfig(context.Background())
	if err == nil {
		t.Fatal("unregistered section loaded")
	}
	if got := yamlkeys.InFile(err, path).Error(); got != `unknown key "postgres" in `+path {
		t.Errorf("err = %s", got)
	}
}
