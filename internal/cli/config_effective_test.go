package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// findSetting returns the rendered line for key from `config show` text output.
func findSetting(t *testing.T, out, key string) string {
	t.Helper()
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, key+" ") || line == key {
			return strings.TrimSpace(strings.TrimPrefix(line, key))
		}
	}
	t.Fatalf("key %q absent from config show output:\n%s", key, out)
	return ""
}

// The licence gate's most consequential setting must be discoverable from the
// tool. With nothing set in the file the effective value is the scope default,
// and the output has to say both the value and that it is a default — an
// operator cannot rely on a gate they can only find by reading the source.
func TestConfigShow_RendersUnknownLicenseDefault(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: \"2\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if got := findSetting(t, out, "license_policy.rules[production].unknown_license"); got != "block  (default)" {
		t.Errorf("production unknown_license = %q, want %q", got, "block  (default)")
	}
	if got := findSetting(t, out, "license_policy.rules[tool].unknown_license"); got != "warn  (default)" {
		t.Errorf("tool unknown_license = %q, want %q", got, "warn  (default)")
	}
}

// An explicitly-set value must render as in force and NOT as a default: the
// two are different answers to "can I rely on this gate".
func TestConfigShow_RendersUnknownLicenseExplicit(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	cfg := domain.DefaultConfig()
	cfg.LicensePolicy.Rules = []domain.LicensePolicyRule{{
		Scope:          "production",
		Allow:          []string{"permissive"},
		Default:        domain.PolicyOutcomeAllow,
		UnknownLicense: domain.UnknownLicenseNotify,
	}}
	activeConfig = cfg

	dir := t.TempDir()
	content := "version: \"2\"\nlicense_policy:\n  rules:\n    - scope: production\n      allow: [permissive]\n      default: allow\n      unknown_license: notify\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findSetting(t, buf.String(), "license_policy.rules[production].unknown_license"); got != "notify" {
		t.Errorf("production unknown_license = %q, want %q (explicit, not a default)", got, "notify")
	}
}

// A rule present in the file but silent on unknown_license still has a gate:
// the domain resolves it to the scope default. Rendering an empty cell there
// would report "no gate" for a scope that blocks.
func TestConfigShow_UnsetRuleFieldFallsBackToScopeDefault(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	cfg := domain.DefaultConfig()
	cfg.LicensePolicy.Rules = []domain.LicensePolicyRule{{
		Scope:   "production",
		Allow:   []string{"permissive"},
		Default: domain.PolicyOutcomeAllow,
	}}
	activeConfig = cfg

	dir := t.TempDir()
	content := "version: \"2\"\nlicense_policy:\n  rules:\n    - scope: production\n      allow: [permissive]\n      default: allow\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findSetting(t, buf.String(), "license_policy.rules[production].unknown_license"); got != "block  (default)" {
		t.Errorf("unset rule field = %q, want %q", got, "block  (default)")
	}
}

// Every policy key the loader parses and a command enforces must appear in the
// effective view. A key that is parsed, enforced and invisible is a setting an
// operator can only find by grepping the source — the defect this guards.
func TestConfigShow_RendersEveryEnforcedPolicyKey(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: \"2\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, key := range []string{
		"version",
		"preferences.json", "preferences.log_level", "preferences.progress",
		"license_policy.categories.permissive",
		"license_policy.rules[production].allow",
		"license_policy.rules[production].notify",
		"license_policy.rules[production].warn",
		"license_policy.rules[production].default",
		"license_policy.rules[production].unknown_license",
		"callgraph.exclude",
		"staleness.ttl",
		"directive_policy.local_path_replace", "directive_policy.module_path_replace",
		"directive_policy.version_replace", "directive_policy.exclude_newer",
		"directive_policy.exclude_older", "directive_policy.default",
		"godebug_policy.red", "godebug_policy.amber", "godebug_policy.green",
		"vendor_policy.on_drift", "vendor_policy.on_inconsistency", "vendor_policy.vendor_only",
		"fips_policy.required", "fips_policy.on_deviation",
		"fetch_policy.allowed_vcs_hosts",
	} {
		if !strings.Contains(out, key) {
			t.Errorf("effective view omits %q", key)
		}
	}
}

// license_overrides are only ever explicit — there is no built-in override —
// so they render without a default marker.
func TestConfigShow_RendersLicenceOverrides(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	cfg := domain.DefaultConfig()
	cfg.LicenseOverrides = map[string]string{"golang.org/x/mod": "MIT"}
	activeConfig = cfg

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: \"2\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findSetting(t, buf.String(), "license_overrides.golang.org/x/mod"); got != "MIT" {
		t.Errorf("override = %q, want MIT", got)
	}
}

// An enforcing VCS host list and an absent one are different postures, and the
// value has to say which — "[]" would report enforcement nobody chose.
func TestConfigShow_FetchPolicyPostureIsNamed(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: \"2\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	activeConfig = domain.DefaultConfig()
	var absent bytes.Buffer
	if err := runStoreConfigShow(dir, false, &absent); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findSetting(t, absent.String(), "fetch_policy.allowed_vcs_hosts"); !strings.Contains(got, "advisory") {
		t.Errorf("absent host list rendered %q, want the advisory posture named", got)
	}

	cfg := domain.DefaultConfig()
	cfg.FetchPolicy.AllowedVCSHosts = []string{"github.com"}
	activeConfig = cfg
	var present bytes.Buffer
	if err := runStoreConfigShow(dir, false, &present); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findSetting(t, present.String(), "fetch_policy.allowed_vcs_hosts"); !strings.Contains(got, "enforcing") {
		t.Errorf("named host list rendered %q, want the enforcing posture named", got)
	}
}

// The JSON view must report the value in force too, not the empty string an
// unset rule literally carries.
func TestConfigShow_JSONReportsEffectiveUnknownLicense(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	cfg := domain.DefaultConfig()
	cfg.LicensePolicy.Rules = []domain.LicensePolicyRule{{Scope: "production"}}
	activeConfig = cfg

	var buf bytes.Buffer
	if err := runStoreConfigShow(t.TempDir(), true, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"unknown_license": "block"`) {
		t.Errorf("JSON view does not report the effective unknown_license:\n%s", out)
	}
	if !strings.Contains(out, `"unknown_license_is_default": true`) {
		t.Errorf("JSON view does not mark the value as a default:\n%s", out)
	}
}

// A config file that is empty or not a mapping is "nothing set", not an error:
// every key then resolves to its built-in default and the view says so.
func TestConfigShow_EmptyFileRendersAllDefaults(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findSetting(t, buf.String(), "preferences.log_level"); got != "warn  (default)" {
		t.Errorf("log_level = %q, want %q", got, "warn  (default)")
	}
}

// A malformed config file must be refused, not silently rendered as an
// all-defaults view that no command actually uses.
func TestConfigShow_MalformedFileIsRefused(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: \"2\"\n  bad: ["), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err == nil {
		t.Fatal("expected an error for a malformed config file")
	}
}

// The scope-keyed rule lookup must not depend on list position: reordering the
// file's rules must not change which rule a reader is told about.
func TestEffectiveUnknownLicense_MatchesRuleByScopeNotPosition(t *testing.T) {
	raw, err := parseRawConfigDoc([]byte(
		"license_policy:\n  rules:\n    - scope: tool\n      unknown_license: allow\n    - scope: production\n"))
	if err != nil {
		t.Fatalf("parseRawConfigDoc: %v", err)
	}
	prod := domain.LicensePolicyRule{Scope: "production"}
	got, explicit := effectiveUnknownLicense(prod, raw)
	if got != domain.UnknownLicenseBlock || explicit {
		t.Errorf("production = (%q, explicit=%v), want (block, explicit=false)", got, explicit)
	}
	tool := domain.LicensePolicyRule{Scope: "tool", UnknownLicense: domain.UnknownLicenseAllow}
	got, explicit = effectiveUnknownLicense(tool, raw)
	if got != domain.UnknownLicenseAllow || !explicit {
		t.Errorf("tool = (%q, explicit=%v), want (allow, explicit=true)", got, explicit)
	}
}

// A rules list whose entries are not mappings, or a license_policy that is not
// a mapping, must answer "not set" rather than panic.
func TestRawConfigDoc_MalformedShapesAnswerNotSet(t *testing.T) {
	for name, src := range map[string]string{
		"policy not a map":     "license_policy: hello\n",
		"rules not a list":     "license_policy:\n  rules: hello\n",
		"rule entry not a map": "license_policy:\n  rules:\n    - hello\n",
		"scope mismatch":       "license_policy:\n  rules:\n    - scope: tool\n",
	} {
		raw, err := parseRawConfigDoc([]byte(src))
		if err != nil {
			t.Fatalf("%s: parseRawConfigDoc: %v", name, err)
		}
		if raw.ruleIsSet("production", "unknown_license") {
			t.Errorf("%s: reported the key as set", name)
		}
	}
	raw, err := parseRawConfigDoc([]byte("preferences: hello\n"))
	if err != nil {
		t.Fatalf("parseRawConfigDoc: %v", err)
	}
	if raw.isSet("preferences", "json") {
		t.Error("scalar section reported a nested key as set")
	}
}

// An unset rule default resolves to the implicit allow the domain applies; an
// empty cell would say the rule has no default at all.
func TestOutcomeOrAllow_NamesTheImplicitAllow(t *testing.T) {
	if got := outcomeOrAllow(""); got != "allow" {
		t.Errorf("unset default = %q, want allow", got)
	}
	if got := outcomeOrAllow(domain.PolicyOutcomeWarn); got != "warn" {
		t.Errorf("set default = %q, want warn", got)
	}
}

// Categories merge by name, so the default marker is per-category: a file that
// names one category has not set the built-ins it leaves alone.
func TestConfigShow_CategoryDefaultMarkerIsPerName(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	cfg := domain.DefaultConfig()
	cfg.LicensePolicy.Categories["permissive"] = []string{"MIT"}
	activeConfig = cfg

	dir := t.TempDir()
	content := "version: \"2\"\nlicense_policy:\n  categories:\n    permissive: [MIT]\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, false, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if got := findSetting(t, out, "license_policy.categories.permissive"); got != "[MIT]" {
		t.Errorf("named category = %q, want %q (set, not a default)", got, "[MIT]")
	}
	if got := findSetting(t, out, "license_policy.categories.restricted"); !strings.HasSuffix(got, "(default)") {
		t.Errorf("unnamed category = %q, want it marked as a default", got)
	}
}

// budgetedWriter fails after n successful writes so both the header and the row
// write paths can be exercised.
type budgetedWriter struct {
	remaining int
}

func (w *budgetedWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errWriteRefused
	}
	w.remaining--
	return len(p), nil
}

var errWriteRefused = errors.New("write refused")

// A write failure while rendering must be reported, not swallowed into a
// truncated view that reads as a complete answer.
func TestWriteEffectiveConfig_WriteErrorsAreReported(t *testing.T) {
	raw, err := parseRawConfigDoc(nil)
	if err != nil {
		t.Fatalf("parseRawConfigDoc: %v", err)
	}
	for name, w := range map[string]*budgetedWriter{
		"header fails": {remaining: 0},
		"row fails":    {remaining: 1},
	} {
		if err := writeEffectiveConfig(w, domain.DefaultConfig(), raw); !errors.Is(err, errWriteRefused) {
			t.Errorf("%s: err = %v, want the write error", name, err)
		}
	}
}

// The JSON view must refuse a malformed file too, rather than report an
// all-defaults posture that no command is running under.
func TestConfigShow_JSONMalformedFileIsRefused(t *testing.T) {
	prev := activeConfig
	defer func() { activeConfig = prev }()
	activeConfig = domain.DefaultConfig()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("version: \"2\"\n  bad: ["), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var buf bytes.Buffer
	if err := runStoreConfigShow(dir, true, &buf); err == nil {
		t.Fatal("expected an error for a malformed config file")
	}
}

// settingSources decodes the per-key provenance out of the `config show --json`
// document.
func settingSources(t *testing.T, doc []byte) map[string]configSettingResult {
	t.Helper()
	var got configShowResult
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("decoding config show JSON: %v", err)
	}
	if len(got.Settings) == 0 {
		t.Fatalf("the document carries no settings, so a consumer cannot tell a setting from a default:\n%s", doc)
	}
	out := make(map[string]configSettingResult, len(got.Settings))
	for _, s := range got.Settings {
		out[s.Key] = s
	}
	return out
}

// TestConfigShowJSON_SeparatesConfiguredFromDefaulted is the defect: the typed
// blocks report what is in force and cannot report where it came from, because
// once the defaults are merged a value set to the default and a value never set
// are the same bytes. An operator asking "can I rely on this gate" is asking the
// second question.
//
// Both directions, on both halves of the answer: a store with no file, where
// every value is a built-in default and the document has to say the file is
// absent; and a store with a file, where the keys it names read as configured
// and the keys it leaves out still read as defaults.
func TestConfigShowJSON_SeparatesConfiguredFromDefaulted(t *testing.T) {
	prevCfg, prevErr := activeConfig, activeConfigErr
	defer func() { activeConfig, activeConfigErr = prevCfg, prevErr }()
	activeConfigErr = nil

	t.Run("no file: every value is a built-in default", func(t *testing.T) {
		activeConfig = domain.DefaultConfig()
		dir := t.TempDir()

		var buf bytes.Buffer
		if err := runStoreConfigShow(dir, true, &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got configShowResult
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("decoding config show JSON: %v", err)
		}
		if got.ConfigFile.Present {
			t.Errorf("config_file.present = true for a store with no config.yaml")
		}
		if got.ConfigFile.Path != filepath.Join(dir, "config.yaml") {
			t.Errorf("config_file.path = %q, want the store's config.yaml", got.ConfigFile.Path)
		}
		for _, s := range got.Settings {
			if s.Source != configSourceDefault {
				t.Errorf("%s reports source %q with no file to have come from", s.Key, s.Source)
			}
		}
	})

	t.Run("a file: the keys it names are configured, the rest are not", func(t *testing.T) {
		cfg := domain.DefaultConfig()
		cfg.Preferences.JSON = true
		cfg.Staleness.TTL = 6 * time.Hour
		activeConfig = cfg

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
			[]byte("version: \"2\"\npreferences:\n  json: true\nstaleness:\n  ttl: 6h\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		var buf bytes.Buffer
		if err := runStoreConfigShow(dir, true, &buf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got configShowResult
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("decoding config show JSON: %v", err)
		}
		if !got.ConfigFile.Present {
			t.Errorf("config_file.present = false for a store that has a config.yaml")
		}
		byKey := settingSources(t, buf.Bytes())
		for key, want := range map[string]configSettingResult{
			// Set in the file, and the value in force is the one it names.
			"preferences.json": {Key: "preferences.json", Value: "true", Source: configSourceFile},
			"staleness.ttl":    {Key: "staleness.ttl", Value: "6h0m0s", Source: configSourceFile},
			// In the same block as a configured key, and still a default: this is
			// why the claim is per value and not per section.
			"preferences.progress": {Key: "preferences.progress", Value: "true", Source: configSourceDefault},
			"preferences.log_level": {Key: "preferences.log_level", Value: "warn",
				Source: configSourceDefault},
		} {
			if got := byKey[key]; got != want {
				t.Errorf("%s = %+v, want %+v", key, got, want)
			}
		}
	})
}

// TestConfigShowJSON_ProvenanceIsDataNotProse holds the new field to the parity
// guard's prose rule: the sentence the text prints, moved into a string value,
// has changed channel and not form.
func TestConfigShowJSON_ProvenanceIsDataNotProse(t *testing.T) {
	prevCfg, prevErr := activeConfig, activeConfigErr
	defer func() { activeConfig, activeConfigErr = prevCfg, prevErr }()
	activeConfig, activeConfigErr = domain.DefaultConfig(), nil

	var buf bytes.Buffer
	if err := runStoreConfigShow(t.TempDir(), true, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding config show JSON: %v", err)
	}
	var strs []string
	jsonStrings(doc, &strs)

	words := statementWords("no config file at " + filepath.Join("x", "config.yaml") +
		" — nothing is set in this store, so every value below is a built-in default")
	for _, s := range strs {
		if isStatementProse(s, words) {
			t.Errorf("the document carries the absent-file sentence as prose in a scalar (%q); field the facts instead", s)
		}
	}
}

// TestConfigShowText_UnchangedByTheProvenanceField is decision 3 on this
// command: the document gained a field, and the text a person reads did not
// move. Byte for byte, on both channels, in both file states.
//
// The bytes themselves are recorded in test/golden/cmd/config_show_text_no_file
// .golden; what this pins is the property that channel selection is the ONLY
// difference between the two runs — that the JSON path cannot start printing to
// the text one, and that neither writes to stderr.
func TestConfigShowText_UnchangedByTheProvenanceField(t *testing.T) {
	prevCfg, prevErr := activeConfig, activeConfigErr
	defer func() { activeConfig, activeConfigErr = prevCfg, prevErr }()
	activeConfig, activeConfigErr = domain.DefaultConfig(), nil

	for _, tc := range []struct {
		name  string
		write []byte
	}{
		{name: "no file"},
		{name: "a file", write: []byte("version: \"2\"\npreferences:\n  json: true\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.write != nil {
				if err := os.WriteFile(filepath.Join(dir, "config.yaml"), tc.write, 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
			var text bytes.Buffer
			if err := runStoreConfigShow(dir, false, &text); err != nil {
				t.Fatalf("text: unexpected error: %v", err)
			}
			if strings.Contains(text.String(), `"source"`) || strings.Contains(text.String(), `"settings"`) {
				t.Errorf("the text channel carries the document's provenance fields:\n%s", text.String())
			}
			// The text is the raw file (when there is one) followed by the
			// effective section, and nothing else: a new field must not have
			// appended a line to it.
			body := text.String()
			if tc.write != nil && !strings.HasPrefix(body, string(tc.write)) {
				t.Errorf("text no longer opens with the raw file:\n%s", body)
			}
			if !strings.HasSuffix(body, "  (default)\n") {
				t.Errorf("text no longer ends with the last effective-configuration row:\n%s", body)
			}
		})
	}
}
