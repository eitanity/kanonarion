package cli

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// effectiveSetting is one resolved configuration value: the dotted key an
// operator would use to read or write it, the value actually in force, and
// whether that value came from a built-in default rather than the config file.
//
// The default marker is not decoration. "unknown_license is block" and
// "unknown_license is block because nobody has set it" are different facts to
// an operator deciding whether a gate can be relied on, and a view that renders
// only the first cannot be used to answer the second.
type effectiveSetting struct {
	Key       string
	Value     string
	IsDefault bool
}

// rawConfigDoc is the config file parsed as an untyped document, used only to
// ask whether a key is present. The typed Config cannot answer that: once the
// defaults have been merged in, a value set to the default and a value never
// set are the same bytes.
type rawConfigDoc map[string]any

// parseRawConfigDoc parses the config file bytes into an untyped document.
// A file that is not a mapping (empty, or a scalar) yields an empty document —
// nothing is set — rather than an error, because the typed load already
// refused anything genuinely malformed before this point.
func parseRawConfigDoc(data []byte) (rawConfigDoc, error) {
	// Decoded into a plain map, not rawConfigDoc: yaml.v3 propagates a named
	// map type to every nested mapping, and the presence checks below assert on
	// map[string]any.
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return rawConfigDoc(doc), nil
}

// isSet reports whether the raw document explicitly carries the dotted key
// path. A key present but null ("staleness:" with nothing under it) counts as
// set — the operator wrote it, and the parser's reading of it is the parser's
// business, not this view's.
func (d rawConfigDoc) isSet(path ...string) bool {
	var cur any = map[string]any(d)
	for _, seg := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = m[seg]
		if !ok {
			return false
		}
	}
	return true
}

// ruleIsSet reports whether the file's license_policy.rules list carries a rule
// for scope that sets field. Rules are a scope-keyed whole, so the lookup is by
// scope rather than by list position: reordering the file must not change which
// rule a reader is told about.
func (d rawConfigDoc) ruleIsSet(scope, field string) bool {
	policy, ok := d["license_policy"].(map[string]any)
	if !ok {
		return false
	}
	rules, ok := policy["rules"].([]any)
	if !ok {
		return false
	}
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if s, _ := m["scope"].(string); s != scope {
			continue
		}
		_, present := m[field]
		return present
	}
	return false
}

// effectiveSettings resolves every enforced configuration key against cfg and
// the raw file, in the order an operator reads them.
func effectiveSettings(cfg domain.Config, raw rawConfigDoc) []effectiveSetting {
	var out []effectiveSetting
	add := func(key, value string, set bool) {
		out = append(out, effectiveSetting{Key: key, Value: value, IsDefault: !set})
	}

	add("version", cfg.Version, raw.isSet("version"))
	add("preferences.json", strconv.FormatBool(cfg.Preferences.JSON), raw.isSet("preferences", "json"))
	add("preferences.log_level", cfg.Preferences.LogLevel, raw.isSet("preferences", "log_level"))
	add("preferences.progress", strconv.FormatBool(cfg.Preferences.Progress), raw.isSet("preferences", "progress"))

	categoriesSet := raw.isSet("license_policy", "categories")
	for _, name := range sortedKeys(cfg.LicensePolicy.Categories) {
		add("license_policy.categories."+name,
			"["+strings.Join(cfg.LicensePolicy.Categories[name], ", ")+"]",
			categoriesSet && raw.ruleCategoryIsSet(name))
	}

	for _, r := range cfg.LicensePolicy.Rules {
		prefix := "license_policy.rules[" + r.Scope + "]."
		add(prefix+"allow", "["+strings.Join(r.Allow, ", ")+"]", raw.ruleIsSet(r.Scope, "allow"))
		add(prefix+"notify", "["+strings.Join(r.Notify, ", ")+"]", raw.ruleIsSet(r.Scope, "notify"))
		add(prefix+"warn", "["+strings.Join(r.Warn, ", ")+"]", raw.ruleIsSet(r.Scope, "warn"))
		add(prefix+"default", outcomeOrAllow(r.Default), raw.ruleIsSet(r.Scope, "default"))
		unknown, explicit := effectiveUnknownLicense(r, raw)
		add(prefix+"unknown_license", string(unknown), explicit)
	}

	for _, mod := range sortedKeys(cfg.LicenseOverrides) {
		add("license_overrides."+mod, cfg.LicenseOverrides[mod], true)
	}

	add("callgraph.exclude", "["+strings.Join(cfg.Callgraph.Exclude, ", ")+"]", raw.isSet("callgraph", "exclude"))
	add("staleness.ttl", cfg.Staleness.TTL.String(), raw.isSet("staleness", "ttl"))

	dp := cfg.DirectivePolicy
	add("directive_policy.local_path_replace", string(dp.LocalPathReplace), raw.isSet("directive_policy", "local_path_replace"))
	add("directive_policy.module_path_replace", string(dp.ModulePathReplace), raw.isSet("directive_policy", "module_path_replace"))
	add("directive_policy.version_replace", string(dp.VersionReplace), raw.isSet("directive_policy", "version_replace"))
	add("directive_policy.exclude_newer", string(dp.ExcludeNewer), raw.isSet("directive_policy", "exclude_newer"))
	add("directive_policy.exclude_older", string(dp.ExcludeOlder), raw.isSet("directive_policy", "exclude_older"))
	add("directive_policy.default", string(dp.Default), raw.isSet("directive_policy", "default"))

	gd := cfg.GoDebugPolicy
	add("godebug_policy.red", string(gd.Red), raw.isSet("godebug_policy", "red"))
	add("godebug_policy.amber", string(gd.Amber), raw.isSet("godebug_policy", "amber"))
	add("godebug_policy.green", string(gd.Green), raw.isSet("godebug_policy", "green"))

	vp := cfg.VendorPolicy
	add("vendor_policy.on_drift", string(vp.OnDrift), raw.isSet("vendor_policy", "on_drift"))
	add("vendor_policy.on_inconsistency", string(vp.OnInconsistency), raw.isSet("vendor_policy", "on_inconsistency"))
	add("vendor_policy.vendor_only", strconv.FormatBool(vp.VendorOnly), raw.isSet("vendor_policy", "vendor_only"))

	fp := cfg.FIPSPolicy
	add("fips_policy.required", strconv.FormatBool(fp.Required), raw.isSet("fips_policy", "required"))
	add("fips_policy.on_deviation", string(fp.OnDeviation), raw.isSet("fips_policy", "on_deviation"))

	// Absent is a distinct posture from empty, so the value says which one is in
	// force rather than printing "[]" for a config that never chose to enforce.
	hosts := "(unset: built-in host set, advisory)"
	if cfg.FetchPolicy.AllowedVCSHosts != nil {
		hosts = "[" + strings.Join(cfg.FetchPolicy.AllowedVCSHosts, ", ") + "] (enforcing)"
	}
	add("fetch_policy.allowed_vcs_hosts", hosts, raw.isSet("fetch_policy", "allowed_vcs_hosts"))

	return out
}

// ruleCategoryIsSet reports whether the file names category under
// license_policy.categories. Categories merge by name, so a category the file
// does not name is a built-in even when the file names others.
func (d rawConfigDoc) ruleCategoryIsSet(name string) bool {
	return d.isSet("license_policy", "categories", name)
}

// effectiveUnknownLicense resolves the UnknownLicensePolicy in force for a rule
// and reports whether the file set it. An unset field is not "no policy": the
// domain resolves it to a scope default (block for production, warn elsewhere),
// which is the value that actually gates `audit`.
func effectiveUnknownLicense(r domain.LicensePolicyRule, raw rawConfigDoc) (domain.UnknownLicensePolicy, bool) {
	explicit := raw.ruleIsSet(r.Scope, "unknown_license")
	if r.UnknownLicense == "" {
		return domain.DefaultUnknownLicense(r.Scope), explicit
	}
	return r.UnknownLicense, explicit
}

// outcomeOrAllow renders a PolicyOutcome, naming the implicit allow an unset
// default resolves to rather than printing an empty cell.
func outcomeOrAllow(o domain.PolicyOutcome) string {
	if o == "" {
		return string(domain.PolicyOutcomeAllow)
	}
	return string(o)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeEffectiveConfig renders the resolved configuration: every enforced key,
// the value in force, and whether that value is a built-in default.
func writeEffectiveConfig(w io.Writer, cfg domain.Config, raw rawConfigDoc) error {
	settings := effectiveSettings(cfg, raw)
	width := 0
	for _, s := range settings {
		if len(s.Key) > width {
			width = len(s.Key)
		}
	}
	if _, err := fmt.Fprintf(w, "\n# effective configuration (resolved; (default) = not set in this file)\n"); err != nil {
		return fmt.Errorf("writing effective config: %w", err)
	}
	for _, s := range settings {
		marker := ""
		if s.IsDefault {
			marker = "  (default)"
		}
		if _, err := fmt.Fprintf(w, "%-*s  %s%s\n", width, s.Key, s.Value, marker); err != nil {
			return fmt.Errorf("writing effective config: %w", err)
		}
	}
	return nil
}
