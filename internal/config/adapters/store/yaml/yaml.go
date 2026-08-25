// Package yaml implements ConfigStore by reading a YAML config file from disk.
//
// The YAML schema is versioned. The current supported schema version is "1".
// When the file is absent the adapter returns DefaultConfig without error so
// that callers need no special-case for first-run.
package yaml

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/config/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ConfigStore loads a Config from a YAML file at a fixed path.
type ConfigStore struct {
	path string
}

// New returns a ConfigStore that loads from path.
func New(path string) *ConfigStore {
	return &ConfigStore{path: path}
}

// LoadConfig reads and parses the YAML file at the configured path.
// Returns DefaultConfig when the file does not exist (first-run behaviour).
func (s *ConfigStore) LoadConfig(_ context.Context) (domain.Config, error) {
	data, err := os.ReadFile(s.path) //nolint:gosec // operator-supplied store-root path is intentional
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.DefaultConfig(), nil
		}
		return domain.Config{}, fmt.Errorf("reading config file %s: %w", s.path, err)
	}
	return Parse(data)
}

// configYAML is the YAML wire format for Config.
type configYAML struct {
	Version          string            `yaml:"version"`
	Preferences      preferencesYAML   `yaml:"preferences"`
	LicensePolicy    licensePolicyYAML `yaml:"license_policy"`
	LicenseOverrides map[string]string `yaml:"license_overrides"`
	// CopyrightDeclarations is a map so an entry is addressed by coordinate,
	// and a struct value rather than a string because the line alone is not
	// auditable. Every field is required; see parseCopyrightDeclarations.
	CopyrightDeclarations map[string]copyrightDeclarationYAML `yaml:"copyright_declarations"`
	Callgraph             callgraphYAML                       `yaml:"callgraph"`
	Staleness             *stalenessYAML                      `yaml:"staleness"`

	// Unified supply-chain governance blocks (schema v2). Absent
	// blocks fall back to DefaultConfig so v1 files load unchanged.
	DirectivePolicy *directivePolicyYAML `yaml:"directive_policy"`
	GoDebugPolicy   *godebugPolicyYAML   `yaml:"godebug_policy"`
	VendorPolicy    *vendorPolicyYAML    `yaml:"vendor_policy"`
	FIPSPolicy      *fipsPolicyYAML      `yaml:"fips_policy"`
	FetchPolicy     *fetchPolicyYAML     `yaml:"fetch_policy"`
}

// copyrightDeclarationYAML is the wire form of one operator-recorded copyright.
type copyrightDeclarationYAML struct {
	Copyright  string `yaml:"copyright"`
	DeclaredBy string `yaml:"declared_by"`
	DeclaredOn string `yaml:"declared_on"`
	Basis      string `yaml:"basis"`
}

// fetchPolicyYAML is a pointer in configYAML and its list is left nil when
// absent, because absent and empty mean different things here: absent leaves
// the built-in host set advisory, while naming the key switches to enforcing.
type fetchPolicyYAML struct {
	AllowedVCSHosts []string `yaml:"allowed_vcs_hosts"`
}

type directivePolicyYAML struct {
	LocalPathReplace  string `yaml:"local_path_replace"`
	ModulePathReplace string `yaml:"module_path_replace"`
	VersionReplace    string `yaml:"version_replace"`
	ExcludeNewer      string `yaml:"exclude_newer"`
	ExcludeOlder      string `yaml:"exclude_older"`
	Default           string `yaml:"default"`
}

type godebugPolicyYAML struct {
	Red   string `yaml:"red"`
	Amber string `yaml:"amber"`
	Green string `yaml:"green"`
}

type vendorPolicyYAML struct {
	OnDrift         string `yaml:"on_drift"`
	OnInconsistency string `yaml:"on_inconsistency"`
	VendorOnly      bool   `yaml:"vendor_only"`
}

type fipsPolicyYAML struct {
	Required    bool   `yaml:"required"`
	OnDeviation string `yaml:"on_deviation"`
}

type preferencesYAML struct {
	JSON     bool   `yaml:"json"`
	LogLevel string `yaml:"log_level"`
	// Progress is a pointer so an absent key is distinguishable from an explicit
	// false: nil applies the default (true), false suppresses the heartbeat.
	Progress *bool `yaml:"progress,omitempty"`
}

type licensePolicyYAML struct {
	Categories map[string][]string `yaml:"categories"`
	Rules      []policyRuleYAML    `yaml:"rules"`
}

type policyRuleYAML struct {
	Scope          string   `yaml:"scope"`
	Allow          []string `yaml:"allow"`
	Notify         []string `yaml:"notify"`
	Warn           []string `yaml:"warn"`
	Default        string   `yaml:"default"`
	UnknownLicense string   `yaml:"unknown_license"`
}

type callgraphYAML struct {
	Exclude []string `yaml:"exclude"`
}

// stalenessYAML is a pointer in configYAML so an absent block inherits the
// built-in TTL, while an explicit "ttl: 0" can still switch the ledger off for
// reads. Merging the two would make the off switch unreachable.
type stalenessYAML struct {
	TTL string `yaml:"ttl"`
	// ProbeConcurrency is a POINTER for the same reason the block is: an absent
	// key inherits the measured default, while an explicit 0 selects the serial
	// probe. Merged, "0" and "not set" would be the same edit.
	ProbeConcurrency *int `yaml:"probe_concurrency"`
}

// parseOutcome converts a YAML outcome string to a PolicyOutcome.
// An empty string maps to the zero value (which callers treat as allow).
func parseOutcome(s string) (domain.PolicyOutcome, error) {
	switch s {
	case "", "allow":
		return domain.PolicyOutcomeAllow, nil
	case "notify":
		return domain.PolicyOutcomeNotify, nil
	case "warn":
		return domain.PolicyOutcomeWarn, nil
	default:
		return "", fmt.Errorf("unknown policy outcome %q: must be allow, notify, or warn", s)
	}
}

// parseUnknownLicense converts a YAML unknown_license string to an
// UnknownLicensePolicy. Empty maps to the zero value, which the domain
// resolves to a scope default (block for production, warn otherwise).
func parseUnknownLicense(s string) (domain.UnknownLicensePolicy, error) {
	switch s {
	case "":
		return "", nil
	case "allow":
		return domain.UnknownLicenseAllow, nil
	case "notify":
		return domain.UnknownLicenseNotify, nil
	case "warn":
		return domain.UnknownLicenseWarn, nil
	case "block":
		return domain.UnknownLicenseBlock, nil
	default:
		return "", fmt.Errorf("unknown unknown_license value %q: must be allow, notify, warn, or block", s)
	}
}

// parseStalenessTTL reads staleness.ttl as a Go duration ("1h", "30m", "0").
// An empty value keeps the built-in default rather than silently disabling the
// ledger: "staleness:" with nothing under it is an unfinished edit, not a
// decision to re-pay every proxy sweep.
func parseStalenessTTL(s string) (time.Duration, error) {
	if s == "" {
		return domain.DefaultStalenessTTL, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("staleness.ttl %q: not a duration (e.g. 1h, 30m, 0): %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("staleness.ttl %q: must not be negative (use 0 to disable the ledger)", s)
	}
	return d, nil
}

// parseCopyrightDeclarations converts and validates the copyright_declarations
// block. Validation happens here, at load, rather than at first use: an entry
// missing its author or its basis is an unfinished edit, and discovering that
// halfway through a notice run leaves the operator with a refusal that names
// the module rather than the config line that is wrong.
func parseCopyrightDeclarations(in map[string]copyrightDeclarationYAML) (map[string]domain.CopyrightDeclaration, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]domain.CopyrightDeclaration, len(in))
	for _, key := range slices.Sorted(maps.Keys(in)) {
		y := in[key]
		d := domain.CopyrightDeclaration{
			Copyright:  y.Copyright,
			DeclaredBy: y.DeclaredBy,
			DeclaredOn: y.DeclaredOn,
			Basis:      y.Basis,
		}
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("copyright_declarations.%s: %w", key, err)
		}
		out[key] = d
	}
	return out, nil
}

// Parse parses YAML config bytes into a Config. Exported so callers can
// validate config content without a filesystem path.
func Parse(data []byte) (domain.Config, error) {
	defaults := domain.DefaultConfig()

	var y configYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return domain.Config{}, fmt.Errorf("invalid YAML: %w", err)
	}

	if y.Version == "" {
		return domain.Config{}, fmt.Errorf("missing required field: version")
	}
	if y.Version > domain.SupportedSchemaVersion {
		return domain.Config{}, fmt.Errorf(
			"config schema version %q is newer than supported %q; upgrade kanonarion",
			y.Version, domain.SupportedSchemaVersion,
		)
	}

	cfg := domain.Config{
		Version: y.Version,
		Preferences: domain.Preferences{
			JSON:     y.Preferences.JSON,
			LogLevel: y.Preferences.LogLevel,
			// nil (key absent) applies the default; explicit false suppresses.
			Progress: y.Preferences.Progress == nil || *y.Preferences.Progress,
		},
		LicenseOverrides: y.LicenseOverrides,
		Callgraph: domain.CallgraphConfig{
			Exclude: y.Callgraph.Exclude,
		},
		Staleness: defaults.Staleness,
	}

	decls, err := parseCopyrightDeclarations(y.CopyrightDeclarations)
	if err != nil {
		return domain.Config{}, err
	}
	cfg.CopyrightDeclarations = decls

	if y.Staleness != nil {
		ttl, err := parseStalenessTTL(y.Staleness.TTL)
		if err != nil {
			return domain.Config{}, err
		}
		cfg.Staleness = domain.StalenessConfig{
			TTL:              ttl,
			ProbeConcurrency: defaults.Staleness.ProbeConcurrency,
		}
		if y.Staleness.ProbeConcurrency != nil {
			n := *y.Staleness.ProbeConcurrency
			if n < 0 {
				return domain.Config{}, fmt.Errorf(
					"staleness.probe_concurrency %d: must not be negative (use 0 for a serial probe)", n)
			}
			cfg.Staleness.ProbeConcurrency = n
		}
	}

	// Apply defaults for missing optional fields.
	if cfg.Preferences.LogLevel == "" {
		cfg.Preferences.LogLevel = defaults.Preferences.LogLevel
	}
	if cfg.LicenseOverrides == nil {
		cfg.LicenseOverrides = defaults.LicenseOverrides
	}
	if cfg.CopyrightDeclarations == nil {
		cfg.CopyrightDeclarations = defaults.CopyrightDeclarations
	}
	if cfg.Callgraph.Exclude == nil {
		cfg.Callgraph.Exclude = defaults.Callgraph.Exclude
	}

	// License policy is a sparse overlay on the built-in defaults, so a
	// fully-commented template (or a file that sets only one key) never
	// silently drops the rest. Categories merge by name: a file entry adds or
	// overrides that category and the built-in categories the file omits are
	// kept. Rules, being a scope-keyed whole, replace the built-in rules when
	// the file defines any; an absent rules list keeps the built-in rules.
	cfg.LicensePolicy = defaults.LicensePolicy
	if len(y.LicensePolicy.Categories) > 0 {
		merged := make(map[string][]string, len(defaults.LicensePolicy.Categories)+len(y.LicensePolicy.Categories))
		maps.Copy(merged, defaults.LicensePolicy.Categories)
		maps.Copy(merged, y.LicensePolicy.Categories)
		cfg.LicensePolicy.Categories = merged
	}
	if len(y.LicensePolicy.Rules) > 0 {
		rules := make([]domain.LicensePolicyRule, 0, len(y.LicensePolicy.Rules))
		for i, r := range y.LicensePolicy.Rules {
			outcome, err := parseOutcome(r.Default)
			if err != nil {
				return domain.Config{}, fmt.Errorf("rule %d (scope %q): %w", i, r.Scope, err)
			}
			ulp, err := parseUnknownLicense(r.UnknownLicense)
			if err != nil {
				return domain.Config{}, fmt.Errorf("rule %d (scope %q): %w", i, r.Scope, err)
			}
			rules = append(rules, domain.LicensePolicyRule{
				Scope:          r.Scope,
				Allow:          r.Allow,
				Notify:         r.Notify,
				Warn:           r.Warn,
				Default:        outcome,
				UnknownLicense: ulp,
			})
		}
		cfg.LicensePolicy.Rules = rules
	}

	if err := applyGovernance(&cfg, y, defaults); err != nil {
		return domain.Config{}, err
	}

	return cfg, nil
}

// applyGovernance maps the optional supply-chain governance blocks (schema
// v2) onto cfg. An absent block inherits DefaultConfig so a v1 file
// loads with the default governance posture; a present block's outcomes are
// validated through the domain's single coherent invariant set.
func applyGovernance(cfg *domain.Config, y configYAML, defaults domain.Config) error {
	cfg.DirectivePolicy = defaults.DirectivePolicy
	if d := y.DirectivePolicy; d != nil {
		out := func(field, s string) (domain.PolicyOutcome, error) {
			o, err := parseOutcome(s)
			if err != nil {
				return "", fmt.Errorf("directive_policy.%s: %w", field, err)
			}
			return o, nil
		}
		var err error
		dp := domain.DirectivePolicy{}
		if dp.LocalPathReplace, err = out("local_path_replace", d.LocalPathReplace); err != nil {
			return err
		}
		if dp.ModulePathReplace, err = out("module_path_replace", d.ModulePathReplace); err != nil {
			return err
		}
		if dp.VersionReplace, err = out("version_replace", d.VersionReplace); err != nil {
			return err
		}
		if dp.ExcludeNewer, err = out("exclude_newer", d.ExcludeNewer); err != nil {
			return err
		}
		if dp.ExcludeOlder, err = out("exclude_older", d.ExcludeOlder); err != nil {
			return err
		}
		if dp.Default, err = out("default", d.Default); err != nil {
			return err
		}
		cfg.DirectivePolicy = dp
	}

	cfg.GoDebugPolicy = defaults.GoDebugPolicy
	if g := y.GoDebugPolicy; g != nil {
		out := func(field, s string) (domain.PolicyOutcome, error) {
			o, err := parseOutcome(s)
			if err != nil {
				return "", fmt.Errorf("godebug_policy.%s: %w", field, err)
			}
			return o, nil
		}
		var err error
		gp := domain.GoDebugPolicy{}
		if gp.Red, err = out("red", g.Red); err != nil {
			return err
		}
		if gp.Amber, err = out("amber", g.Amber); err != nil {
			return err
		}
		if gp.Green, err = out("green", g.Green); err != nil {
			return err
		}
		cfg.GoDebugPolicy = gp
	}

	cfg.VendorPolicy = defaults.VendorPolicy
	if v := y.VendorPolicy; v != nil {
		out := func(field, s string) (domain.PolicyOutcome, error) {
			o, err := parseOutcome(s)
			if err != nil {
				return "", fmt.Errorf("vendor_policy.%s: %w", field, err)
			}
			return o, nil
		}
		var err error
		vp := domain.VendorPolicy{VendorOnly: v.VendorOnly}
		if vp.OnDrift, err = out("on_drift", v.OnDrift); err != nil {
			return err
		}
		if vp.OnInconsistency, err = out("on_inconsistency", v.OnInconsistency); err != nil {
			return err
		}
		cfg.VendorPolicy = vp
	}

	cfg.FIPSPolicy = defaults.FIPSPolicy
	if fp := y.FIPSPolicy; fp != nil {
		o, err := parseOutcome(fp.OnDeviation)
		if err != nil {
			return fmt.Errorf("fips_policy.on_deviation: %w", err)
		}
		cfg.FIPSPolicy = domain.FIPSPolicy{Required: fp.Required, OnDeviation: o}
	}

	cfg.FetchPolicy = defaults.FetchPolicy
	if fp := y.FetchPolicy; fp != nil && fp.AllowedVCSHosts != nil {
		// Validated here rather than at first use: a malformed or empty host
		// list must fail while the operator is looking at the config file, not
		// halfway through a walk. The domain owns what a usable list is.
		if _, err := fetchdomain.NewVCSHostAllowlist(fp.AllowedVCSHosts); err != nil {
			return fmt.Errorf("fetch_policy.allowed_vcs_hosts: %w", err)
		}
		cfg.FetchPolicy = domain.FetchPolicy{AllowedVCSHosts: fp.AllowedVCSHosts}
	}

	if err := cfg.ValidateGovernance(); err != nil {
		return fmt.Errorf("invalid governance policy: %w", err)
	}
	return nil
}
