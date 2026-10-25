package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// configHashForm versions the canonical form below. A change to what is hashed
// changes this, so two hashes from different forms never read as one config.
const configHashForm = 1

// Hash is the content hash of the configuration's meaning: every section that
// decides an answer, with defaults resolved, sets sorted and file layout gone.
// Preferences (display) and storage (where records go, including backend
// sections) are left out because they change no answer.
func (c Config) Hash() (string, error) {
	b, err := marshalCanonical(c.canonical())
	if err != nil {
		return "", fmt.Errorf("hashing configuration: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// marshalCanonical is a seam: the canonical form holds only strings, bools,
// numbers and collections of them, so only a test makes it fail.
var marshalCanonical = json.Marshal

// canonicalConfig is the hashed form. Outcomes are the ones the evaluators
// return, so an unset key and the default it resolves to hash alike.
type canonicalConfig struct {
	Form                  int                             `json:"form"`
	LicenseCategories     map[string][]string             `json:"license_categories"`
	LicenseRules          []canonicalRule                 `json:"license_rules"`
	LicenseOverrides      map[string]LicenseOverride      `json:"license_overrides"`
	CopyrightDeclarations map[string]CopyrightDeclaration `json:"copyright_declarations"`
	CallgraphExclude      []string                        `json:"callgraph_exclude"`
	CallgraphToolchain    string                          `json:"callgraph_toolchain"`
	StalenessTTL          time.Duration                   `json:"staleness_ttl"`
	StalenessProbes       int                             `json:"staleness_probe_concurrency"`
	Directive             map[string]PolicyOutcome        `json:"directive_policy"`
	GoDebug               map[string]PolicyOutcome        `json:"godebug_policy"`
	Vendor                map[string]PolicyOutcome        `json:"vendor_policy"`
	VendorOnly            bool                            `json:"vendor_only"`
	FIPSRequired          bool                            `json:"fips_required"`
	FIPSOnDeviation       PolicyOutcome                   `json:"fips_on_deviation"`
	// AllowedVCSHosts keeps nil apart from a list: nil is advisory mode.
	AllowedVCSHosts []string `json:"allowed_vcs_hosts"`
	VulnDBMirror    string   `json:"vulndb_mirror"`
}

type canonicalRule struct {
	Scope          string               `json:"scope"`
	Allow          []string             `json:"allow"`
	Notify         []string             `json:"notify"`
	Warn           []string             `json:"warn"`
	Default        PolicyOutcome        `json:"default"`
	UnknownLicense UnknownLicensePolicy `json:"unknown_license"`
}

func (c Config) canonical() canonicalConfig {
	out := canonicalConfig{
		Form:                  configHashForm,
		LicenseCategories:     map[string][]string{},
		LicenseRules:          []canonicalRule{},
		LicenseOverrides:      map[string]LicenseOverride{},
		CopyrightDeclarations: map[string]CopyrightDeclaration{},
		CallgraphExclude:      sortedSet(c.Callgraph.Exclude),
		CallgraphToolchain:    string(c.Callgraph.Toolchain),
		StalenessTTL:          max(c.Staleness.TTL, 0),
		StalenessProbes:       max(c.Staleness.ProbeConcurrency, 0),
		VendorOnly:            c.VendorPolicy.VendorOnly,
		FIPSRequired:          c.FIPSPolicy.Required,
		FIPSOnDeviation:       FIPSPolicy{Required: true, OnDeviation: c.FIPSPolicy.OnDeviation}.Evaluate(FIPSDeviation),
		VulnDBMirror:          c.VulnDB.Mirror(),
	}
	for name, ids := range c.LicensePolicy.Categories {
		out.LicenseCategories[name] = sortedSet(ids)
	}
	for _, r := range c.LicensePolicy.Rules {
		out.LicenseRules = append(out.LicenseRules, canonicalRule{
			Scope:          r.Scope,
			Allow:          sortedSet(r.Allow),
			Notify:         sortedSet(r.Notify),
			Warn:           sortedSet(r.Warn),
			Default:        r.resolveOutcome(""),
			UnknownLicense: resolveUnknownLicense(r, true, normaliseScope(r.Scope)),
		})
	}
	for k, v := range c.LicenseOverrides {
		out.LicenseOverrides[k] = v
	}
	for k, v := range c.CopyrightDeclarations {
		out.CopyrightDeclarations[k] = v
	}
	out.Directive = outcomesOf(c.DirectivePolicy.Evaluate, DirectiveLocalPathReplace, DirectiveModulePathReplace,
		DirectiveVersionReplace, DirectiveExcludeNewer, DirectiveExcludeOlder, "")
	out.GoDebug = outcomesOf(c.GoDebugPolicy.Evaluate, GoDebugRed, GoDebugAmber, GoDebugGreen, "")
	out.Vendor = outcomesOf(c.VendorPolicy.Evaluate, VendorDrift, VendorInconsistency, "")
	if c.FetchPolicy.AllowedVCSHosts != nil {
		out.AllowedVCSHosts = sortedSet(c.FetchPolicy.AllowedVCSHosts)
	}
	return out
}

// outcomesOf records what each category evaluates to; "" stands for any
// category the policy does not name.
func outcomesOf(eval func(string) PolicyOutcome, categories ...string) map[string]PolicyOutcome {
	out := make(map[string]PolicyOutcome, len(categories))
	for _, c := range categories {
		out[c] = eval(c)
	}
	return out
}

// sortedSet is a membership list in one spelling: sorted, without repeats,
// and never nil.
func sortedSet(in []string) []string {
	out := slices.Clone(in)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
