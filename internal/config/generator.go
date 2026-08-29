package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// knownSections is the ordered list of top-level config sections this binary produces.
// "version" is excluded because it is not a standalone appendable block.
//
// This list must stay in lockstep with the top-level keys of the config schema
// (see the configYAML wire struct): a schema section absent here is undiscoverable
// via `config init` and is never appended to an existing file on upgrade.
var knownSections = []string{
	"preferences", "license_policy", "license_overrides",
	"copyright_declarations", "callgraph",
	"staleness",
	"directive_policy", "godebug_policy", "vendor_policy", "fips_policy",
	"fetch_policy",
}

// sectionDefaults maps a top-level section name to the YAML block appended
// when that section is absent from an existing config file.
var sectionDefaults = map[string]string{
	"preferences": `
preferences:
  # Output preferences. Each key is commented out so it inherits the live
  # built-in default; uncomment and set a value only to override it. A key
  # left commented is NOT frozen to disk, so built-in default changes in a
  # new kanonarion version take effect automatically.
  #
  # Emit JSON output for every command (equivalent to passing --json).
  # json: false
  # Log level: debug | info | warn | error
  # log_level: warn
  # Throttled fetch-phase progress heartbeat on long walk/inspect runs, written
  # to stderr (never stdout, so --json is unaffected). Set false (or pass
  # --no-progress) for fully silent runs.
  # progress: true
`,
	"license_policy": `
license_policy:
  # License policy is a sparse overlay on the built-in defaults: uncomment and
  # edit only what you want to change. Setting one category adds or overrides
  # it and keeps the others; defining 'rules' replaces the built-in rules.
  # Anything left commented keeps its live built-in default (shown below).
  #
  # Named groups of SPDX identifiers. Reference these names in rules below.
  # categories:
  #   permissive:      [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
  #   weak_copyleft:   [LGPL-2.1-only, LGPL-3.0-only, MPL-2.0]
  #   strong_copyleft: [GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only, AGPL-3.0-only]
  #   restricted:      [SSPL-1.0, BSL-1.1, AGPL-3.0-only]
  # Per-scope rules. Outcomes: allow | notify | warn.
  # Categories not listed resolve to 'default'; absent default resolves to allow.
  # rules:
  #   - scope: production
  #     allow:   [permissive]
  #     notify:  [weak_copyleft]
  #     warn:    [strong_copyleft, restricted]
  #     default: allow
  #   - scope: tool
  #     allow:   [permissive, weak_copyleft, strong_copyleft]
  #     notify:  [restricted]
  #     default: allow
`,
	"license_overrides": `
license_overrides:
  # Correct scanner gaps: map module path (optionally @version) to an SPDX ID.
  # golang.org/x/mod: MIT
`,
	"copyright_declarations": `
copyright_declarations:
  # Copyright lines a human read upstream, for modules whose archive carries
  # none, so 'notice' can publish an attribution document instead of refusing.
  # Every field is required: without an author, a date and a cited basis the
  # line cannot be checked by anyone reading the document. An extracted notice
  # always wins — a declaration beside one is kept as corroboration.
  # example.com/mod:
  #   copyright: "Copyright 2019 Example Authors"
  #   declared_by: "you@example.com"
  #   declared_on: "2026-01-31"
  #   basis: "LICENSE header at example.com/mod v1.2.3, read 2026-01-31"
`,
	"callgraph": `
callgraph:
  # Package import paths excluded from call-tree analysis. Defaults to none;
  # uncomment to exclude specific packages.
  # exclude:
  #   - github.com/some/huge/package
`,
	"staleness": `
staleness:
  # How long a recorded latest-version lookup may be served before the module
  # proxy is asked again. Commands that report staleness (latest, audit) write
  # every successful lookup to the store and read it back inside this window,
  # and always state the lookup time they used, so a served answer is never
  # mistaken for a live one. Pass --fresh to bypass the ledger for one run.
  #
  # Set to 0 to disable serving entirely (every command re-pays the sweep).
  # ttl: 1h
  #
  # How many newer-major probe requests may be in flight at once. The probe asks
  # whether a path one major above the pin exists, which is one request per
  # module in the closure, and issuing them serially is what made a large sweep
  # take tens of minutes. Wider is not simply faster: past the default the proxy
  # starts answering 200 with an empty body, which is a lost answer rather than
  # an error. Set to 0 for a serial probe.
  # probe_concurrency: 16
`,
	"directive_policy": `
directive_policy:
  # Governs go.mod/go.work replace & exclude directives by risk class. Every
  # outcome is one of: allow | notify | warn. Uncomment to override; a key left
  # commented keeps its live built-in default (shown below).
  #
  # replace -> a local filesystem path (highest risk: no remote checksum).
  # local_path_replace: warn
  # replace -> a different module path (a fork).
  # module_path_replace: warn
  # replace -> a different version of the same module.
  # version_replace: notify
  # exclude of a version newer than the resolved one.
  # exclude_newer: warn
  # exclude of a version older than the resolved one.
  # exclude_older: allow
  # unclassified directive.
  # default: notify
`,
	"godebug_policy": `
godebug_policy:
  # Governs GODEBUG / //go:debug settings by versioned risk tier. Every outcome
  # is one of: allow | notify | warn. Uncomment to override; a key left commented
  # keeps its live built-in default (shown below).
  #
  # red = security-weakening settings.
  # red: warn
  # amber = behaviour-changing but not security-weakening.
  # amber: notify
  # green = benign / informational.
  # green: allow
`,
	"vendor_policy": `
vendor_policy:
  # Governs vendored-tree analysis. on_drift and on_inconsistency outcomes are
  # each one of: allow | notify | warn. Uncomment to override; a key left
  # commented keeps its live built-in default (shown below).
  #
  # vendored tree hash disagrees with the go.sum checksum.
  # on_drift: warn
  # vendor/modules.txt is inconsistent with go.mod.
  # on_inconsistency: warn
  # Treat the vendored set as the only source of truth (no proxy fallback).
  # vendor_only: false
`,
	"fips_policy": `
fips_policy:
  # Governs FIPS toolchain eligibility assessment. on_deviation outcome is one
  # of: allow | notify | warn. Uncomment to override; a key left commented keeps
  # its live built-in default (shown below).
  #
  # Require FIPS eligibility (a non-eligible build counts as a deviation).
  # required: false
  # Outcome when a non-FIPS algorithm or cgo-crypto use is detected.
  # on_deviation: warn
`,
	"fetch_policy": `
fetch_policy:
  # Governs which forges kanonarion may hand to a git subprocess when it
  # verifies a module's VCS provenance. Uncomment to override; the key left
  # commented keeps the built-in host set (shown below) in ADVISORY mode,
  # where a host outside it is reported and still contacted.
  #
  # Naming the key switches to ENFORCING mode: a host outside the list is
  # refused. An empty list is rejected at load time rather than read as
  # "trust nobody" — that is --skip-vcs-verify.
  # allowed_vcs_hosts:
  #   - bitbucket.org
  #   - codeberg.org
  #   - github.com
  #   - gitlab.com
  #   - go.googlesource.com
  #   - gopkg.in
`,
}

// DefaultYAML returns the full commented default config.yaml content.
//
// The version header is stamped from domain.SupportedSchemaVersion rather than
// written as a literal. The loader only rejects versions NEWER than supported,
// so a stale literal loads silently while claiming a schema the binary no
// longer emits — a defect no test of the load path can catch.
func DefaultYAML() []byte {
	header := fmt.Sprintf(`# kanonarion configuration — edit to customise behaviour.
# Run 'kanonarion config show' to see the resolved effective config.
version: %q
`, domain.SupportedSchemaVersion)
	out := []byte(header)
	for _, section := range knownSections {
		out = append(out, []byte(sectionDefaults[section])...)
	}
	return out
}

// EnsureConfig writes the default config file at path when it does not exist.
// When the file exists but is missing sections known to this binary, the missing
// sections are appended (non-destructive: existing content and comments are
// preserved).
func EnsureConfig(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied store-root path is intentional
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reading config %s: %w", path, err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}
		if err := os.WriteFile(path, DefaultYAML(), 0o600); err != nil { // #nosec G304 -- same path
			return fmt.Errorf("writing config %s: %w", path, err)
		}
		return nil
	}

	// File present: detect missing sections and append defaults for each.
	var existing map[string]any
	if err := yaml.Unmarshal(data, &existing); err != nil {
		// Unparseable file — leave it untouched; Parse will report the error
		// when the config is loaded.
		return nil //nolint:nilerr
	}

	var appended []byte
	for _, section := range knownSections {
		if _, ok := existing[section]; !ok {
			appended = append(appended, []byte(sectionDefaults[section])...)
		}
	}
	if len(appended) == 0 {
		return nil
	}

	data = append(data, appended...)
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G304 G703 -- same operator-supplied path
		return fmt.Errorf("writing config %s: %w", path, err)
	}
	return nil
}
