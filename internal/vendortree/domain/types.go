// Package domain holds the pure business rules for the vendor bounded context
// reconciling a project's vendor/ tree, vendor/modules.txt, go.mod
// require set and go.sum into a classified set of findings (drift /
// inconsistency / unverified) plus a deterministic record. It performs no
// I/O — filesystem reading, modules.txt/go.mod/go.sum parsing and per-module
// hashing are a port-backed adapter concern; policy evaluation lives in the
// config context.
//
// A vendored project (vendor/ + vendor/modules.txt, -mod=vendor builds) is
// the gold standard for reproducible/airgapped builds, and the vendored code
// is what actually compiles. Kanonarion therefore treats the vendored tree
// as a first-class input and resolves the closure from modules.txt rather
// than re-fetching from the proxy.
package domain

import (
	"errors"
	"time"
)

// VendorSchemaVersion is the version of the Record JSON schema. Bump on a
// backwards-incompatible serialisation change.
// v2 adds the ecosystem scope marker.
const VendorSchemaVersion = "2"

// EcosystemGo is the only ecosystem kanonarion records describe. The ecosystem
// field declares the schema's scope — kanonarion is fitted for Go — rather than
// enabling polyglot mode. There is deliberately no "npm" or "cargo".
const EcosystemGo = "go"

// ErrUnsupportedEcosystem is returned when a stored record's ecosystem is
// absent or holds a value other than EcosystemGo.
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem: kanonarion records are Go-only")

// PipelineVersion tracks the vendor reconciliation logic. Bump when finding
// detection or hashing changes such that a re-scan of unchanged inputs would
// differ from a cached record.
const PipelineVersion = "0.1.0"

// FindingKind classifies a vendor reconciliation discrepancy.
type FindingKind string

const (
	// FindingDrift — a vendored module's recomputed tree hash does not
	// match the expected checksum recorded in go.sum.
	FindingDrift FindingKind = "drift"
	// FindingMissingFromVendor — modules.txt lists a module but no files
	// for it exist under vendor/.
	FindingMissingFromVendor FindingKind = "missing_from_vendor"
	// FindingExtraInVendor — files exist under vendor/ for a module that
	// modules.txt does not list.
	FindingExtraInVendor FindingKind = "extra_in_vendor"
	// FindingMissingFromModulesTxt — go.mod requires a module that
	// vendor/modules.txt does not list (vendor/ stale vs go.mod).
	FindingMissingFromModulesTxt FindingKind = "missing_from_modules_txt"
	// FindingVersionMismatch — modules.txt records a different version for
	// a module than go.mod resolves it to.
	FindingVersionMismatch FindingKind = "version_mismatch"
	// FindingUnverified — a vendored module has no go.sum entry, so its
	// integrity cannot be confirmed. Per this is a surfaced
	// uncertainty, never silently treated as clean.
	FindingUnverified FindingKind = "unverified"
)

// PolicyCategory maps a finding kind onto the config VendorPolicy category
// token. Drift is its own axis; every other discrepancy (including the
// unverified uncertainty) is an inconsistency. The mapping lives here so the
// config context stays ignorant of the vendor bounded context.
func (k FindingKind) PolicyCategory() string {
	if k == FindingDrift {
		return "drift"
	}
	return "inconsistency"
}

// VendoredModule is one module reconciled from the vendored tree.
type VendoredModule struct {
	Path    string
	Version string
	// Explicit mirrors the `## explicit` marker in modules.txt (a direct
	// dependency of the main module).
	Explicit bool
	// Dir is the module's directory relative to the project root
	// (e.g. "vendor/example.com/dep"); it is the reachability target —
	// vendored code is what compiles, so walk/callgraph must analyse this,
	// not the proxy version (consumption is the shared follow-up).
	Dir string
	// Present is false when modules.txt lists the module but no files for
	// it exist under vendor/.
	Present bool
	// ComputedHash is the recomputed dirhash of the vendored module tree;
	// ExpectedHash is the go.sum h1 for Path@Version ("" when go.sum has
	// no entry). Equal & non-empty ⇒ integrity verified.
	ComputedHash string
	ExpectedHash string
}

// Finding is one classified discrepancy with enough provenance for an agent
// to act: which module, which axis, and (for drift) both hashes.
type Finding struct {
	Kind     FindingKind
	Module   string // module path
	Version  string
	Detail   string
	Expected string // expected hash / version, when applicable
	Actual   string // actual hash / version, when applicable

	// PolicyOutcome is the resolved governance verdict ("allow" | "notify"
	// | "warn"); PolicyBlocking marks a hard failure that fails the command.
	PolicyOutcome  string
	PolicyBlocking bool
}

// ParseResult is the raw, unreconciled output of the scanner port.
type ParseResult struct {
	ProjectModulePath string
	// VendorDir is the vendor directory relative to the project root
	// ("vendor"); empty when the project is not vendored.
	VendorDir string
	// VendorOnly records that the scan ran in airgapped mode (no proxy
	// contact). This scanner never contacts the proxy, so the field is an
	// asserted guarantee captured for audit.
	VendorOnly bool

	// ModulesTxt is the parsed vendor/modules.txt entry set.
	ModulesTxt []VendoredModule
	// GoModRequires maps module path → version from the main module's
	// require set, for the vendor-vs-go.mod consistency check.
	GoModRequires map[string]string
	// GoSum maps "path@version" → expected h1 hash (may be empty).
	GoSum map[string]string
	// PresentDirs is the set of module paths that actually have files
	// under vendor/ (top-level module directories).
	PresentDirs map[string]bool
	// ComputedHashes maps module path → recomputed vendored-tree dirhash.
	ComputedHashes map[string]string
}

// Record is the persisted, deterministic result of a vendored-closure scan.
type Record struct {
	// Ecosystem declares the schema's scope; always EcosystemGo.
	Ecosystem         string
	ProjectModulePath string
	VendorDir         string
	VendorOnly        bool
	Modules           []VendoredModule
	Findings          []Finding
	// OverallStatus is "clean" when there are no findings, else "findings".
	OverallStatus string

	ExtractedAt     time.Time
	SchemaVersion   string
	PipelineVersion string
	ContentHash     string
}
