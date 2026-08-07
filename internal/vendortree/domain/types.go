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
// v3 drops the vendored tree's whole-directory hash from each module and names
// the offending file on a drift finding: drift is now decided per file against
// the go.sum-verified module zip, so a single tree-wide hash describes nothing
// a reader can act on.
// v4 records each module's package count and adds the scope statement, so a
// record says how much of the vendored tree it describes rather than leaving a
// correct narrowing to read as completeness.
// v5 carries the replacement coordinate a module's bytes actually are, and the
// number of files the comparison looked at, per module and in total: without
// the first a record names a module whose bytes it does not describe, and
// without the second "no drift" is a claim with no stated size.
const VendorSchemaVersion = "5"

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
//
// 0.2.0 replaces the whole-tree hash comparison with a per-file comparison
// against the go.sum-verified module zip. A re-scan of an unchanged tree now
// produces a different finding set from a 0.1.0 record, so the records are not
// interchangeable and must not be served for one another.
//
// 0.3.0 stops reporting a module that contributes no package as missing from
// the vendored tree: `go mod vendor` correctly writes no directory for it, so
// the old finding described the toolchain's normal output as drift. The
// finding set for an unchanged tree therefore differs from a 0.2.0 record's,
// and the content hash covers each module's package count as well.
//
// 0.4.0 resolves a module through vendor/modules.txt's replace clause before
// looking up go.sum, so a replaced module is checked against the checksum of
// the coordinate the build actually resolves. A 0.3.0 record reports every
// replaced module as having no go.sum entry, which is not merely less than this
// one says but the opposite of what go.sum holds, so the two records are not
// interchangeable and must not be served for one another. The content hash
// covers the replacement coordinate and the files-compared count as well.
const PipelineVersion = "0.4.0"

// FindingKind classifies a vendor reconciliation discrepancy.
type FindingKind string

const (
	// FindingDrift — a file under vendor/ is not the file the module's
	// go.sum-verified zip publishes: either its bytes differ, or the zip
	// holds no such file at all.
	//
	// Drift is decided per file, over the files vendor/ actually holds. It
	// used to be decided by hashing the whole vendored directory and
	// comparing that against go.sum's h1, which cannot work: `go mod vendor`
	// prunes to the imported packages and strips test files and go.mod,
	// while go.sum's h1 covers the complete published zip. The two hash
	// different things by construction, so every pruned module read as
	// drifted — tamper-shaped evidence for an intact tree. Files the zip
	// publishes and vendor/ omits are that pruning, and are not a finding.
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
	// PackageCount is how many packages modules.txt lists under this entry —
	// the package lines that follow its `# path version` heading.
	//
	// It is zero for a module the build list carries but no package of the
	// build imports. `go mod vendor` writes the heading anyway (the module is
	// in the graph) and vendors no directory for it, so a zero-package entry is
	// correctly absent from the tree. Without this count that absence is
	// indistinguishable from a module whose files went missing, and the tree
	// reports drift for a tree that is exactly as `go mod vendor` left it.
	PackageCount int
	// ReplacementPath and ReplacementVersion name the module vendor/modules.txt
	// says stands in for this one: the right-hand side of its `=> …` clause,
	// both empty when the entry carries none.
	//
	// They are carried because `go mod vendor` writes a replaced module's files
	// under the ORIGINAL module path, recording the replacement only on the
	// heading comment. The directory is therefore named for a module whose bytes
	// it does not hold, while the coordinate the build resolves — and so the
	// coordinate go.sum attests — is the replacement. A record naming only the
	// left-hand side describes a module that was never compiled. It is the same
	// one-node-two-names shape the walk's OriginalCoordinate already reads.
	//
	// A filesystem replacement (`=> ../fork`) carries a path and no version.
	// That absence is load-bearing rather than incidental: such a replacement
	// publishes no module zip, so go.sum can hold no line for it and there is
	// nothing for the vendored bytes to be checked against.
	ReplacementPath    string
	ReplacementVersion string
	// FilesCompared is how many files under vendor/<Path> were compared against
	// the verified module zip, file by file. It is zero for every module that
	// was not verified — an unverified module compared nothing — so the total
	// over a record is the size of the measurement the record's clean status
	// rests on. "No drift across 133 modules" says nothing a reader can argue
	// with until it says whether that was twelve files or twelve thousand.
	FilesCompared int
	// ExpectedHash is the go.sum h1 for the module's attested coordinate ("" when
	// go.sum has no entry for it, and always for a filesystem replacement, which
	// has no such coordinate). For a replaced module that is the REPLACEMENT's
	// h1, because the replacement is what the bytes under vendor/ are.
	// It names the checksum the comparison oracle — the module zip
	// kanonarion holds — was verified against, not a hash of anything under
	// vendor/. There is deliberately no counterpart hash of the vendored
	// tree: a pruned tree's whole-directory hash can never equal this value,
	// so reporting the pair side by side asserted a mismatch that was an
	// artefact of the measurement rather than a property of the tree.
	ExpectedHash string
}

// AttestedCoordinate returns the module path and version whose published
// artefact the bytes under vendor/<Path> actually are, and whether such an
// artefact exists at all.
//
// For an unreplaced module that is the module's own coordinate. For a module
// replaced by another module it is the REPLACEMENT: `go mod vendor` copied the
// replacement's source into a directory named for the original, so looking
// go.sum up under the original asks for a checksum of bytes the tree does not
// hold — and finding none, reports the two modules a project most needs
// verified, the ones whose bytes are not upstream's, as the two it cannot
// verify.
//
// attested is false for a filesystem replacement. There is no published module
// behind `=> ../fork` and go.sum can carry no line for it, so the honest answer
// is that nothing exists to check against — which is a different statement from
// a checksum that is missing, and must not borrow the original coordinate's
// checksum to look like one. Borrowing it would be worse than useless: go.sum
// may well still hold the upstream line, and comparing a fork's files against
// upstream's zip reports the fork as wholesale drift.
func (m VendoredModule) AttestedCoordinate() (path, version string, attested bool) {
	switch {
	case m.ReplacementPath == "":
		return m.Path, m.Version, true
	case m.ReplacementVersion == "":
		return "", "", false
	default:
		return m.ReplacementPath, m.ReplacementVersion, true
	}
}

// IsReplaced reports whether vendor/modules.txt names a replacement for this
// module — whether the directory's name and its bytes come from two modules.
func (m VendoredModule) IsReplaced() bool { return m.ReplacementPath != "" }

// ReplacementCoordinate renders the replacement for a reader, as
// "path version" or just "path" for the versionless filesystem form. Empty for
// an unreplaced module.
func (m VendoredModule) ReplacementCoordinate() string {
	switch {
	case m.ReplacementPath == "":
		return ""
	case m.ReplacementVersion == "":
		return m.ReplacementPath
	default:
		return m.ReplacementPath + " " + m.ReplacementVersion
	}
}

// DigestIrregularPrefix marks a vendored directory entry that is not a regular
// file (a symlink, device, pipe, …) in the digest position, suffixed with what
// it is. Its content was deliberately not read: a symlink resolves at build
// time to bytes outside the tree being measured. A published module zip holds
// only regular files, so the marker can never equal a zip digest and the entry
// always reports as drift.
const DigestIrregularPrefix = "irregular:"

// ModuleFiles is the per-file evidence for one module: what the vendored tree
// holds, and what the go.sum-verified module zip publishes. Both maps are keyed
// by the module-relative, slash-separated file path and hold that file's
// content digest ("sha256:<hex>"); a vendored entry that is not a regular file
// instead carries a DigestIrregularPrefix marker naming what it is.
//
// The zip is the oracle and the vendored tree is what is checked against it, so
// the comparison is directional: it is scoped to the subtree vendor/ actually
// holds. ZipHeld distinguishes "the oracle says these files" from "there is no
// oracle" — without it an unheld zip would present as a zip that publishes
// nothing, and every vendored file would read as drift.
type ModuleFiles struct {
	// ZipHeld reports whether kanonarion holds the module zip whose bytes
	// hash to the module's go.sum h1.
	ZipHeld bool
	// Zip maps each file the verified module zip publishes to its digest.
	Zip map[string]string
	// Vendored maps each file present under vendor/<path> to its digest,
	// excluding any subtree that is itself a separately vendored module.
	Vendored map[string]string
}

// Finding is one classified discrepancy with enough provenance for an agent
// to act: which module, which axis, and (for drift) both hashes.
type Finding struct {
	Kind     FindingKind
	Module   string // module path
	Version  string
	File     string // module-relative file path, for the per-file drift axis
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
	// Replacements maps a replacement module path to the original module path it
	// stands in for, one entry per `# original ver => replacement ver` line in
	// modules.txt.
	//
	// It exists because `go mod vendor` writes a replaced module's files under
	// the ORIGINAL module path, recording the replacement only on that comment
	// line. A consumer holding the replacement coordinate — which is what a
	// resolved build list keys on — therefore cannot find the module in
	// ModulesTxt or PresentDirs at all, and without this mapping would conclude
	// the tree does not hold a module it holds under another name.
	//
	// It is derived from the same lines ModulesTxt is and is deliberately not
	// carried onto the persisted Record: it is a reading aid for resolving a
	// coordinate against this tree, not a fact about the closure.
	Replacements map[string]string
	// GoModRequires maps module path → version from the main module's
	// require set, for the vendor-vs-go.mod consistency check.
	GoModRequires map[string]string
	// GoSum maps "path@version" → expected h1 hash (may be empty).
	GoSum map[string]string
	// PresentDirs is the set of module paths that actually have files
	// under vendor/ (top-level module directories).
	PresentDirs map[string]bool
	// Files maps module path → the per-file evidence for that module. A
	// module with no entry has no evidence at all, which the domain reports
	// as an unverified module rather than as a clean one.
	Files map[string]ModuleFiles
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
	// Scope states how much of the vendored tree this record describes, and
	// names every module it does not. A record that covers a smaller set than
	// the tree and does not say so reads as complete.
	Scope VendorScope

	ExtractedAt     time.Time
	SchemaVersion   string
	PipelineVersion string
	ContentHash     string
}
