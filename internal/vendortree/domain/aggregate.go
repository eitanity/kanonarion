package domain

import (
	"fmt"
	"sort"
	"strings"
)

// Aggregate reconciles the raw scan inputs into the classified module set and
// findings. It is the pure heart of every discrepancy axis the ticket
// enumerates is decided here, deterministically, with no I/O.
//
// Axes, in the order findings are emitted per module then globally:
//
// 1. modules.txt entry with no files under vendor/ → MissingFromVendor
// 2. vendored module with no go.sum entry for the coordinate its bytes are, or
// whose go.sum-verified zip kanonarion does not hold → Unverified (absence of
// an oracle is uncertainty, never a clean pass)
// 3. a file under vendor/ that the verified zip does not publish, or publishes
// with different bytes → Drift, one finding per file
// 4. modules.txt version ≠ go.mod require version → VersionMismatch
// 5. files under vendor/ for a module modules.txt
// does not list → ExtraInVendor
// 6. go.mod require absent from modules.txt → MissingFromModulesTxt
//
// It also returns the scope statement: how much of the vendored tree the
// reconciliation describes, and every module it does not with the reason. A
// module modules.txt lists with no package under it is out of scope by
// construction — it emits no finding at all, and appears only there.
//
// Every go.sum lookup goes through the module's ATTESTED coordinate, not the
// name of the directory its files sit in. A replaced module is vendored under
// the original path while go.sum attests the replacement, so keying the lookup
// on the directory's name asks go.sum about bytes the tree does not hold. The
// three answers that lookup can give are kept apart in the finding text, because
// they are three different things a reader has to act on differently: the bytes
// were checked against the replacement (no finding, and both coordinates are on
// the module record); nothing exists to check them against, which a filesystem
// replacement guarantees; or a checksum exists and the bytes disagree with it,
// which stays a hard stop.
func Aggregate(in ParseResult) ([]VendoredModule, []Finding, VendorScope) {
	listed := make(map[string]bool, len(in.ModulesTxt))
	mods := make([]VendoredModule, 0, len(in.ModulesTxt))
	var findings []Finding

	for _, e := range in.ModulesTxt {
		listed[e.Path] = true
		m := VendoredModule{
			Path:               e.Path,
			Version:            e.Version,
			Explicit:           e.Explicit,
			Dir:                in.VendorDir + "/" + e.Path,
			Present:            in.PresentDirs[e.Path],
			PackageCount:       e.PackageCount,
			ReplacementPath:    e.ReplacementPath,
			ReplacementVersion: e.ReplacementVersion,
		}
		attPath, attVersion, attested := e.AttestedCoordinate()

		switch {
		case !m.Present && m.PackageCount == 0:
			// modules.txt names the module and lists no package under it: no
			// package of the build imports it, so `go mod vendor` wrote no
			// directory. The tree is exactly as the toolchain left it. This is
			// not drift and must never be reported as a missing module — the
			// scope statement is where the reader is told the document
			// describes nothing of it, and why.
		case !m.Present:
			findings = append(findings, Finding{
				Kind: FindingMissingFromVendor, Module: e.Path, Version: e.Version,
				Detail: "modules.txt lists this module but no files exist under vendor/",
			})
		default:
			if attested {
				m.ExpectedHash = in.GoSum[attPath+"@"+attVersion]
			}
			files := in.Files[e.Path]
			switch {
			case !attested:
				findings = append(findings, Finding{
					Kind: FindingUnverified, Module: e.Path, Version: e.Version,
					Detail: "vendor/modules.txt replaces this module with the filesystem path " + e.ReplacementPath +
						", which publishes no module and so has no go.sum checksum by construction; there is nothing for the vendored bytes to be checked against",
				})
			case m.ExpectedHash == "":
				findings = append(findings, Finding{
					Kind: FindingUnverified, Module: e.Path, Version: e.Version,
					Detail: noChecksumDetail(e, attPath, attVersion),
				})
			case !files.ZipHeld:
				findings = append(findings, Finding{
					Kind: FindingUnverified, Module: e.Path, Version: e.Version,
					Detail: "go.sum records a checksum for " + attPath + " " + attVersion +
						" but the module zip it verifies is not held; the vendored tree has nothing to be compared against",
					Expected: m.ExpectedHash,
				})
			default:
				m.FilesCompared = len(files.Vendored)
				findings = append(findings, driftFindings(e.Path, e.Version, oracleName(e, attPath, attVersion), files)...)
			}
		}

		if reqV, ok := in.GoModRequires[e.Path]; ok && reqV != e.Version {
			findings = append(findings, Finding{
				Kind: FindingVersionMismatch, Module: e.Path, Version: e.Version,
				Detail:   "vendor/modules.txt version disagrees with the go.mod require version",
				Expected: reqV, Actual: e.Version,
			})
		}
		mods = append(mods, m)
	}

	// Files vendored for a module modules.txt never lists. The map order does not
	// survive: the module is the map key, so SortFindings — which every caller
	// runs before hashing or serialising — totally orders what this appends.
	for path := range in.PresentDirs {
		if !listed[path] {
			findings = append(findings, Finding{
				Kind: FindingExtraInVendor, Module: path,
				Detail: "files exist under vendor/ for a module vendor/modules.txt does not list",
			})
		}
	}

	// go.mod requires that the vendored tree omits entirely. Ordered by
	// SortFindings on the module, as above.
	for path, v := range in.GoModRequires {
		if !listed[path] {
			findings = append(findings, Finding{
				Kind: FindingMissingFromModulesTxt, Module: path, Version: v,
				Detail: "go.mod requires this module but vendor/modules.txt does not list it",
			})
		}
	}

	return mods, findings, ScopeOverTree(mods, nil)
}

// noChecksumDetail is the statement owed a module whose attested coordinate
// genuinely has no go.sum line. It names that coordinate, and for a replaced
// module names both — a reader told only that "github.com/PaesslerAG/gval has
// no checksum" would go looking in go.sum under a name the build never
// resolved, and conclude the tool was wrong.
func noChecksumDetail(m VendoredModule, attPath, attVersion string) string {
	if !m.IsReplaced() {
		return "no go.sum entry; vendored tree integrity cannot be verified"
	}
	return "vendor/modules.txt replaces this module with " + attPath + " " + attVersion +
		", which is the coordinate go.sum would attest, and go.sum records no entry for it;" +
		" vendored tree integrity cannot be verified"
}

// oracleName describes, for a finding a reader has to act on, which module's
// published zip the vendored files were held against. For a replaced module
// that is not the module the directory is named for, and saying so is the
// difference between a reader who can reproduce the check and one who cannot.
func oracleName(m VendoredModule, attPath, attVersion string) string {
	if !m.IsReplaced() {
		return "the module's go.sum-verified zip"
	}
	return "the go.sum-verified zip of " + attPath + " " + attVersion +
		", the replacement vendor/modules.txt names for this module"
}

// driftFindings compares the files vendor/ holds for one module against the
// files the module's go.sum-verified zip publishes, and returns one finding per
// file that is not what the zip says it is.
//
// The comparison is deliberately one-directional. Every file vendor/ holds must
// be accounted for by the zip, because a file that is in the tree the project
// compiles and is not in the published module is either an edit or an
// insertion, which is exactly the tampering this axis exists to catch. A file
// the zip publishes and vendor/ omits is `go mod vendor` pruning to the
// imported packages — it is the normal shape of a vendored tree and says
// nothing about the integrity of the files that are there.
//
// Findings are emitted in file-path order so a re-scan of an unchanged tree
// hashes identically.
//
// oracle names the published artefact the comparison was made against, in the
// reader's words, so a replaced module's findings say which module's zip they
// were held to.
func driftFindings(path, version, oracle string, files ModuleFiles) []Finding {
	names := make([]string, 0, len(files.Vendored))
	for name := range files.Vendored {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []Finding
	for _, name := range names {
		vendored := files.Vendored[name]
		published, ok := files.Zip[name]
		switch {
		case strings.HasPrefix(vendored, DigestIrregularPrefix):
			out = append(out, Finding{
				Kind: FindingDrift, Module: path, Version: version, File: name,
				Detail: "this path under vendor/ is not a regular file, so its content is not what the scan measured; " +
					oracle + " holds only regular files",
				Expected: published, Actual: vendored,
			})
		case !ok:
			out = append(out, Finding{
				Kind: FindingDrift, Module: path, Version: version, File: name,
				Detail: "this file exists under vendor/ but " + oracle + " does not publish it",
				Actual: vendored,
			})
		case published != vendored:
			out = append(out, Finding{
				Kind: FindingDrift, Module: path, Version: version, File: name,
				Detail:   "this vendored file's content differs from " + oracle,
				Expected: published, Actual: vendored,
			})
		}
	}
	return out
}

// OverallStatus is "clean" iff there are no findings. Absence of findings over
// an actually-reconciled tree is a confident clean (distinct from the
// not-analysed case the query layer surfaces via found=false, per).
func OverallStatus(findings []Finding) string {
	if len(findings) == 0 {
		return "clean"
	}
	return "findings"
}

// FindingSummary is a short human label used in CLI gate messages.
func (f Finding) FindingSummary() string {
	subject := f.Module
	if f.File != "" {
		subject = f.Module + "/" + f.File
	}
	if f.Expected != "" || f.Actual != "" {
		return fmt.Sprintf("%s %s (expected %s, got %s)", f.Kind, subject, f.Expected, f.Actual)
	}
	return fmt.Sprintf("%s %s", f.Kind, subject)
}
