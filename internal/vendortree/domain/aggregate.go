package domain

import "fmt"

// Aggregate reconciles the raw scan inputs into the classified module set and
// findings. It is the pure heart of every discrepancy axis the ticket
// enumerates is decided here, deterministically, with no I/O.
//
// Axes, in the order findings are emitted per module then globally:
//
// 1. modules.txt entry with no files under vendor/ → MissingFromVendor
// 2. vendored module with no go.sum entry → Unverified (
// absence of a checksum is uncertainty, never a clean pass)
// 3. recomputed hash ≠ go.sum hash → Drift (both hashes
// reported)
// 4. modules.txt version ≠ go.mod require version → VersionMismatch
// 5. files under vendor/ for a module modules.txt
// does not list → ExtraInVendor
// 6. go.mod require absent from modules.txt → MissingFromModulesTxt
func Aggregate(in ParseResult) ([]VendoredModule, []Finding) {
	listed := make(map[string]bool, len(in.ModulesTxt))
	mods := make([]VendoredModule, 0, len(in.ModulesTxt))
	var findings []Finding

	for _, e := range in.ModulesTxt {
		listed[e.Path] = true
		m := VendoredModule{
			Path:     e.Path,
			Version:  e.Version,
			Explicit: e.Explicit,
			Dir:      in.VendorDir + "/" + e.Path,
			Present:  in.PresentDirs[e.Path],
		}
		key := e.Path + "@" + e.Version

		switch {
		case !m.Present:
			findings = append(findings, Finding{
				Kind: FindingMissingFromVendor, Module: e.Path, Version: e.Version,
				Detail: "modules.txt lists this module but no files exist under vendor/",
			})
		default:
			m.ComputedHash = in.ComputedHashes[e.Path]
			m.ExpectedHash = in.GoSum[key]
			switch {
			case m.ExpectedHash == "":
				findings = append(findings, Finding{
					Kind: FindingUnverified, Module: e.Path, Version: e.Version,
					Detail: "no go.sum entry; vendored tree integrity cannot be verified",
				})
			case m.ComputedHash != m.ExpectedHash:
				findings = append(findings, Finding{
					Kind: FindingDrift, Module: e.Path, Version: e.Version,
					Detail:   "vendored tree hash does not match the expected go.sum checksum",
					Expected: m.ExpectedHash, Actual: m.ComputedHash,
				})
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

	// Files vendored for a module modules.txt never lists.
	for path := range in.PresentDirs {
		if !listed[path] {
			findings = append(findings, Finding{
				Kind: FindingExtraInVendor, Module: path,
				Detail: "files exist under vendor/ for a module vendor/modules.txt does not list",
			})
		}
	}

	// go.mod requires that the vendored tree omits entirely.
	for path, v := range in.GoModRequires {
		if !listed[path] {
			findings = append(findings, Finding{
				Kind: FindingMissingFromModulesTxt, Module: path, Version: v,
				Detail: "go.mod requires this module but vendor/modules.txt does not list it",
			})
		}
	}

	return mods, findings
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
	if f.Expected != "" || f.Actual != "" {
		return fmt.Sprintf("%s %s (expected %s, got %s)", f.Kind, f.Module, f.Expected, f.Actual)
	}
	return fmt.Sprintf("%s %s", f.Kind, f.Module)
}
