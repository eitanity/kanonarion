package domain

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// NativeFIPS140Variant is the toolchain variant recorded when capability
// comes from the standard toolchain's native FIPS 140-3 mode (the Go
// Cryptographic Module) rather than an out-of-tree distribution.
const NativeFIPS140Variant = "go-fips140"

// nativeFIPS140MinGo is the first Go language version whose standard
// toolchain ships the Go Cryptographic Module; below it a fips140 directive
// has no effect and the toolchain is not native-FIPS capable.
const nativeFIPS140MinGo = "v1.24.0"

// recogniseNativeFIPS reports the native-FIPS variant when the standard
// toolchain's FIPS 140-3 mode is both available (go version >= 1.24) and
// requested (a fips140 godebug value other than "off"). It returns "" — not
// capable — otherwise, so an ineffective directive (set under an older go
// version) never reads as a confident yes.
func recogniseNativeFIPS(goVersion, fips140 string) string {
	if fips140 == "" || fips140 == "off" {
		return ""
	}
	v := "v" + goVersion
	if !semver.IsValid(v) {
		return ""
	}
	if semver.Compare(semver.Canonical(v), nativeFIPS140MinGo) < 0 {
		return ""
	}
	return NativeFIPS140Variant
}

// ClassifyFinding maps a raw finding (kind + toolchain capability) onto a
// policy Category. Pure: it never inspects the value beyond Kind.
//
// Toolchain findings are compliant when ToolchainCapable is true (i.e.
// recognised on the catalogue), deviation otherwise. Algorithm imports are
// always deviations. Direct crypto/rand is recorded as compliant — under a
// FIPS-capable toolchain the runtime re-routes crypto/rand to a validated
// DRBG, so its presence is a surface fact, not a violation; under a
// non-capable toolchain the toolchain finding itself already carries the
// deviation. Cgo-crypto sits in the known cgo gap and is
// classified unknown so an unclassified crypto fact never silently passes
func ClassifyFinding(kind FindingKind, toolchainCapable bool) Category {
	switch kind {
	case FindingToolchain:
		if toolchainCapable {
			return CategoryCompliant
		}
		return CategoryDeviation
	case FindingAlgorithm:
		return CategoryDeviation
	case FindingDirectRandom:
		return CategoryCompliant
	case FindingCgoCrypto:
		return CategoryUnknown
	default:
		return CategoryUnknown
	}
}

// AssembleAssessment is the pure assembly step: from a parse result and a
// policy evaluator it produces a sorted, classified finding set; the
// toolchain capability / variant; a stable compliance-assessment line; and
// the content hash. It does not touch I/O, time, or the policy block
// directly — the caller injects an evaluator so this package stays free of
// a config import (mirroring godebug's classify/sort split).
//
// The toolchain finding is synthesised here (the scanner returns only the
// raw string) so the headline fact is always present, even when no
// algorithm findings exist.
func AssembleAssessment(
	res ParseResult,
	evaluate func(category Category) (outcome string, blocking bool),
) (
	toolchainCapable bool,
	toolchainVariant string,
	findings []Finding,
	contentHash string,
	complianceAssessment string,
) {
	toolchainVariant = RecogniseToolchain(res.ToolchainRaw)
	if toolchainVariant == "" {
		// No out-of-tree distribution marker; fall back to the standard
		// toolchain's native FIPS 140-3 mode if it is available and requested.
		toolchainVariant = recogniseNativeFIPS(res.GoVersion, res.FIPS140)
	}
	toolchainCapable = toolchainVariant != ""

	findings = append(findings, Finding{
		Kind:         FindingToolchain,
		Module:       res.ProjectModulePath,
		Toolchain:    toolchainVariant,
		ToolchainRaw: res.ToolchainRaw,
	})
	findings = append(findings, res.Findings...)

	for i := range findings {
		findings[i].Category = ClassifyFinding(findings[i].Kind, toolchainCapable)
		outcome, blocking := evaluate(findings[i].Category)
		findings[i].PolicyOutcome = outcome
		findings[i].PolicyBlocking = blocking
	}
	Sort(findings)

	complianceAssessment = composeAssessment(toolchainCapable, toolchainVariant, res.GoVersion, res.FIPS140, findings)
	contentHash = Hash(toolchainCapable, toolchainVariant, res.ToolchainRaw, findings)
	return toolchainCapable, toolchainVariant, findings, contentHash, complianceAssessment
}

// composeAssessment produces the short, deterministic compliance summary
// the consumer sees first. It is driven entirely by the (already-sorted)
// finding set so identical inputs yield identical text. The
// eligibility-vs-validation caveat lives separately on Record.Caveat —
// every emission carries both fields.
func composeAssessment(toolchainCapable bool, toolchainVariant, goVersion, fips140 string, findings []Finding) string {
	if !toolchainCapable {
		return composeNotCapable(goVersion, fips140)
	}
	algoDevs := map[string]struct{}{}
	cgoMods := map[string]struct{}{}
	for _, f := range findings {
		switch f.Kind {
		case FindingAlgorithm:
			algoDevs[f.Package] = struct{}{}
		case FindingCgoCrypto:
			if f.Module != "" {
				cgoMods[f.Module] = struct{}{}
			}
		}
	}
	switch {
	case len(algoDevs) > 0:
		pkgs := keysSorted(algoDevs)
		return fmt.Sprintf("not eligible: toolchain %s recognised but non-FIPS algorithm in use: %s",
			toolchainVariant, strings.Join(pkgs, ", "))
	case len(cgoMods) > 0:
		mods := keysSorted(cgoMods)
		return fmt.Sprintf("limited: toolchain %s recognised but cgo crypto dependency(ies) %s require separate cgo analysis",
			toolchainVariant, strings.Join(mods, ", "))
	default:
		return fmt.Sprintf("eligible: toolchain %s recognised, no non-FIPS algorithm imports detected", toolchainVariant)
	}
}

// composeNotCapable explains *why* the toolchain is not FIPS-capable so the
// consumer can act, rather than reading one flat "not eligible" for every
// cause. Three distinct states:
//
//   - The toolchain already ships native FIPS 140-3 (go >= the native floor)
//     but the fips140 directive is absent or off — the mode is merely not
//     enabled; the remediation is to set fips140, named explicitly.
//   - The declared go version predates the native floor — genuinely ineligible
//     until the toolchain is upgraded.
//   - The go version is absent or unparseable and no out-of-tree FIPS
//     distribution was recognised — capability cannot be asserted.
//
// Absence is never reported as a confident, unexplained negative.
func composeNotCapable(goVersion, fips140 string) string {
	v := "v" + goVersion
	floor := strings.TrimPrefix(nativeFIPS140MinGo, "v")
	switch {
	case goVersion != "" && semver.IsValid(v) && semver.Compare(semver.Canonical(v), nativeFIPS140MinGo) >= 0:
		directiveState := "is not set"
		if fips140 == "off" {
			directiveState = "is set to off"
		}
		return fmt.Sprintf(
			"not enabled: toolchain go%s ships native FIPS 140-3 but the fips140 directive %s; set //go:debug fips140=on (or GODEBUG=fips140=on) to enable",
			goVersion, directiveState)
	case goVersion != "" && semver.IsValid(v):
		return fmt.Sprintf(
			"not eligible: toolchain go%s predates native FIPS 140-3 (requires go%s or newer)",
			goVersion, floor)
	default:
		return "not eligible: toolchain does not provide native FIPS 140-3 and no FIPS-capable distribution was recognised"
	}
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
