package domain

// StdlibLicenseSPDX is the SPDX identifier for the Go standard library. The Go
// project (and therefore the standard library that ships with the toolchain)
// is distributed under BSD-3-Clause — a published, version-independent fact
// about the Go project, distinct from the extracted chain-of-custody evidence
// StdlibFacts carries.
const StdlibLicenseSPDX = "BSD-3-Clause"

// StdlibLicense resolves the SPDX identifier for the synthetic
// standard-library node: the licence extracted from the source tarball's
// LICENSE file when chain-of-custody facts are present, falling back to the
// known StdlibLicenseSPDX constant for a legacy or offline node that carries
// no facts. fromFacts reports which of the two answered, so a surface can
// state whether it is relaying extracted evidence or published knowledge.
//
// The fallback is deliberate and shared: the standard library ships with the
// toolchain rather than through the module proxy, so it has no fetched
// licence record, and treating a factless node as licence-undetermined would
// let the unknown-licence gate block a project over its own standard library
// — reporting as unknown a licence that is published, stable, and already
// known. Every consumer (SBOM, license-compat, audit) resolves through this
// one function so the answer cannot drift between surfaces.
func StdlibLicense(facts *StdlibFacts) (spdx string, fromFacts bool) {
	if facts != nil && facts.LicenseSPDX != "" {
		return facts.LicenseSPDX, true
	}
	return StdlibLicenseSPDX, false
}
