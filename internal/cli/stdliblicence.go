package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// StdlibCustodyReader reads the recorded standard-library chain of custody for
// one toolchain version. It is the read half of the stdlib fact ledger: a
// command that reports a licence never writes to it, so it is declared here
// narrowly rather than taken as the whole store port.
type StdlibCustodyReader interface {
	// Get returns the composed measurement for a canonical Go version
	// ("go1.26.5"). The bool is false when the ledger holds none.
	Get(ctx context.Context, goVersion string) (stdlibdomain.Facts, bool, error)
}

// StdlibCustodyLister is the optional history read: every measurement the
// ledger holds for one toolchain version, oldest first. Callers type-assert
// for it, on the same terms as the licence ledger's own history read.
type StdlibCustodyLister interface {
	ListFactsFor(ctx context.Context, goVersion string) ([]stdlibdomain.Facts, error)
}

// The two bases a standard-library licence answer can rest on. They are the
// same words audit's LicenseSource column prints, so the surfaces cannot drift
// apart in what they claim the answer came from.
const (
	// stdlibLicenceBasisTarball relays evidence: the SPDX identifier extracted
	// from the acquired source tarball's LICENSE file.
	stdlibLicenceBasisTarball = "stdlib-tarball"
	// stdlibLicenceBasisKnown relays published knowledge: the BSD-3-Clause the
	// Go project distributes under, used where no measurement carries a licence.
	stdlibLicenceBasisKnown = "stdlib-known"
)

// stdlibCustodyRemedy names the command that establishes the chain of custody.
// The standard library arrives with the toolchain, never through the module
// proxy, so `kanonarion fetch` cannot take its coordinate and must never be
// offered as the way to obtain it.
const stdlibCustodyRemedy = "kanonarion walk --gomod ./go.mod"

// isStdlibPath reports whether a module path names the synthetic
// standard-library node rather than a fetchable module.
func isStdlibPath(path string) bool { return path == walkdomain.StdlibModulePath }

// isStdlibCoordinate reports whether a coordinate names the synthetic
// standard-library node rather than a fetchable module.
func isStdlibCoordinate(coord coordinate.ModuleCoordinate) bool {
	return isStdlibPath(coord.Path())
}

// stdlibLicence is the licence answer for the standard-library coordinate,
// read off the recorded chain of custody rather than a licence record — the
// standard library has none, because it is never fetched or extracted.
//
// SPDX and Basis are one axis and Verification is another. A measurement can
// establish custody and still identify no licence, so a factless answer
// (Basis stdlib-known) is not the same statement as an unestablished chain
// (Verification empty), and neither is inferred from the other.
type stdlibLicence struct {
	Coordinate coordinate.ModuleCoordinate
	// GoVersion is the canonical toolchain version the coordinate names,
	// empty when the coordinate carries no usable version.
	GoVersion string
	SPDX      string
	Basis     string
	// Verification is the recorded stdlib verification status
	// ("VerifiedGoDevChecksum", "VerifiedLocalToolchain", …). Empty means no
	// measurement was found: the chain of custody is not established here.
	Verification string
	Detail       string
	Route        string
	SourceURL    string
	VCSURL       string
	VCSRef       string
	VCSCommit    string
	SHA256       string
	AcquiredAt   time.Time
}

// Established reports whether the ledger holds a measurement for this
// toolchain version. False means nothing has looked, and the answer below it
// rests on published knowledge alone.
func (s stdlibLicence) Established() bool { return s.Verification != "" }

// resolveStdlibLicence answers the licence question for a standard-library
// coordinate from the recorded custody chain.
//
// The SPDX resolution is walkdomain.StdlibLicense — the one rule audit, the
// SBOM and license-compat already apply — so a reader added here cannot
// disagree with them about what the standard library is licensed under. What
// this adds is the coordinate-scoped lookup those three did not need: they
// hold a walk node carrying the facts, and a command given only
// `stdlib@<version>` has to ask the ledger for them.
func resolveStdlibLicence(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	custody StdlibCustodyReader,
) (stdlibLicence, error) {
	out := stdlibLicence{
		Coordinate: coord,
		GoVersion:  stdlibdomain.CanonicalGoVersion(coord.Version()),
	}

	var facts *walkdomain.StdlibFacts
	if custody != nil && out.GoVersion != "" {
		rec, found, err := custody.Get(ctx, out.GoVersion)
		if err != nil {
			return stdlibLicence{}, fmt.Errorf(
				"reading the standard-library chain of custody for %s: %w", out.GoVersion, err)
		}
		if found {
			out.Verification = string(rec.VerificationStatus)
			out.Detail = rec.VerificationDetail
			out.Route = rec.AcquisitionRoute.String()
			out.SourceURL, out.VCSURL = rec.SourceURL, rec.VCSURL
			out.VCSRef, out.VCSCommit = rec.VCSRef, rec.VCSCommit
			out.SHA256 = rec.Digests.SHA256
			out.AcquiredAt = rec.AcquiredAt
			facts = &walkdomain.StdlibFacts{
				LicenseSPDX:        rec.LicenseSPDX,
				VerificationStatus: string(rec.VerificationStatus),
			}
		}
	}

	spdx, fromFacts := walkdomain.StdlibLicense(facts)
	out.SPDX = spdx
	out.Basis = stdlibLicenceBasisKnown
	if fromFacts {
		out.Basis = stdlibLicenceBasisTarball
	}
	return out, nil
}

// basisStatement renders what the answer rests on, in one clause a reader can
// act on without holding the store open.
func (s stdlibLicence) basisStatement() string {
	if !s.Established() {
		return "published knowledge of the Go project's licence; no chain of custody is recorded for " +
			s.GoVersion + " — establish one with: " + stdlibCustodyRemedy
	}
	if s.Basis == stdlibLicenceBasisTarball {
		return "extracted from the acquired source tree's LICENSE file (" + s.Verification + ")"
	}
	return "published knowledge of the Go project's licence; the recorded measurement (" +
		s.Verification + ") identified none"
}
