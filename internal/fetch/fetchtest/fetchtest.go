// Package fetchtest builds fetch fact records for tests. Import it from any
// test in the module that needs a FactRecord; it is a normal package rather
// than a _test one for the same reason internal/cli/testfakes is.
//
// A test should say what is interesting about the record it needs and nothing
// else. Record covers the valid case and seals the record itself, so no test
// calls CanonicalHasher.SetContentHash by hand; Unsealed and Tampered cover the
// two ways a record can be invalid, so a test that exists to prove an invalid
// record is rejected keeps proving it. Reaching for Record where Unsealed or
// Tampered is meant leaves such a test green while it tests nothing — the
// builder cannot detect that, so choose deliberately.
//
// The records produced here are byte-for-byte what the fetch pipeline persists:
// the defaults, the go.mod-only shape and the module-hash serialisation all
// follow domain.NewFactRecord rather than approximating it.
package fetchtest

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Option configures the record a builder produces. Options are applied in the
// order given, before the record is sealed.
type Option func(*domain.FactRecord)

// Record returns a valid, sealed fact record: schema version and ecosystem are
// set, every option has been applied, and ContentHash covers the result. It is
// what a test wants whenever the record is a fixture rather than the subject.
func Record(t testing.TB, opts ...Option) domain.FactRecord {
	t.Helper()
	sealed, err := domain.CanonicalHasher{}.SetContentHash(build(opts))
	if err != nil {
		t.Fatalf("fetchtest: sealing record: %v", err)
	}
	return sealed
}

// Unsealed returns a record with no content hash at all. Use it for tests that
// prove an unsealed record is rejected — Record would seal it and the test
// would pass without exercising the guard.
func Unsealed(t testing.TB, opts ...Option) domain.FactRecord {
	t.Helper()
	r := build(opts)
	r.ContentHash = ""
	return r
}

// TamperDetail is the verification detail Tampered writes after sealing. It is
// the mutated field because it is covered by the canonical hash yet is part of
// neither the store key nor any status assertion, so tampering is visible to
// the integrity check without disturbing how the record is looked up.
const TamperDetail = "tampered after sealing"

// Tampered returns a sealed record whose body was altered afterwards, so its
// stored content hash no longer recomputes. Use it for tests that prove a
// mutated record is rejected; Record would return a self-consistent record and
// the test would pass while testing nothing.
func Tampered(t testing.TB, opts ...Option) domain.FactRecord {
	t.Helper()
	r := Record(t, opts...)
	r.VerificationDetail = TamperDetail
	return r
}

// build applies opts to a record carrying the invariant fields every persisted
// record has. Everything else stays zero unless an option sets it: a default
// coordinate or timestamp would be a value no test asked for.
func build(opts []Option) domain.FactRecord {
	r := domain.FactRecord{
		SchemaVersion: domain.SchemaVersion,
		Ecosystem:     domain.EcosystemGo,
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

// H1 is the h1 module hash of value, the only algorithm current Go toolchains
// produce. It exists so callers pass a hash rather than a pre-formatted string
// and the ":" separator stays the domain's business.
func H1(value string) domain.ModuleHash {
	return domain.ModuleHash{Algorithm: "h1", Value: value}
}

// Coordinate sets the module path and version.
func Coordinate(c coordinate.ModuleCoordinate) Option {
	return func(r *domain.FactRecord) {
		r.ModulePath = c.Path
		r.ModuleVersion = c.Version
	}
}

// Module sets the module path and version from their parts.
func Module(path, version string) Option {
	return Coordinate(coordinate.ModuleCoordinate{Path: path, Version: version})
}

// Path sets the module path, leaving the version as it is. It is for the tests
// whose subject is the path alone.
func Path(path string) Option {
	return func(r *domain.FactRecord) { r.ModulePath = path }
}

// PipelineVersion sets the pipeline version the record is filed under.
func PipelineVersion(v string) Option {
	return func(r *domain.FactRecord) { r.PipelineVersion = v }
}

// Status sets the verification status.
func Status(s domain.VerificationStatus) Option {
	return func(r *domain.FactRecord) { r.VerificationStatus = string(s) }
}

// Detail sets the verification detail that explains the status.
func Detail(d string) Option {
	return func(r *domain.FactRecord) { r.VerificationDetail = d }
}

// Content sets the blob handle the module zip is stored under.
func Content(handle string) Option {
	return func(r *domain.FactRecord) { r.ContentLocation = handle }
}

// GoMod sets the blob handle the standalone go.mod is stored under.
func GoMod(handle string) Option {
	return func(r *domain.FactRecord) { r.GoModLocation = handle }
}

// GoModOnly shapes the record as the go.mod-only acquisition path produces it:
// the go.mod is stored while the zip was never fetched, so ContentLocation is
// empty and no module hash was computed.
//
// The absent module hash is written as ":" rather than "": domain.NewFactRecord
// stores ModuleHash.String(), which is Algorithm + ":" + Value, so a zero hash
// serialises as the bare separator. Records already in the store carry that
// value, and absence is tested with ModuleHash.IsZero(), so writing "" here
// would make the fixture diverge from both production and the persisted data.
func GoModOnly(goModHandle string) Option {
	return func(r *domain.FactRecord) {
		r.ContentLocation = ""
		r.GoModLocation = goModHandle
		r.ModuleHash = domain.ModuleHash{}.String()
	}
}

// ModuleHash sets the h1 hash of the module zip.
func ModuleHash(h domain.ModuleHash) Option {
	return func(r *domain.FactRecord) { r.ModuleHash = h.String() }
}

// GoModHash sets the h1 hash of the module's go.mod.
func GoModHash(h domain.ModuleHash) Option {
	return func(r *domain.FactRecord) { r.GoModHash = h.String() }
}

// Digests sets the raw artefact digests of the module zip.
func Digests(d domain.ArtifactDigests) Option {
	return func(r *domain.FactRecord) {
		r.ZipSHA256 = d.SHA256
		r.ZipSHA384 = d.SHA384
		r.ZipSHA512 = d.SHA512
	}
}

// GitReference sets the VCS provenance the record was cross-verified against.
func GitReference(g domain.GitReference) Option {
	return func(r *domain.FactRecord) {
		r.GitURL = g.URL
		r.GitRef = g.Ref
		r.GitCommitHash = g.CommitHash
	}
}

// AcquisitionMode sets the path the module's bytes arrived by, which is what
// makes the content handle resolvable.
func AcquisitionMode(m domain.AcquisitionMode) Option {
	return func(r *domain.FactRecord) { r.AcquisitionMode = string(m) }
}

// FetchedAt sets the measurement time, stored in UTC as the record does.
func FetchedAt(at time.Time) Option {
	return func(r *domain.FactRecord) { r.FetchedAt = at.UTC().Truncate(0) }
}

// Retracted marks the module version as retracted by its author.
func Retracted(retracted bool) Option {
	return func(r *domain.FactRecord) { r.Retracted = retracted }
}

// SumDBLookupFailed marks the record's checksum-database lookup as having
// failed rather than answered, which is what makes it ineligible as a cache hit.
func SumDBLookupFailed(failed bool) Option {
	return func(r *domain.FactRecord) { r.SumDBLookupFailed = failed }
}

// SchemaVersion overrides the schema version. It is for tests whose subject is
// the schema field itself; every other record should carry the current version
// the default supplies.
func SchemaVersion(v string) Option {
	return func(r *domain.FactRecord) { r.SchemaVersion = v }
}

// Ecosystem overrides the ecosystem. It is for tests that prove a foreign
// ecosystem is rejected; kanonarion only ever writes domain.EcosystemGo.
func Ecosystem(e string) Option {
	return func(r *domain.FactRecord) { r.Ecosystem = e }
}
