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
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
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

// Sealed returns the same record as Record, wrapped in the SealedRecord the
// fact store accepts for writing. It is the counterpart the append-only ledger
// needs: PutFetchRecord takes only a sealed record, so a test that seeds a store
// goes through here rather than hand-rolling the seal.
//
// It takes testing.TB, not *testing.T, so the walk fakes and the vulnerability
// benchmark — neither of which has a *testing.T — can seed records too.
func Sealed(t testing.TB, opts ...Option) domain.SealedRecord {
	t.Helper()
	sealed, err := domain.Rehydrate(Record(t, opts...))
	if err != nil {
		t.Fatalf("fetchtest: sealing record: %v", err)
	}
	return sealed
}

// Composite returns the composed view of a single measurement — what a reader
// gets back from the store for an artefact measured once. It is what a test
// wants wherever production now hands out a CompositeRecord and the test's
// subject is the record's contents rather than the composition itself.
func Composite(t testing.TB, opts ...Option) domain.CompositeRecord {
	t.Helper()
	c, err := domain.Compose([]domain.FactRecord{Record(t, opts...)})
	if err != nil {
		t.Fatalf("fetchtest: composing record: %v", err)
	}
	return c
}

// ZipIdentity returns the blob identity of the record's module zip, failing the
// test when the record describes no zip. Tests that seed a blob store must key
// the bytes by identity, because that is how production asks for them.
func ZipIdentity(t testing.TB, r domain.FactRecord) ports.BlobIdentity {
	t.Helper()
	identity, ok, err := ports.ZipIdentity(r)
	if err != nil {
		t.Fatalf("fetchtest: deriving zip identity: %v", err)
	}
	if !ok {
		t.Fatalf("fetchtest: record for %s carries no module zip; set ModuleHash", r.Coordinate())
	}
	return identity
}

// GoModIdentity returns the blob identity of the record's standalone go.mod,
// failing the test when the record carries no go.mod hash.
func GoModIdentity(t testing.TB, r domain.FactRecord) ports.BlobIdentity {
	t.Helper()
	identity, ok, err := ports.GoModIdentity(r)
	if err != nil {
		t.Fatalf("fetchtest: deriving go.mod identity: %v", err)
	}
	if !ok {
		t.Fatalf("fetchtest: record for %s carries no go.mod hash; set GoModHash", r.Coordinate())
	}
	return identity
}

// MeasurementKind sets what the measurement did — acquired or revalidated.
func MeasurementKind(k domain.MeasurementKind) Option {
	return func(r *domain.FactRecord) { r.MeasurementKind = string(k) }
}

// SumDBCheck sets how the measurement came by its checksum-database leg, and
// source names the record it was inherited from (empty when rechecked).
func SumDBCheck(p domain.LegProvenance, source string) Option {
	return func(r *domain.FactRecord) {
		r.SumDBCheck = string(p)
		r.SumDBCheckSource = source
	}
}

// VCSCheck sets how the measurement came by its VCS cross-verification leg, and
// source names the record it was inherited from (empty when rechecked). Leaving
// it unset is how a --skip-vcs run is represented: the leg is absent, which is a
// different claim from a check that ran and could not confirm.
func VCSCheck(p domain.LegProvenance, source string) Option {
	return func(r *domain.FactRecord) {
		r.VCSCheck = string(p)
		r.VCSCheckSource = source
	}
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
//
// It panics on a value the domain refuses, and takes no testing.TB in order to
// do so: hashes are built in table-driven cases and package-level vars where no
// testing handle is in scope, on the same terms as coordinatetest.MustNew. A
// panic here is a bad fixture, reported with a stack trace pointing at it.
func H1(value string) domain.ModuleHash {
	return Hash("h1", value)
}

// Hash is the module hash of value under algorithm, for the tests whose subject
// is an artefact hashed by something other than h1 — a stdlib source tarball
// addressed by its SHA-256, say. It panics on a hash the domain refuses; see
// H1 for why it takes no testing.TB.
func Hash(algorithm, value string) domain.ModuleHash {
	h, err := domain.NewModuleHash(algorithm, value)
	if err != nil {
		panic(fmt.Sprintf("fetchtest: invalid module hash %s:%s: %v", algorithm, value, err))
	}
	return h
}

// ZipArtefact is the artefact identity of a module zip with the h1 hash of
// value, and GoModArtefact the identity of a go.mod-only measurement. They are
// for the tests whose subject is an identity rather than the record carrying
// one; a test that has a record should derive the identity from it with
// domain.ArtefactIdentityOf, which is what production does.
//
// Both go through domain.ParseArtefactIdentity, so a fixture identity is one
// the reader can read — a hand-built value object could claim a shape the
// parser rejects and no test would notice.
func ZipArtefact(value string) domain.ArtefactIdentity {
	return artefact("zip", H1(value))
}

// GoModArtefact is the artefact identity of a go.mod-only measurement whose
// go.mod has the h1 hash of value. See ZipArtefact.
func GoModArtefact(value string) domain.ArtefactIdentity {
	return artefact("gomod", H1(value))
}

// Blob is the blob identity of one artefact of a module version, for the tests
// that key a fake blob store directly rather than deriving the address from a
// record. A test that has a record should use ZipIdentity or GoModIdentity,
// which is the route production takes.
//
// It goes through ports.NewBlobIdentity, so a fixture identity is one the
// constructor accepts, and it panics rather than taking a testing.TB for the
// reason H1 does — identities are built in table cases and package-level vars
// where no testing handle is in scope.
func Blob(kind ports.BlobKind, hash domain.ModuleHash) ports.BlobIdentity {
	identity, err := ports.NewBlobIdentity(kind, hash)
	if err != nil {
		panic(fmt.Sprintf("fetchtest: invalid blob identity %s:%s: %v", kind, hash, err))
	}
	return identity
}

// artefact parses the persisted spelling of an identity at the given depth,
// panicking on one the domain refuses.
func artefact(prefix string, hash domain.ModuleHash) domain.ArtefactIdentity {
	identity, err := domain.ParseArtefactIdentity(prefix + ":" + hash.String())
	if err != nil {
		panic(fmt.Sprintf("fetchtest: invalid artefact identity %s:%s: %v", prefix, hash, err))
	}
	return identity
}

// Coordinate sets the module path and version.
func Coordinate(c coordinate.ModuleCoordinate) Option {
	return func(r *domain.FactRecord) {
		r.ModulePath = c.Path()
		r.ModuleVersion = c.Version()
	}
}

// Module sets the module path and version from their parts.
func Module(path, version string) Option {
	return Coordinate(coordinatetest.MustNew(path, version))
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

// Content records where a measurement put the module zip, and gives the record
// a module hash to be addressed by when it has none.
//
// The location is provenance only — production stores an artefact under the
// identity it measured, and a store either holds that identity or does not — so
// a record carrying a content location must also carry the zip hash that
// identifies it. Deriving one here from the handle keeps that invariant without
// every caller having to state a hash it does not care about; a caller that does
// care sets ModuleHash explicitly, and this leaves it alone.
func Content(handle string) Option {
	return func(r *domain.FactRecord) {
		r.ContentLocation = handle
		if handle != "" && r.ModuleHash == "" {
			r.ModuleHash = H1(handle).String()
		}
	}
}

// GoMod records where a measurement put the standalone go.mod, and gives the
// record a go.mod hash to be addressed by when it has none. See Content.
func GoMod(handle string) Option {
	return func(r *domain.FactRecord) {
		r.GoModLocation = handle
		if handle != "" && r.GoModHash == "" {
			r.GoModHash = H1(handle).String()
		}
	}
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
		if r.GoModHash == "" {
			r.GoModHash = H1(goModHandle).String()
		}
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
