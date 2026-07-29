package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

type spec struct {
	route  domain.AcquisitionRoute
	status domain.VerificationStatus
	sha    string
	at     time.Time
	commit string
}

func measurement(t *testing.T, s spec) domain.Facts {
	t.Helper()
	sha := s.sha
	if sha == "" {
		sha = "sha-of-the-tarball"
	}
	at := s.at
	if at.IsZero() {
		at = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	f := domain.Facts{
		GoVersion:          "go1.26.5",
		Digests:            fetchdomain.ArtifactDigests{SHA256: sha, SHA384: sha + "-384", SHA512: sha + "-512"},
		VerificationStatus: s.status,
		AcquisitionRoute:   s.route,
		VCSCommit:          s.commit,
		AcquiredAt:         at,
	}
	if s.status == domain.VerifiedGoDevChecksum {
		f.PublishedSHA256 = sha
	}
	out, err := domain.FactsHasher{}.SetContentHash(f)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return out
}

// TestCompose_DefiniteAnchorOutranksRecency is the defect this conversion exists
// for, stated as a unit.
//
// A run that could not reach go.dev/dl states nothing about the published
// checksum. It must not displace a run that matched it, however much later it
// was taken.
func TestCompose_DefiniteAnchorOutranksRecency(t *testing.T) {
	t.Parallel()
	verified := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.VerifiedGoDevChecksum,
		at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	// Deliberately newer on every other axis, so a pass can only come from the
	// anchor ladder.
	unavailable := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.UnverifiedGoDevUnavailable,
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.Facts{verified, unavailable}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Fatalf("composed read served %q; a transient failure displaced a verified anchor", got.VerificationStatus)
	}
}

// TestCompose_MismatchIsEvidenceNotAWeakerVerification pins the rung a naive
// ladder gets wrong.
//
// A checksum mismatch is tamper evidence. Ranking it below "the manifest was
// unavailable" would let a later run that simply could not reach go.dev bury it —
// the finding decaying to a non-finding with no stated reason.
func TestCompose_MismatchIsEvidenceNotAWeakerVerification(t *testing.T) {
	t.Parallel()
	mismatch := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.GoDevChecksumMismatch,
		at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	unavailable := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.UnverifiedGoDevUnavailable,
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	got, err := domain.Compose([]domain.Facts{mismatch, unavailable}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.VerificationStatus != domain.GoDevChecksumMismatch {
		t.Fatal("a later unavailable-anchor run buried a checksum mismatch")
	}
}

// TestCompose_TwoDefiniteAndOpposingAnswersAreAConflict: the same bytes cannot
// both match and not match the published checksum.
func TestCompose_TwoDefiniteAndOpposingAnswersAreAConflict(t *testing.T) {
	t.Parallel()
	verified := measurement(t, spec{route: domain.RouteGoDev, status: domain.VerifiedGoDevChecksum})
	mismatch := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.GoDevChecksumMismatch,
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	_, err := domain.Compose([]domain.Facts{verified, mismatch}, domain.ComposeRequest{})
	var conflict domain.FactsConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a FactsConflict", err)
	}
	if conflict.Field != "verification_status" {
		t.Fatalf("conflict field = %q, want verification_status", conflict.Field)
	}
}

// TestCompose_DifferentBytesAreAConflict: one toolchain version and one route
// yielding two digests means Go republished the tarball or a download was
// corrupt. Nothing orders answers about different bytes.
func TestCompose_DifferentBytesAreAConflict(t *testing.T) {
	t.Parallel()
	a := measurement(t, spec{route: domain.RouteGoDev, status: domain.VerifiedGoDevChecksum, sha: "bytes-a"})
	b := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.VerifiedGoDevChecksum, sha: "bytes-b",
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	_, err := domain.Compose([]domain.Facts{a, b}, domain.ComposeRequest{})
	var conflict domain.FactsConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a FactsConflict", err)
	}
	if conflict.Field != "artefact_identity" {
		t.Fatalf("conflict field = %q, want artefact_identity", conflict.Field)
	}
}

// TestCompose_RouteIsADimensionNotALadder: the published tarball and the local
// toolchain's source tree are different bytes answering different questions, so
// composition must never serve one for the other.
func TestCompose_RouteIsADimensionNotALadder(t *testing.T) {
	t.Parallel()
	// The local measurement is newer AND equally definite, so if the route were
	// laddered it could win the unscoped read.
	godev := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.VerifiedGoDevChecksum, sha: "tarball",
		at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	local := measurement(t, spec{
		route: domain.RouteLocalToolchain, status: domain.VerifiedLocalToolchain, sha: "goroot-src",
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.Facts{godev, local}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.AcquisitionRoute != domain.RouteGoDev {
		t.Fatal("the unscoped read served the local toolchain; the default is the published tarball")
	}

	scoped, err := domain.Compose([]domain.Facts{godev, local},
		domain.ComposeRequest{Route: domain.RouteLocalToolchain})
	if err != nil {
		t.Fatalf("Compose(local): %v", err)
	}
	if scoped.AcquisitionRoute != domain.RouteLocalToolchain {
		t.Fatal("naming the local route did not select the local measurement")
	}
}

// TestCompose_DifferentRoutesAreNotAnIdentityConflict. Two routes legitimately
// digest different bytes — a tarball is an archive, $GOROOT/src is a directory —
// so grouping by route BEFORE checking identity is what stops every mixed store
// reporting a false divergence.
func TestCompose_DifferentRoutesAreNotAnIdentityConflict(t *testing.T) {
	t.Parallel()
	godev := measurement(t, spec{route: domain.RouteGoDev, status: domain.VerifiedGoDevChecksum, sha: "tarball"})
	local := measurement(t, spec{route: domain.RouteLocalToolchain, status: domain.VerifiedLocalToolchain, sha: "goroot-src"})
	if _, err := domain.Compose([]domain.Facts{godev, local}, domain.ComposeRequest{}); err != nil {
		t.Fatalf("two routes reported as an identity conflict: %v", err)
	}
}

// TestCompose_LocalAnswersWhenNoPublishedMeasurementExists: an offline-only store
// must still get an answer.
func TestCompose_LocalAnswersWhenNoPublishedMeasurementExists(t *testing.T) {
	t.Parallel()
	local := measurement(t, spec{route: domain.RouteLocalToolchain, status: domain.VerifiedLocalToolchain})
	got, err := domain.Compose([]domain.Facts{local}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.AcquisitionRoute != domain.RouteLocalToolchain {
		t.Fatal("an offline-only ledger produced no answer")
	}
}

// TestCompose_ARecordNamingNoRouteIsLadderedNotSegregated is the upgrade-path
// guard.
//
// Every row written before the route existed names none — which is every row in
// an un-migrated store. Treating those as their own group would mean the FIRST
// re-acquisition lands in a different group from the measurement it should be
// laddered against, and a failed re-acquisition would then displace a verified
// one. That is the exact defect this ticket removes, reintroduced by the fix for
// a different one; it was found this way once already, on the call-graph ledger.
func TestCompose_ARecordNamingNoRouteIsLadderedNotSegregated(t *testing.T) {
	t.Parallel()
	legacy := measurement(t, spec{status: domain.VerifiedGoDevChecksum, at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	failed := measurement(t, spec{
		route: domain.RouteGoDev, status: domain.UnverifiedGoDevUnavailable,
		at: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	got, err := domain.Compose([]domain.Facts{legacy, failed}, domain.ComposeRequest{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Fatal("a failed re-acquisition displaced a verified measurement that named no route")
	}
}

// TestCompose_UnknownRouteIsRefusedRatherThanGuessed: a route this build cannot
// name must not be quietly grouped with one it can.
func TestCompose_UnknownRouteIsRefusedRatherThanGuessed(t *testing.T) {
	t.Parallel()
	alien := measurement(t, spec{route: domain.AcquisitionRoute("from-the-future"), status: domain.VerifiedGoDevChecksum})
	_, err := domain.Compose([]domain.Facts{alien}, domain.ComposeRequest{})
	var conflict domain.FactsConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a FactsConflict", err)
	}
	if !strings.Contains(conflict.Error(), "from-the-future") {
		t.Fatalf("the conflict must name the route it could not read: %s", conflict.Error())
	}
}

// TestCompose_NoRecords reports the programming error rather than an empty
// answer: absence is the store's word, not composition's.
func TestCompose_NoRecords(t *testing.T) {
	t.Parallel()
	if _, err := domain.Compose(nil, domain.ComposeRequest{}); !errors.Is(err, domain.ErrNoFactsToCompose) {
		t.Fatalf("err = %v, want ErrNoFactsToCompose", err)
	}
}

// TestServesAsCacheHit is the read-side home of the rule a persisted
// "the lookup failed" flag would otherwise carry.
//
// A measurement whose anchor was never consulted is a record of a run that could
// not establish custody, not a fact about the toolchain. Serving it from cache is
// what turned one transient go.dev failure into a permanent downgrade surviving
// every later run until --force.
func TestServesAsCacheHit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status domain.VerificationStatus
		want   bool
	}{
		{domain.VerifiedGoDevChecksum, true},
		{domain.GoDevChecksumMismatch, true},  // definite, and evidence worth keeping
		{domain.VerifiedLocalToolchain, true}, // definite about the bytes it read
		{domain.UnverifiedGoDevUnavailable, false},
		{domain.VerificationStatus(""), false}, // states nothing at all
	}
	for _, tc := range cases {
		f := measurement(t, spec{route: domain.RouteGoDev, status: tc.status})
		if got := domain.ServesAsCacheHit(f); got != tc.want {
			t.Errorf("ServesAsCacheHit(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// TestArtefactIdentity_IsTheDigestNotThePublishedChecksum pins the choice the
// ticket's own analysis turns on.
//
// Using PublishedSHA256 as identity would be wrong in exactly the case that
// matters most: a local-toolchain measurement consults no published checksum, so
// every offline record would collapse onto one empty identity — and a mismatch
// record would be filed under the bytes it did NOT describe.
func TestArtefactIdentity_IsTheDigestNotThePublishedChecksum(t *testing.T) {
	t.Parallel()
	local := measurement(t, spec{route: domain.RouteLocalToolchain, status: domain.VerifiedLocalToolchain, sha: "goroot-src"})
	if local.PublishedSHA256 != "" {
		t.Fatal("premise broken: a local measurement must consult no published checksum")
	}
	if got := domain.ArtefactIdentity(local); got != "goroot-src" {
		t.Fatalf("ArtefactIdentity = %q, want the artefact's own digest", got)
	}

	mismatch := measurement(t, spec{route: domain.RouteGoDev, status: domain.GoDevChecksumMismatch, sha: "what-we-got"})
	mismatch.PublishedSHA256 = "what-was-published"
	if got := domain.ArtefactIdentity(mismatch); got != "what-we-got" {
		t.Fatalf("ArtefactIdentity = %q — a mismatch must be filed under the bytes it describes", got)
	}
}

// TestAcquisitionRoute_StringNamesTheZeroValue: an empty route rendered as an
// empty string reads to an operator as an absence of route rather than as a
// measurement that did not say.
func TestAcquisitionRoute_StringNamesTheZeroValue(t *testing.T) {
	t.Parallel()
	if got := domain.RouteUnrecorded.String(); got != "not recorded" {
		t.Errorf("zero value renders %q, want %q", got, "not recorded")
	}
}

// TestFactsHasher_UnsealedRecordVerifiesVacuously keeps every pre-seal row
// readable. Refusing them would make an un-migrated store unreadable, which is
// the opposite of what a ledger is for.
func TestFactsHasher_UnsealedRecordVerifiesVacuously(t *testing.T) {
	t.Parallel()
	var h domain.FactsHasher
	unsealed := domain.Facts{GoVersion: "go1.26.5", VerificationStatus: domain.VerifiedGoDevChecksum}
	if err := h.VerifyContentHash(unsealed); err != nil {
		t.Fatalf("a measurement carrying no seal failed verification: %v", err)
	}
	if domain.IsSealed(unsealed) {
		t.Fatal("IsSealed must distinguish 'nothing to verify' from 'verified'")
	}

	sealed, err := h.SetContentHash(unsealed)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if !domain.IsSealed(sealed) {
		t.Fatal("a sealed measurement reports itself unsealed")
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("a freshly sealed measurement failed its own check: %v", err)
	}
	tampered := sealed
	tampered.VCSCommit = "altered-after-sealing"
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Fatal("an altered measurement passed its seal")
	}
}
