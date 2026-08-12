package fetchfacts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/origin/fetchfacts"
)

// fakeFacts is a FactStore that composes from a fixed table.
type fakeFacts struct {
	records map[coordinate.ModuleCoordinate]fetchdomain.FactRecord
	err     error
}

func (f *fakeFacts) PutFetchRecord(context.Context, fetchdomain.SealedRecord) error { return nil }

func (f *fakeFacts) GetFetchRecord(
	context.Context, coordinate.ModuleCoordinate, string,
) (fetchdomain.CompositeRecord, bool, error) {
	return fetchdomain.CompositeRecord{}, false, nil
}

func (f *fakeFacts) ComposeFetchRecord(
	_ context.Context, coord coordinate.ModuleCoordinate,
) (fetchdomain.CompositeRecord, bool, error) {
	if f.err != nil {
		return fetchdomain.CompositeRecord{}, false, f.err
	}
	rec, ok := f.records[coord]
	if !ok {
		return fetchdomain.CompositeRecord{}, false, nil
	}
	return fetchdomain.CompositeRecord{FactRecord: rec}, true, nil
}

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestOnlyACrossVerifiedRecordYieldsAnOrigin pins the gate. A fact record can
// carry a git URL that nothing confirmed — it is inferred from the module path
// when the proxy supplies no Origin metadata, and it survives in the record when
// the VCS leg could not run. Emitting that would put a guess into a shipped
// document wearing the appearance of a measurement.
func TestOnlyACrossVerifiedRecordYieldsAnOrigin(t *testing.T) {
	verified := mustCoord(t, "github.com/example/ok", "v1.0.0")
	sumdbOnly := mustCoord(t, "github.com/example/novcs", "v1.0.0")
	noURL := mustCoord(t, "github.com/example/nourl", "v1.0.0")
	noCommit := mustCoord(t, "github.com/example/nocommit", "v1.0.0")
	absent := mustCoord(t, "github.com/example/absent", "v1.0.0")

	facts := &fakeFacts{records: map[coordinate.ModuleCoordinate]fetchdomain.FactRecord{
		verified: {
			VerificationStatus: string(fetchdomain.Verified),
			GitURL:             "https://github.com/example/ok",
			GitRef:             "refs/tags/v1.0.0",
			GitCommitHash:      "abcdef0123456789abcdef0123456789abcdef01",
		},
		sumdbOnly: {
			// The URL was inferred and the VCS check never confirmed it.
			VerificationStatus: string(fetchdomain.VerifiedBySumDBOnly),
			GitURL:             "https://github.com/example/novcs",
			GitCommitHash:      "abcdef0123456789abcdef0123456789abcdef01",
		},
		noURL: {
			VerificationStatus: string(fetchdomain.Verified),
			GitCommitHash:      "abcdef0123456789abcdef0123456789abcdef01",
		},
		noCommit: {
			VerificationStatus: string(fetchdomain.Verified),
			GitURL:             "https://github.com/example/nocommit",
		},
	}}
	r := fetchfacts.New(facts)

	origin, ok, err := r.ModuleOrigin(t.Context(), verified)
	if err != nil {
		t.Fatalf("ModuleOrigin(verified): %v", err)
	}
	if !ok {
		t.Fatal("cross-verified record yielded no origin")
	}
	if origin.VCSURL != "https://github.com/example/ok" ||
		origin.VCSRef != "refs/tags/v1.0.0" ||
		origin.VCSCommit != "abcdef0123456789abcdef0123456789abcdef01" {
		t.Errorf("origin = %+v, want the recorded repository, ref and commit", origin)
	}

	for name, coord := range map[string]coordinate.ModuleCoordinate{
		"verified by sumdb only": sumdbOnly,
		"no git url":             noURL,
		"no commit":              noCommit,
		"no record at all":       absent,
	} {
		got, found, gerr := r.ModuleOrigin(t.Context(), coord)
		if gerr != nil {
			t.Errorf("ModuleOrigin(%s): %v", name, gerr)
			continue
		}
		if found || !got.IsZero() {
			t.Errorf("ModuleOrigin(%s) = (%+v, %v), want no origin", name, got, found)
		}
	}
}

// TestReadFailureIsReported verifies a store that cannot answer is reported
// rather than read as "nothing recorded". The two are different claims, and only
// one of them belongs in a document that leaves the building.
func TestReadFailureIsReported(t *testing.T) {
	boom := errors.New("ledger disagrees with itself")
	r := fetchfacts.New(&fakeFacts{err: boom})
	_, _, err := r.ModuleOrigin(t.Context(), mustCoord(t, "github.com/example/x", "v1.0.0"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the store failure", err)
	}
}
