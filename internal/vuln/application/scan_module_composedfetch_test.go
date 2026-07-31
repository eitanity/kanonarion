package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// The vuln stage's failure mode is quieter than licence's and worse. Its fetch
// lookup returning "not found" is not an error: Scan reads it as "the module's
// source is not in the store" and routes to a metadata-only verdict whose note
// says the module was never fetched. For a module measured only under a retired
// fetch pipeline version that note was false — the zip was in the blob store —
// and the resulting record is indistinguishable from a deliberate coverage limit,
// so it reads downstream as a genuine reason call-graph reachability is absent.
//
// A loud refusal an operator can act on is recoverable. This is not, which is why
// the site is included in the fix rather than left as the smaller of the two.
func TestScanModule_ScansSourceForAModuleMeasuredUnderARetiredFetchVersion(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("example.com/retiredfetch", "v1.6.0")
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()

	seed := []fetchtest.Option{
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("retired-fetch-0.0.1"),
		fetchtest.Content("zip content"),
		fetchtest.Status(fetchdomain.Verified),
	}
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, fetchtest.Record(t, seed...)), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, seed...)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, &fakeScanner{}, &fakeDatabase{
			snapshot: vulntest.MustNewAt("test", "v1", now),
			content:  "vulndb content",
		}, nil, fixedClock{t: now}, "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-retired-fetch",
		Force:      true, // skip the metadata pre-filter so the source path runs
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscannableReason != "" {
		t.Errorf("UnscannableReason = %q, want empty — the module's source is in the blob store, so a metadata-only verdict asserts something false about it",
			res.UnscannableReason)
	}
	// The verdict written to the ledger, not just the in-flight result: a record
	// that says "Unscannable" is what a downstream reader sees, and it would read
	// as a genuine coverage limit rather than as a lookup that asked the wrong
	// question.
	if coverage, _ := vulndomain.RecordAxes(res); coverage != vulndomain.CoverageAnalysed {
		t.Errorf("coverage axis = %q, want %q", coverage, vulndomain.CoverageAnalysed)
	}
}
